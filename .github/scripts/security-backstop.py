#!/usr/bin/env python3
"""Read-only scheduled history and secret-free strict scan reporting.

This helper never gates a run. The independent security_gate CLI owns the
verdict; missing history only removes the comparison, never the strict check.
"""
import argparse
from collections import Counter
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
import zipfile

MAX_BYTES = 8 * 1024 * 1024
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def gh_read(args, timeout=30):
    """Bound each GET/list by elapsed time AND bytes, including archive reads."""
    with subprocess.Popen(["gh", *args], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        assert process.stdout is not None
        deadline = time.monotonic() + timeout
        output = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired("gh", timeout)
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_BYTES:
                        raise ValueError("response too large")
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise ValueError("GitHub read failed")
        except BaseException:
            process.kill()
            process.wait()
            raise
    return bytes(output)


def validate_snapshot(data):
    """Reject corrupt history, including unsupported schemas and provenance."""
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("unsupported snapshot")
    if not re.fullmatch(r"[0-9a-f]{40,64}", str(data.get("commit", ""))):
        raise ValueError("invalid commit")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(data.get("image", ""))):
        raise ValueError("invalid image identity")
    findings, counts = data.get("findings"), data.get("counts")
    if not isinstance(findings, dict) or not isinstance(counts, dict) or findings.keys() != counts.keys():
        raise ValueError("invalid findings")
    for key, severity in findings.items():
        if (not re.fullmatch(r"[0-9a-f]{64}", key) or severity not in SEVERITIES
                or type(counts[key]) is not int or counts[key] < 1):
            raise ValueError("invalid finding")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict) or type(coverage.get("complete")) is not bool:
        raise ValueError("invalid coverage")
    for field in ("selected", "produced", "missing", "excluded_scope", "failure_count"):
        if type(coverage.get(field)) is not int or coverage[field] < 0:
            raise ValueError("invalid coverage count")
    if coverage["complete"] != (coverage["failure_count"] == 0) or (coverage["missing"] and coverage["complete"]):
        raise ValueError("inconsistent completeness")
    severity_counts = data.get("severity_counts")
    if (not isinstance(severity_counts, dict) or set(severity_counts) != set(SEVERITIES)
            or any(type(n) is not int or n < 0 for n in severity_counts.values())
            or sum(severity_counts.values()) != sum(counts.values())):
        raise ValueError("invalid severity counts")
    expected = "fail" if (not coverage["complete"] or any(
        severity_counts[s] for s in ("HIGH", "CRITICAL"))) else "pass"
    if data.get("strict_verdict") != expected:
        raise ValueError("inconsistent strict verdict")
    return data


def retrieve(repository, fetch=gh_read):
    """At most three reads, 30s/8MiB each; never fall back to older history."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return None, "invalid repository"
    try:
        runs = json.loads(fetch([
            "run", "list", "--repo", repository, "--workflow", "security.yml",
            "--event", "schedule", "--branch", "main", "--status", "completed",
            "--limit", "1", "--json", "databaseId,headSha"]))
        if not runs:
            return None, "no completed scheduled main run (first run)"
        run = runs[0]
        run_id = run["databaseId"]
        if type(run_id) is not int or run_id < 1:
            raise ValueError("invalid run")
        artifacts = json.loads(fetch([
            "api", f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"]))
        matches = [a for a in artifacts["artifacts"]
                   if a.get("name") == "strict-security-snapshot" and not a.get("expired")]
        if len(matches) != 1:
            return None, "previous scheduled snapshot missing or expired"
        artifact_id = matches[0]["id"]
        if type(artifact_id) is not int or artifact_id < 1:
            raise ValueError("invalid artifact")
        raw = fetch(["api", f"repos/{repository}/actions/artifacts/{artifact_id}/zip"])
        if len(raw) > MAX_BYTES:
            raise ValueError("archive too large")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if (len(entries) != 1 or entries[0].filename != "snapshot.json"
                    or entries[0].file_size > MAX_BYTES):
                raise ValueError("invalid archive layout")
            # Never extract a downloaded path onto disk.
            previous = validate_snapshot(json.loads(archive.read(entries[0])))
        if previous["commit"] != run["headSha"]:
            raise ValueError("snapshot commit does not match run")
        return previous, ""
    except Exception:  # History is optional; never turn a transport/decoder error into a verdict.
        return None, "previous snapshot unavailable: API, archive or schema failure"


def build_snapshot(tools_dir, manifest_path, commit, image, excludes):
    # Retrieval runs before dependency installation and the target checkout.
    # Only reporting needs the gate's shared scanner parser.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skill"))
    import scripts.security_gate as gate

    manifest = gate.load_manifest(manifest_path)
    findings, _dispositions, failures, high, _suppressed = gate.evaluate(
        tools_dir, manifest_path, exclude_globs=excludes)
    identities: dict[str, str] = {}
    counts: Counter[str] = Counter()
    severity_counts = Counter({severity: 0 for severity in SEVERITIES})
    for finding in findings:
        key = hashlib.sha256(json.dumps(gate.finding_identity(finding),
                                      ensure_ascii=True).encode()).hexdigest()
        severity = finding["severity"]
        if severity not in SEVERITIES:
            raise ValueError("unknown severity")
        if key not in identities or SEVERITIES.index(severity) > SEVERITIES.index(identities[key]):
            identities[key] = severity
        counts[key] += 1
        severity_counts[severity] += 1
    # Coverage failures' prose may contain raw scanner text. Publish counts,
    # never failure messages, locations, titles or scanner-provided snippets.
    return validate_snapshot({
        "version": 1, "commit": commit, "image": image,
        "coverage": {"complete": not failures, "failure_count": len(failures),
                     **{key: len(manifest[key]) for key in
                        ("selected", "produced", "missing", "excluded_scope")}},
        "strict_verdict": "fail" if failures or high else "pass",
        "gate_severities": sorted(gate.GATE_SEVERITIES),
        "findings": dict(sorted(identities.items())),
        "counts": dict(sorted(counts.items())),
        "severity_counts": dict(severity_counts),
    })


def compare(current, previous):
    now, before = current["findings"], previous["findings"]
    shared = now.keys() & before.keys()
    return {"added": sorted(now.keys() - before.keys()),
            "removed": sorted(before.keys() - now.keys()),
            "regraded": sorted(key for key in shared if now[key] != before[key]),
            "count_changed": sorted(key for key in shared
                                    if current["counts"][key] != previous["counts"][key]),
            "severity_counts": {severity: current["severity_counts"].get(severity, 0)
                                - previous["severity_counts"].get(severity, 0)
                                for severity in SEVERITIES}}


def safe_text(value):
    text = html.escape(" ".join(str(value).split())[:160])
    return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", text)


def render_summary(current, previous, reason):
    coverage = current["coverage"]
    coverage_summary = (
        f"Coverage: {'complete' if coverage['complete'] else 'incomplete'}; "
        f"{coverage['selected']} selected, {coverage['produced']} produced, "
        f"{coverage['missing']} missing, {coverage['failure_count']} failures, "
        f"{coverage['excluded_scope']} excluded by scope.")
    lines = ["## Strict full-tree security backstop", "",
             f"Commit: {safe_text(current['commit'])}",
             f"Image ID: {safe_text(current['image'])}",
             f"Raw strict verdict: **{current['strict_verdict']}** (comparison never changes it).",
             coverage_summary,
             "", "Severity | Current count | Change", "--- | ---: | ---:"]
    delta = compare(current, previous) if previous is not None else None
    for severity in SEVERITIES:
        change = f"{delta['severity_counts'][severity]:+d}" if delta else "unavailable"
        lines.append(f"{severity} | {current['severity_counts'][severity]} | {change}")
    if delta is None:
        lines.extend(["", "Comparison unavailable: " + safe_text(reason)])
    else:
        lines.extend(["", f"Previous scheduled commit: {safe_text(previous['commit'])}."])
        if not coverage["complete"] or not previous["coverage"]["complete"]:
            lines.append("Comparison is partial: current or previous coverage is incomplete; removals do not prove fixes.")
        for kind in ("added", "removed", "regraded", "count_changed"):
            keys = delta[kind]
            lines.extend(["", f"{kind}: {len(keys)} identities (first 20 shown)."])
            for key in keys[:20]:
                if kind == "regraded":
                    detail = f"{previous['findings'][key]} → {current['findings'][key]}"
                elif kind == "count_changed":
                    detail = f"{previous['counts'][key]} → {current['counts'][key]} occurrences"
                else:
                    source = previous if kind == "removed" else current
                    detail = f"{source['findings'][key]}, {source['counts'][key]} occurrences"
                lines.append(f"- {safe_text(key)}: {detail}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    history = sub.add_parser("retrieve")
    history.add_argument("--repository", required=True)
    history.add_argument("--output", type=Path, required=True)
    report = sub.add_parser("report")
    for name in ("tools-dir", "manifest", "image-file", "history", "output", "summary"):
        report.add_argument("--" + name, type=Path, required=True)
    report.add_argument("--commit", required=True)
    report.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)
    if args.command == "retrieve":
        previous, reason = retrieve(args.repository)
        args.output.write_text(json.dumps({"previous": previous, "reason": reason}), encoding="utf-8")
        return 0
    previous, reason = None, "previous history capture missing or corrupt"
    try:
        history_data = json.loads(args.history.read_text(encoding="utf-8"))
        candidate = history_data["previous"]
        history_reason = history_data["reason"]
        if not isinstance(history_reason, str):
            raise ValueError("invalid history reason")
        previous = validate_snapshot(candidate) if candidate is not None else None
        reason = history_reason
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        current = build_snapshot(args.tools_dir, args.manifest, args.commit,
                                 args.image_file.read_text(encoding="utf-8").strip(), args.exclude)
    except (OSError, ValueError):
        with args.summary.open("a", encoding="utf-8") as stream:
            stream.write("## Strict full-tree security backstop\n\nSnapshot unavailable: capture or image provenance is insufficient.\n")
        return 1
    args.output.write_text(json.dumps(current, sort_keys=True) + "\n", encoding="utf-8")
    with args.summary.open("a", encoding="utf-8") as stream:
        stream.write(render_summary(current, previous, reason))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
