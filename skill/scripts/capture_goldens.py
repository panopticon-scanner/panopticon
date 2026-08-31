"""Capture one authentic raw payload per tool adapter, trimmed to a few findings.

Runs INSIDE the fixtures image, where every adapter has a target that actually
produces findings. The output seeds a normalization-contract test, so the
payloads must be real tool output rather than hand-written approximations --
the whole point is to prove parse() handles what the tools really emit.
"""
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, "/opt/panopticon")
from scripts.tools import ADAPTERS  # noqa: E402

F = "/opt/panopticon-fixtures"
TARGETS = {
    "brakeman": f"{F}/railsgoat",
    "bundler-audit": f"{F}/railsgoat",
    "semgrep": f"{F}/railsgoat",
    "spotbugs": f"{F}/WebGoat",
    "dependency-check": f"{F}/WebGoat",
    "roslyn-secguard": f"{F}/AspGoat",
    "cargo-audit": f"{F}/vulnerable-rust",
    "bandit": "/mnt/panopticon",
    "gitleaks": "/mnt/panopticon",
    "trivy": "/mnt/panopticon",
    "osv-scanner": "/src",
    "gosec": "/mnt/gotify",
    "eslint-security": "/src",       # mounted at /src: eslint's flat config
                                     # ignores files outside its base path
    "npm-audit": "/mnt/npmprobe",
    "pip-audit": "/mnt/pipprobe",
}

# Where each format keeps its finding list, so a trim keeps the envelope intact.
LIST_KEYS = ("warnings", "results", "dependencies", "vulnerabilities", "advisories")
KEEP = 3


def _trim_xml(raw: bytes) -> bytes:
    """Keep the first KEEP finding elements of an XML report, still well-formed."""
    try:
        root = ET.fromstring(raw.decode("utf-8", "replace"))  # nosec B314
    except ET.ParseError:
        return raw
    kept = 0
    for child in list(root):
        if child.tag in ("BugInstance", "result", "finding"):
            kept += 1
            if kept > KEEP:
                root.remove(child)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _has_vulns_osv(pkg) -> bool:
    return bool(isinstance(pkg, dict) and pkg.get("vulnerabilities"))


def _has_vulns(entry) -> bool:
    """dependency-check lists every dependency it saw, and most are clean.
    Keeping the first N kept 3 clean ones and produced a golden that parsed to
    ZERO findings -- a golden that proves nothing. Prefer the entries that
    actually carry vulnerabilities."""
    return bool(isinstance(entry, dict) and entry.get("vulnerabilities"))


def trim(raw: bytes) -> bytes:
    """Shrink a payload to a few findings without changing its shape.

    XML is trimmed structurally, never sliced: spotbugs emits a BugCollection
    document, and cutting it at a byte offset produced an unclosed element that
    no longer parsed. A golden that cannot be parsed is worse than a large one,
    but 579 KB of it is not worth committing either -- so drop whole
    BugInstance elements and keep the document well-formed.
    """
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return _trim_xml(raw)
    if isinstance(data, list):
        return json.dumps(data[:KEEP], indent=1).encode()
    if isinstance(data, dict):
        if "runs" in data and isinstance(data["runs"], list):      # SARIF
            data["runs"] = data["runs"][:1]
            for run in data["runs"]:
                if isinstance(run.get("results"), list):
                    run["results"] = run["results"][:KEEP]
                # rules can be enormous; keep enough to resolve the results
                drv = (run.get("tool") or {}).get("driver") or {}
                if isinstance(drv.get("rules"), list):
                    drv["rules"] = drv["rules"][:10]
        else:
            # osv-scanner nests two levels deep (results[].packages[]), so a
            # trim of `results` alone leaves every package behind it -- 243 KB.
            if isinstance(data.get("results"), list) and any(
                    isinstance(r, dict) and "packages" in r for r in data["results"]):
                results = []
                for r in data["results"][:1]:
                    pkgs = r.get("packages") or []
                    vuln_pkgs = [pk for pk in pkgs if _has_vulns_osv(pk)]
                    r = dict(r)
                    r["packages"] = (vuln_pkgs or pkgs)[:KEEP]
                    results.append(r)
                data["results"] = results
            for k in LIST_KEYS:
                v = data.get(k)
                if isinstance(v, list):
                    # Findings-bearing entries first, so the trim cannot leave a
                    # golden that parses to nothing.
                    interesting = [e for e in v if _has_vulns(e)]
                    data[k] = (interesting[:KEEP] if interesting else v[:KEEP])
                elif isinstance(v, dict):
                    data[k] = dict(list(v.items())[:KEEP])
        return json.dumps(data, indent=1).encode()
    return raw


def main():
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    only = sys.argv[2:] or sorted(ADAPTERS)
    report = {}
    for name in only:
        adapter = ADAPTERS.get(name)
        target = TARGETS.get(name)
        if adapter is None or target is None or not os.path.isdir(target):
            report[name] = {"status": "no-target", "target": target}
            continue
        try:
            applicable = adapter.is_applicable(target)
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "is_applicable-error", "error": str(exc)[:120]}
            continue
        if not applicable:
            report[name] = {"status": "not-applicable", "target": target}
            continue
        try:
            raw, rc = adapter.invoke(target)
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "invoke-error", "error": str(exc)[:160]}
            continue
        try:
            parsed = adapter.parse(raw, "Probe")
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "parse-error", "rc": rc,
                            "error": str(exc)[:160], "bytes": len(raw)}
            continue
        small = trim(raw)
        # A trimmed payload must still parse, or the golden is useless.
        try:
            reparsed = adapter.parse(small, "Probe")
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "trim-broke-parse", "error": str(exc)[:160]}
            continue
        with open(os.path.join(out_dir, "%s.raw" % name), "wb") as fh:
            fh.write(small)
        report[name] = {"status": "ok", "rc": rc, "raw_bytes": len(raw),
                        "findings": len(parsed), "golden_bytes": len(small),
                        "golden_findings": len(reparsed)}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
