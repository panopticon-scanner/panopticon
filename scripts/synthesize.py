#!/usr/bin/env python3
"""Merge panopticon finding files into a validated CodeReviewReport with
grades and a CI gate verdict. Stdlib-only.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.citations as citations
from scripts.citations import _compute_citation_quality
import scripts.html_report as html_report
import scripts.ingest_tools as ingest_tools

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CONFIDENCES = {"CERTAIN", "LIKELY", "POSSIBLE", "NOTE"}
VERDICT_TO_CONFIDENCE = {"CONFIRMED": "CERTAIN", "PLAUSIBLE": "LIKELY"}
MODE_TO_REVIEW_TYPE = {
    "repo": "repo", "file": "file", "directory": "directory",
    "group": "group", "files": "changes", "changes": "changes",
}
VALID_PANELS = {"code", "test", "security", "architecture", "database", "redteam"}
PANEL_ORDER = ["code", "test", "security", "architecture", "database", "redteam"]
_ADVISOR_TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agents", "advisor.md")
_KIMI_VERSION_CACHE = {}
RELATED_PANELS = {
    "security": {"architecture", "database", "redteam"},
    "redteam": {"security", "architecture", "database"},
    "architecture": {"security", "redteam"},
    "database": {"security", "redteam"},
}


def load_json_tolerant(body):
    """Parse JSON from text, stripping markdown code blocks and searching for JSON object."""
    body = body.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\s*", "", body)
        body = re.sub(r"\s*```\s*$", "", body).strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\})", body, re.DOTALL)
        if m:
            return json.loads(m.group(1))
        raise


def normalize_finding(f):
    """Normalize and validate finding fields with sensible defaults."""
    sev = str(f.get("severity", "INFO")).upper()
    f["severity"] = sev if sev in SEVERITIES else "INFO"
    conf = str(f.get("confidence", "")).upper()
    if conf in CONFIDENCES:
        f["confidence"] = conf
    else:
        verdict = str(f.get("verdict", "")).upper()
        f["confidence"] = VERDICT_TO_CONFIDENCE.get(verdict, "POSSIBLE")
    if f.get("panel") not in VALID_PANELS:
        f["panel"] = "code"
    lens = f.get("lens")
    if lens:
        f["lens"] = str(lens)
    else:
        f.pop("lens", None)
    if not isinstance(f.get("location"), dict):
        f["location"] = {}
    loc = f["location"]
    loc.setdefault("line_end", loc.get("line_start"))
    loc.setdefault("function", None)
    f.setdefault("references", [])
    f.setdefault("impact", "")
    f.setdefault("remediation", "")
    title = f.get("title")
    if not title:
        desc = str(f.get("description", "")).strip()
        title = desc.splitlines()[0].strip() if desc else "(untitled)"
    f["title"] = " ".join(str(title).split())
    if not f.get("category"):
        f["category"] = "general"
    return f


def load_findings(paths):
    """Load and normalize findings from JSON files."""
    out = []
    for path in paths:
        if not os.path.isfile(path):
            print("MISSING: %s" % path, file=sys.stderr)
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = load_json_tolerant(fh.read())
        except Exception as e:  # noqa: BLE001 - tolerant by design
            print("PARSE ERROR %s: %s" % (path, e), file=sys.stderr)
            continue
        if not isinstance(data, dict):
            print("not a JSON object: %s" % path, file=sys.stderr)
            continue
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            print("no findings list in %s" % path, file=sys.stderr)
            continue
        m = GROUP_RE.match(os.path.basename(path))
        group = m.group(1) if m else None
        for f in findings:
            if not isinstance(f, dict):
                print("skipping non-object finding in %s" % path, file=sys.stderr)
                continue
            nf = normalize_finding(f)
            if group is not None:
                nf["_group"] = group
            out.append(nf)
    return out


def _sev_rank(f):
    try:
        return SEV_ORDER.index(f.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def _conf_rank(f):
    order = ["CERTAIN", "LIKELY", "POSSIBLE", "NOTE"]
    try:
        return order.index(f.get("confidence", "NOTE"))
    except ValueError:
        return len(order)


def _is_tool_sourced(f):
    """Tool-emitted findings carry source='tool:<name>'; agent/panel findings
    carry no source field. Mirrors the provenance convention in validate_report
    and render_summary (anything not 'tool:' is agent-sourced)."""
    return str(f.get("source", "")).startswith("tool:")


def _role_from_discovered_by(discovered_by):
    """Map a provenance discovered_by value to a model role."""
    if not discovered_by:
        return None
    discovered_by = str(discovered_by)
    if discovered_by.startswith("agent:"):
        return discovered_by.split(":", 1)[1]
    return discovered_by


def _collect_models_used(findings):
    """Collect unique model/version/role triples from agent findings.

    Tool findings (model is null) are skipped. Agent findings contribute their
    provenance model/version plus a role derived from discovered_by. Advisor
    confirmations contribute the confirming model with role 'advisor'.
    """
    seen = set()
    out = []
    for f in findings:
        prov = f.get("provenance") or {}
        model = prov.get("model")
        version = prov.get("model_version")
        # Skip tool and other entries without a model identifier.
        if not model:
            continue
        role = _role_from_discovered_by(prov.get("discovered_by"))
        key = (model, version, role)
        if key in seen:
            continue
        seen.add(key)
        entry = {"model": model, "role": role}
        if version:
            entry["version"] = version
        out.append(entry)
        confirmed_by_model = prov.get("confirmed_by_model")
        if confirmed_by_model:
            advisor_key = (confirmed_by_model, None, "advisor")
            if advisor_key not in seen:
                seen.add(advisor_key)
                out.append({"model": confirmed_by_model, "role": "advisor"})
    return out


def _merge_citations(best, other):
    """Merge other['citations'] into best['citations'] without overwriting
    keys that already exist in best."""
    oc = other.get("citations")
    if not oc:
        return
    if not best.get("citations"):
        best["citations"] = {}
    bc = best["citations"]
    for key, value in oc.items():
        if not value:
            continue
        if key not in bc or not bc[key]:
            bc[key] = value


def _reinforce_merge(best, other):
    """Pull missing enrichment from other into best. The agent's cvss and
    exploit_scenario are preferred when either finding has them; other text
    fields are filled only if best lacks them; citations are merged rather
    than overwritten."""
    # Prefer agent-authored cvss/exploit_scenario.
    if not _is_tool_sourced(other):
        for field in ("cvss", "exploit_scenario"):
            if other.get(field):
                best[field] = other[field]
    # Fall back to the other finding for any still-missing enrichment.
    for field in ("cvss", "exploit_scenario", "impact", "remediation", "references"):
        if not best.get(field) and other.get(field):
            best[field] = other[field]
    _merge_citations(best, other)


def _norm_line(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def dedupe(findings):
    """Cluster findings by (file, line). An exactly-two cluster with one tool- and
    one agent-sourced finding is treated as the same issue seen twice (even across
    categories) -> collapse to one reinforced survivor. Larger clusters keep one
    survivor per category — the most severe — never merging across categories (so
    distinct issues at a busy line are not silently lost); a category corroborated
    by BOTH a tool and an agent within such a cluster is still reinforced in place.
    Same file+line+category findings are intentionally deduped to the most severe.
    Findings without a file OR without a concrete integer line pass through
    unmerged (clustering them on file+category alone would drop distinct issues
    that merely omit a line number)."""
    passthrough = []
    by_locus = {}
    order = []
    for f in findings:
        loc = f.get("location") or {}
        fkey = loc.get("file")
        line = _norm_line(loc.get("line_start"))
        if not fkey or not isinstance(line, int):
            passthrough.append(f)
            continue
        key = (fkey, line)
        if key not in by_locus:
            by_locus[key] = []
            order.append(key)
        by_locus[key].append(f)

    result = []
    for key in order:
        group = by_locus[key]
        tool_srcd = [f for f in group if _is_tool_sourced(f)]
        agent_srcd = [f for f in group if not _is_tool_sourced(f)]
        if len(group) == 2 and len(tool_srcd) == 1 and len(agent_srcd) == 1:
            best = min(group, key=lambda f: (_sev_rank(f), _conf_rank(f)))
            other = agent_srcd[0] if _is_tool_sourced(best) else tool_srcd[0]
            best["reinforced"] = True
            best["confidence"] = "CERTAIN"
            _reinforce_merge(best, other)
            result.append(best)
        else:
            by_cat = {}
            corder = []
            for f in group:
                ck = f.get("category")
                if ck not in by_cat:
                    by_cat[ck] = []
                    corder.append(ck)
                by_cat[ck].append(f)
            for ck in corder:
                members = by_cat[ck]
                best = min(members, key=lambda f: (_sev_rank(f), _conf_rank(f)))
                if (any(_is_tool_sourced(m) for m in members)
                        and any(not _is_tool_sourced(m) for m in members)):
                    best["reinforced"] = True
                    best["confidence"] = "CERTAIN"
                    for m in members:
                        if m is best:
                            continue
                        _reinforce_merge(best, m)
                result.append(best)
    return result + passthrough


# Cross-panel corroboration groups findings from DIFFERENT panels at a nearby
# locus. Anchor-bounded so a cluster never spans more than this many lines (no
# transitive chaining); 2 catches adjacent-line citations (e.g. a function def
# vs the vulnerable call inside it) while staying tight against false joins.
CORROBORATION_LINE_WINDOW = 2

# ascending confidence ranks (weakest -> strongest) for a monotonic raise
_CONF_ASC = ["NOTE", "POSSIBLE", "LIKELY", "CERTAIN"]


def _bump_confidence(conf):
    """Raise a confidence one rank (capped at CERTAIN); never lowers it."""
    try:
        idx = _CONF_ASC.index(str(conf).upper())
    except ValueError:
        idx = 0
    return _CONF_ASC[min(idx + 1, len(_CONF_ASC) - 1)]


def _max_severity(findings):
    """Return the most-severe severity label among findings."""
    return min(findings, key=_sev_rank).get("severity", "INFO")


def cross_panel_corroboration(findings, window=CORROBORATION_LINE_WINDOW):
    """Surface cross-LENS agreement WITHOUT collapsing the distinct-lens findings.

    Distinct from dedupe (which collapses true same-lens duplicates and handles
    tool+agent reinforce). Cross-panel corroboration keys on (file, line-proximity)
    across DIFFERENT panels — deliberately NOT on category, because the same real
    issue seen through security/test/code lenses carries different categories by
    nature. When >=2 DISTINCT panels flag a nearby locus, each participating
    finding is annotated in place (`corroborated`/`corroborated_by`, confidence
    bumped one rank) and a summary entry is returned for cross_panel.
    integration_findings. Requiring >=2 distinct panels is the guard against
    false corroboration: two same-panel findings, or findings at different files
    or beyond the line window, do NOT corroborate.
    """
    candidates = []
    for f in findings:
        loc = f.get("location") or {}
        fkey = loc.get("file")
        line = _norm_line(loc.get("line_start"))
        if fkey and isinstance(line, int):
            candidates.append((fkey, line, f))
    candidates.sort(key=lambda t: (t[0], t[1]))

    def _panels_related(p1, p2):
        if p1 == p2:
            return False
        # Panels outside the explicit map retain the legacy behavior: any two
        # distinct panels corroborate (preserves code/test/security pairings).
        if p1 in RELATED_PANELS and p2 in RELATED_PANELS:
            return p2 in RELATED_PANELS[p1] or p1 in RELATED_PANELS[p2]
        return True

    integration = []
    i, n = 0, len(candidates)
    while i < n:
        fkey, anchor = candidates[i][0], candidates[i][1]
        j = i + 1
        # admit while same file and within `window` lines of the anchor (the
        # cluster's lowest line) — bounds cluster width, so no runaway chaining.
        while j < n and candidates[j][0] == fkey and candidates[j][1] - anchor <= window:
            j += 1
        cluster = candidates[i:j]
        members = [c[2] for c in cluster]
        panels = sorted({m.get("panel") for m in members if m.get("panel")})
        if len(panels) >= 2 and any(_panels_related(p1, p2)
                                    for p1 in panels for p2 in panels):
            for m in members:
                m["corroborated"] = True
                m["corroborated_by"] = list(panels)
                m["confidence"] = _bump_confidence(m.get("confidence"))
            line_starts = [c[1] for c in cluster]
            line_ends = []
            for c in cluster:
                le = _norm_line((c[2].get("location") or {}).get("line_end"))
                line_ends.append(le if isinstance(le, int) else c[1])
            ls = min(line_starts)
            categories = sorted({m.get("category") for m in members if m.get("category")})
            ids = [m.get("id") for m in members if m.get("id")]
            integration.append({
                "location": {"file": fkey, "line_start": ls,
                             "line_end": max(line_ends)},
                "panels": panels,
                "categories": categories,
                "finding_ids": ids,
                "severity": _max_severity(members),
                "confidence": "CERTAIN",
                "summary": "%d panels (%s) independently flagged %s:%d" % (
                    len(panels), ", ".join(panels), fkey, ls),
            })
        i = j
    return integration


def flag_for_advisor(findings, depth="standard"):
    """Return findings that need independent advisor review."""
    flagged = []
    for f in findings:
        refs = f.get("references") or []
        confidence = f.get("confidence", "POSSIBLE")
        severity = f.get("severity", "INFO")

        # HIGH/CRITICAL uncited and low confidence
        if (severity in ("HIGH", "CRITICAL")
                and confidence in ("NOTE", "POSSIBLE")
                and not refs):
            flagged.append(f)
            continue

        # HIGH/CRITICAL with fewer than 2 citations
        if severity in ("HIGH", "CRITICAL") and len(refs) < 2:
            flagged.append(f)
            continue

        # Deep mode: any uncited finding in risky panels
        if depth == "deep" and f.get("panel") in ("security", "redteam") and not refs:
            flagged.append(f)
            continue
    return flagged


def apply_advisor_verdict(finding, verdict):
    """Update a finding based on advisor verdict.

    Also mirrors the verdict into ``provenance.confirmation_status`` so that
    downstream partitioning treats pre-advised findings consistently with
    findings that went through the runtime advisor loop.
    """
    finding["advisor_verdict"] = verdict.get("verdict")
    prov = finding.setdefault("provenance", {})
    if verdict.get("verdict") == "CONFIRMED":
        prov["confirmation_status"] = "CONFIRMED"
        prov["confirmed_by"] = "agent:advisor"
        prov["confirmation_reasoning"] = verdict.get("reasoning")
        finding["confidence"] = _bump_confidence(finding.get("confidence"))
        existing = set(finding.get("references") or [])
        for ref in verdict.get("references", []):
            if ref not in existing:
                finding.setdefault("references", []).append(ref)
    elif verdict.get("verdict") == "REJECTED":
        prov["confirmation_status"] = "REJECTED"
        prov["confirmed_by"] = "agent:advisor"
        prov["confirmation_reasoning"] = verdict.get("reasoning")
        finding["severity"] = "INFO"
        finding["confidence"] = "NOTE"
    # NEEDS_MORE_INFO: leave as-is, just mark verdict
    advisor_citations = verdict.get("citations")
    if advisor_citations:
        _merge_citations(finding, {"citations": advisor_citations})
    finding["citation_quality"] = _compute_citation_quality(
        finding.get("citations", {}), finding.get("cvss")
    )
    # A confirmed verdict is only trustworthy when backed by hard citations.
    # Downgrade to NEEDS_MORE_INFO if citation quality is still none or minimal.
    if prov.get("confirmation_status") == "CONFIRMED" and finding.get("citation_quality") in ("none", "minimal"):
        prov["confirmation_status"] = "NEEDS_MORE_INFO"
        prov["confirmation_reasoning"] = (
            (prov.get("confirmation_reasoning") or "")
            + " Advisor confirmed but provided no hard citations; downgraded."
        ).strip()
        finding["severity"] = "INFO"
        finding["confidence"] = "NOTE"


def _read_code_context(finding, window=10, repo_root=None):
    """Read up to ``window`` lines before and after the finding's line_start.

    Relative file paths are resolved against ``repo_root`` (defaulting to the
    current working directory for backward compatibility).
    """
    loc = finding.get("location") or {}
    fpath = loc.get("file")
    line_start = loc.get("line_start")
    if not fpath or line_start is None:
        return "No file/line context available."
    if repo_root is None:
        repo_root = os.getcwd()
    target = fpath if os.path.isabs(fpath) else os.path.join(repo_root, fpath)
    if not os.path.isfile(target):
        return "File not found: %s" % fpath
    try:
        with open(target, encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception as e:  # noqa: BLE001 - context read is best-effort
        return "Could not read file %s: %s" % (fpath, e)
    try:
        idx = max(0, int(line_start) - 1)
    except (TypeError, ValueError):
        return "Invalid line number: %s" % line_start
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    out = []
    for i in range(start, end):
        out.append("%4d | %s" % (i + 1, lines[i].rstrip("\n")))
    return "\n".join(out) if out else "Empty context."


def _render_advisor_prompt(finding, repo_root=None):
    """Render the advisor prompt template with claim JSON and code context."""
    try:
        with open(_ADVISOR_TEMPLATE_PATH, encoding="utf-8") as fh:
            template = fh.read()
    except Exception:  # noqa: BLE001 - tolerant fallback template
        template = (
            "## Claim\n\n{claim_json}\n\n"
            "## Code context\n\n{code_context}\n\n"
            "Return JSON with verdict, reasoning, references, citations."
        )
    # The advisor markdown file carries YAML frontmatter metadata for Kimi Code;
    # strip it so the rendered prompt contains only the instructions + placeholders.
    if template.startswith("---"):
        m = re.search(r"^---\s*\n.*?\n---\s*\n", template, re.DOTALL)
        if m:
            template = template[m.end():]
    claim_json = json.dumps(finding, indent=2, default=str)
    code_context = _read_code_context(finding, repo_root=repo_root)
    # Two-step replacement avoids claim_json containing {code_context} corrupting
    # the prompt.
    t1, t2 = "§§CLAIM_JSON§§", "§§CODE_CONTEXT§§"
    rendered = template.replace("{claim_json}", t1).replace("{code_context}", t2)
    rendered = rendered.replace(t1, claim_json).replace(t2, code_context)
    if "{claim_json}" in rendered or "{code_context}" in rendered:
        raise ValueError("Advisor prompt still contains unsubstituted placeholders")
    return rendered


def _get_kimi_version(kimi_bin):
    """Return a normalized version string for the Kimi Code CLI, cached."""
    if kimi_bin in _KIMI_VERSION_CACHE:
        return _KIMI_VERSION_CACHE[kimi_bin]
    version = "kimi-cli-unknown"
    try:
        result = subprocess.run(
            [kimi_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            text=True,
        )
        output = (result.stdout or "").strip()
        m = re.search(r"(\d+\.\d+\.\d+)", output)
        if m:
            version = "kimi-cli-%s" % m.group(1)
        elif output:
            version = "kimi-cli-%s" % output
    except Exception:  # noqa: BLE001 - version lookup is best-effort
        pass
    _KIMI_VERSION_CACHE[kimi_bin] = version
    return version


def _dispatch_advisor(finding):
    """Dispatch the advisor agent for an agentic finding via the Kimi Code CLI.

    Resolves ``kimi`` in PATH, invokes it with ``--agent-file agents/advisor.md``
    and the rendered prompt. Parses the JSON verdict from the ``stream-json``
    stdout (JSONL with ``role``-typed lines). Any failure (CLI missing,
    subprocess error, timeout, invalid JSON, missing assistant message, or
    malformed verdict key) falls back to a safe ``NEEDS_MORE_INFO`` verdict so
    the pipeline never crashes.
    """
    kimi = shutil.which("kimi")
    if not kimi:
        return {"verdict": "NEEDS_MORE_INFO",
                "reasoning": "Kimi Code CLI not available; cannot dispatch advisor."}
    repo_root = finding.get("_repo_root") or os.getcwd()
    prompt = _render_advisor_prompt(finding, repo_root=repo_root)
    # The prompt is passed as a single --prompt argument. The CLI's stream-json
    # output format requires prompt mode, so stdin cannot be used here; revisit
    # if the CLI later supports streaming output with piped input.
    env = os.environ.copy()
    env["KIMI_CODE_EXPERIMENTAL_FLAG"] = "1"
    try:
        result = subprocess.run(
            [kimi, "--agent-file", _ADVISOR_TEMPLATE_PATH, "--prompt", prompt,
             "--output-format", "stream-json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "")[:500]
            print("advisor subprocess exited %d: %s" % (result.returncode, stderr),
                  file=sys.stderr)
            return {"verdict": "NEEDS_MORE_INFO",
                    "reasoning": "Advisor subprocess exited with code %d." % result.returncode}

        assistant_content = None
        system_version = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            role = obj.get("role")
            if role == "assistant":
                assistant_content = obj.get("content")
            elif role == "meta" and obj.get("type") == "system.version":
                system_version = obj.get("version")

        if assistant_content is None:
            print("advisor subprocess returned no assistant message", file=sys.stderr)
            return {"verdict": "NEEDS_MORE_INFO",
                    "reasoning": "Advisor returned no assistant message."}

        verdict = load_json_tolerant(assistant_content)
        if not isinstance(verdict, dict) or "verdict" not in verdict:
            print("advisor subprocess returned malformed verdict", file=sys.stderr)
            return {"verdict": "NEEDS_MORE_INFO",
                    "reasoning": "Advisor returned malformed verdict."}

        confirmed_by_model = None
        if verdict.get("verdict") in ("CONFIRMED", "REJECTED"):
            version = _get_kimi_version(kimi)
            if version == "kimi-cli-unknown" and system_version:
                version = "kimi-cli-%s" % system_version
            confirmed_by_model = version
        return {
            "verdict": verdict.get("verdict"),
            "reasoning": verdict.get("reasoning"),
            "references": verdict.get("references", []),
            "citations": verdict.get("citations", {}),
            "confirmed_by_model": confirmed_by_model,
        }
    except Exception as e:  # noqa: BLE001 - advisor failure is non-fatal
        print("advisor dispatch failed: %s" % e, file=sys.stderr)
        return {"verdict": "NEEDS_MORE_INFO",
                "reasoning": "Advisor dispatch failed: %s" % e}


def _is_agentic(f):
    prov = f.get("provenance") or {}
    return str(prov.get("discovered_by", "")).startswith("agent:")


def _partition_findings(findings, advisor_dispatch=None):
    """Separate findings into confirmed, discarded, and unverified sets.

    Tool findings are confirmed automatically. Agentic findings are sent to
    the advisor unless they already have full/partial citations and a CONFIRMED
    status. Unconfirmed agentic findings are downgraded to INFO.

    Findings without a ``confirmation_status`` are treated as confirmed only
    when they are tool-sourced or predate provenance tracking; agentic findings
    without a status are routed through the advisor loop and, if no advisor is
    available, downgraded to unverified INFO-level findings.
    """
    confirmed = []
    discarded = []
    unverified = []

    for f in findings:
        prov = f.get("provenance") or {}
        status = prov.get("confirmation_status")
        discovered_by = str(prov.get("discovered_by", ""))

        if status == "TOOL":
            confirmed.append(f)
            continue

        if status == "CONFIRMED":
            confirmed.append(f)
            continue

        if status == "REJECTED":
            f["severity"] = "INFO"
            f["confidence"] = "NOTE"
            discarded.append(f)
            continue

        # No explicit status: legacy reports without provenance are kept as
        # confirmed. Agentic findings without a status still need review.
        if status is None:
            if discovered_by.startswith("agent:"):
                status = "UNVERIFIED"
            else:
                confirmed.append(f)
                continue

        # UNVERIFIED or NEEDS_MORE_INFO: agentic findings needing review.
        if advisor_dispatch and _is_agentic(f):
            try:
                advisor_result = advisor_dispatch(f)
            except Exception as e:  # noqa: BLE001 - advisor failure is non-fatal
                advisor_result = None
                print("advisor dispatch failed: %s" % e, file=sys.stderr)
            if not isinstance(advisor_result, dict):
                print("advisor dispatch returned non-dict result", file=sys.stderr)
                advisor_result = {"verdict": "NEEDS_MORE_INFO",
                                  "reasoning": "Advisor returned invalid response."}
            verdict = str(advisor_result.get("verdict", "")).upper()
            if verdict == "CONFIRMED":
                prov["confirmed_by"] = "agent:advisor"
                prov["confirmation_status"] = "CONFIRMED"
                prov["confirmation_reasoning"] = advisor_result.get("reasoning")
                confirmed_by_model = advisor_result.get("confirmed_by_model")
                if confirmed_by_model:
                    prov["confirmed_by_model"] = confirmed_by_model
                # Merge advisor citations and references if present without
                # overwriting keys that already exist on the finding.
                advisor_citations = advisor_result.get("citations")
                if advisor_citations:
                    _merge_citations(f, {"citations": advisor_citations})
                existing = set(f.get("references") or [])
                for ref in advisor_result.get("references", []):
                    if ref not in existing:
                        f.setdefault("references", []).append(ref)
                f["citation_quality"] = _compute_citation_quality(
                    f.get("citations", {}), f.get("cvss")
                )
                # A confirmed verdict is only trustworthy when backed by hard
                # citations. Downgrade to NEEDS_MORE_INFO if citation quality is
                # still none or minimal.
                if f.get("citation_quality") in ("none", "minimal"):
                    prov["confirmation_status"] = "NEEDS_MORE_INFO"
                    prov["confirmation_reasoning"] = (
                        (prov.get("confirmation_reasoning") or "")
                        + " Advisor confirmed but provided no hard citations; downgraded."
                    ).strip()
                    f["severity"] = "INFO"
                    f["confidence"] = "NOTE"
                    unverified.append(f)
                    continue
                confirmed.append(f)
                continue
            if verdict == "REJECTED":
                prov["confirmed_by"] = "agent:advisor"
                prov["confirmation_status"] = "REJECTED"
                prov["confirmation_reasoning"] = advisor_result.get("reasoning")
                confirmed_by_model = advisor_result.get("confirmed_by_model")
                if confirmed_by_model:
                    prov["confirmed_by_model"] = confirmed_by_model
                f["severity"] = "INFO"
                f["confidence"] = "NOTE"
                discarded.append(f)
                continue

        # Fallback: keep as unverified, downgrade severity.
        prov["confirmation_status"] = "NEEDS_MORE_INFO"
        f["severity"] = "INFO"
        f["confidence"] = "NOTE"
        unverified.append(f)

    return confirmed, discarded, unverified


def _present(findings, sev):
    return any(f.get("severity") == sev for f in findings)


def grade(findings):
    """Assign letter grade (A-F) based on highest severity finding."""
    if _present(findings, "CRITICAL"):
        return "F"
    if _present(findings, "HIGH"):
        return "D"
    if _present(findings, "MEDIUM"):
        return "C"
    if _present(findings, "LOW"):
        return "B"
    return "A"


def risk_level(findings):
    """Determine overall risk level (CRITICAL/HIGH/MEDIUM/LOW) from findings."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if _present(findings, sev):
            return sev
    return "LOW"


def gate_verdict(findings, fail_on):
    """Return CI gate verdict (PASS/FAIL/OFF) based on findings and threshold."""
    if not fail_on:
        return "OFF"
    threshold = SEV_ORDER.index(str(fail_on).upper())
    for f in findings:
        try:
            if SEV_ORDER.index(f.get("severity", "INFO")) <= threshold:
                return "FAIL"
        except ValueError:
            continue
    return "PASS"


def severity_stats(findings):
    """Count findings by severity level."""
    stats = {s.lower(): 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").lower()
        if sev in stats:
            stats[sev] += 1
    return stats


ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")
GROUP_RE = re.compile(r"^findings-(.+)-(?:code|test|security|architecture|database|redteam)\.json$")
_GRADE_ORDER = ["A", "B", "C", "D", "F"]


def _worst_grade(grades):
    present = [g for g in grades if g in _GRADE_ORDER]
    return max(present, key=_GRADE_ORDER.index) if present else "A"


def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", advisor_results=None, advisor_dispatch=None):
    """Build complete CodeReviewReport with deduplication, grading, and CI gate verdict."""
    findings = dedupe(findings)
    if advisor_results:
        for finding_id, verdict in advisor_results.items():
            for f in findings:
                if f.get("id") == finding_id:
                    apply_advisor_verdict(f, verdict)
                    break
    confirmed, discarded, unverified = _partition_findings(findings, advisor_dispatch=advisor_dispatch)
    # Confirmed findings drive grades/gate. Unverified findings stay visible in the
    # main report body at INFO/NOTE severity but do not influence grades. Discarded
    # claims are moved to a separate appendix.
    findings = confirmed + unverified
    by_panel = {p: [] for p in VALID_PANELS}
    for f in findings:
        by_panel.get(f["panel"], by_panel["code"]).append(f)

    known_groups = {g["name"] for g in groups_meta}
    group_objs = []
    for g in groups_meta:
        gfiles = set(g["files"])
        # Attribute a finding to this group if its _group tag matches by name, or
        # (when _group is absent OR names a group that isn't in this run's metadata)
        # its file belongs to the group. The latter fallback keeps a finding from
        # vanishing from per-group grades just because its _group token — derived
        # from the finding filename — doesn't line up with a groups_meta name.
        gfind = [f for f in findings
                 if (f.get("_group") == g["name"])
                 or (f.get("_group") not in known_groups
                     and (f.get("location") or {}).get("file") in gfiles)]
        gp = {p: [x for x in gfind if x["panel"] == p] for p in by_panel}
        group_objs.append({
            "name": g["name"],
            "files": g["files"],
            "panel_grades": {p: grade(gp[p]) for p in by_panel},
            "panel_summaries": {},
            "key_findings": [f.get("title", "") for f in gfind
                             if f["severity"] in ("CRITICAL", "HIGH")][:5],
        })

    overall = _worst_grade([grade(by_panel[p]) for p in by_panel])
    stats = severity_stats(findings)
    # Cross-panel corroboration runs AFTER dedupe on the surviving findings: it
    # annotates them in place and yields the integration summary. It does not
    # touch severity, so grade/gate/stats above are unaffected.
    integration_findings = cross_panel_corroboration(findings)
    for f in findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
    for f in discarded:
        f.pop("_group", None)
        f.pop("_repo_root", None)
    return {
        "meta": {
            "target": target,
            "review_type": review_type,
            "timestamp": timestamp,
            "version": "3.0.0",
            "security_mode": security_mode,
            "models_used": _collect_models_used(confirmed + unverified + discarded),
        },
        "summary": {
            "overall_grade": overall,
            "risk_level": risk_level(findings),
            "top_issues": [f.get("title", "") for f in
                           sorted(findings, key=_sev_rank)[:3]],
            "effort_to_remediate": "MEDIUM",
            "gate": gate_verdict(findings, fail_on),
            "stats": stats,
            "discarded_claims_count": len(discarded),
            "unverified_findings_count": len(unverified),
        },
        "groups": group_objs,
        "findings": findings,
        "discarded_claims": discarded,
        "cross_panel": {"integration_findings": integration_findings},
        "recommendations": {"immediate": [], "short_term": [], "long_term": []},
    }


def validate_report(report):
    """Validate report structure and content, returning error and warning lists."""
    errors, warnings = [], []
    for key in ("meta", "summary", "groups", "findings", "cross_panel", "recommendations"):
        if key not in report:
            errors.append("missing top-level key: %s" % key)
    for i, f in enumerate(report.get("findings", [])):
        if not ID_RE.match(f.get("id", "")):
            errors.append("finding[%d] bad id: %r" % (i, f.get("id")))
        if not f.get("title"):
            errors.append("finding[%d] missing title" % i)
        if not f.get("category"):
            errors.append("finding[%d] missing category" % i)
        if f.get("severity") not in SEVERITIES:
            errors.append("finding[%d] bad severity: %r" % (i, f.get("severity")))
        if f.get("confidence") not in CONFIDENCES:
            errors.append("finding[%d] bad confidence: %r" % (i, f.get("confidence")))
        if f.get("panel") not in VALID_PANELS:
            errors.append("finding[%d] bad panel: %r" % (i, f.get("panel")))
        loc = f.get("location") or {}
        if not loc.get("file") or loc.get("line_start") is None:
            warnings.append("finding[%d] missing location.file/line_start" % i)
        agent_sourced = not str(f.get("source", "")).startswith("tool:")
        if agent_sourced and f.get("panel") in ("security", "redteam") and f.get("severity") in ("CRITICAL", "HIGH"):
            if not f.get("cvss"):
                errors.append("finding[%d] %s %s missing cvss" % (i, f["panel"], f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] %s %s missing exploit_scenario" % (i, f["panel"], f["severity"]))
    id_counts = {}
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings


def render_summary(report):
    """Render markdown summary of report with grades, stats, groups, and top findings."""
    s = report["summary"]
    lines = [
        "# panopticon — %s" % report["meta"]["target"],
        "",
        "**Grade:** %s  **Risk:** %s  **Gate:** %s" % (
            s["overall_grade"], s["risk_level"], s["gate"]),
        "",
        "**Findings:** %s" % ", ".join(
            "%s %d" % (k.upper(), v) for k, v in s["stats"].items() if v),
        "",
        "## Groups",
    ]
    for g in report["groups"]:
        pg = g["panel_grades"]
        grades = " / ".join("%s %s" % (p, pg[p]) for p in PANEL_ORDER)
        lines.append("- **%s** — %s" % (g["name"], grades))
    lines.append("")
    lines.append("## Top findings")
    for f in sorted(report["findings"], key=_sev_rank)[:10]:
        loc = f.get("location") or {}
        where = "%s:%s" % (loc.get("file", "?"), loc.get("line_start", "?"))
        chips = []
        c = f.get("citations") or {}
        for w in (c.get("cwe") or []):
            chips.append(w.get("id", ""))
        chips += (c.get("owasp") or [])
        if c.get("ssvc"):
            chips.append("SSVC:%s" % c["ssvc"].get("decision", ""))
        if c.get("epss"):
            chips.append("EPSS:%.2f" % max(e.get("score", 0.0) for e in c["epss"]))
        prov = "reinforced" if f.get("reinforced") else (
            "tool" if str(f.get("source", "")).startswith("tool:") else "agent")
        suffix = (" — " + ", ".join(x for x in chips if x)) if chips else ""
        cor = " ⁂corroborated" if f.get("corroborated") else ""
        lines.append("- `[%s]` **%s** %s (%s) [%s·%s%s]%s" % (
            f["severity"], f.get("title", ""), where, f["confidence"], prov,
            f.get("panel", ""), cor, suffix))
    integ = (report.get("cross_panel") or {}).get("integration_findings") or []
    if integ:
        lines.append("")
        lines.append("## Cross-panel corroboration")
        for it in integ:
            loc = it.get("location") or {}
            lines.append("- `[%s]` %s:%s — %s (%s)" % (
                it.get("severity", ""), loc.get("file", "?"),
                loc.get("line_start", "?"), ", ".join(it.get("panels") or []),
                ", ".join(it.get("categories") or [])))
    return "\n".join(lines)


def write_report(report, out_path, max_bytes=800000):
    """Write report to JSON file, splitting into parts if size exceeds max_bytes."""
    blob = json.dumps(report, indent=2)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    if len(blob.encode("utf-8")) <= max_bytes:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(blob)
        return [out_path]
    findings = report["findings"]
    half = max(1, len(findings) // 2)
    stem, ext = os.path.splitext(out_path)
    part_path = "%s_part2%s" % (stem, ext)
    main_report = dict(report)
    main_report["meta"] = dict(report["meta"])
    main_report["meta"]["parts"] = [os.path.basename(part_path)]
    main_report["findings"] = findings[:half]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(main_report, fh, indent=2)
    with open(part_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": findings[half:]}, fh, indent=2)
    return [out_path, part_path]


def _derive_html_path(json_path):
    if json_path.lower().endswith(".json"):
        return json_path + ".html"
    return os.path.join(json_path, "report.html")


def main(argv=None):
    """Main entry point: load findings, enrich citations, build and validate report."""
    ap = argparse.ArgumentParser(description="panopticon synthesizer")
    ap.add_argument("--target", default="unknown")
    ap.add_argument("--groups", metavar="PATH")
    ap.add_argument("--security", choices=["standard", "redteam"], default=None,
                    help="Override security mode from groups.json")
    ap.add_argument("--fail-on", metavar="SEV", type=str.lower,
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--severity", metavar="LEVEL", type=str.lower,
                    choices=["all", "medium", "high", "critical"], default="all",
                    help="Minimum severity to include in the report (all, medium, high, critical)")
    ap.add_argument("--changes", "-c", action="store_true",
                    help="Alias for a changes/diff review type")
    ap.add_argument("--out", default=None)
    ap.add_argument("--html-out", metavar="PATH", default=None,
                    help="Write HTML report to PATH")
    ap.add_argument("--compare", metavar="JSON", nargs=2, default=None,
                    help="Compare two JSON reports and emit HTML")
    ap.add_argument("--epss", action="store_true")
    ap.add_argument("--tools-dir", metavar="DIR")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args(argv)

    if args.compare:
        a_path, b_path = args.compare
        try:
            with open(a_path, encoding="utf-8") as fh:
                report_a = json.load(fh)
        except OSError as e:
            print("ERROR: cannot read %s: %s" % (a_path, e), file=sys.stderr)
            return 2
        except ValueError as e:
            print("ERROR: invalid JSON in %s: %s" % (a_path, e), file=sys.stderr)
            return 2
        try:
            with open(b_path, encoding="utf-8") as fh:
                report_b = json.load(fh)
        except OSError as e:
            print("ERROR: cannot read %s: %s" % (b_path, e), file=sys.stderr)
            return 2
        except ValueError as e:
            print("ERROR: invalid JSON in %s: %s" % (b_path, e), file=sys.stderr)
            return 2
        html_out = args.html_out or (_derive_html_path(args.out) if args.out else None)
        if not html_out:
            print("ERROR: --compare requires --html-out or --out", file=sys.stderr)
            return 2
        html_report.write_html(report_b, html_out, compare_report=report_a)
        print("Compare HTML: %s" % html_out)
        return 0

    groups_meta = []
    review_type = "changes" if args.changes else "repo"
    security_mode = args.security
    if args.groups and os.path.isfile(args.groups):
        try:
            with open(args.groups, encoding="utf-8") as fh:
                gj = json.load(fh)
            if isinstance(gj, dict):
                groups_meta = gj.get("groups", [])
                review_type = MODE_TO_REVIEW_TYPE.get(gj.get("mode"), review_type)
                if security_mode is None:
                    security_mode = gj.get("security_mode", "standard")
            else:
                print("synthesize: --groups is not a JSON object; ignoring", file=sys.stderr)
        except (OSError, ValueError) as e:  # tolerant by design: never abort a run
            print("synthesize: could not read --groups (%s); ignoring" % e, file=sys.stderr)
    if security_mode is None:
        security_mode = "standard"

    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out or os.path.join(".panopticon", "report-%s.json" % ts.replace(":", ""))

    findings = load_findings(args.files)
    if args.tools_dir and os.path.isdir(args.tools_dir):
        for tf in ingest_tools.ingest_dir(args.tools_dir, None):
            findings.append(normalize_finding(tf))
    catalog = citations.load_cwe_catalog()
    citations.enrich_citations(findings, catalog, epss_enabled=args.epss,
                               cache_path=os.path.join(".panopticon", "epss-cache.json"))
    if args.severity and args.severity != "all":
        threshold = SEV_ORDER.index(args.severity.upper())
        findings = [f for f in findings if _sev_rank(f) <= threshold]
    if os.path.isdir(args.target):
        repo_root = os.path.abspath(args.target)
    elif args.groups:
        repo_root = os.path.abspath(os.path.dirname(args.groups))
    else:
        repo_root = os.path.abspath(os.getcwd())
    for f in findings:
        f["_repo_root"] = repo_root
    report = build_report(findings, groups_meta, args.target, args.fail_on, ts, review_type,
                          security_mode, advisor_dispatch=_dispatch_advisor)
    errors, warnings = validate_report(report)
    for w in warnings:
        print("WARN: %s" % w, file=sys.stderr)
    for e in errors:
        print("SCHEMA: %s" % e, file=sys.stderr)

    paths = write_report(report, out)
    html_out = args.html_out
    if html_out is None and args.out:
        html_out = _derive_html_path(paths[0])
    if html_out:
        html_report.write_html(report, html_out)
        print("HTML artifact: %s" % html_out)
    print(render_summary(report))
    print("\nJSON artifact: %s" % ", ".join(paths))
    return 1 if report["summary"]["gate"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
