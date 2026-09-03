"""Emit a StrainReport (see skill/reference/strain-report-schema.json) — the
catalog-MIS-FIT companion to x0x_report.

X0X reports ABSENCE: a reviewer found nothing in its domain menu that fit and
filed `<DOM>-X0X`. That is the only gap signal the pipeline had, and it is
structurally blind to the commoner case — a gap whose NEIGHBOURS are good
enough. There the reviewer files a real code in good faith and the catalog never
learns. Measured on the calibration corpus: 61 findings reason explicitly about
algorithmic complexity, a concept with no OCRDb code at 0.5.0, and not one of
them carried an X0X.

Strain reports the disagreement instead. Two signals, both already on disk:

  advisor_recode          The verify advisor re-read the code independently and
                          landed on a different OCRDb code than the panel that
                          filed the finding. High confidence, low volume
                          (~1.5% of verified findings on btcpayserver run-1).
                          Read from `provenance.advisor_code`, which
                          `evidence.apply_verdict` records but never applies.

  cross_run_disagreement  Two runs over the SAME ref coded the same site
                          differently. Lower confidence per instance — either
                          run may simply be wrong — but far higher volume (27%
                          of co-reviewed windows on the btcpayserver cap-64
                          pair) and free on any repeat run.

The two signals are COMPLEMENTARY, not redundant. A verify advisor is dispatched
per (domain, group) cell and sees only its own domain's menu, so `advisor_recode`
can only ever report WITHIN-domain strain (measured: 0% cross-domain). Two runs
may assign a file to different domains entirely, so `cross_run_disagreement` is
the only signal that surfaces cross-DOMAIN strain — 64% of its signals on the
btcpayserver cap-64 pair, including the DAT-C1C / OPS-D1B boundary that flipped
symmetrically between the two runs. Neither signal subsumes the other.

MECHANICAL by design, exactly like x0x_report: it clusters and carries the
evidence as-is. It does NOT adjudicate. The disposition (`boundary` /
`refine_existing` / `new_code` / `not_a_gap`) is a pool decision, and strain
exists precisely because X0X could only ever argue `new_code` while OCRDb's
vocabulary already had the other three.
"""
import os

SCHEMA_VERSION = 1

_X0X_SUFFIX = "-X0X"


def _is_gap(code):
    return bool(code) and str(code).upper().endswith(_X0X_SUFFIX)


def _domain(code):
    """Domain prefix of an OCRDb code (`DAT-C1B` -> `DAT`), or None."""
    if not code:
        return None
    head = str(code).split("-", 1)[0].strip().upper()
    return head or None


def direction(code_filed, code_preferred):
    """Which way the disagreement runs — see the schema's `direction` enum."""
    filed_gap, pref_gap = _is_gap(code_filed), _is_gap(code_preferred)
    if pref_gap and not filed_gap:
        return "declares_gap"
    if filed_gap and not pref_gap:
        return "refutes_gap"
    return "code_to_code"


def _canonical_pair(a, b):
    """Order a symmetric code pair so the same disagreement always clusters to
    one record. A real code sorts before an `-X0X` (so `direction` reports
    `declares_gap` rather than `refutes_gap` for a code-vs-gap split); otherwise
    lexical order, which is arbitrary but stable."""
    if _is_gap(a) != _is_gap(b):
        return (b, a) if _is_gap(a) else (a, b)
    return (a, b) if a <= b else (b, a)


def _occurrence(finding, run_id=None):
    """An occurrence record, or None when the finding has no file (the schema
    requires `file` on every occurrence)."""
    loc = finding.get("location") or {}
    if not loc.get("file"):
        return None
    o = {"file": loc["file"]}
    if loc.get("line_start") is not None:
        o["line_start"] = loc["line_start"]
    if loc.get("line_end") is not None:
        o["line_end"] = loc["line_end"]
    if finding.get("id"):
        o["finding_id"] = finding["id"]
    if run_id:
        o["run_id"] = run_id
    return o


def advisor_recode_signals(findings, run_id=None):
    """Signals from `provenance.advisor_code` — the advisor's own second opinion.

    Clustered by the (code_filed, code_preferred) PAIR, because that pair is the
    unit of adjudication: one occurrence is an anecdote, the same pair recurring
    across independent sites is a boundary that does not hold.
    """
    clusters = {}
    for f in findings:
        preferred = (f.get("provenance") or {}).get("advisor_code")
        filed = f.get("code")
        if not preferred or not filed or str(preferred) == str(filed):
            continue
        occ = _occurrence(f, run_id)
        if occ is None:
            continue
        clusters.setdefault((str(filed), str(preferred)), []).append((f, occ))

    out = []
    for (filed, preferred), pairs in clusters.items():
        lead = pairs[0][0]
        sig = {
            "signal": "advisor_recode",
            "code_filed": filed,
            "code_preferred": preferred,
            "direction": direction(filed, preferred),
            "cross_domain": _domain(filed) != _domain(preferred),
            "recurrence": len(pairs),
            "occurrences": [o for _f, o in pairs],
        }
        dom = _domain(filed)
        if dom:
            sig["domain"] = dom
        title = lead.get("short_title") or lead.get("title")
        if title:
            sig["summary"] = title
        if lead.get("severity"):
            sig["severity"] = lead["severity"]
        # The advisor argued the boundary in its own words; that argument is the
        # most useful thing in the record, so carry it verbatim.
        reasoning = (lead.get("provenance") or {}).get("confirmation_reasoning")
        if reasoning:
            sig["rationale"] = reasoning
        out.append(sig)
    return out


def _window(finding, size=20):
    """Cluster key for 'the same place in the same file'. Line numbers drift
    between runs for the same defect, so an exact line match would miss almost
    every real agreement; a coarse window is the honest join."""
    loc = finding.get("location") or {}
    f = loc.get("file")
    if not f:
        return None
    return (f, int(loc.get("line_start") or 0) // size)


def cross_run_signals(runs, window=20):
    """Signals from two or more runs over the SAME ref.

    `runs` is ``[(run_id, [finding, ...]), ...]``. Callers MUST have checked the
    runs share a ref: two runs over different code did not disagree about
    anything, they reviewed different things.

    A site counts as strain only when the runs share NO code for it. Partial
    overlap (one run also found something else there) is ordinary sampling
    variance, not a coding disagreement.
    """
    per_run = []
    for run_id, findings in runs:
        buckets = {}
        for f in findings:
            key = _window(f, window)
            if key is None:
                continue
            buckets.setdefault(key, []).append(f)
        per_run.append((run_id, buckets))

    clusters = {}
    for i in range(len(per_run)):
        for j in range(i + 1, len(per_run)):
            run_a, a = per_run[i]
            run_b, b = per_run[j]
            for key in set(a) & set(b):
                codes_a = {str(f.get("code")) for f in a[key] if f.get("code")}
                codes_b = {str(f.get("code")) for f in b[key] if f.get("code")}
                if not codes_a or not codes_b or (codes_a & codes_b):
                    continue          # agreed on at least one code -> not strain
                # The pair is SYMMETRIC here: neither run is authoritative, so
                # which code lands in `code_filed` is an artifact of argument
                # order. Canonicalize, or the same boundary splits into two
                # records and its recurrence is understated (observed: QAL-D1A
                # vs ARC-A3A emitted as x3 and x2 instead of one x5). A real
                # code sorts before a gap so `direction` still reads correctly.
                filed, preferred = _canonical_pair(sorted(codes_a)[0],
                                                   sorted(codes_b)[0])
                occ = []
                for run_id, fs in ((run_a, a[key]), (run_b, b[key])):
                    o = _occurrence(fs[0], run_id)
                    if o is not None:
                        occ.append(o)
                if not occ:
                    continue
                clusters.setdefault((filed, preferred), []).append((a[key][0], occ))

    out = []
    for (filed, preferred), pairs in clusters.items():
        lead = pairs[0][0]
        occurrences = [o for _f, occ in pairs for o in occ]
        sig = {
            "signal": "cross_run_disagreement",
            "code_filed": filed,
            "code_preferred": preferred,
            "direction": direction(filed, preferred),
            "cross_domain": _domain(filed) != _domain(preferred),
            "recurrence": len(pairs),
            "occurrences": occurrences,
        }
        dom = _domain(filed)
        if dom:
            sig["domain"] = dom
        title = lead.get("short_title") or lead.get("title")
        if title:
            sig["summary"] = title
        if lead.get("severity"):
            sig["severity"] = lead["severity"]
        # No `rationale`: neither run knew it was disagreeing. That absence is
        # the honest marker of why this signal is weaker than an advisor recode.
        out.append(sig)
    return out


def build_report(findings, meta, run_id, panopticon_version=None, target=None,
                 cross_runs=None):
    """Assemble a schema-valid StrainReport.

    `cross_runs`, when given, is ``[(run_id, [finding, ...]), ...]`` for runs
    over the same ref as this one — including this run, so a two-run comparison
    passes both.
    """
    meta = meta or {}
    if target is None and meta.get("target"):
        target = {"name": str(meta["target"])}
    signals = advisor_recode_signals(findings, run_id)
    generated_by = {
        "panopticon_version": (panopticon_version or meta.get("version")
                               or "unknown"),
        "run_id": str(run_id) if run_id else "unknown",
    }
    if cross_runs:
        signals.extend(cross_run_signals(cross_runs))
        generated_by["compared_runs"] = [str(r) for r, _ in cross_runs]
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": generated_by,
        "ocrdb_version": meta.get("ocrdb_version") or "unknown",
        "signals": signals,
    }
    if target:
        report["target"] = target
    if meta.get("timestamp"):
        report["generated_at"] = meta["timestamp"]
    return report


def write_report(report, out_path):
    """Write `report` beside its review report as `<stem>-strain.json`."""
    import json
    stem = out_path[:-len(".json")] if out_path.endswith(".json") else out_path
    path = stem + "-strain.json"
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return path
