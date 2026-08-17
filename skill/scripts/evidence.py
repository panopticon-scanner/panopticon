#!/usr/bin/env python3
"""Evidence axis for panopticon findings: status derivation, verify-queue
triage, and advisor verdict ingestion. Stdlib-only.

Two-axis model: severity means "impact if true" and is never mutated here;
evidence.status records how hard the claim has been verified.
"""

import hashlib
import json
import os
import re
import sys
import uuid

try:
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    from _version import __version__

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
# Canonical panel list, in display order. synthesize's VALID_PANELS/PANEL_ORDER,
# html_report's _PANEL_ORDER, and the findings-filename regexes in synthesize
# and group_runner all derive from this one definition.
PANELS = ["code", "test", "security", "architecture", "database", "redteam"]
EVIDENCE_STATUSES = ("tool_reported", "tool_confirmed", "advisor_confirmed",
                     "corroborated", "needs_more_info", "unverified",
                     "rejected")
GATE_ELIGIBLE_DEFAULT = frozenset({"tool_confirmed", "advisor_confirmed"})
VERDICT_VALUES = {"CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"}


def is_tool_sourced(finding):
    """Tool-emitted findings carry source='tool:<name>'; everything else is agentic."""
    return str(finding.get("source", "")).startswith("tool:")


def tool_name(finding):
    """The <name> of a tool-sourced finding's 'tool:<name>' source, else None."""
    src = str(finding.get("source", ""))
    return src[len("tool:"):] if src.startswith("tool:") else None


def tool_rule_id(finding):
    """The scanner rule a tool finding came from, wherever its adapter put it.

    Two adapter families disagree: the dependency scanners (pip_audit,
    bundler_audit, dependency_check, eslint_security) set
    `tool_evidence.rule_id`, while everything on the SARIF path (bandit,
    semgrep, trivy, ...) sets no tool_evidence at all and carries the rule id
    in `provenance.confirmation_reasoning` via attach_tool_provenance. Reading
    only the first form made every SARIF finding look rule-less, which silently
    disabled both aggregation and rule-based fingerprint identity for them.
    """
    rule = (finding.get("tool_evidence") or {}).get("rule_id")
    if rule:
        return rule
    return (finding.get("provenance") or {}).get("confirmation_reasoning") or None


def norm_path(p):
    """Canonicalize a finding path for identity/clustering comparisons.

    Backslashes become slashes; a `./` prefix is stripped. Strip only a `./`
    prefix — `lstrip("./")` would eat the leading dot of every dotfile path,
    collapsing `.github/x` onto `github/x`. Deliberately NO os.path.normpath:
    collapsing `a/../a` would change finding_fingerprint identity for paths no
    real emitter produces (#977). Sole owner of this normalization — used by
    finding_fingerprint, reconcile_key, and synthesize's clustering keys
    (dedupe / cross-panel corroboration / tool aggregation), which must all
    agree on when two spellings are the same file.
    """
    fpath = str(p or "").replace("\\", "/")
    while fpath.startswith("./"):
        fpath = fpath[2:]
    return fpath


def finding_fingerprint(finding):
    """Stable cross-run identity for a finding.

    Keys on panel + category + normalized file + the discriminator that is
    actually stable for that source: a tool's rule_id, or an agent finding's
    title. Deliberately EXCLUDES line numbers (issues survive code moves) and
    free-text description (agent prose is re-worded every run). Also the
    verify-queue's queue_id (P2) — the same identity both passes compute.
    """
    loc = finding.get("location") or {}
    fpath = norm_path(loc.get("file"))
    # Gate on tool-sourcing: on an AGENT finding, confirmation_reasoning holds
    # advisor prose, which would be a disastrous identity discriminator.
    rule = tool_rule_id(finding) if is_tool_sourced(finding) else None
    discriminator = str(rule) if rule else str(finding.get("title") or "")
    payload = "|".join([str(finding.get("panel") or ""),
                        str(finding.get("category") or ""),
                        fpath, discriminator]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def matrix_finding_id(finding):
    """Deterministic, schema-valid (^[A-Z]{2,8}-[0-9]{3,}$), stable per-finding
    identity for a matrix (domain-scoped) finding.

    Pure over the finding's OWN stable fields, so the driver (per-cell, Slice B)
    and synthesize (global) compute the SAME id independently. Callers MUST pass a
    finding already run through synthesize.normalize_finding so title/category
    defaults agree on both sides. Deliberately NOT keyed on finding_fingerprint:
    that hashes `panel`, which a raw cell finding lacks but normalize derives, so
    the two views would diverge. Includes line_start so two findings sharing a
    (domain, category, file, title) but at different lines get distinct ids.
    """
    dom = finding.get("domain")
    if not dom:
        code = finding.get("code") or ""
        dom = code.split("-", 1)[0] if "-" in code else "GEN"
    if not (isinstance(dom, str) and re.fullmatch(r"[A-Z]{2,8}", dom)):
        dom = "GEN"
    loc = finding.get("location") or {}
    title = " ".join(str(finding.get("title") or "").split())
    seed = "|".join([dom, str(finding.get("category") or ""),
                     norm_path(loc.get("file")), title,
                     str(loc.get("line_start"))])
    num = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
    return "%s-%03d" % (dom, num)   # %03d: >=3 digits, never truncates a big num


def reconcile_key(finding):
    """Coarse CROSS-RUN identity: (normalized_file, panel, category) -- or,
    once a finding carries an OCRDb domain code (5.0), the tighter
    (normalized_file, "code", code).

    Separate from finding_fingerprint (the within-run identity, left untouched):
    reconcile keys on this to match a finding across two independent agentic
    runs, where the free-text title finding_fingerprint uses as an agent
    finding's discriminator is re-worded every run. Dropping the title (keeping
    file + panel + category) lets a re-worded finding match; a genuinely-fixed
    one's key vanishes (#914). The file normalization is finding_fingerprint's
    exactly -- both call norm_path.

    5.0: this was the seam the #914-era docstring flagged -- the finding-code
    catalog now exists (OCRDb), so a code-bearing finding reconciles on
    (file, code) instead of the free-text `category`, a strictly more precise
    identity (two reviewers naming the same OCRDb code agree even when their
    prose category differs). A code-less finding is UNCHANGED: it falls through
    to the legacy (file, panel, category) tuple exactly as before, so reconcile.py
    (this function's only consumer) sees no behavior change for pre-5.0/code-less
    findings. The two arms are disjoint EXCEPT one narrow case -- a code-less
    finding whose `panel` is the literal "code" (itself a real PANELS value) and
    whose `category` happens to equal a code-string aliases a code-bearing
    finding at the same file. That coarse cross-run match is benign (both keys
    resolve to the same reconcile identity, not a correctness bug); it is NOT the
    impossibility earlier wording claimed.
    """
    loc = finding.get("location") or {}
    code = finding.get("code")
    if code:
        return (norm_path(loc.get("file")), "code", str(code))
    return (norm_path(loc.get("file")), str(finding.get("panel") or ""),
            str(finding.get("category") or ""))


def sev_rank(finding):
    """Lower is more severe; unknown severities sort last."""
    try:
        return SEV_ORDER.index(finding.get("severity", "INFO"))
    except ValueError:
        return len(SEV_ORDER)


def derive_evidence(finding, verdict=None):
    """Return the evidence dict for a finding.

    Precedence (P2, #446): an advisor VERDICT decides first, whatever the
    source — previously tool-sourcing short-circuited ahead of verdicts, so an
    advisor could never refute a scanner. Without a verdict, a tool-sourced or
    reinforced finding is `tool_reported`: reported, not verified, and NOT
    gate-eligible. Never mutates the finding. Self-asserted
    provenance.confirmation_status is deliberately ignored — a reviewer cannot
    confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    reinforced = bool(finding.get("reinforced"))
    tool_like = is_tool_sourced(finding) or reinforced
    origin = "tool+agent" if reinforced else finding.get("source")

    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        if v == "REJECTED":
            status = "rejected"
        elif v == "NEEDS_MORE_INFO":
            status = "needs_more_info"
        else:
            status = "tool_confirmed" if tool_like else "advisor_confirmed"
        return {"status": status,
                "verified_by": ([origin, "agent:advisor"] if tool_like
                                else "agent:advisor"),
                "reasoning": (verdict or {}).get("reasoning"),
                "citation_quality": quality}

    if tool_like:
        return {"status": "tool_reported", "verified_by": origin,
                "reasoning": ("Same locus reported independently by a tool and "
                              "an agent" if reinforced
                              else prov.get("confirmation_reasoning")
                              or "Reported by static-analysis tool"),
                "citation_quality": quality}

    if finding.get("corroborated"):
        panels = list(finding.get("corroborated_by") or [])
        return {"status": "corroborated", "verified_by": panels,
                "reasoning": "Nearby locus independently flagged by panels: %s"
                % ", ".join(panels),
                "citation_quality": quality}
    return {"status": "unverified", "verified_by": None, "reasoning": None,
            "citation_quality": quality}


def triage_priority(finding):
    """Sort key for the verify queue; lower verifies first.

    Spec order: corroborated CRITICAL/HIGH -> uncorroborated CRITICAL/HIGH ->
    corroborated MEDIUM -> everything else descending by severity.
    """
    sev = str(finding.get("severity", "INFO")).upper()
    corroborated = bool(finding.get("corroborated") or finding.get("reinforced"))
    if sev in ("CRITICAL", "HIGH"):
        return 0 if corroborated else 1
    if sev == "MEDIUM" and corroborated:
        return 2
    try:
        return 3 + SEV_ORDER.index(sev)
    except ValueError:
        return 3 + len(SEV_ORDER)


def _queue_tiebreak(f):
    """Last-resort content discriminator for build_verify_queue's sort key.

    finding_fingerprint deliberately excludes line numbers, so two findings
    at different lines in the same file can share one fingerprint; if they
    also share (or both lack) an `id` -- normalize_finding never assigns a
    missing one -- the sort key up to this point ties completely. `sorted`
    is stable, so a total tie falls back to INPUT ORDER: exactly the
    invariant this module exists to remove, and it would decide which
    finding gets the bare fingerprint vs. the `-1` suffix, so a shuffled
    input could hand each finding the other's advisor verdict.

    Deliberately limited to fields BOTH synthesize passes see identically on
    the same finding object: location/severity/source/id survive unchanged
    from the --emit-verify-queue pass to the report-build pass. `_group` is
    NOT safe -- synthesize.build_report strips it (`f.pop("_group", None)`)
    before the second pass would ever see it -- and hashing the whole
    finding dict is NOT safe either, since later pipeline stages add keys
    (`evidence`, `fingerprint`) the emit pass never sees. Either would
    reintroduce pass divergence in a subtler form than the bug this fixes.
    A residual tie after this means the two findings are identical in every
    field that could distinguish them: genuinely fungible claims.
    """
    loc = f.get("location") or {}
    return (str(loc.get("file") or ""), str(loc.get("line_start") or ""),
           str(f.get("severity") or ""), str(f.get("source") or ""))


def build_verify_queue(findings, max_verify=None):
    """Return (entries, cut) for ALL findings, priority-sorted.

    Entries hold REFERENCES to the original finding dicts (verdict application
    must mutate the real objects).

    P2 (#446): tool-sourced and reinforced findings queue too — they are claims
    like any other, and `tool_confirmed` now requires an advisor verdict.
    P2 (#443/#438): the sort key and queue_id are pure functions of finding
    CONTENT — no input index anywhere, including in the collision-suffix
    assignment (see `_queue_tiebreak`) — so both passes of a run compute the
    same ids and a --max-verify cut cannot depend on filename order.
    """
    ordered = sorted(findings, key=lambda f: (triage_priority(f), sev_rank(f),
                                              finding_fingerprint(f),
                                              str(f.get("id") or ""),
                                              _queue_tiebreak(f)))
    cut = 0
    if max_verify is not None and max_verify >= 0 and len(ordered) > max_verify:
        cut = len(ordered) - max_verify
        ordered = ordered[:max_verify]
    entries = []
    seen = {}
    for f in ordered:
        fp = finding_fingerprint(f)
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        qid = fp if n == 0 else "%s-%d" % (fp, n)
        if n:
            # NOT evidence of a dedupe miss. finding_fingerprint deliberately
            # excludes line numbers, so two findings sharing
            # panel+category+file+discriminator at DIFFERENT lines collide by
            # construction, benignly and routinely (dedupe reinforces only on
            # an exact (file, line) match). The suffix keeps them separately
            # addressable by an advisor verdict; the log records that one
            # identity is now carrying more than one claim.
            #
            # KNOWN DIVERGENCE (unchanged behavior, recorded): the -<n> suffix
            # lives only in the queue. synthesize.build_report exports
            # `fingerprint` straight from finding_fingerprint, so BOTH members
            # of a colliding pair export the bare `fp` -- a
            # fingerprint -> queue_id lookup is ambiguous for them, and `fp-1`
            # never appears as an exported identity at all.
            print("evidence: fingerprint collision %s (finding %r) -> %s"
                  % (fp, f.get("id"), qid), file=sys.stderr)
        entries.append({"queue_id": qid, "priority": triage_priority(f),
                        "finding": f})
    return entries, cut


def write_verify_queue(entries, cut, path, run_id=None):
    """Serialize the queue for the orchestrating agent (pass 1 artifact)."""
    run_id = run_id or uuid.uuid4().hex
    payload = {
        "version": __version__,
        "run_id": run_id,
        "cut_by_max_verify": cut,
        "entries": [{"queue_id": e["queue_id"], "priority": e["priority"],
                     "finding": {k: v for k, v in e["finding"].items()
                                 if not k.startswith("_")}}
                    for e in entries],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def merge_citations(best, other):
    """Merge other['citations'] into best['citations'] without overwriting
    keys that already exist in best. (Moved from synthesize._merge_citations.)"""
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


def _iter_verdict_files(verdicts_dir):
    """Yield (name, path) for every *.json in verdicts_dir, sorted by name.

    Yields nothing when verdicts_dir is falsy or not a directory -- callers
    rely on this to preserve their empty-accumulator early-return behavior.
    """
    if not verdicts_dir or not os.path.isdir(verdicts_dir):
        return
    for name in sorted(os.listdir(verdicts_dir)):
        if not name.endswith(".json"):
            continue
        yield name, os.path.join(verdicts_dir, name)


def load_verdicts_detailed(verdicts_dir):
    """Load advisor verdict files, also reporting which ones could not be used.

    Returns (verdicts, unloadable). ``verdicts`` is keyed by queue_id (filename
    stem); ``unloadable`` is a list of {"file": name, "reason": str} for every
    ``*.json`` that failed to parse or lacked a valid verdict key.

    Tolerant by design: unreadable/malformed files and files without a valid
    verdict key are skipped (never raises). Advisors routinely wrap their JSON
    output in a markdown fence (see agents/advisor.md's own output example) or
    add surrounding prose, so parsing goes through load_json_tolerant rather
    than a strict json.load. But load_json_tolerant cannot repair arbitrary
    unescaped quotes inside a string value, so a malformed advisor return would
    previously vanish with only a stderr note -- hiding a lost verdict from
    meta.coverage. Callers surface ``unloadable`` in the report so a corrupt
    verdict is visible, not silently dropped (#938).

    A verdict BUNDLE ({"verdicts": [...], "_panopticon": {...}}, the P5 per-cell
    flow) is a different file shape, not a legacy single-verdict file, and is
    skipped here -- symmetric with how load_verdict_bundles skips single-verdict
    files -- so it is handled exactly once, by load_verdict_bundles, instead of
    being misreported here as "missing/invalid verdict key".
    """
    out = {}
    unloadable = []
    for name, path in _iter_verdict_files(verdicts_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                data = load_json_tolerant(fh.read())
        except (OSError, ValueError) as e:
            print("evidence: skipping malformed verdict %s: %s" % (name, e),
                  file=sys.stderr)
            kind = "unreadable" if isinstance(e, OSError) else "unparseable"
            unloadable.append({"file": name,
                               "reason": "%s: %s"
                               % (kind, (str(e).splitlines() or [""])[0])})
            continue
        if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
            continue   # a verdict BUNDLE (handled by load_verdict_bundles); not a legacy single-verdict file
        if (not isinstance(data, dict)
                or str(data.get("verdict", "")).upper() not in VERDICT_VALUES):
            print("evidence: skipping verdict %s: missing/invalid verdict key" % name,
                  file=sys.stderr)
            unloadable.append({"file": name, "reason": "missing/invalid verdict key"})
            continue
        out[name[:-len(".json")]] = data
    return out, unloadable


def load_verdicts(verdicts_dir):
    """Load advisor verdict files keyed by queue_id (filename stem).

    Verdicts-only wrapper over load_verdicts_detailed (unchanged contract for
    callers that don't need the un-loadable-file accounting).
    """
    return load_verdicts_detailed(verdicts_dir)[0]


def match_verdict(entry, verdicts, run_id=None):
    """Return the verdict for a queue entry, enforcing the finding_id echo.

    A missing or mismatched echo means the verdict cannot be bound to the
    queued claim -> treated as malformed (None). Filename routing alone is not
    evidence that an advisor answered the intended finding.
    """
    v = verdicts.get(entry["queue_id"])
    if v is None:
        return None
    fid = entry["finding"].get("id")
    echoed = v.get("finding_id")
    if echoed is None:
        print("evidence: verdict %s has no finding_id echo; ignoring"
              % entry["queue_id"], file=sys.stderr)
        return None
    if str(echoed) != str(fid):
        print("evidence: verdict %s echoes finding_id %r, expected %r; ignoring"
              % (entry["queue_id"], echoed, fid), file=sys.stderr)
        return None
    if run_id is not None and v.get("run_id") != run_id:
        print("evidence: verdict %s has run_id %r, expected %r; ignoring"
              % (entry["queue_id"], v.get("run_id"), run_id), file=sys.stderr)
        return None
    return v


def load_verdict_bundles(verdicts_dir):
    """Load per-cell verdict BUNDLES ({"verdicts": [...], "_panopticon": {...}})
    into a finding_id -> list of candidate verdicts map.

    A single-verdict file (top-level "verdict", the legacy queue_id flow) is NOT
    a bundle and is ignored here (handled by load_verdicts_detailed). Tolerant:
    unreadable/unparseable files land in `unloadable`, never raise. Each flattened
    verdict inherits the bundle's `_panopticon.run_id` and `stage` when its own are
    absent, so match_verdict_by_id can enforce the run_id.

    Deliberately does NOT collapse multiple candidates for the same finding_id
    at load time -- backup-preference and run_id filtering both belong in
    match_verdict_by_id, where the caller's run_id is known. Collapsing here
    (e.g. backup-wins on stage alone) let a stale cross-run backup evict a
    valid same-run primary before run_id was ever consulted.
    """
    by_fid = {}
    unloadable = []
    for name, path in _iter_verdict_files(verdicts_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                data = load_json_tolerant(fh.read())
        except (OSError, ValueError) as e:
            unloadable.append({"file": name, "reason": str(e).splitlines()[0]})
            continue
        if not isinstance(data, dict) or not isinstance(data.get("verdicts"), list):
            continue   # not a bundle
        pano = data.get("_panopticon")
        if not isinstance(pano, dict):
            pano = {}
        run_id = pano.get("run_id")
        stage_default = pano.get("stage") or "primary"
        for raw in data["verdicts"]:
            if not (isinstance(raw, dict)
                    and str(raw.get("verdict", "")).upper() in VERDICT_VALUES
                    and raw.get("finding_id")):
                continue
            v = dict(raw)
            v.setdefault("run_id", run_id)
            v.setdefault("stage", stage_default)
            by_fid.setdefault(str(v["finding_id"]), []).append(v)
    return by_fid, unloadable


def match_verdict_by_id(finding, by_fid, run_id=None):
    """Match a bundle verdict to a finding by its assigned `id`. by_fid maps a
    finding_id to a LIST of candidate verdicts (primary and/or backup, possibly
    across runs). When run_id is given, only same-run candidates are eligible
    (so a stale cross-run verdict can never evict a valid one); among the
    eligible, a backup-stage verdict wins over a primary."""
    fid = finding.get("id")
    if not fid:
        return None
    candidates = by_fid.get(str(fid))
    if not candidates:
        return None
    if run_id is not None:
        candidates = [c for c in candidates if c.get("run_id") == run_id]
        if not candidates:
            return None
    for c in candidates:
        if c.get("stage") == "backup":
            return c
    return candidates[0]


def apply_verdict(finding, verdict):
    """Merge an advisor verdict into provenance/citations/references.

    Never touches severity or confidence — the two-axis invariant. Citation
    re-validation happens afterwards via citations.enrich_citations.
    """
    prov = finding.setdefault("provenance", {})
    v = str(verdict.get("verdict", "")).upper()
    prov["confirmation_status"] = {"CONFIRMED": "CONFIRMED",
                                   "REJECTED": "REJECTED"}.get(v, "NEEDS_MORE_INFO")
    prov["confirmed_by"] = "agent:advisor"
    prov["confirmation_reasoning"] = verdict.get("reasoning")
    if verdict.get("model"):
        prov["confirmed_by_model"] = verdict["model"]
    merge_citations(finding, {"citations": verdict.get("citations") or {}})
    existing = set(finding.get("references") or [])
    for ref in verdict.get("references") or []:
        if ref not in existing:
            finding.setdefault("references", []).append(ref)
            existing.add(ref)
