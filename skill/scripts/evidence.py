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
    from scripts import safe_write
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    import safe_write
    from _version import __version__

# #1639 P15 F3: the pinned types live in ONE module (it both enforces them on
# the way out and normalizes to them on the way in), and the verdict boundary
# is one of the places that has to normalize. `validate_schema` imports nothing
# of ours, so this cannot cycle back through `synth`.
#
# Fix round 3, R2-5: this module must stay importable FLAT (with skill/scripts
# itself on sys.path) -- `citations` and `html_report` reach it that way, and
# round 2 narrowed the mode by accident. The `_version` idiom three lines up
# cannot be copied here, though: `synth` is a PACKAGE, and layout rule 2
# (tests/test_layout.py) forbids `import synth.validate_schema` anywhere under
# skill/scripts, because a flat package import builds a SECOND module object
# with its own state and its own patch targets. So flat mode gets None and the
# repair becomes a no-op there -- narrower than the package path and said out
# loud rather than crashing four modules at import. No flat caller adjudicates
# verdicts: every verdict reader (`phases/verify`, `synthesize`) is
# package-imported, which `tests/test_agent_verdict_guard.py` enumerates.
try:
    import scripts.synth.validate_schema as validate_schema_mod
except ModuleNotFoundError:            # imported flat: see above
    validate_schema_mod = None

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
# Canonical panel list, in display order. synthesize's VALID_PANELS/PANEL_ORDER,
# html_report's _PANEL_ORDER, and the findings-filename regexes in synthesize
# and group_runner all derive from this one definition.
PANELS = ["code", "test", "security", "architecture", "database", "redteam"]
# `backup_scope_limited` (#1638 P16, owner ruling D4): the PRIMARY advisor
# confirmed this claim and the backup could not check it, because the files it
# needed were outside the bounded evidence closure it was granted. It is a
# confirmed finding wearing a disclosure, not a contested one -- see
# `match_verdict_by_id`.
BACKUP_SCOPE_LIMITED = "backup_scope_limited"
EVIDENCE_STATUSES = ("tool_reported", "tool_confirmed", "advisor_confirmed",
                     "corroborated", "needs_more_info", "unverified",
                     "rejected", BACKUP_SCOPE_LIMITED)
# `backup_scope_limited` is gate-eligible for the same reason it exists: a
# primary CONFIRMED stands. Before #1638 P16 the same finding was demoted to
# `needs_more_info` and silently dropped out of the gate -- an evidence-scope
# failure quietly deciding a release gate is the defect, not the fix.
GATE_ELIGIBLE_DEFAULT = frozenset({"tool_confirmed", "advisor_confirmed",
                                   BACKUP_SCOPE_LIMITED})
VERDICT_VALUES = {"CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"}

# Internal carrier, underscore-prefixed like `_merged_ids`: the paths a
# scope-limited backup named, hung on the PRIMARY verdict that survived it so
# `derive_evidence` and the report can say what the backup could not see.
# CONTROLLER-OWNED: `match_verdict_by_id` is its only writer, which `_agent_verdict`
# below is what actually enforces -- fix round 1 F1 found the comment asserting
# it while both loaders copied an agent's object verbatim.
SCOPE_LIMITED_FIELD = "_backup_missing_evidence"


# Identity an advisor may not assert about its own verdict. `stage` decides how
# the verdict is READ rather than what it says: it picks which candidate is
# treated as the adversarial second opinion, and fix round 2 N2 demonstrated one
# PRIMARY bundle declaring a second entry `stage: "backup"` and fabricating a
# gate-eligible `backup_scope_limited` disclosure with no private key at all.
# The loaders put the controller's own value back -- from `_panopticon.stage`
# for a stamped bundle, from the controller-chosen FILENAME for a legacy
# single-verdict file.
#
# `run_id` is deliberately NOT here. On the bundle path the stamp overrides it
# anyway (`load_verdict_bundles` assigns rather than defaults), and on the legacy
# queue path there is no stamp to restore it from: it is an ECHO the advisor was
# handed and `match_verdict` checks, exactly like `finding_id`, and echoing it
# wrongly only drops the advisor's own verdict. An echo confers nothing; `stage`
# confers a round.
CONTROLLER_STAMPED = ("stage",)


def _agent_verdict(raw):
    """THE trust boundary for an agent-written verdict. One sanitizer, used by
    every read path (`tests/test_agent_verdict_guard.py` walks the tree and
    fails if a fourth reader appears without it).

    Two jobs:

    (a) strip every private (`_`-prefixed) key. They are the pipeline's own
        carriers -- `_backup_missing_evidence` here, `_merged_ids`/`_group` on
        findings -- so an advisor that plants one is asserting a controller
        decision. Round 1 F1 demonstrated a backup REJECTION laundered into a
        retained primary CONFIRMED (rejected, factor 0.0, out of the gate ->
        backup_scope_limited, factor 1.5, IN the gate) and a primary-only
        verdict fabricating a "backup could not see" disclosure about a round
        that never ran; round 2 N1 then found the same key emptying a cell's
        whole backup scope through `phases/verify._cell_verdicts`, so no
        adversarial round was dispatched;

    (b) drop `CONTROLLER_STAMPED` (`stage`), which is round 2 N2: an advisor may
        say what it concluded, never which ROUND it was.

    A rule at the door rather than a check at each reader, for the same reason
    the `_panopticon` stamp is controller-owned: per-reader discipline is what
    failed, twice. Everything an advisor is actually asked for -- including the
    public `missing_evidence` and `evidence_scope` -- passes through with its
    CONTENT untouched.

    Three jobs since #1639 P15 fix round 2 (F3). The third is TYPE repair: the
    verify round writes this verdict's `reasoning`, `model`, `code`,
    `references` and `citations` onto an already-normalized finding, into
    fields `report-schema.json` pins -- after the findings boundary, with
    nothing between. One advisor answering in a list where a string belongs
    ended a completed run in `error`. `validate_schema.repair_verdict` does it
    against the schema nodes those fields land in, so this boundary and the
    findings boundary cannot disagree about a type.
    """
    clean = {k: v for k, v in raw.items()
             if not str(k).startswith("_") and k not in CONTROLLER_STAMPED}
    if validate_schema_mod is None:
        return clean                   # flat import: no schema to repair against
    return validate_schema_mod.repair_verdict(clean)


def scope_limited_paths(verdict):
    """The files a NEEDS_MORE_INFO verdict says it was NOT granted, or [].

    The PUBLIC field only (`missing_evidence`), and only once the verdict is
    established as NEEDS_MORE_INFO: a CONFIRMED or REJECTED advisor decided, and
    whatever it did not read is not a scope failure. This is what
    `match_verdict_by_id` consults, so no agent-supplied key can reach the
    retain-the-primary branch. Defensive about shape -- the field is
    agent-supplied.
    """
    if not isinstance(verdict, dict):
        return []
    if str(verdict.get("verdict", "")).upper() != "NEEDS_MORE_INFO":
        return []
    missing = verdict.get("missing_evidence")
    if not isinstance(missing, list):
        return []
    return [p for p in missing if isinstance(p, str) and p]


def carried_paths(verdict):
    """What `match_verdict_by_id` RECORDED on the verdict it kept, or [].

    The controller carrier, read by `derive_evidence` and `synth.codes` alone.
    Separate from `scope_limited_paths` so the two directions cannot be confused:
    one reads what an agent said, the other what the controller decided.
    """
    if not isinstance(verdict, dict):
        return []
    carried = verdict.get(SCOPE_LIMITED_FIELD)
    if not isinstance(carried, list):
        return []
    return [p for p in carried if isinstance(p, str) and p]


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
    finding already run through synth.findings.normalize_finding so title/category
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
        derived = {"status": status,
                   "verified_by": ([origin, "agent:advisor"] if tool_like
                                   else "agent:advisor"),
                   "reasoning": (verdict or {}).get("reasoning"),
                   "citation_quality": quality}
        # #1638 P16: a CONFIRMED that survived a scope-limited backup is still
        # confirmed, and the report says which files the backup could not see.
        missing = carried_paths(verdict or {})
        if missing and v == "CONFIRMED":
            derived["status"] = BACKUP_SCOPE_LIMITED
            derived["missing_evidence"] = list(missing)
        return derived

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
    NOT safe -- synth.report.build_report strips it (`f.pop("_group", None)`)
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
            # lives only in the queue. synth.report.build_report exports
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
    # #1735: `<run_dir>/verify-queue.json` sits in the reviewed tree's
    # `.panopticon`. Confine first -- the makedirs below would otherwise walk a
    # symlinked intermediate directory -- then open without following a link.
    safe_write.confine_artifact_path(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with safe_write.open_w_nofollow(path) as fh:
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


def _first_balanced_json(body):
    """Return the first balanced, parseable ``{...}`` object embedded in ``body``,
    or None. Scans brace depth while respecting string literals and escapes, so a
    stray brace in surrounding prose -- before OR after the object -- does not
    derail extraction the way a greedy ``\\{.*\\}`` span does (it runs from the
    first ``{`` to the LAST ``}``, swallowing any prose brace at either end).
    Advances to the next ``{`` when a balanced span fails to parse, so a non-JSON
    ``{see note}`` ahead of the real object is skipped, not mistaken for it.
    Pure; never raises."""
    n = len(body)
    i = 0
    while True:
        start = body.find("{", i)
        if start < 0:
            return None
        depth, in_str, esc = 0, False, False
        for j in range(start, n):
            c = body[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(body[start:j + 1])
                    except json.JSONDecodeError:
                        break   # not parseable; try the next '{'
        i = start + 1


def load_json_tolerant(body):
    """Parse JSON from text, stripping markdown code blocks and searching for JSON object."""
    body = body.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\s*", "", body)
        body = re.sub(r"\s*```\s*$", "", body).strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError as first_err:
        # #1058: first-class brace extraction. Narrative wrapping ("Here is my
        # verdict: {...}. Set {x} in config.") lost 8/79 advisor verdicts in
        # run-5; 3 repeated on retry, so it is prompt-induced, not noise. The
        # balanced scanner accepts the first well-formed object regardless of
        # prose braces at either end; the greedy regex stays as a last-resort
        # fallback for shapes the scanner can't balance. A total miss re-raises
        # so a genuinely-corrupt return still lands in `unloadable` (#938).
        obj = _first_balanced_json(body)
        if obj is not None:
            return obj
        m = re.search(r"(\{.*\})", body, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        raise first_err


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
    ``*.json`` that failed to parse, was malformed, or lacked a valid verdict key
    or finding_id echo.

    Single-verdict files are parsed strictly with ``json.load`` (#1193): a
    markdown fence or surrounding prose makes the file unloadable, so an LLM
    that failed to follow the output contract cannot bypass the echo-check by
    accident. The echo-check itself (match_verdict) already requires a
    ``finding_id``; load_verdicts_detailed now enforces the same requirement at
    load time so a verdict without a finding_id can never be treated as "done".
    Callers surface ``unloadable`` in the report so a corrupt verdict is visible,
    not silently dropped (#938).

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
                data = json.load(fh)
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
        if not data.get("finding_id"):
            print("evidence: skipping verdict %s: missing/empty finding_id echo" % name,
                  file=sys.stderr)
            unloadable.append({"file": name, "reason": "missing/empty finding_id echo"})
            continue
        # F1: the same trust boundary as the bundle loader -- a single-verdict
        # file is agent-written too, and `match_verdict` feeds it to the same
        # `derive_evidence`. The stage this path has is PATH-derived (fix round
        # 2, N2): the controller chose the filename, so `-backup.json` is its
        # own stamp, and an advisor's declared `stage` is gone with the rest.
        queue_id = name[:-len(".json")]
        out[queue_id] = dict(_agent_verdict(data),
                             stage="backup" if queue_id.endswith("-backup")
                             else "primary")
    return out, unloadable


def load_verdicts(verdicts_dir):
    """Load advisor verdict files keyed by queue_id (filename stem).

    Verdicts-only wrapper over load_verdicts_detailed (unchanged contract for
    callers that don't need the un-loadable-file accounting).
    """
    return load_verdicts_detailed(verdicts_dir)[0]


def match_verdict(entry, verdicts, run_id=None, misrouted=None):
    """Return the verdict for a queue entry, enforcing the finding_id echo.

    A missing or mismatched echo means the verdict cannot be bound to the
    queued claim -> treated as malformed (None). Filename routing alone is not
    evidence that an advisor answered the intended finding.

    `misrouted` (optional list): when a verdict FILE exists for this cell but
    cannot be bound to it, a record is appended describing why.

    #1475: without that list, a rejection here is indistinguishable downstream
    from a cell no advisor ever answered -- both land in `unanswered`. Run-6
    lost its certification to exactly one such rejection (the advisor dispatched
    for SG-006 echoed ESS-036), and the report said only "1 unanswered", which
    reads as a dispatch that never happened. Diagnosing it took a hand-dig
    through the raw agent transcript to establish that the advisor HAD run,
    HAD adjudicated, and had simply mislabelled its answer. The rejection is
    correct; its invisibility was the defect.
    """
    v = verdicts.get(entry["queue_id"])
    if v is None:
        return None

    def _reject(reason, **extra):
        print("evidence: verdict %s %s; ignoring" % (entry["queue_id"], reason),
              file=sys.stderr)
        if misrouted is not None:
            rec = {"queue_id": entry["queue_id"], "reason": reason}
            rec.update(extra)
            misrouted.append(rec)
        return None

    fid = entry["finding"].get("id")
    echoed = v.get("finding_id")
    if echoed is None:
        return _reject("has no finding_id echo", expected=fid, echoed=None)
    if str(echoed) != str(fid):
        return _reject("echoes finding_id %r, expected %r" % (echoed, fid),
                       expected=fid, echoed=str(echoed))
    if run_id is not None and v.get("run_id") != run_id:
        return _reject("has run_id %r, expected %r" % (v.get("run_id"), run_id),
                       expected_run_id=run_id, run_id=v.get("run_id"))
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
            unloadable.append({"file": name, "reason": (str(e).splitlines() or [""])[0]})
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
            v = _agent_verdict(raw)
            # Assigned, not setdefault'ed (fix round 2, N2): the CONTROLLER
            # stamp is the only authority for either. The sanitizer has already
            # dropped any declared `stage`; `run_id` is overwritten here for the
            # same reason. An unstamped bundle gets run_id None and stage
            # "primary" -- fail closed, since there is no authority for "backup"
            # and persist refuses such a bundle anyway.
            v["run_id"], v["stage"] = run_id, stage_default
            by_fid.setdefault(str(v["finding_id"]), []).append(v)
    return by_fid, unloadable


MERGED_IDS_FIELD = "_merged_ids"


def merged_ids(finding):
    """Ids of findings collapsed INTO this one by dedupe, if any.

    #1476: dedupe drops the non-survivor outright, so its assigned id vanishes
    from the report and every verdict that echoed it binds to nothing. Run-6 lost
    148 of 2,043 supplied verdicts that way -- roughly 7% of the most expensive
    phase of a run, and a CONFIRMED verdict among them means a real finding is
    reported as unverified.

    The id is content-derived and must stay so (the driver and synthesize compute
    it independently and have to agree), so the survivor keeps the collapsed ids
    as ALIASES instead. Underscore-prefixed like `_group`: an internal carrier
    stripped before the report is written, never a trust field an agent asserts.
    """
    ids = finding.get(MERGED_IDS_FIELD)
    return [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []


def record_merged_id(best, other):
    """Carry `other`'s identity onto the survivor dedupe kept, transitively.

    Transitive because a cluster larger than two collapses in stages: an alias a
    first merge recorded must survive a second, or the earliest twin's verdict
    unbinds anyway. Lives here beside `merged_ids` so the alias vocabulary has
    exactly one home.
    """
    aliases = list(merged_ids(best))
    for candidate in [other.get("id")] + merged_ids(other):
        if (isinstance(candidate, str) and candidate
                and candidate != best.get("id") and candidate not in aliases):
            aliases.append(candidate)
    if aliases:
        best[MERGED_IDS_FIELD] = aliases


# Least favourable to the FINDING, first. A BACKUP advisor that says two things
# about one claim has the more sceptical of them taken (fix round 2, N6):
# first-wins silently discarded a REJECTED that arrived after a
# NEEDS_MORE_INFO in the same bundle, which is a refutation thrown away. Ties
# and unknown values keep arrival order, so a single-candidate pool is unchanged.
#
# Deliberately NOT applied to duplicate PRIMARIES, and the asymmetry is the
# point. The backup round is adversarial by construction -- scepticism is what
# it is for, and a backup that wanted to refute could simply emit the REJECTED
# alone, so the rule hands a hostile backup nothing it did not already have. A
# primary is the round that establishes a finding, and demoting on contradiction
# there WOULD be a new lever: an advisor that disliked a claim could emit
# CONFIRMED + NEEDS_MORE_INFO and drop it out of the gate at no cost. Duplicate
# primaries keep today's first-wins.
# REJECTED > NEEDS_MORE_INFO (bare) > NEEDS_MORE_INFO (scope-limited) >
# CONFIRMED. The two NMI shapes are NOT equal (fix round 3, D4): a bare one says
# the advisor looked and the code does not say; a scope-limited one says it was
# not allowed to look. Scoring them the same left `min`'s stability -- i.e. the
# advisor's own array order -- deciding between factor 0.5 and out of the gate
# and factor 1.5 and in it, which is the rule not being applied rather than a
# rule with a tie in it.
_VERDICT_SCEPTICISM = {"REJECTED": 0, "NEEDS_MORE_INFO": 1, "CONFIRMED": 3}
_SCOPE_LIMITED_SCEPTICISM = 2
_UNKNOWN_SCEPTICISM = 4


def _scepticism(candidate):
    """How unfavourable to the finding this verdict is; lower wins."""
    verdict = str(candidate.get("verdict", "")).upper()
    rank = _VERDICT_SCEPTICISM.get(verdict, _UNKNOWN_SCEPTICISM)
    if verdict == "NEEDS_MORE_INFO" and scope_limited_paths(candidate):
        return _SCOPE_LIMITED_SCEPTICISM
    return rank


def _least_favourable(candidates):
    """The most sceptical of several BACKUP verdicts for one finding."""
    return min(candidates, key=_scepticism)


def resolve_duplicates(candidates, stage="primary"):
    """THE rule for several verdicts about one finding at one stage, or None.

    One definition, called by BOTH the driver (`verify._cell_backup_findings`,
    via `by_finding_id`) and synthesis (`match_verdict_by_id`) -- fix round 3,
    D1, where they disagreed. The driver's map was a dict comprehension
    (last-wins) and synthesis took `candidates[0]` (first-wins), so a primary
    bundle emitting CONFIRMED then REJECTED for one finding made the driver see
    `rejected`, drop the finding from the backup scope and dispatch NO
    adversarial round, while synthesis published `advisor_confirmed` at factor
    1.5 with nothing recording that the second opinion never happened. Two
    readers of one bundle must not answer differently.

    BACKUP duplicates take the least favourable to the finding (N6); PRIMARY
    duplicates keep first-wins. The asymmetry is deliberate and documented in
    `match_verdict_by_id`.
    """
    candidates = [c for c in candidates if isinstance(c, dict)]
    if not candidates:
        return None
    return (_least_favourable(candidates) if stage == "backup"
            else candidates[0])


def by_finding_id(verdicts, stage="primary"):
    """`finding_id -> the one verdict that counts`, duplicates resolved by
    `resolve_duplicates`. The driver's shape; synthesis keeps the candidate
    LISTS because it also filters them by run_id first."""
    pools = {}
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        fid = v.get("finding_id")
        if fid is not None:
            pools.setdefault(str(fid), []).append(v)
    return {fid: resolve_duplicates(pool, stage) for fid, pool in pools.items()}


def match_verdict_by_id(finding, by_fid, run_id=None):
    """Match a bundle verdict to a finding by its assigned `id`. by_fid maps a
    finding_id to a LIST of candidate verdicts (primary and/or backup, possibly
    across runs). When run_id is given, only same-run candidates are eligible
    (so a stale cross-run verdict can never evict a valid one); among the
    eligible, a backup-stage verdict wins over a primary -- EXCEPT when the
    backup's NEEDS_MORE_INFO is an evidence-SCOPE failure (#1638 P16, ruling 3).

    A backup that returns NEEDS_MORE_INFO naming the files it was not granted
    (`missing_evidence`) is not disagreeing with the primary; it is reporting
    that it could not look. Run-13's redaction-order defect was CONFIRMED by the
    primary, reproduced by hand, and then published as unverifiable because the
    backup -- granted the claim file alone -- said NEEDS_MORE_INFO about a
    cross-file call order. So a scope-limited backup NMI displaces NO primary:
    the primary verdict is returned, carrying the paths the backup named, and
    `derive_evidence` spends that carrier only on a CONFIRMED -- which is what
    makes the honest `backup_scope_limited`, while a primary REJECTED stays
    `rejected` and a bare primary NMI stays `needs_more_info` (fix round 4, N1;
    the branch used to retain a CONFIRMED only, so a rejected finding was
    published as a gate-eligible disclosure instead). A backup NMI that names
    NOTHING is a substantive "the code does not say", and keeps today's
    backup-wins semantics.

    Where several BACKUP verdicts exist for one finding, the LEAST FAVOURABLE to
    it is the one that counts, and where several PRIMARY verdicts do, first-wins
    -- BOTH through `resolve_duplicates`, so the retained primary above is the
    same verdict the driver acted on. `stage`
    itself is controller-stamped at load, so "the backup" is a round the driver
    dispatched, never a label an advisor chose for itself -- which is also what
    makes the retained primary and the scope-limited backup necessarily
    different bundles.
    """
    fid = finding.get("id")
    if not fid:
        return None
    # #1476: the finding's OWN id first, then the ids dedupe collapsed into it.
    # Order is the whole discipline -- an alias must never outrank the real id,
    # because the survivor's own verdict adjudicated the finding that survived.
    # Aliasing widens WHICH id may bind, never which RUN: the run_id filter below
    # is applied to alias candidates identically, so a stale cross-run verdict
    # gains no new way in.
    candidates = None
    for key in [str(fid)] + merged_ids(finding):
        pool = by_fid.get(key)
        if not pool:
            continue
        if run_id is not None:
            pool = [c for c in pool if c.get("run_id") == run_id]
        if pool:
            candidates = pool
            break
    if not candidates:
        return None
    backups = [c for c in candidates if c.get("stage") == "backup"]
    if not backups:
        return resolve_duplicates(candidates, "primary")
    backup = resolve_duplicates(backups, "backup")
    missing = scope_limited_paths(backup)
    if missing:
        # Fix round 4, N1: WHICH primary is the shared rule's job, not a local
        # `next(... == "CONFIRMED")`. A primary bundle emitting REJECTED then
        # CONFIRMED for one finding used to hand this branch the CONFIRMED that
        # first-wins had already discarded -- publishing `backup_scope_limited`
        # (factor 1.5) where the driver said `rejected`.
        primary = resolve_duplicates(
            [c for c in candidates if c.get("stage") != "backup"], "primary")
        if primary is not None:
            # Whatever that verdict is: a scope failure is not a disagreement,
            # so it displaces NOTHING. The carrier rides along and
            # `derive_evidence` spends it only on a CONFIRMED, so a rejection
            # stays `rejected` and a bare NMI stays `needs_more_info` instead of
            # being upgraded into a gate-eligible disclosure.
            kept = dict(primary)
            kept[SCOPE_LIMITED_FIELD] = missing
            return kept
    return backup


def apply_verdict(finding, verdict):
    """Merge an advisor verdict into provenance/citations/references.

    Never touches severity or confidence — the two-axis invariant. Citation
    re-validation happens afterwards via citations.enrich_citations.

    The advisor's own `code` is RECORDED, never applied. An advisor that lands
    on a different OCRDb code than the panel did is stating a considered second
    opinion about the catalog — it re-read the code independently — and that
    disagreement is the only mis-fit signal the pipeline produces. It used to be
    dropped here: on btcpayserver run-1, 7 findings whose advisor said "this is
    actually a gap" (`<DOM>-X0X`) kept the panel's real code and never reached
    the gap pool, while 2 whose advisor found a real code for a panel-declared
    gap stayed in it — exactly the wrong half of the signal surviving.

    Recorded rather than applied for the same reason severity is untouched: one
    advisor is not an authority on the catalog, and silently re-coding a finding
    would change what the report claims on a single opinion. `advisor_code` is
    set only when it DIFFERS, so its presence is itself the strain flag.
    """
    prov = finding.setdefault("provenance", {})
    advisor_code = verdict.get("code")
    if advisor_code and str(advisor_code) != str(finding.get("code") or ""):
        prov["advisor_code"] = str(advisor_code)
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
