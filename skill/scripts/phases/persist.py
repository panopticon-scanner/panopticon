"""The one place a RETURN-PERSIST reply becomes a file (spec 4.5, plan 6).

`driver persist ENTRY_ID` (session mode) and the headless loop both call
`write_reply`: parse the reply tolerantly (fence- or prose-wrapped JSON), apply
the SAME acceptance the phase's own done predicate applies, and write the
entry's out_file atomically. The model never parses JSON, never picks a path,
never writes a findings file by hand. Refusals write nothing.
"""
import os
import re
import tempfile

import scripts._version as version
import scripts.claim_scope as claim_scope
import scripts.evidence as evidence
import scripts.findings_contract as findings_contract
import scripts.group_runner as group_runner
import scripts.probes.common as probes_common
import scripts.redact as redact
import scripts.run_manifest as run_manifest
import scripts.tolerant_json as tolerant_json
from . import budget
from . import coverage
from . import requests
from . import review
from . import runio
from . import verify

ROLES = ("scout", "setup-scan", "review-cell", "verify-cell", "tool-advisor")
_STAMP_KEYS = ("run_id", "group", "domain", "stage")
# D10 ruling 1: refused replies are kept HERE, beside the run's other
# artifacts -- one folder, one shape, never read by a done predicate.
REJECTED_DIR = "rejected"
# #3231 A2: a tool advisor's ONE re-dispatch replies in `verdicts/lift/`, which no verdict
# reader lists, so the first answer stands until `verify_tools._promote_lifts`.
LIFT_DIR = "lift"


def run_dir(review_root, namespace=None):
    """The folder this invocation's run artifacts live in -- `runs/<tag>/` for
    a review, the flat `.panopticon/` for `--setup`.

    ONE resolver, shared by `orchestrate.loop` (which needs it for the ledger
    and the guard files), `persist_cli` and `requests._materialize_prompts`
    (D10 ruling 2, which has to find the rejected records the loop wrote).
    `probes.common.headless_settings_path` is that resolver -- namespace-aware,
    and the file the runner actually arms -- so the run folder is its dirname
    and never a second spelling of the same lookup."""
    return os.path.dirname(probes_common.headless_settings_path(review_root, namespace))


# D10 ruling 3: the PUBLISHED receipt schema each returning role is accepted
# against. Claude also uses it at generation; #3241 gives Codex narrower
# projections below. Scout and setup-scan are absent on purpose: their shape
# lives in code, and publishing a second definition is how the two drift.
ROLE_SCHEMAS = {"review-cell": "findings-envelope-schema.json",
                "verify-cell": "verdict-bundle-schema.json",
                "tool-advisor": "advisor-verdict-schema.json"}

# #3241: provider-facing projections are NOT receipt contracts. Codex needs
# every object closed and every exposed property required; replacing the broad
# role schemas with those projections would reject legacy/optional receipt
# shapes and would also change Claude's calibrated inline `--json-schema` argv.
# Keep the split explicit: `role_schema` remains the receipt authority, while
# `generation_schema` is selected only for the families listed here.
STRICT_GENERATION_HOSTS = frozenset(("codex",))
GENERATION_SCHEMAS = {
    "review-cell": "review-cell-generation-schema.json",
    "verify-primary": "verify-primary-generation-schema.json",
    "verify-backup": "verify-backup-generation-schema.json",
    "tool-advisor": "tool-advisor-generation-schema.json",
}


def role_schema(entry):
    """Absolute path of this entry's published receipt schema, or None."""
    name = ROLE_SCHEMAS.get(role_of(entry))
    return os.path.abspath(version.reference_path(name)) if name else None


def generation_schema(entry):
    """Absolute provider projection for one production entry, or None.

    Verify has two prompt shapes. An absent stage is the controller's existing
    spelling of primary; an unknown future stage falls back to receipt-only
    validation rather than ending a run on an optimization it cannot express.
    """
    role = role_of(entry)
    if role == "verify-cell":
        stage = (entry.get("stage") or "primary"
                 if isinstance(entry, dict) else "primary")
        if stage not in ("primary", "backup"):
            return None
        key = "verify-%s" % stage
    else:
        key = role
    name = GENERATION_SCHEMAS.get(key)
    return os.path.abspath(version.reference_path(name)) if name else None


def launch_schema(entry, host):
    """The schema this host sees at generation; receipt stays `role_schema`."""
    if host in STRICT_GENERATION_HOSTS:
        return generation_schema(entry)
    return role_schema(entry)


def production_probe_schema(host):
    """#3394: Schema a returning production review cell hands this host.

    Keep the proof on ``launch_schema``, the selection seam used by every entry."""
    return launch_schema({"out_file": "findings-probe-COD.json"}, host)


# D10 ruling 2: what the retry is told to return, one line per role. The
# refusal reason says what was wrong; this says what right looks like, in the
# shape the role's own acceptance checks -- `accepts` below is the authority
# on each of these, and they are written to match it, not the templates.
ENVELOPE_SHAPES = {
    "scout": '{"domains": [...], "files": [...], "tools": [...]}',
    "setup-scan": "a single JSON object (the setup proposal)",
    "review-cell": '{"schema_version": 1, "findings": [ ... ], "_panopticon": {"run_id": "...", "group": "...", "domain": "..."}}',
    "verify-cell": '{"schema_version": 1, "verdicts": [ ... ], "_panopticon": {"run_id": "...", "group": "...", "domain": "...", "stage": "..."}}',
    "tool-advisor": '{"schema_version": 1, "finding_id": "...", "verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO", "confidence": "...", "reasoning": "...", "explored": [...], "references": [...], "citations": {...}}',
}


REASON_CAP = redact.REASON_CAP


def envelope_shape(entry):
    """The one-line envelope this entry's role is accepted against."""
    return ENVELOPE_SHAPES.get(role_of(entry)) or "a single JSON object"


def role_of(entry):
    """Which acceptance rule applies, keyed on the out_file NAME (R-P6-3):
    the driver's file families are the stable contract; entry ids vary by
    round. None for a family no rule knows -- refused, fail-closed."""
    out_file = entry.get("out_file") if isinstance(entry, dict) else None
    if not isinstance(out_file, str) or not out_file:
        return None
    name = os.path.basename(out_file)
    parent = os.path.basename(os.path.dirname(out_file))
    # D10 F6: the folder before the name. A retained record is named after the
    # ENTRY (`rejected/scout-app-1.json`), which for a scout collides with the
    # scout artifact family exactly; nothing under `rejected/` is a role.
    if parent == REJECTED_DIR:
        return None
    if name.startswith("scout-") and name.endswith(".json"):
        return "scout"
    if name == "setup-proposal.json":
        return "setup-scan"
    if name.startswith("findings-") and name.endswith(".json"):
        return "review-cell"
    if parent == "verdicts" and name.endswith(".json"):
        return "verify-cell" if name.startswith("verdicts-") else "tool-advisor"
    if (parent == LIFT_DIR and name.endswith(".json") and not name.startswith("verdicts-")
            and os.path.basename(os.path.dirname(os.path.dirname(out_file))) == "verdicts"):
        return "tool-advisor"
    return None


def _stamp_matches(entry, data):
    declared = {k: entry.get(k) for k in _STAMP_KEYS if entry.get(k) is not None}
    if not declared:
        return True, ""
    meta = data.get("_panopticon")
    if not isinstance(meta, dict):
        return False, "reply carries no _panopticon stamp; the entry declares %s" % sorted(declared)
    for k, v in declared.items():
        if meta.get(k, "primary" if k == "stage" else None) != v:
            return False, "_panopticon.%s is %s, the entry is %r" % (
                k, redact._reason_repr(meta.get(k)), v)
    return True, ""


# D10 ruling 4: the roles whose RETURN-PERSIST reply the controller will stamp
# for itself. Both are cells the driver named on the entry it dispatched; the
# tool-advisor and the scout declare no cell identity to fill.
_CONTROLLER_STAMP_ROLES = ("review-cell", "verify-cell")


def _controller_stamp(entry, data):
    """`data` with any cell-identity key the reply OMITTED filled in from the
    entry, marked `stamped_by: "controller"` -- or `data` unchanged when the
    reply already says everything the entry declares (D10 ruling 4).

    Only ever called from `write_reply`, i.e. only for a reply the controller
    itself is about to persist. The driver wrote those keys onto the entry, is
    holding the entry, and is choosing the path: on this path the identity was
    never in question, and demanding the agent echo it back is a shape tax that
    cost run-13 seven of its eight failed attempts.

    A key the reply DOES carry is never touched, so a stamp that contradicts
    the entry still meets `_stamp_matches` and is still refused: the controller
    fills a silence, it does not overrule a claim. A `_panopticon` that is
    present but not an object is likewise left alone -- that is a malformed
    claim, not an absent one.
    """
    meta = data.get("_panopticon")
    if meta is not None and not isinstance(meta, dict):
        return data
    meta = dict(meta or {})
    missing = {k: entry.get(k) for k in _STAMP_KEYS
               if entry.get(k) is not None and k not in meta}
    if not missing:
        return data
    return dict(data, _panopticon={**meta, **missing, "stamped_by": "controller"})


def _version_defect(entry, data):
    """#2104: the reply's declared format version, or None. Its own check,
    beside the identity stamp and never folded into it, so each refusal says
    which one failed. A verdict BUNDLE is refused whole for any unknown version
    in it, so the retry runs (`findings_contract.bundle_version_defect`)."""
    role = role_of(entry)
    if role == "verify-cell":
        verdicts = data.get("verdicts") if isinstance(data, dict) else None
        return findings_contract.bundle_version_defect(data, [
            evidence._agent_verdict(v) for v in verdicts or () if isinstance(v, dict)])
    if role in ("review-cell", "tool-advisor"):
        return findings_contract.schema_version_defect(data)
    return None


def accepts(entry, data):
    """(ok, reason): would the phase's own done predicate accept this data at
    the entry's out_file? Mirrors coverage (scout shape), review (findings
    contract + stamp), verify (verdict list + stamp) and the tool round
    (a valid verdict value)."""
    role = role_of(entry)
    if role is None:
        return False, "no persist role for out_file %r" % entry.get("out_file")
    if role == "scout":
        errs = coverage._scout_shape_errors(data)
        return (not errs), ("; ".join(errs) if errs else "")
    if role == "setup-scan":
        from scripts.tools.base import inert_text
        # #3631: the same validator ingest applies, so an empty or shapeless proposal
        # (`{}` from an agent whose reads were refused) is a failed dispatch HERE,
        # naming the role, not an accepted reply that setup rejects later.
        from scripts import claim_scope, setup_proposal
        out_file = entry.get("out_file") or ""
        review_root = claim_scope.review_root_of_artifact_path(out_file)
        if review_root is None:
            # Fail closed (#3632 r2): without the root the absolute-glob check cannot run,
            # so a reply nobody can place is refused, never accepted unchecked.
            return False, ("setup-scan reply cannot be placed: out_file %r has no .panopticon "
                           "segment" % inert_text(out_file, limit=REASON_CAP))
        errors = setup_proposal.validate_proposal(data, review_root=review_root)
        # The errors quote agent-written text (capability names): masked and capped like
        # every reply reason FIRST (so no token is cut before the masker sees it), then made
        # inert -- no control or bidi characters reach a terminal.
        return (not errors), ("setup-scan proposal is not valid: %s" % inert_text(
            _safe_schema_reason(errors), limit=REASON_CAP) if errors else "")
    version = _version_defect(entry, data)
    if version:
        return False, version
    if role == "review-cell":
        if not findings_contract.is_acceptable(data):
            return False, "not an acceptable findings file (a `findings` list of objects)"
        return _stamp_matches(entry, data)
    if role == "verify-cell":
        if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
            return False, "a verdict bundle must carry a `verdicts` list"
        return _verify_accepts(entry, data)
    raw_verdict = data.get("verdict", "") if isinstance(data, dict) else ""
    verdict = str(raw_verdict).upper()
    if verdict not in evidence.VERDICT_VALUES:
        return False, "verdict %s is not one of %s" % (
            redact._reason_repr(raw_verdict), sorted(evidence.VERDICT_VALUES))
    return verify.verify_tools.echo_matches(entry, data)


# `verdicts-<group>-<domain>[-backup][-partN].json` (verify._verify_out_file):
# part 0 keeps the unsuffixed name, so an absent suffix IS part 0.
_VERIFY_PART = re.compile(r"-part(\d+)\.json$")


def _verify_cell_of(entry):
    """(review_root, manifest, group, domain, stage, part) for a verify-cell
    entry, or None when it cannot be placed on disk.

    Entry-anchored, exactly as the review-cell rule is: `run_id` comes off the
    entry that ASKED for this bundle -- the same key `_stamp_matches` checks --
    and `review_root` off the artifact path it was told to write, the segment
    above its own `.panopticon` (`claim_scope.review_root_of_artifact_path`,
    shared with the advisor renderer). The verify phase reads only `run_id`
    off the manifest, so that one key is the whole manifest a placement needs.

    None is fail-closed at both call sites: a bundle nobody can place is
    refused, and an entry nobody can place is never `done`.
    """
    out_file = os.path.abspath(entry.get("out_file") or "")
    review_root = claim_scope.review_root_of_artifact_path(out_file)
    if review_root is None or not entry.get("group") or not entry.get("domain"):
        return None
    run_id = entry.get("run_id")
    if run_id is None:
        run_id = (run_manifest.load_manifest(review_root) or {}).get("run_id")
    match = _VERIFY_PART.search(os.path.basename(out_file))
    return (review_root, {"run_id": run_id}, entry["group"], entry["domain"],
            entry.get("stage") or "primary", int(match.group(1)) if match else 0)


def _verify_claims(review_root, manifest, group, domain, stage):
    """The claim set this cell's advisor was handed, re-derived the way the
    phase derives it: the review cell for `primary`, and for `backup` the
    backup round's OWN severity-gated scope -- loading the review cell there
    would demand verdicts nobody asked for (verify._verify_cell_done's note)."""
    if stage == "backup":
        return verify._cell_backup_findings(review_root, manifest, group, domain)
    return review._load_cell_findings(review_root, manifest, group, domain)


def _verify_accepts(entry, data):
    """(ok, reason) for a verdict bundle, applying the verify phase's own
    completeness rule to the file this reply WOULD write (I3, spec 4.5).

    Per-PART rather than per-cell because #1521 chunks an oversized cell
    across several advisors: `verify._part_done` -- the predicate
    `verify_execute` re-dispatches on -- asks only whether THIS slice's claims
    came back, and a cell split across parts can only ever be completed one
    part at a time. Accepting less would write a bundle the phase immediately
    re-dispatches, and A2 (run-9) is what happens when the gap is not caught:
    an advisor re-coded a cell's findings, ten claims came back as nine
    verdicts, and two went unadjudicated behind a bundle that looked fine.
    """
    ok, reason = _stamp_matches(entry, data)
    if not ok:
        return False, reason
    placed = _verify_cell_of(entry)
    if placed is None:
        return False, ("cannot place verdict bundle %r against a review root"
                       % entry.get("out_file"))
    review_root, manifest, group, domain, stage, part = placed
    if stage != "primary":
        # verify._part_done: a backup bundle is answered once it is LABELED
        # for its cell, and the stamp check above is that label, entry-anchored.
        return True, ""
    chunks = verify._cell_chunks(
        _verify_claims(review_root, manifest, group, domain, stage))
    if part >= len(chunks):
        return False, ("bundle is part %d of a cell with %d chunk(s)"
                       % (part, len(chunks)))
    # Sanitized like every other verdict read path (#1638 P16 fix round 2): this
    # one only asks "was every claim adjudicated", but the rule is that an agent
    # verdict enters the controller exactly one way, so there is no reader left
    # to reason about separately.
    mine = [evidence._agent_verdict(v) for v in data.get("verdicts") or []
            if isinstance(v, dict)]
    # Parts strictly BEFORE this one, from disk -- `_part_done` merges parts
    # 0..part and this reply stands in for part `part` itself.
    earlier = (verify._cell_verdicts(review_root, group, domain, stage, part)
               if part else [])
    if not verify._chunk_answered(chunks[part], earlier + mine):
        return False, ("does not adjudicate every claim it was handed "
                       "(%d verdict(s) for %d claim(s) in part %d)"
                       % (len(mine), len(chunks[part]), part))
    return True, ""


def is_done(entry):
    """The phase's own answer to 'is this entry's out_file already good?'."""
    out_file = entry.get("out_file")
    role = role_of(entry)
    if role is None or not out_file or not os.path.isfile(out_file):
        return False
    if role in ("scout", "setup-scan"):
        data = runio._load_return_json(out_file)
        return data is not None and accepts(entry, data)[0]
    if role == "review-cell":
        return group_runner.entry_is_done(out_file, entry)
    if role == "verify-cell":
        # I3, spec 4.5: the verify PHASE's own done predicate, verbatim --
        # `_pending` filters on this, so anything looser drops a cell the
        # engine still wants and the loop launches nothing for it. Mirrors
        # how `review-cell` delegates to group_runner.entry_is_done.
        placed = _verify_cell_of(entry)
        if placed is None:
            return False
        review_root, manifest, group, domain, stage, _part = placed
        return verify._verify_cell_done(
            review_root, manifest, group, domain, stage,
            cell=_verify_claims(review_root, manifest, group, domain, stage))
    data = runio._load_return_json(out_file)
    return data is not None and accepts(entry, data)[0]


def rollback_markers(review_root, checkpoint, entries):
    """Undo the PER-DISPATCH marker a cancelled checkpoint charged, and return
    the keys it cleared (#1662).

    Deleting a batch's artifacts is only half of "the phase re-runs from its
    checkpoint". The other half is the retry budget: `review_execute` charges
    `cell-attempts.json` at DISPATCH time -- "the whole point is to bound
    cells that never complete" -- and a cell that has spent its three
    attempts is skipped for the rest of the run
    (`review._cell_exhausted`). An operator's Ctrl-C is not the host failing
    to answer, so leaving the charge standing means three interrupts silently
    drop a cell from the review, with no line anywhere saying so. #1623 adds
    the second caller on identical reasoning: a host-wide outage (auth, quota,
    a rate limit) is not the CELL failing to answer either -- it was never
    given a turn -- so the loop's `paused` path gives the charge back too, or
    three paused runs during one outage drop the cells exactly as three
    automatic iterations of the outage used to. The charge
    is exactly one per dispatched cell per checkpoint, so undoing it is a
    decrement of one; a key already at zero is left alone, and earlier real
    failures keep their own charges.

    #3185: verify charges at dispatch too (`verify._charge_verify_dispatch`), so
    its charge is refunded on the same reasoning. Scouts are NOT: the scout
    charge is a fact about a PREVIOUS reply that failed shape validation.
    """
    if checkpoint == "verify":
        return verify._give_back_verify_dispatch(review_root, entries)
    if checkpoint != "review":
        return []
    keys = [review._cell_key(e.get("group"), e.get("domain"))
            for e in entries or [] if isinstance(e, dict)
            and e.get("group") and e.get("domain")]
    return _give_back_attempts(runio._pano(review_root, review._ATTEMPTS_FILE), keys)


def _give_back_attempts(path, keys):
    """Refund one attempt to each DISTINCT key in the attempts document at
    `path`; returns the keys changed. The arithmetic -- and the refusal a
    document or a value it cannot read earns -- is `budget`'s (#1809/#1767).
    This copy `continue`d past an unreadable value, which made a value the
    target planted indistinguishable from a key nothing had ever charged."""
    return budget.give_back(path, keys, review._ATTEMPTS_WHAT)


def _parse_reply(text):
    """Tolerant parse of a reply, through the SAME reader the phases use
    (runio._load_return_json reads a path, so spool the text first)."""
    fd, tmp = tempfile.mkstemp(prefix="panopticon-reply-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text or "")
        return runio._load_return_json(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _safe_schema_reason(errors):
    """Bound only after every schema error is independently redacted."""
    safe_errors = [redact.redact_diagnostic(error, REASON_CAP)
                   for error in errors]
    return "; ".join(safe_errors[:3])[:REASON_CAP]


def write_reply(entry, text):
    """(ok, reason). Refuses -- writing nothing -- when the entry is not
    return-persist, is already done, the reply does not parse, or the parsed
    value fails the role's acceptance. Writes `<out_file>.tmp` then
    os.replace, so a reader never sees a partial file."""
    if not isinstance(entry, dict):
        return False, "entry is not an object"
    if entry.get("delivery") != "return_json":
        return False, "entry %r is not return-persist (delivery != return_json); its agent self-writes" % entry.get("id")
    if is_done(entry):
        return False, "entry %r is already done at %s" % (entry.get("id"), entry.get("out_file"))
    data = _parse_reply(text)
    if data is None:
        return False, "reply for %r does not parse as JSON (%s)" % (
            entry.get("id"), tolerant_json.unparsed_reason(text or ""))
    # D10 ruling 4, BEFORE the acceptance: the stamp is the controller's to
    # fill on the return-persist path only. `accepts` itself is untouched, so
    # the self-write done predicates still require the agent's own stamp on a
    # file nobody checked on the way in.
    if isinstance(data, dict) and role_of(entry) in _CONTROLLER_STAMP_ROLES:
        data = _controller_stamp(entry, data)
    # #2104, BEFORE the schema: its error text would echo the declared value.
    version = _version_defect(entry, data)
    if version:
        return False, "reply for %r rejected: %s" % (entry.get("id"), version)
    # Provider-side constraints are only an optimization: validate every
    # returned role with a published contract at receipt, after the controller
    # has supplied the identity fields that contract requires.
    schema = role_schema(entry)
    if schema:
        from scripts.synth import validate_schema
        errors = validate_schema.schema_errors(data, schema_path=schema)
        if errors:
            detail = _safe_schema_reason(errors)
            return False, "reply for %r rejected by %s: %s" % (
                entry.get("id"), os.path.basename(schema), detail)
    ok, reason = accepts(entry, data)
    if not ok:
        return False, "reply for %r rejected: %s" % (entry.get("id"), reason)
    out_file = entry["out_file"]
    try:
        runio._write_json(out_file, data)
    except (OSError, ValueError) as exc:
        return False, "could not write %s: %s" % (out_file, exc)
    if role_of(entry) == "setup-scan":
        from . import setup      # #3277 S2; local: setup reaches persist through loop_batch
        return setup.record_proposal(out_file)
    return True, ""


def find_entry(review_root, entry_id, namespace=None):
    """`(entry_or_None, refusal_or_None, run_id)` for this id in the current request.

    #1727: `driver persist` is a SEPARATE process, and the entry it finds here
    names the `out_file` it is about to write -- so the request is read
    through `load_bound_request`, which refuses a file that does not match
    the hash this run recorded. A refusal and a missing id are DIFFERENT
    answers and the caller says so differently: one means the file is not
    ours, the other that the operator typed an id that is not in it. `run_id`
    is that request's, for the refused reply's record to be bound to (#3253).
    """
    req, refusal = requests.load_bound_request(review_root, namespace)
    if refusal:
        return None, refusal, None
    for e in (req or {}).get("entries") or []:
        if isinstance(e, dict) and e.get("id") == entry_id:
            return e, None, req.get("run_id")
    return None, None, None
