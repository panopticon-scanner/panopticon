"""The one place a RETURN-PERSIST reply becomes a file (spec 4.5, plan 6).

`driver persist ENTRY_ID` (session mode) and the headless loop both call
`write_reply`: parse the reply tolerantly (fence- or prose-wrapped JSON), apply
the SAME acceptance the phase's own done predicate applies, and write the
entry's out_file atomically. The model never parses JSON, never picks a path,
never writes a findings file by hand. Refusals write nothing.
"""
import json
import os
import re
import stat
import sys
import tempfile
import time

import scripts._version as version
import scripts.evidence as evidence
import scripts.findings_contract as findings_contract
import scripts.group_runner as group_runner
import scripts.probes.common as probes_common
import scripts.redact as redact
import scripts.run_manifest as run_manifest
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
# What a record is a record OF (D10 F4). The two are kept apart because only
# one of them is a statement about a REPLY: a refusal means the agent returned
# something and the controller would not take it, which is the only case the
# retry note can honestly quote. A launch failure -- a timeout, a non-zero exit
# -- produced no reply at all, and telling its next attempt to "return the same
# findings, fix only the format" is false in every clause and, on a
# self-writing entry, actively harmful.
REFUSAL = "refusal"
LAUNCH_FAILURE = "launch_failure"
# 256 KiB of reply, after which the record says `truncated`. A refused reply
# is evidence, not an artifact: enough to see what shape came back and to
# quote the reason at the retry, bounded so one runaway agent cannot fill the
# run folder with the same megabyte three times.
REJECTED_CAP = 256 * 1024
# How much of an oversized reply the REDACTOR is allowed to scan before the
# cap applies (D10 F2). Redaction has to come first -- two of redact's rules
# (PEM and JWT) are delimiter-terminated, so a cut inside such a block removes
# the terminator, the pattern stops matching, and the surviving prefix stays in
# plaintext; measured, a PEM straddling the 256 KiB cut left 1531 characters of
# key material in the record. This bound is what keeps "redact first" from
# meaning "run a DOTALL `.*?` over an unbounded reply".
REDACT_CAP = 4 * 1024 * 1024
# The one rule whose opening delimiter can survive the final cut with its
# closing one beyond the REDACT_CAP horizon, i.e. unmasked. Nothing after a
# dangling header is kept.
_DANGLING_PEM = re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")
_ATTEMPT = re.compile(r"-(\d+)\.json$")


def _cut(text, limit):
    """`text` clipped to `limit` BYTES of UTF-8, never splitting a character."""
    return text.encode("utf-8")[:limit].decode("utf-8", "ignore")


def _safe_reply(text):
    """(kept, truncated): the reply as it may be stored (D10 F2).

    Redacted BEFORE the cap, so the cap only ever cuts text that has already
    been through every pattern; pre-cut at REDACT_CAP first, so the redactor's
    DOTALL rules are never handed an unbounded body. Whatever survives the
    final cut is then swept for a private-key HEADER left without its `END`:
    the only way an unmasked secret can reach the record is a block whose
    terminator lay beyond the horizon, and a header with nothing to close it is
    the signature of exactly that.

    `truncated` compares what was KEPT against what there was to keep, at each
    of the three steps (D10 N4). Deriving it from `len(kept) == REJECTED_CAP`
    was wrong in both directions: a cut through a multibyte character leaves
    `kept` a byte or two short of the cap -- `_cut` drops the partial
    character -- so a truncated record claimed to be whole, and a reply that
    exactly filled the cap claimed a truncation that never happened.
    """
    scanned = _cut(text, REDACT_CAP)
    redacted = redact.redact_tree(scanned)
    kept = _cut(redacted, REJECTED_CAP)
    dangling = [m for m in _DANGLING_PEM.finditer(kept)
                if "-----END" not in kept[m.end():]]
    if dangling:
        kept = kept[:dangling[0].start()]
    return kept, scanned != text or kept != redacted


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


# D10 ruling 3: the PUBLISHED schema each returning role's reply is accepted
# against, for the CLIs that can constrain their output to one. scout and
# setup-scan are absent on purpose: their shape lives in code
# (coverage._scout_shape_errors, "a JSON object") and publishing a second
# definition of it is how the two drift.
ROLE_SCHEMAS = {"review-cell": "findings-envelope-schema.json",
                "verify-cell": "verdict-bundle-schema.json",
                "tool-advisor": "advisor-verdict-schema.json"}


def role_schema(entry):
    """Absolute path of this entry's published output schema, or None.

    Stamped onto the entry by `requests._materialize_prompts` and read off it
    by whichever runner's CLI takes one -- the runners package may not import
    `phases`, and should not have to know what a role is anyway.
    """
    name = ROLE_SCHEMAS.get(role_of(entry))
    return os.path.abspath(version.reference_path(name)) if name else None


# D10 ruling 2: what the retry is told to return, one line per role. The
# refusal reason says what was wrong; this says what right looks like, in the
# shape the role's own acceptance checks -- `accepts` below is the authority
# on each of these, and they are written to match it, not the templates.
ENVELOPE_SHAPES = {
    "scout": '{"domains": [...], "files": [...], "tools": [...]}',
    "setup-scan": "a single JSON object (the setup proposal)",
    "review-cell": '{"findings": [ ... ], "_panopticon": {"run_id": "...", "group": "...", "domain": "..."}}',
    "verify-cell": '{"verdicts": [ ... ], "_panopticon": {"run_id": "...", "group": "...", "domain": "...", "stage": "..."}}',
    "tool-advisor": '{"finding_id": "...", "verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO", "confidence": "...", "reasoning": "...", "explored": [...], "references": [...], "citations": {...}}',
}
# Fixed text, not a per-role paragraph: the agent is being asked to repeat
# itself in a different wrapper, and the one thing that varies is the reason.
RETRY_PROMPT_BLOCK = (
    "\n\n## Your previous reply was refused -- return the same answer, correctly wrapped\n\n"
    "Your previous attempt%(attempt)s was refused: %(reason)s\n"
    "Return the SAME findings/verdicts you returned then; fix only the FORMAT.\n"
    "The required envelope is exactly: %(shape)s\n")


# How much of a refusal reason the retry prompt may quote (D10 F3).
REASON_CAP = 200
# The highest attempt number the retry prompt will quote (#1752 AGT-1863884584).
# An entry's attempts are bounded by the run's per-entry cap, an order of
# magnitude below this; a record claiming more is not a number worth printing.
ATTEMPT_CAP = 99


def _attempt_number(value):
    """The record's attempt number, or None -- the field is target-writable.

    Same rationale as REASON_CAP, same interpolation: the record is a file, and
    for `--setup` it is a file at a fixed path in the flat `.panopticon/` that a
    target repo can commit. `reason` was typed and bounded on the way out and
    this field was not, so 10 kB of attacker prose -- or a dict -- went straight
    into the prompt and into `prompt_file`. Anything that is not a plausible
    attempt number becomes None, and the block then says "your previous attempt"
    with no number at all: an unusable field must not be paraphrased into a
    claim about the run. `bool` is excluded explicitly because `True` is an int
    to isinstance and would print as attempt 1.
    """
    return value if (isinstance(value, int) and not isinstance(value, bool)
                     and 0 < value <= ATTEMPT_CAP) else None


def envelope_shape(entry):
    """The one-line envelope this entry's role is accepted against."""
    return ENVELOPE_SHAPES.get(role_of(entry)) or "a single JSON object"


def last_rejection(run_folder, entry_id):
    """The most recent `rejected/` record for this entry, or None."""
    if not run_folder or not entry_id:
        return None
    directory = os.path.join(run_folder, REJECTED_DIR)
    component = requests.entry_file_component(entry_id)
    record, newest = _latest_record(directory, component, entry_id)
    if newest:
        return record
    # Older builds substituted unsafe characters with underscores. A shared
    # legacy basename is only history for the exact ID inside the record.
    legacy = requests._PROMPT_FILE_SAFE.sub("_", str(entry_id)) or "entry"
    if legacy != component:
        record, _ = _latest_record(directory, legacy, entry_id, legacy=True)
    return record


def retry_block(run_folder, entry):
    """(prompt_block, prior_rejection) for an entry whose last reply was
    refused; (None, None) for one with no record -- D10 ruling 2.

    The retry is otherwise the SAME prompt, regenerated: `driver.run` rebuilds
    the dispatch request from disk and nothing in it knows an attempt ever
    happened. Run-13 spent three launches of one cell that way, each one
    making the identical mistake, because nobody ever told the agent what the
    controller had objected to.

    The LATEST record only: a reply refused twice gets told about the second
    refusal, which is the one its next attempt has to clear.

    Two gates, both from D10 F4. The record must be a REFUSAL: a timed-out
    launch returned nothing, so there is no "same findings" to return and no
    format to fix. And the entry must be return-persist: this whole block is
    about the envelope the CONTROLLER will persist, and a self-writing reviewer
    that obeyed it would return its findings as a message instead of writing
    its out_file -- the done predicate would never fire and the cell would burn
    its remaining attempts. A record with no `kind` (an older build's) reads as
    neither, which is the fail-safe answer.
    """
    if not isinstance(entry, dict) or entry.get("delivery") != "return_json":
        return None, None
    record = last_rejection(run_folder, entry.get("id"))
    if record is None or record.get("kind") != REFUSAL:
        return None, None
    # D10 F3: capped again on the way OUT. The record's reason is already
    # bounded and masked, but this string is about to be appended to a prompt
    # and written to `prompt_file`, and a record written by an older build --
    # or by a path that bounds nothing, a runner's own error string -- must not
    # be able to grow the launch argv. Belt and braces, one line.
    prior = {"attempt": _attempt_number(record.get("attempt")),
             "reason": str(record.get("reason") or "")[:REASON_CAP]}
    # The SAME sanitized value both ways: `prior` is stamped onto the entry as
    # `prior_rejection` (`requests._materialize_prompts`) and hashed into the
    # dispatch request, so the prompt and the request must not disagree about
    # what the record said.
    numbered = "" if prior["attempt"] is None else " %d" % prior["attempt"]
    return RETRY_PROMPT_BLOCK % {"attempt": numbered, "reason": prior["reason"],
                                 "shape": envelope_shape(entry)}, prior


def _read_rejection(path):
    """Read one confined regular record without following a planted link."""
    try:
        runio._confine_artifact_path(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, encoding="utf-8") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _latest_record(directory, component, entry_id, *, legacy=False):
    """Latest record and attempt for this ID; verify every legacy candidate.

    A new-name record owns its basename even when unreadable: do not reuse
    that attempt or fall back to older history. Legacy names may contain rows
    for other IDs, so search them until an exact original ID is found.
    """
    try:
        names = os.listdir(directory)
    except OSError:
        return None, 0
    attempts = []
    for name in names:
        match = _ATTEMPT.search(name)
        if match and name[:match.start()] == component:
            attempts.append((int(match.group(1)), name))
    for attempt, name in sorted(attempts, reverse=True):
        record = _read_rejection(os.path.join(directory, name))
        if record is not None and record.get("entry_id") == entry_id:
            return record, attempt
        if not legacy:
            return None, attempt
    return None, 0


def _next_attempt(directory, entry_id):
    """Continue this ID's numbered history, including verified legacy rows."""
    component = requests.entry_file_component(entry_id)
    _, highest = _latest_record(directory, component, entry_id)
    legacy = requests._PROMPT_FILE_SAFE.sub("_", str(entry_id)) or "entry"
    if legacy != component:
        _, old_highest = _latest_record(directory, legacy, entry_id, legacy=True)
        highest = max(highest, old_highest)
    return highest + 1


def retain_rejected(run_folder, entry, text, reason, *, kind):
    """Keep a refused reply as `<run_dir>/rejected/<entry-id>-<attempt>.json`;
    return the path, or None when there is nothing to keep (D10 ruling 1).

    `write_reply` refuses and writes NOTHING -- correct for the artifact, and
    it used to mean the reply itself was gone. Run-13: 7 of 8 failed attempts
    were replies missing `_panopticon`, each rerun from scratch, with no way to
    see what the agent had actually returned or to tell it what was wrong.

    The record is redacted (`redact.redact_tree`, the same masking the report
    goes through -- a reply can quote a secret it found) and capped, and it
    goes through the confined/nofollow writer every other run-folder artifact
    uses, so a planted `rejected` symlink cannot carry the write outside.
    The entry id is flattened into ONE filename component first: an id embeds
    an operator-supplied group name.

    Best-effort by construction: this is evidence about a failure, so a
    failure to record it must not become a second, louder failure. Nothing
    under `rejected/` is ever read by a done predicate -- `role_of` gives the
    path no role, so no reply can advance an entry by landing here.

    `kind` is keyword-only and has no default (D10 F4): every caller must say
    whether this is a REFUSAL -- a reply the controller would not take -- or a
    LAUNCH_FAILURE, which produced no reply at all. `retry_block` quotes only
    the first, and a default would let a new call site pick the wrong one by
    saying nothing.
    """
    entry_id = entry.get("id") if isinstance(entry, dict) else None
    body = str(text or "")
    if not run_folder or not entry_id or not body:
        return None
    safe_id = requests.entry_file_component(entry_id)
    directory = os.path.join(run_folder, REJECTED_DIR)
    kept, truncated = _safe_reply(body)
    attempt = _next_attempt(directory, entry_id)
    record = {"schema_version": 1, "entry_id": entry_id, "attempt": attempt, "kind": kind,
              # D10 F3: the reason is built by interpolating REPLY content, so
              # it gets the same masking the reply does. Bounded at the source
              # (`%.200r`), not here, so every consumer sees the same string.
              "reason": redact.redact(reason),
              # the stamp format the ledger's own rows carry, so the two sort
              # against each other as plain strings.
              "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "reply": kept}
    if truncated:
        record["truncated"] = True
    try:
        return runio._write_json(os.path.join(directory, "%s-%d.json" % (safe_id, attempt)), record)
    except (OSError, ValueError) as exc:
        print("driver: could not retain the refused reply for %s (%s)" % (entry_id, exc),
              file=sys.stderr, flush=True)
        return None


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
            # %.200r, not %r (D10 F3): `meta` is the PARSED REPLY, so this
            # string carries content an agent -- possibly a prompt-injected one
            # reviewing a hostile target -- chose. It is stored in the rejected
            # record and quoted into the next attempt's prompt, so it is bounded
            # where it is built rather than at each of those two consumers. `%r`
            # honours a precision and keeps escaping newlines, which is what
            # stops a reason from forging lines of its own.
            return False, "_panopticon.%s is %.200r, the entry is %r" % (k, meta.get(k), v)
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
        return isinstance(data, dict), "a setup proposal must be a JSON object"
    if role == "review-cell":
        if not findings_contract.is_acceptable(data):
            return False, "not an acceptable findings file (a `findings` list of objects)"
        return _stamp_matches(entry, data)
    if role == "verify-cell":
        if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
            return False, "a verdict bundle must carry a `verdicts` list"
        return _verify_accepts(entry, data)
    verdict = str(data.get("verdict", "")).upper() if isinstance(data, dict) else ""
    if verdict not in evidence.VERDICT_VALUES:
        return False, "verdict %.200r is not one of %s" % (verdict, sorted(evidence.VERDICT_VALUES))
    return True, ""


# `verdicts-<group>-<domain>[-backup][-partN].json` (verify._verify_out_file):
# part 0 keeps the unsuffixed name, so an absent suffix IS part 0.
_VERIFY_PART = re.compile(r"-part(\d+)\.json$")


def _verify_cell_of(entry):
    """(review_root, manifest, group, domain, stage, part) for a verify-cell
    entry, or None when it cannot be placed on disk.

    Entry-anchored, exactly as the review-cell rule is: `run_id` comes off the
    entry that ASKED for this bundle -- the same key `_stamp_matches` checks --
    and `review_root` off the artifact path it was told to write, the segment
    above its own `.panopticon` (the anchor `runio._confine_artifact_path`
    already uses). The verify phase reads only `run_id` off the manifest, so
    that one key is the whole manifest these predicates need.

    None is fail-closed at both call sites: a bundle nobody can place is
    refused, and an entry nobody can place is never `done`.
    """
    out_file = os.path.abspath(entry.get("out_file") or "")
    parts = out_file.split(os.sep)
    if ".panopticon" not in parts or not entry.get("group") or not entry.get("domain"):
        return None
    review_root = os.sep.join(parts[:parts.index(".panopticon")]) or os.sep
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

    The other two counters are deliberately NOT rolled back, because neither
    is a charge against THIS dispatch: `coverage._bump_scout_attempts` fires
    when a scout reply already on disk fails shape validation, and
    `verify._bump_verify_attempts` when a verdict bundle already on disk came
    back short. Both are facts about a PREVIOUS reply that this checkpoint
    merely noticed, and erasing them would return a budget something really
    did spend.
    """
    if checkpoint != "review":
        return []
    keys = [review._cell_key(e.get("group"), e.get("domain"))
            for e in entries or [] if isinstance(e, dict)
            and e.get("group") and e.get("domain")]
    return _give_back_attempts(runio._pano(review_root, review._ATTEMPTS_FILE), keys)


def _give_back_attempts(path, keys):
    """Decrement each of `keys` by one in the attempts document at `path`,
    skipping what is absent or already zero; returns the keys changed."""
    data = runio._load_json(path)
    if not isinstance(data, dict):
        return []
    cleared = []
    for key in keys:
        if key in cleared:
            continue                      # one charge per cell, one give-back
        try:
            used = int(data.get(key, 0))
        except (TypeError, ValueError):
            continue
        if used <= 0:
            continue
        data[key] = used - 1
        cleared.append(key)
    if cleared:
        runio._write_json(path, data)
    return cleared


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
        return False, "reply for %r does not parse as JSON (fence- and prose-wrapped both tried)" % entry.get("id")
    # D10 ruling 4, BEFORE the acceptance: the stamp is the controller's to
    # fill on the return-persist path only. `accepts` itself is untouched, so
    # the self-write done predicates still require the agent's own stamp on a
    # file nobody checked on the way in.
    if isinstance(data, dict) and role_of(entry) in _CONTROLLER_STAMP_ROLES:
        data = _controller_stamp(entry, data)
    ok, reason = accepts(entry, data)
    if not ok:
        return False, "reply for %r rejected: %s" % (entry.get("id"), reason)
    out_file = entry["out_file"]
    tmp = out_file + ".tmp"
    try:
        runio._confine_artifact_path(out_file)
        os.makedirs(os.path.dirname(out_file), exist_ok=True)
        with runio._open_w_nofollow(tmp) as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, out_file)
    except (OSError, ValueError) as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False, "could not write %s: %s" % (out_file, exc)
    return True, ""


def find_entry(review_root, entry_id, namespace=None):
    """`(entry_or_None, refusal_or_None)` for this id in the current request.

    #1727: `driver persist` is a SEPARATE process, and the entry it finds here
    names the `out_file` it is about to write -- so the request is read
    through `load_bound_request`, which refuses a file that does not match
    the hash this run recorded. A refusal and a missing id are DIFFERENT
    answers and the caller says so differently: one means the file is not
    ours, the other that the operator typed an id that is not in it.
    """
    req, refusal = requests.load_bound_request(review_root, namespace)
    if refusal:
        return None, refusal
    for e in (req or {}).get("entries") or []:
        if isinstance(e, dict) and e.get("id") == entry_id:
            return e, None
    return None, None
