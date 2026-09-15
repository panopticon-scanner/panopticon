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
import sys
import tempfile
import time

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
# 256 KiB of reply, after which the record says `truncated`. A refused reply
# is evidence, not an artifact: enough to see what shape came back and to
# quote the reason at the retry, bounded so one runaway agent cannot fill the
# run folder with the same megabyte three times.
REJECTED_CAP = 256 * 1024
_ATTEMPT = re.compile(r"-(\d+)\.json$")


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


def _next_attempt(directory, safe_id):
    """1 + the highest attempt already recorded for this entry. Keyed on the
    numbers on disk rather than on a count, so a record an operator deleted
    cannot make the next one collide with a surviving sibling."""
    try:
        names = os.listdir(directory)
    except OSError:
        return 1
    seen = [0]
    for name in names:
        match = _ATTEMPT.search(name)
        if match and name[:match.start()] == safe_id:
            seen.append(int(match.group(1)))
    return 1 + max(seen)


def retain_rejected(run_folder, entry, text, reason):
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
    """
    entry_id = entry.get("id") if isinstance(entry, dict) else None
    body = str(text or "")
    if not run_folder or not entry_id or not body:
        return None
    safe_id = requests._PROMPT_FILE_SAFE.sub("_", str(entry_id)) or "entry"
    directory = os.path.join(run_folder, REJECTED_DIR)
    kept = body.encode("utf-8")[:REJECTED_CAP].decode("utf-8", "ignore")
    attempt = _next_attempt(directory, safe_id)
    record = {"schema_version": 1, "entry_id": entry_id, "attempt": attempt,
              "reason": reason,
              # the stamp format the ledger's own rows carry, so the two sort
              # against each other as plain strings.
              "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "reply": redact.redact_tree(kept)}
    if kept != body:
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
            return False, "_panopticon.%s is %r, the entry is %r" % (k, meta.get(k), v)
    return True, ""


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
        return False, "verdict %r is not one of %s" % (verdict, sorted(evidence.VERDICT_VALUES))
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
    mine = [v for v in data.get("verdicts") or [] if isinstance(v, dict)]
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
    """The current dispatch request's entry with this id, or None."""
    req = requests.load_dispatch_request(review_root, namespace)
    for e in (req or {}).get("entries") or []:
        if isinstance(e, dict) and e.get("id") == entry_id:
            return e
    return None
