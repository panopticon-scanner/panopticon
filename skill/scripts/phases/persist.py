"""The one place a RETURN-PERSIST reply becomes a file (spec 4.5, plan 6).

`driver persist ENTRY_ID` (session mode) and the headless loop both call
`write_reply`: parse the reply tolerantly (fence- or prose-wrapped JSON), apply
the SAME acceptance the phase's own done predicate applies, and write the
entry's out_file atomically. The model never parses JSON, never picks a path,
never writes a findings file by hand. Refusals write nothing.
"""
import json
import os
import tempfile

import scripts.evidence as evidence
import scripts.findings_contract as findings_contract
import scripts.group_runner as group_runner
from . import coverage
from . import requests
from . import runio

ROLES = ("scout", "setup-scan", "review-cell", "verify-cell", "tool-advisor")
_STAMP_KEYS = ("run_id", "group", "domain", "stage")


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
        return _stamp_matches(entry, data)
    verdict = str(data.get("verdict", "")).upper() if isinstance(data, dict) else ""
    if verdict not in evidence.VERDICT_VALUES:
        return False, "verdict %r is not one of %s" % (verdict, sorted(evidence.VERDICT_VALUES))
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
