"""#3676: the backup advisors a run summoned, and what came back from them.

A backup advisor is summoned for a cell whose primary verdicts cleared the
backup gate (a CRITICAL, say). When it never answered -- a non-zero exit, an
empty reply, a timeout -- the report used to read as fully certified: the
findings simply lost `backup_confirmed`, and nothing on any surface said a
second opinion was owed and missing. A MALFORMED backup reply sank
certification through `verdicts.unloadable` but named nothing.

The verify phase charges one attempt per dispatched cell/stage in
`verify-attempts.json` (`phases/verify._charge_verify_dispatch`), keyed
`<group>/<domain>/backup` for a backup round. That record is what "summoned"
means here. Beside it, `<group>/<domain>/backup/parts` records how many parts the
cell was dispatched in: a scope of more than 25 claims is split, and each part is
answered separately (#3679). Each summoned cell is then read off the verdicts
directory:

- `unloadable`: a backup bundle file for the cell failed to load;
- `answered`: EVERY recorded part has a loadable bundle the controller stamped
  `stage: backup`, bound to this run, holding at least one sanitized verdict,
  AND every claim the cell was handed has a verdict in those bundles (#3695);
- `unanswered`: anything else -- a missing part (a gap in the part numbers
  included), an empty bundle, one from another run, no recorded part count, no
  recorded scope, a scoped claim with no verdict, or no verify queue to bind the
  run to (a backup cannot be summoned without one).

#3695: coverage is also counted per scoped CLAIM. A backup that confirmed 1 of
its 20 claims and said nothing of the other 19 used to make its cell `answered`:
those 19 findings lost `backup_confirmed` and no surface named them. Verify
records the ids it handed each backup beside the part count
(`<group>/<domain>/backup/claims`), and `evidence.claims_unanswered` -- the one
rule the verify phase applies to a part -- says which of them have no verdict.
`claims_scoped` and `claims_unanswered` are those counts. A cell whose record
holds no scope (written before the scope was recorded) is never `answered`: it
is `unanswered`, or `unloadable` when one of its bundle files failed to load. It
is counted in `scope_not_recorded` (and in `scope_not_recorded_unloadable` when
that is where it landed) and stays out of both claim counts: nothing can show
which claims it was owed, so its zero must not read as "none missing", and the
reason for the state it landed in says so.

`grading.grade_shortfalls` turns `unanswered`, `unloadable` and
`claims_unanswered` into reasons, so they hold the letter back under the one
shared rule (#3667).
"""

import os
import re

import scripts.evidence as evidence_mod
from . import artifacts as artifacts_mod

# The verify phase's own record (`phases/verify._VERIFY_ATTEMPTS_FILE`). Spelled
# here because synth may not import phases; tests pin the two names equal.
ATTEMPTS_FILE = "verify-attempts.json"
BACKUP_SUFFIX = "/backup"
# `phases/verify._parts_key`: the part count beside the attempt count.
PARTS_SUFFIX = "/parts"
# `phases/verify._claims_key`: the claim ids the cell was handed (#3695).
CLAIMS_SUFFIX = "/claims"


def _count(value):
    """A recorded count: a non-bool int of at least 1, else None."""
    return value if type(value) is int and value >= 1 else None


def _scope(value):
    """A recorded scope: a non-empty list of non-empty strings, else None. Verify
    never dispatches a backup with an empty scope, so an empty list is not one."""
    if isinstance(value, list) and value and all(isinstance(i, str) and i for i in value):
        return value
    return None


def _summoned(run_dir):
    """Sorted (group, domain, parts, scope) cells a backup advisor was dispatched
    for: `parts` None when no valid part count was recorded and `scope` None when
    no valid claim list was; None when the run left no record (no verify phase,
    or a direct synthesize call), and "unreadable" when the record is present but
    not a JSON object."""
    path = os.path.join(run_dir or "", ATTEMPTS_FILE)
    if not run_dir or not os.path.lexists(path):
        return None
    try:
        body = artifacts_mod.read_json(path, announce=True)
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(body, dict):
        return "unreadable"
    cells = {}
    for key, count in body.items():
        if not (isinstance(key, str) and key.endswith(BACKUP_SUFFIX)):
            continue
        if _count(count) is None:
            continue
        cell = key[:-len(BACKUP_SUFFIX)]
        group, sep, domain = cell.rpartition("/")
        if sep and group and domain:
            cells[group, domain] = (group, domain, _count(body.get(key + PARTS_SUFFIX)),
                                    _scope(body.get(key + CLAIMS_SUFFIX)))
    return [cells[cell] for cell in sorted(cells)]


def _cell_files(names, group, domain):
    """The backup bundle file names (`verdicts-<g>-<d>-backup[-partN].json`) for a cell."""
    pattern = re.compile(r"verdicts-%s-%s-backup(-part[0-9]+)?\.json\Z"
                         % (re.escape(group), re.escape(domain)))
    return [name for name in names if pattern.match(name)]


def _part_file(group, domain, part):
    """Part `part`'s bundle name, as `phases/verify._verify_out_file` spells it."""
    return "verdicts-%s-%s-backup%s.json" % (group, domain, "-part%d" % part if part else "")


def _answered(stamp, run_id):
    """A loaded bundle the CONTROLLER stamped a backup, bound to this run, with at
    least one verdict through the sanitizer."""
    return (isinstance(stamp, dict) and stamp.get("stage") == "backup"
            and stamp.get("run_id") == run_id
            and _count(stamp.get("kept")) is not None)


def _cell_answered(stamps, group, domain, parts, run_id):
    """#3679 review: every recorded part answered. Without a part count, or without
    a run to bind to, nothing can show that the whole cell did."""
    if parts is None or run_id is None:
        return False
    return all(_answered(stamps.get(_part_file(group, domain, part)), run_id)
               for part in range(parts))


def _claims_unanswered(stamps, group, domain, parts, scope, run_id):
    """#3695: the scoped claims with no backup verdict, by the verify phase's own
    rule. Only a part the controller recorded, stamped a backup and bound to this
    run can answer one, and only for an id in `scope`: the ids in a stamp are what
    an advisor wrote, so one outside the scope, or said twice, answers nothing."""
    got: list[str] = []
    for part in range(parts or 0):
        stamp = stamps.get(_part_file(group, domain, part))
        if run_id is not None and _answered(stamp, run_id):
            ids = stamp.get("finding_ids")
            if isinstance(ids, list):
                got.extend(i for i in ids if isinstance(i, str))
    return evidence_mod.claims_unanswered(scope, got)


def coverage(run_dir, bundle_files, verdict_unloadable=(), run_id=None):
    """`meta.coverage.backups`: {summoned, answered, unanswered, unloadable} counted
    in cells, {claims_scoped, claims_unanswered} in the claims those cells were
    handed, {scope_not_recorded, scope_not_recorded_unloadable} in cells again (the
    second is how many of the first are `unloadable`; the rest are `unanswered`),
    and record_unreadable; None when the run left no record.

    `bundle_files` is `evidence.load_verdict_bundles(accepted=)`'s per-file map and
    `verdict_unloadable` the loaders' unloadable rows: no verdict file is read here."""
    summoned = _summoned(run_dir)
    if summoned is None:
        return None
    if summoned == "unreadable":
        return {"summoned": None, "answered": None, "unanswered": None,
                "unloadable": None, "claims_scoped": None, "claims_unanswered": None,
                "scope_not_recorded": None, "scope_not_recorded_unloadable": None,
                "record_unreadable": True}
    stamps = bundle_files if isinstance(bundle_files, dict) else {}
    bad = {str(u.get("file")) for u in verdict_unloadable or () if isinstance(u, dict)}
    names = set(stamps) | bad
    answered = unanswered = unloadable = 0
    claims_scoped = claims_unanswered = scope_not_recorded = unrecorded_unloadable = 0
    for group, domain, parts, scope in summoned:
        if scope is None:
            scope_not_recorded += 1
            missing = None
        else:
            missing = _claims_unanswered(stamps, group, domain, parts, scope, run_id)
            claims_scoped += len(set(scope))
            claims_unanswered += len(missing)
        cell = _cell_files(names, group, domain)
        if any(name in bad for name in cell):
            unloadable += 1
            unrecorded_unloadable += scope is None
        elif missing == [] and _cell_answered(stamps, group, domain, parts, run_id):
            answered += 1
        else:
            unanswered += 1
    return {"summoned": len(summoned), "answered": answered, "unanswered": unanswered,
            "unloadable": unloadable, "claims_scoped": claims_scoped,
            "claims_unanswered": claims_unanswered,
            "scope_not_recorded": scope_not_recorded,
            "scope_not_recorded_unloadable": unrecorded_unloadable,
            "record_unreadable": False}


def shortfall_reasons(backups):
    """The `grade_shortfalls` reasons this block carries; [] when every summoned
    backup answered or none was summoned."""
    if not isinstance(backups, dict):
        return []
    if backups.get("record_unreadable"):
        return ["the backup advisor record is unreadable"]
    reasons = []
    # The cells with no recorded scope, by the state each landed in: the claim
    # counts leave them out, so the reason for that state says so (#3697 N1).
    in_all = _count(backups.get("scope_not_recorded")) or 0
    in_unloadable = min(_count(backups.get("scope_not_recorded_unloadable")) or 0, in_all)
    unrecorded = {"unanswered": in_all - in_unloadable, "unloadable": in_unloadable}
    for key in ("unanswered", "unloadable"):
        count = _count(backups.get(key))
        if count:
            reasons.append("%d backup advisor%s %s" % (count, "" if count == 1 else "s", key))
            if unrecorded[key]:
                reasons[-1] += " (%d scope not recorded)" % min(unrecorded[key], count)
    # #3695: the cells say how many advisors fell short, this how many findings.
    claims = _count(backups.get("claims_unanswered"))
    if claims:
        reasons.append("%d finding%s unanswered by %s backup advisor%s" % (
            claims, "" if claims == 1 else "s", "its" if claims == 1 else "their",
            "" if claims == 1 else "s"))
    return reasons
