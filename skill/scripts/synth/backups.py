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
  `stage: backup`, bound to this run, holding at least one sanitized verdict;
- `unanswered`: anything else -- a missing part (a gap in the part numbers
  included), an empty bundle, one from another run, no recorded part count, or
  no verify queue to bind the run to (a backup cannot be summoned without one).

`grading.grade_shortfalls` turns `unanswered` and `unloadable` into reasons, so
they hold the letter back under the one shared rule (#3667).
"""

import os
import re

from . import artifacts as artifacts_mod

# The verify phase's own record (`phases/verify._VERIFY_ATTEMPTS_FILE`). Spelled
# here because synth may not import phases; tests pin the two names equal.
ATTEMPTS_FILE = "verify-attempts.json"
BACKUP_SUFFIX = "/backup"
# `phases/verify._backup_parts_key`: the part count beside the attempt count.
PARTS_SUFFIX = "/parts"


def _count(value):
    """A recorded count: a non-bool int of at least 1, else None."""
    return value if type(value) is int and value >= 1 else None


def _summoned(run_dir):
    """Sorted (group, domain, parts) cells a backup advisor was dispatched for,
    `parts` None when no valid part count was recorded; None when the run left no
    record (no verify phase, or a direct synthesize call), and "unreadable" when
    the record is present but not a {key: count} map."""
    path = os.path.join(run_dir or "", ATTEMPTS_FILE)
    if not run_dir or not os.path.lexists(path):
        return None
    try:
        body = artifacts_mod.read_json(path, announce=True)
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(body, dict):
        return "unreadable"
    cells = set()
    for key, count in body.items():
        if not (isinstance(key, str) and key.endswith(BACKUP_SUFFIX)):
            continue
        if _count(count) is None:
            continue
        cell = key[:-len(BACKUP_SUFFIX)]
        group, sep, domain = cell.rpartition("/")
        if sep and group and domain:
            cells.add((group, domain, _count(body.get(key + PARTS_SUFFIX))))
    return sorted(cells, key=lambda cell: cell[:2])


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


def coverage(run_dir, bundle_files, verdict_unloadable=(), run_id=None):
    """`meta.coverage.backups`: {summoned, answered, unanswered, unloadable,
    record_unreadable}, counted in cells; None when the run left no record.

    `bundle_files` is `evidence.load_verdict_bundles(accepted=)`'s per-file map and
    `verdict_unloadable` the loaders' unloadable rows: no verdict file is read here."""
    summoned = _summoned(run_dir)
    if summoned is None:
        return None
    if summoned == "unreadable":
        return {"summoned": None, "answered": None, "unanswered": None,
                "unloadable": None, "record_unreadable": True}
    stamps = bundle_files if isinstance(bundle_files, dict) else {}
    bad = {str(u.get("file")) for u in verdict_unloadable or () if isinstance(u, dict)}
    names = set(stamps) | bad
    answered = unanswered = unloadable = 0
    for group, domain, parts in summoned:
        cell = _cell_files(names, group, domain)
        if any(name in bad for name in cell):
            unloadable += 1
        elif _cell_answered(stamps, group, domain, parts, run_id):
            answered += 1
        else:
            unanswered += 1
    return {"summoned": len(summoned), "answered": answered, "unanswered": unanswered,
            "unloadable": unloadable, "record_unreadable": False}


def shortfall_reasons(backups):
    """The `grade_shortfalls` reasons this block carries; [] when every summoned
    backup answered or none was summoned."""
    if not isinstance(backups, dict):
        return []
    if backups.get("record_unreadable"):
        return ["the backup advisor record is unreadable"]
    reasons = []
    for key, what in (("unanswered", "unanswered"), ("unloadable", "unloadable")):
        count = _count(backups.get(key))
        if count:
            reasons.append("%d backup advisor%s %s" % (count, "" if count == 1 else "s", what))
    return reasons
