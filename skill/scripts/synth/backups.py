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
means here. Each summoned cell is then read off the verdicts directory:

- `unloadable`: a backup bundle file for the cell failed to load;
- `answered`: a loadable bundle the controller stamped `stage: backup`, bound to
  this run, holds at least one sanitized verdict;
- `unanswered`: anything else -- no file, an empty bundle, or one from another
  run.

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


def _summoned(run_dir):
    """Sorted (group, domain) cells a backup advisor was dispatched for; None when
    the run left no record (no verify phase, or a direct synthesize call), and
    "unreadable" when the record is present but not a {key: count} map."""
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
        if type(count) is not int or count < 1:
            continue
        cell = key[:-len(BACKUP_SUFFIX)]
        group, sep, domain = cell.rpartition("/")
        if sep and group and domain:
            cells.add((group, domain))
    return sorted(cells)


def _cell_files(names, group, domain):
    """The backup bundle file names (`verdicts-<g>-<d>-backup[-partN].json`) for a cell."""
    pattern = re.compile(r"verdicts-%s-%s-backup(-part[0-9]+)?\.json\Z"
                         % (re.escape(group), re.escape(domain)))
    return [name for name in names if pattern.match(name)]


def _answered(stamp, run_id):
    """A loaded bundle the CONTROLLER stamped a backup, bound to this run (or to no
    queue at all), with at least one verdict through the sanitizer."""
    return (isinstance(stamp, dict) and stamp.get("stage") == "backup"
            and (run_id is None or stamp.get("run_id") == run_id)
            and type(stamp.get("kept")) is int and stamp["kept"] >= 1)


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
    for group, domain in summoned:
        cell = _cell_files(names, group, domain)
        if any(name in bad for name in cell):
            unloadable += 1
        elif any(_answered(stamps.get(name), run_id) for name in cell):
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
        count = backups.get(key) or 0
        if count:
            reasons.append("%d backup advisor%s %s" % (count, "" if count == 1 else "s", what))
    return reasons
