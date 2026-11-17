"""#3702: which claims each verify advisor was handed, so that a verdict counts
only for one of them.

Bundle verdicts are matched to findings by finding id across the whole run
(`evidence.load_verdict_bundles` -> `match_verdict_by_id`), and a backup-stage
verdict wins over a primary one. Nothing asked whether the advisor that wrote a
verdict had been handed that claim. So a backup advisor handed ONE claim could
say REJECTED about two claims no primary had answered: both were discarded, the
"unanswered" shortfall vanished and the run certified. A primary could do the
same to another cell's claims, and where two primaries spoke of one claim the
first FILE NAME won, not the claim's own advisor.

The verify phase records what it hands out, at dispatch, in the same write as the
charge (`phases/verify._scope_record`, in `verify-attempts.json`). For each
dispatched cell and stage:

- `<group>/<domain>/<stage>/claims`: the claim ids, in the order handed;
- `<group>/<domain>/<stage>/parts`: how many parts they were dispatched in;
- `<group>/<domain>/<stage>/part_size`: how many claims a part holds.

Part N was handed `claims[N * part_size : (N + 1) * part_size]`, and its bundle is
`verdicts-<group>-<domain>[-backup][-partN].json`. `Scope.handed` answers for one
bundle file, and `evidence.load_verdict_bundles(scope=)` drops every verdict it
does not cover:

- a set of ids: the claims that part was handed. A verdict for any other id is
  OUT OF SCOPE, whether the id is another part's, another cell's or nothing's;
- an empty set: the record knows the cell and this file is not one of its parts
  (a part past the recorded count, or a name that is not the stamped cell's);
- `None`: NOT RECORDED. There is no record, it is unreadable, or it holds no
  whole scope for the cell and stage this bundle is stamped for. Nothing in such
  a bundle counts: a run whose verify phase ran before the record existed, or a
  hand `--verdicts-dir` call, fails closed and says so.

`reasons` turns the two counts into `grade_shortfalls` reasons, so either holds
the letter back under the one shared rule (#3667).
"""

import os
import re

from . import artifacts as artifacts_mod
from . import backups as backups_mod

# `phases/verify._part_size_key`: spelled here because synth may not import
# phases; tests pin the names equal, as for the two suffixes `backups` holds.
PART_SIZE_SUFFIX = "/part_size"
STAGES = ("primary", "backup")
_PART = re.compile(r"-part([0-9]+)\.json\Z")


def _bundle_name(group, domain, stage, part):
    """Part `part`'s bundle name, as `phases/verify._verify_out_file` spells it."""
    return "verdicts-%s-%s%s%s.json" % (group, domain, "-backup" if stage == "backup" else "",
                                        "-part%d" % part if part else "")


class Scope:
    """The run's dispatch record, read once. `record` is the parsed document, or
    None when there is none to go by."""

    def __init__(self, record=None):
        self._record = record if isinstance(record, dict) else None

    @classmethod
    def load(cls, run_dir):
        """The record in `run_dir`; a `Scope` that knows nothing when the file is
        absent, unreadable or not an object."""
        path = os.path.join(run_dir or "", backups_mod.ATTEMPTS_FILE)
        if not run_dir or not os.path.lexists(path):
            return cls()
        try:
            return cls(artifacts_mod.read_json(path))
        except (OSError, ValueError):
            return cls()

    def _parts(self, group, domain, stage):
        """The recorded parts of one cell and stage, each a list of claim ids, or
        None when the three keys are not all there, not all valid, or disagree."""
        key = "%s/%s/%s" % (group, domain, stage)
        record = self._record or {}
        claims = backups_mod._scope(record.get(key + backups_mod.CLAIMS_SUFFIX))
        parts = backups_mod._count(record.get(key + backups_mod.PARTS_SUFFIX))
        size = backups_mod._count(record.get(key + PART_SIZE_SUFFIX))
        if claims is None or size is None:
            return None
        split = [claims[start:start + size] for start in range(0, len(claims), size)]
        return split if len(split) == parts else None      # `parts` None: no count recorded

    def handed(self, name, stamp):
        """The claim ids the bundle file `name` was handed, by its controller
        `stamp` ({group, domain, stage}); None when that is not recorded."""
        group, domain, stage = (stamp or {}).get("group"), (stamp or {}).get("domain"), \
            (stamp or {}).get("stage")
        if self._record is None:
            return None
        if not (isinstance(group, str) and group and isinstance(domain, str) and domain
                and stage in STAGES):
            return frozenset()      # stamped for no cell: no part of any
        parts = self._parts(group, domain, stage)
        if parts is None:
            return None
        match = _PART.search(name)
        part = int(match.group(1)) if match else 0
        if name != _bundle_name(group, domain, stage, part) or part >= len(parts):
            return frozenset()
        return frozenset(parts[part])


def counts(bundle_files):
    """(out of scope, scope not recorded): the verdicts the loader dropped, summed
    over its per-file stamps."""
    stamps = [stamp for stamp in (bundle_files or {}).values() if isinstance(stamp, dict)]

    def total(key):
        return sum(backups_mod._count(stamp.get(key)) or 0 for stamp in stamps)

    return total("out_of_scope"), total("scope_not_recorded")


def reasons(verdict_stats):
    """The `grade_shortfalls` reasons `meta.coverage.verdicts` carries for dropped
    verdicts; [] when every bundle verdict was for a claim its advisor was handed."""
    stats = verdict_stats if isinstance(verdict_stats, dict) else {}
    out = []
    outside = backups_mod._count(stats.get("out_of_scope"))
    if outside:
        out.append("%d advisor verdict%s outside %s handed scope" % (
            outside, "" if outside == 1 else "s", "its" if outside == 1 else "their"))
    unrecorded = backups_mod._count(stats.get("scope_not_recorded"))
    if unrecorded:
        out.append("verify scope not recorded: %d advisor verdict%s not counted" % (
            unrecorded, "" if unrecorded == 1 else "s"))
    return out
