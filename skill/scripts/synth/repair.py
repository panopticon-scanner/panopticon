"""Type repair at the boundaries where panopticon READS what it did not write.

THE PRINCIPLE (module docstring of `validate_schema`, and `synth/coverage_io`):
`skill/reference/report-schema.json` pins the CONTROLLER's output, so every
input that arrives from a review agent or from a target-writable file is
normalized to the pinned types AT ITS BOUNDARY -- never trusted, never allowed
to fail the artifact it rides into. A malformed row costs a warning and the
row; it never costs the run.

These repairs normalize the tools manifest's exclusions, Git-driver
declarations, suppression counts and #3269 dependency-audit receipt --
target-carried or target-adjacent content that reaches the artifact. They split out of `validate_schema` as the boundary work outgrew its
700-line ratchet. Agent-sourced repairs (`repair_finding` and `repair_verdict`)
stay there with the schema-node machinery this module uses. Since #3273 the
manifest's run-written blocks are read as written (its producers bound them,
first contact vouches for the file), and `groups.json` is shape-gated whole at
its read (`plan._groups_shape_fault`) rather than repaired.

BOUNDS. These functions bound already-parsed content for the report and HTML:
row counts, names and values, plus the diagnostics about dropped or repaired
content. They do not bound the bytes the caller reads before parsing JSON.
Producer-side limits alone cannot protect these readers of target-writable
artifacts.
"""
import json
import sys

from scripts import tools_manifest


# One bound for every target-carried block read here: the numbers a hostile one
# is held to. The controller's own output is an order of magnitude inside all three.
ROWS_MAX = 200
NAME_MAX = 200
VALUE_MAX = 200

# A path's length bound (the carve-out's files, a Git-driver row's repo): PATH_MAX
# on every platform panopticon runs on, so a longer one names nothing.
PATH_MAX = 4096

# How many repair lines a single read may announce before it summarises the
# rest. The content bounds above stopped a hostile manifest from reaching the
# artifact; without this one it still reached synthesize's STDERR, 120,401
# lines and 17.9 MB of it -- which is the same denial-of-attention `_bounded`
# exists to prevent, one layer out. Nothing is hidden: the tail line carries
# the true remaining count.
WARN_LINES_MAX = 20

def repair_dependency_audit(value, warn=None):
    """Repair the target-adjacent #3269 SCA receipt to closed enums.

    ``None`` is a legacy manifest with no measurement. Any present malformed
    receipt becomes one fixed applicable/zero-output state, so corrupting it
    can only cost certification and no target-authored value reaches a report.
    """
    if value is None:
        return None
    fallback = {"applicable": ["unknown"], "selected": [], "produced": []}
    if not isinstance(value, dict) or set(value) != {"applicable", "selected", "produced"}:
        warn_repairs("tools-manifest.json", [("dependency_audit", "repaired")], warn)
        return fallback
    allowed = {
        "applicable": tools_manifest.DEPENDENCY_AUDIT_ECOSYSTEMS,
        "selected": tools_manifest.DEPENDENCY_AUDIT_TOOLS,
        "produced": tools_manifest.DEPENDENCY_AUDIT_TOOLS,
    }
    repaired = {}
    for key, enum in allowed.items():
        rows = value.get(key)
        if not isinstance(rows, list) or any(not isinstance(row, str) or row not in enum
                                             for row in rows):
            warn_repairs("tools-manifest.json",
                         [("dependency_audit.%s" % key, "repaired")], warn)
            return fallback
        repaired[key] = sorted(set(rows))
    if (not set(repaired["produced"]).issubset(repaired["selected"])
            or ("unknown" in repaired["applicable"]
                and (repaired["selected"] or repaired["produced"]))):
        warn_repairs("tools-manifest.json", [("dependency_audit", "repaired")], warn)
        return fallback
    return repaired


def warn_repairs(artifact, changes, warn):
    """Announce the repairs a boundary read made, one line each -- through
    `warn` when a caller supplied one (synthesis collects them), on stderr
    otherwise. The boundary repairers share this wording and its disclosure
    limits rather than implementing separate warning loops.

    BOUNDED on both axes, like the content it describes: at most
    `WARN_LINES_MAX` lines, each naming a path cut to `NAME_MAX`. A repair
    path can embed a target-authored key, and an unbounded one turned a single
    100 KB field name into a single 100 KB log line.
    """
    def emit(message):
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)

    for path, what in changes[:WARN_LINES_MAX]:
        emit("%s: %s %s -- it did not match the type "
             "report-schema.json pins for it"
             % (artifact, what, str(path)[:NAME_MAX]))
    remaining = len(changes) - WARN_LINES_MAX
    if remaining > 0:
        emit("%s: ... and %d more repairs, not listed -- this artifact did not "
             "match the types report-schema.json pins for it at all"
             % (artifact, remaining))


def _bounded(rows, path, changes):
    """`rows` cut to `ROWS_MAX`, announced ONCE rather than per dropped row.

    An aggregate line, because the alternative on the case this exists for --
    a manifest carrying thousands of rows -- is thousands of warnings, which is
    the same denial-of-attention the bound is there to prevent.
    """
    if len(rows) > ROWS_MAX:
        changes.append((path, "kept the first %d of %d rows in"
                        % (ROWS_MAX, len(rows))))
    return rows[:ROWS_MAX]


def _named_rows(value, path, changes, *, cut_names=False):
    """Sorted, bounded mapping rows with string names and disclosed repairs.

    Tool identities are dropped if overlong. Suppression tallies opt into
    cutting names and sum any resulting collisions in their caller.
    """
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append((path, "dropped: not an object"))
        value = {}
    for name, row in _bounded(sorted(value.items(), key=lambda kv: str(kv[0])),
                              path, changes):
        if not isinstance(name, str):
            changes.append(("%s[%r]" % (path, name), "dropped: name is not a string"))
            continue
        if len(name) > NAME_MAX:
            label = "%s.%s..." % (path, name[:40])
            if not cut_names:
                changes.append((label, "dropped: name is longer than %d characters in" % NAME_MAX))
                continue
            changes.append((label, "cut a name to %d of %d characters in" % (NAME_MAX, len(name))))
            name = name[:NAME_MAX - 1] + "\u2026"
        yield name, row


def _cut_to(text, path, changes, limit):
    """`text` cut to `limit`, announced when it was actually cut.

    Announced, not silent: a reader who meets a value at its published limit has
    to be able to tell a complete one from a bounded one.
    """
    if len(text) <= limit:
        return text
    changes.append((path, "cut a value to %d of %d characters in"
                    % (limit, len(text))))
    return text[:limit]


def _cut(text, path, changes):
    """`text` cut to the shared published-value bound."""
    return _cut_to(text, path, changes, VALUE_MAX)


def repair_tools_excluded(value, warn=None):
    """The `--tools-exclude` / committed `exclude_paths:` policy block,
    normalized to what the schema pins for `meta.coverage.tools_excluded`
    (#1740 fix round 2).

    `{"globs": [str], "count": int}` -- which globs scoped this run's tool
    ingest, and how many findings they dropped. The globs come from the
    repository's own root config file (`repo_config`), so they are a target-carried input
    reaching a published artifact and are repaired here like every other one:
    a non-string or over-long glob is DROPPED rather than cut (a cut glob is a
    different glob, which would misstate the policy), the list is bounded, and
    a count with no honest integer becomes 0 rather than a fabrication.

    Always returns the full block, `{"globs": [], "count": 0}` included: the
    field's absence must never be readable as "nothing was excluded".
    """
    changes = []
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append(("tools_excluded", "dropped: not an object"))
        value = {}
    raw = value.get("globs")
    if raw is not None and not isinstance(raw, list):
        changes.append(("tools_excluded.globs", "dropped: not a list"))
        raw = []
    globs = []
    for glob in _bounded(list(raw or []), "tools_excluded.globs", changes):
        if not isinstance(glob, str) or not glob:
            changes.append(("tools_excluded.globs[%r]" % (glob,),
                            "dropped: not a non-empty string"))
            continue
        if len(glob) > NAME_MAX:
            changes.append(("tools_excluded.globs.%s..." % glob[:40],
                            "dropped: longer than %d characters in" % NAME_MAX))
            continue
        globs.append(glob)
    count = value.get("count", 0)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        if count not in (None, 0):
            changes.append(("tools_excluded.count",
                            "dropped: not a non-negative integer"))
        count = 0
    warn_repairs("tool ingest", changes, warn)
    return {"globs": globs, "count": count}


def _bounded_strings(raw, path, limit, changes):
    """`raw` as a bounded list of non-empty strings no longer than `limit`.

    Over-long entries are DROPPED rather than cut, which is the rule both
    callers need for their own reason: a cut glob is a different glob and would
    misstate the policy, and a cut path names a file that does not exist.
    """
    if raw is not None and not isinstance(raw, list):
        changes.append((path, "dropped: not a list"))
        raw = []
    kept = []
    for entry in _bounded(list(raw or []), path, changes):
        if not isinstance(entry, str) or not entry:
            changes.append(("%s[%r]" % (path, entry),
                            "dropped: not a non-empty string"))
        elif len(entry) > limit:
            changes.append(("%s.%s..." % (path, entry[:40]),
                            "dropped: longer than %d characters in" % limit))
        else:
            kept.append(entry)
    return kept


def repair_sec_carve_out(value, warn=None):
    """The #1757 (AGT-1355709320) SEC carve-out disclosure, normalized to what
    the schema pins for `meta.coverage.exclude_paths_sec_carve_out`.

    `{"globs": [str], "files": [str], "count": int}` -- which committed
    `exclude_paths:` globs scoped the exclusion, which matched files were
    code-shaped and therefore kept for SEC (#3338), and how many. Target-carried
    twice over:
    the globs are authored in the reviewed repository's own root config and the
    paths are repo-relative names out of the reviewed tree, so both lists are
    repaired here exactly as `tools_excluded`'s globs and `groups[].files` are.

    The COUNT is the measurement and survives a bound applied to the list beside
    it: a repaired `files` shorter than `count` says both true things at once,
    where recomputing the count from the kept rows would publish a number no
    measurement made. A count that is not an honest non-negative integer becomes
    0 for that same reason.

    Always returns the full block -- `{"globs": [], "files": [], "count": 0}`
    included. The KEY is omitted upstream when a run committed no
    `exclude_paths:` at all (zero behaviour change, zero output change), so
    ABSENCE is the "no policy" answer and this function must never produce it:
    a block that is present and unreadable repairs to the empty block, which
    reads as "measured, nothing carved".
    """
    changes = []
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append(("exclude_paths_sec_carve_out",
                            "dropped: not an object"))
        value = {}
    globs = _bounded_strings(value.get("globs"),
                             "exclude_paths_sec_carve_out.globs", NAME_MAX, changes)
    files = _bounded_strings(value.get("files"),
                             "exclude_paths_sec_carve_out.files", PATH_MAX, changes)
    count = value.get("count", 0)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        if count not in (None, 0):
            changes.append(("exclude_paths_sec_carve_out.count",
                            "dropped: not a non-negative integer"))
        count = 0
    warn_repairs("exclude_paths", changes, warn)
    return {"globs": globs, "files": files, "count": count}


def repair_git_drivers_suppressed(value, warn=None):
    """The suppressed-Git-driver disclosure, normalized to what the schema pins
    for `meta.coverage.git_drivers_suppressed` (#2013).

    `[{"repo": str, "key": str}, ...]` -- which of the TARGET's own Git driver
    commands the probe emptied for this scan, and in which repository. The KEY
    half is repository-authored (git's subsection is whatever the target wrote
    into `.git/config`) and the whole block arrives over an argv the driver
    built from the run manifest, so it is repaired here like every other
    target-carried block that reaches a published artifact.

    Accepts the argv's JSON string as well as a parsed list, because the child
    is handed the one and tests drive the other. A row that is not a
    `{"repo": str, "key": str}` pair is DROPPED rather than coerced: a
    disclosure that cannot be read is not a disclosure, and inventing a shape
    for it would publish a claim nobody measured. Unparseable JSON is the same
    answer as no rows -- `[]`, never a raise, because the disclosure must not
    cost the report.

    Always returns a list, `[]` included: the field's absence must never be
    readable as "the target configured none".
    """
    changes = []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            changes.append(("git_drivers_suppressed", "dropped: not JSON"))
            value = []
    if value is None:
        value = []
    if not isinstance(value, list):
        changes.append(("git_drivers_suppressed", "dropped: not a list"))
        value = []
    rows = []
    for row in _bounded(value, "git_drivers_suppressed", changes):
        repo = row.get("repo") if isinstance(row, dict) else None
        key = row.get("key") if isinstance(row, dict) else None
        if not isinstance(repo, str) or not isinstance(key, str) or not key:
            changes.append(("git_drivers_suppressed[]",
                            "dropped: not a {repo, key} pair of strings in"))
            continue
        if len(repo) > PATH_MAX or len(key) > NAME_MAX:
            changes.append(("git_drivers_suppressed[]",
                            "dropped: repo or key longer than the bound in"))
            continue
        rows.append({"repo": repo, "key": key})
    warn_repairs("target git drivers", changes, warn)
    return rows


def repair_tools_suppressed(value, warn=None):
    """The source-scope suppression tally, normalized to what the schema pins
    for `meta.coverage.tools_suppressed` (#1578, widened by #1740).

    `{reason: count}` -- how many tool findings a controlled rule dropped, and
    why. The keys come from a vocabulary the controller owns (including the
    vendored/virtualenv segments and reserved run-artifact, bytecode and fixture
    tokens), and
    the counts are the controller's own tally, so this boundary is a thinner
    one than its two `tools-manifest.json` siblings above -- but the tally is
    DERIVED from `location.file` values a scanner read out of the reviewed
    tree, and the rule is that a target-carried input is repaired at its
    boundary rather than trusted to match what the schema pins. Applying it
    here costs one call and removes the need to reason about whether a future
    caller feeds this from somewhere less controlled.

    DROPPED, never coerced, for the reason `repair_tools_sanitized` gives: a
    count with no honest integer has no repair, only a fabrication. A bool is
    not an integer (jsonschema rejects `True` where `integer` is pinned), and
    neither is a negative number -- nothing can be dropped fewer than zero
    times, and publishing one would be publishing a measurement nobody made.
    A name over `NAME_MAX` is CUT, with the marker `_cut` uses and the count
    kept (#1839 review round 1 N4). It used to be dropped, like `network`'s, on
    the grounds that a segment name is an identity and a cut could collide two
    rows -- true, and it stopped mattering when `pyvenv.cfg:<dir>` became the
    first key shape here to embed an arbitrary target PATH: the bound is now
    reachable by a virtualenv nested under ~190 characters, and a dropped row is
    absent from the report an operator reads. Colliding rows are SUMMED, so the
    total a reader adds up stays exact, and the marker says the name was cut.
    """
    changes: list[tuple[str, str]] = []
    out: dict[str, int] = {}
    for name, count in _named_rows(value, "tools_suppressed", changes, cut_names=True):
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            changes.append(("tools_suppressed.%s" % name,
                            "dropped: not a non-negative integer"))
            continue
        # `get`, because two cut names can be one row: their counts add up
        # rather than the later one replacing the earlier (N4).
        out[name] = out.get(name, 0) + count
    warn_repairs("tool ingest", changes, warn)
    return out
