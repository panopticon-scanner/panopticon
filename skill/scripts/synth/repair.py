"""Type repair at the boundaries where panopticon READS what it did not write.

THE PRINCIPLE (module docstring of `validate_schema`, and `synth/coverage_io`):
`skill/reference/report-schema.json` pins the CONTROLLER's output, so every
input that arrives from a review agent or from a target-writable file is
normalized to the pinned types AT ITS BOUNDARY -- never trusted, never allowed
to fail the artifact it rides into. A malformed row costs a warning and the
row; it never costs the run.

These repairs normalize target-writable `groups.json` and the tools manifest's
sanitized inputs, network posture, exclusions, Git-driver declarations and
suppression counts. They split out of `validate_schema` as the boundary work
outgrew its 700-line ratchet. Agent-sourced repairs (`repair_finding` and
`repair_verdict`) stay there with the schema-node machinery this module uses.

BOUNDS. These functions bound already-parsed content for the report and HTML:
row counts, names and values, plus the diagnostics about dropped or repaired
content. They do not bound the bytes the caller reads before parsing JSON.
Producer-side limits alone cannot protect these readers of target-writable
artifacts.

The one thing NOT cut, said plainly rather than covered by "identically":
`groups.json`'s `files[]` entries. They are repo-relative paths, a cut path
names a file that does not exist, and corrupting a location is worse than
republishing a long one -- so they are type-checked (`string_list`, and the
schema node) and bounded by DROPPING rather than cutting: a list is kept to
its first `FILES_MAX` entries (the group row cap says nothing about how many
files ONE group may list), and an entry longer than `PATH_MAX` -- longer than
any filesystem lets a path be, so a name for nothing -- is dropped whole.
"""
import json
import sys

from scripts import redact as redact_mod
from . import validate_schema as schema


# One bound for every artifact read here. The controller's own manifests are an
# order of magnitude inside all three; these are the numbers a hostile one is
# held to. `sanitized`'s producer uses the same 200/200 for its own output.
ROWS_MAX = 200
NAME_MAX = 200
VALUE_MAX = 200
CLEANUP_KIND_MAX = 64
CLEANUP_DETAIL_MAX = 500

# How many repair lines a single read may announce before it summarises the
# rest. The content bounds above stopped a hostile manifest from reaching the
# artifact; without this one it still reached synthesize's STDERR, 120,401
# lines and 17.9 MB of it -- which is the same denial-of-attention `_bounded`
# exists to prevent, one layer out. Nothing is hidden: the tail line carries
# the true remaining count.
WARN_LINES_MAX = 20

# `groups[].files[]` is the one list bounded by dropping, not cutting (module
# docstring). The count is an order of magnitude above the largest group the
# grouping engine forms and the fixture sinks a hand-written config
# carries; the length is PATH_MAX on every platform panopticon runs on.
FILES_MAX = 10000
PATH_MAX = 4096


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


def _bounded_paths(files, changes):
    """`groups[].files[]` kept to `FILES_MAX` entries, each no longer than
    `PATH_MAX` -- by dropping, never cutting, because a cut path is a location
    that does not exist. Both announced once per list, not once per entry."""
    if len(files) > FILES_MAX:
        changes.append(("groups[].files", "kept the first %d of %d rows in"
                        % (FILES_MAX, len(files))))
        files = files[:FILES_MAX]
    kept = [f for f in files if not (isinstance(f, str) and len(f) > PATH_MAX)]
    if len(kept) != len(files):
        changes.append(("groups[].files[]", "dropped %d paths longer than %d in"
                        % (len(files) - len(kept), PATH_MAX)))
    return kept


_GROUPS_KEEP_KEYS = ("name", "files", "parent")


# ---------------------------------------------------------------------------
# The TARGET boundary: `.panopticon/groups.json`.
# ---------------------------------------------------------------------------
# Same principle, third source (#1639 P15 fix round 2, F6). `groups.json` is
# read out of `.panopticon/` inside the reviewed tree -- the same
# target-writable directory as the `coverage-*.json` files `coverage_io`
# already repairs -- and `plan.load_groups_json` is tolerant BY DESIGN: it
# announces a corrupt file and returns {} rather than abort a paid-for run.
# That promise stopped at the parse. Five of its fields reach the artifact or a
# bare subscript untouched: `groups[].name` and `groups[].files` are copied
# into the report's type-pinned `groups[]`, `parent` becomes a rolled-up unit's
# name, `security_mode` becomes `meta.security_mode` (an enum), and `mode` is
# used as a dict KEY -- so a list there raised TypeError, and a group without
# `files` a KeyError, from a file the target can write.
def repair_groups_json(gj, warn=None):
    """Normalize the run's `groups.json` to the types the report pins.

    Repairs in place and returns `gj` ({} when it is not a dict). Never raises
    and never aborts: a group that cannot be repaired is dropped with a warning
    and the rest of the run proceeds, which is `load_groups_json`'s contract
    carried all the way to the artifact instead of only to the parse.
    """
    if not isinstance(gj, dict):
        return {}
    props = schema._report_doc().get("properties") or {}
    item = (((props.get("groups") or {}).get("items") or {}).get("properties")) or {}
    meta = ((props.get("meta") or {}).get("properties")) or {}
    changes = []
    if "groups" in gj:
        raw = gj["groups"]
        if not isinstance(raw, list):
            changes.append(("groups", "dropped"))
            raw = []
        kept = []
        for g in _bounded(raw, "groups", changes):
            if not isinstance(g, dict) or not isinstance(g.get("name"), (str, int, float)) \
                    or isinstance(g.get("name"), bool):
                changes.append(("groups[]", "dropped"))
                continue
            for key in _GROUPS_KEEP_KEYS:
                node = item.get(key) or ({"type": "string"} if key == "parent" else None)
                if node is None or key not in g:
                    continue
                ok, repaired = schema._repair_node(g[key], node, "groups[].%s" % key, changes)
                if ok:
                    g[key] = repaired
                else:
                    g.pop(key, None)
            # `name` and `parent` are NAMES that ride into the report's
            # type-pinned `groups[]` and its HTML, from a file the target can
            # pre-commit -- so they are bounded like every other name here.
            # `files[]` entries are NOT cut: they are repo-relative paths, and
            # a cut path names a file that does not exist, which corrupts a
            # location rather than bounding text -- they are bounded below by
            # dropping instead (`_bounded_paths`). See the module docstring.
            for key in ("name", "parent"):
                if isinstance(g.get(key), str):
                    g[key] = _cut(g[key], "groups[].%s" % key, changes)
            if not isinstance(g.get("files"), list):
                # grading subscripts `g["files"]` directly; absent is not a
                # shape the report's groups[] can carry either (it is required).
                g["files"] = []
                changes.append(("groups[].files", "defaulted to []"))
            else:
                g["files"] = _bounded_paths(g["files"], changes)
            kept.append(g)
        gj["groups"] = kept
    if "mode" in gj and not isinstance(gj["mode"], str):
        # Read as a dict KEY (findings.MODE_TO_REVIEW_TYPE): unhashable raises.
        gj.pop("mode")
        changes.append(("mode", "dropped"))
    node = meta.get("security_mode") or {}
    if "security_mode" in gj and gj["security_mode"] is not None \
            and not schema._conforms(gj["security_mode"], node):
        gj.pop("security_mode")            # from_args then defaults it
        changes.append(("security_mode", "dropped"))
    warn_repairs("groups.json", changes, warn)
    return gj


_SANITIZED_ROW = ("source", "kept", "dropped", "hashes_stripped",
                  "truncated", "dropped_truncated")


def repair_tools_sanitized(value, warn=None):
    """`tools-manifest.json`'s `sanitized` block, normalized to what the schema
    pins for `meta.tools.sanitized` (#1646).

    THE PRINCIPLE (see the module docstring and `synth/coverage_io`): the schema
    pins the CONTROLLER's output, so a target-sourced input is repaired to the
    pinned types AT ITS BOUNDARY. The manifest is written into the scanned tree
    and a hostile target can pre-commit one, so every field this block carries
    into the report -- and the HTML renders -- is checked here rather than
    trusted, and a malformed row costs a warning and the row, never the run and
    never an `artifact invalid` exit on a report the target authored a corner of.

    DROPPED, never coerced: a `kept` of "lots" has no honest integer, and
    inventing one would publish a number nobody measured. A bool is not an
    integer for this purpose -- `jsonschema` rejects `True` where `integer` is
    pinned, so an unrepaired one would fail the artifact it rode into. Keys the
    schema does not describe go too: `meta` is closed and the parity walk is
    stricter still.

    BOUNDED HERE, not at the producer (#1645 fix round 2, N2). `scripts.tools.
    pip_audit` caps what it writes at 200 rows and 200 published characters --
    but the manifest this function exists for is the one a HOSTILE TARGET
    pre-committed into the scanned tree, which never passed through that
    producer at all. A producer cap is a statement about the controller's own
    output; the bound at the read is the one that holds on the path the
    repairer was written for.
    """
    changes: list[tuple[str, str]] = []
    out = {}
    for name, row in _named_rows(value, "sanitized", changes):
        if not isinstance(row, dict):
            changes.append(("sanitized.%s" % name, "dropped: not an object"))
            continue
        kept_row = {}
        for field in _SANITIZED_ROW:
            if field not in row:
                continue
            got = row[field]
            if field == "source" and isinstance(got, str):
                kept_row[field] = _cut(got, "sanitized.%s.source" % name, changes)
            elif field == "kept" and isinstance(got, int) and not isinstance(got, bool):
                kept_row[field] = got
            elif field in ("hashes_stripped", "truncated") and isinstance(got, bool):
                kept_row[field] = got
            elif field == "dropped_truncated" and isinstance(got, int) \
                    and not isinstance(got, bool):
                kept_row[field] = got
            elif field == "dropped" and isinstance(got, list):
                path = "sanitized.%s.dropped" % name
                rows = _bounded(got, path, changes)
                kept_row[field] = [
                    {"line": _cut(r["line"], path + ".line", changes),
                     "reason": _cut(r["reason"], path + ".reason", changes)}
                    for r in rows
                    if isinstance(r, dict) and isinstance(r.get("line"), str)
                    and isinstance(r.get("reason"), str)]
                if len(kept_row[field]) != len(rows):
                    changes.append((path, "dropped %d malformed row(s) from"
                                    % (len(rows) - len(kept_row[field]))))
            else:
                changes.append(("sanitized.%s.%s" % (name, field), "dropped"))
        for extra in sorted(set(row) - set(_SANITIZED_ROW)):
            changes.append(("sanitized.%s.%s" % (name, str(extra)[:NAME_MAX]),
                            "dropped: the schema describes no such field in"))
        out[name] = kept_row
    warn_repairs("tools-manifest.json", changes, warn)
    return out


def repair_tools_network(value, warn=None):
    """`tools-manifest.json`'s `network` block, normalized to what the schema
    pins for `meta.tools.network` (#1645).

    The principle and the manifest's hostility are `repair_tools_sanitized`'s
    above, unchanged: a malformed row costs a warning and the row, never the
    run and never an `artifact invalid` exit.

    Flat by design: a posture is one string per tool (`none`,
    `proxied:<allowlist>`, `excluded:<reason>`), so anything that is not a
    string is DROPPED rather than stringified -- `str({"kind": "none"})` would
    publish a posture nobody recorded. Cutting an over-long POSTURE is the one
    coercion, the same one every other block of republished target text gets; a
    NAME over the bound is dropped instead, because a name is an identity and
    cutting one could collide two rows and file an adapter's posture under
    another's. Rows are taken sorted-first, so one manifest always yields one
    report.
    """
    changes: list[tuple[str, str]] = []
    out = {}
    for name, posture in _named_rows(value, "network", changes):
        if not isinstance(posture, str):
            changes.append(("network.%s" % name, "dropped: not a string"))
            continue
        out[name] = _cut(posture, "network.%s" % name, changes)
    warn_repairs("tools-manifest.json", changes, warn)
    return out


def repair_tool_cleanup_failures(value, warn=None):
    """Repair scanner-container cleanup failures from `tools-manifest.json`.

    The capture path writes one `{kind, detail}` row per affected tool. The
    manifest sits inside the reviewed tree, so synthesis treats that shape as
    target-writable: malformed rows and extra fields are dropped, tool names
    and row counts are bounded deterministically, and the operator detail is
    redacted and bounded again before it reaches report JSON or either human
    renderer. A bad disclosure never costs the rest of a paid-for run.
    """
    changes: list[tuple[str, str]] = []
    out = {}
    for name, row in _named_rows(value, "cleanup_failures", changes):
        path = "cleanup_failures.%s" % name
        if not isinstance(row, dict):
            changes.append((path, "dropped: not an object"))
            continue
        kind, detail = row.get("kind"), row.get("detail")
        if not isinstance(kind, str) or not kind:
            changes.append((path + ".kind", "dropped row: not a non-empty string"))
            continue
        if not isinstance(detail, str) or not detail:
            changes.append((path + ".detail", "dropped row: not a non-empty string"))
            continue
        for extra in sorted(set(row) - {"kind", "detail"}):
            changes.append((path + "." + str(extra)[:NAME_MAX],
                            "dropped: the schema describes no such field in"))
        safe_detail = redact_mod.redact_diagnostic(
            detail, CLEANUP_DETAIL_MAX)
        if len(detail) > CLEANUP_DETAIL_MAX:
            changes.append((path + ".detail",
                            "cut a value to %d of %d characters in"
                            % (CLEANUP_DETAIL_MAX, len(detail))))
        out[name] = {
            "kind": _cut_to(kind, path + ".kind", changes, CLEANUP_KIND_MAX),
            "detail": safe_detail,
        }
    warn_repairs("tools-manifest.json", changes, warn)
    return out


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
    `exclude_paths:` globs scoped the exclusion, which of the files they matched
    the objective SEC floor also matched (so the SEC domain reviews them anyway,
    per the owner ruling of 2026-09-25), and how many. Target-carried twice over:
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
    """The directory-NAME suppression tally, normalized to what the schema pins
    for `meta.coverage.tools_suppressed` (#1578, widened by #1740).

    `{segment: count}` -- how many tool findings a name-based exclusion
    dropped, and under which conventional directory name. The keys come from a
    closed vocabulary the controller owns (`ingest_tools._VENDORED_DIRS`,
    `_VENV_NAME_SEGMENTS` and `FIXTURE_SEGMENT`) and
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
