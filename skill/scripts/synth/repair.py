"""Type repair at the boundaries where panopticon READS what it did not write.

THE PRINCIPLE (module docstring of `validate_schema`, and `synth/coverage_io`):
`skill/reference/report-schema.json` pins the CONTROLLER's output, so every
input that arrives from a review agent or from a target-writable file is
normalized to the pinned types AT ITS BOUNDARY -- never trusted, never allowed
to fail the artifact it rides into. A malformed row costs a warning and the
row; it never costs the run.

Three such boundaries live here, all of them files inside the reviewed tree
that a hostile target can pre-commit: `.panopticon/groups.json` (#1639 P15),
and `tools-manifest.json`'s `sanitized` (#1646) and `network` (#1645) blocks.
They split out of `validate_schema` when the third one arrived and pushed that
module past the 700-line ratchet -- the agent-sourced repairs (`repair_finding`,
`repair_verdict`) stay there with the schema-node machinery they are built on,
which this module reaches by module attribute for `repair_groups_json`.

BOUNDS. Everything here is text bound for two published artifacts (the report
and its HTML), so every read is bounded on three axes: how many rows, how long
a name, how long a value. One set of numbers, applied identically at all three
boundaries -- a producer that caps its own output (`scripts.tools.pip_audit`)
is a statement about the CONTROLLER's manifest and no defence at all on the
path these functions exist for.
"""
import sys

from . import validate_schema as schema


# One bound for every artifact read here. The controller's own manifests are an
# order of magnitude inside all three; these are the numbers a hostile one is
# held to. `sanitized`'s producer uses the same 200/200 for its own output.
ROWS_MAX = 200
NAME_MAX = 200
VALUE_MAX = 200


def warn_repairs(artifact, changes, warn):
    """Announce every repair a boundary read made, one line each -- through
    `warn` when a caller supplied one (synthesis collects them), on stderr
    otherwise. Shared by the three repairers below, which each held the same
    seven lines: a fourth must not have to remember the wording.
    """
    for path, what in changes:
        message = ("%s: %s %s -- it did not match the type "
                   "report-schema.json pins for it" % (artifact, what, path))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)


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


def _cut(text, path, changes):
    """`text` cut to `VALUE_MAX`, announced when it was actually cut.

    Announced, not silent: a reader who meets a 200-character value has to be
    able to tell a complete one from a bounded one.
    """
    if len(text) <= VALUE_MAX:
        return text
    changes.append((path, "cut a value to %d of %d characters in"
                    % (VALUE_MAX, len(text))))
    return text[:VALUE_MAX]


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
        for g in raw:
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
            if not isinstance(g.get("files"), list):
                # grading subscripts `g["files"]` directly; absent is not a
                # shape the report's groups[] can carry either (it is required).
                g["files"] = []
                changes.append(("groups[].files", "defaulted to []"))
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
    changes = []
    out = {}
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append(("sanitized", "dropped: not an object"))
        value = {}
    for name, row in _bounded(sorted(value.items(), key=lambda kv: str(kv[0])),
                              "sanitized", changes):
        if not isinstance(name, str):
            changes.append(("sanitized[%r]" % (name,), "dropped: name is not a string"))
            continue
        if len(name) > NAME_MAX:
            changes.append(("sanitized.%s..." % name[:40],
                            "dropped: name is longer than %d characters in" % NAME_MAX))
            continue
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
                    {"line": _cut(r["line"], path, changes),
                     "reason": _cut(r["reason"], path, changes)} for r in rows
                    if isinstance(r, dict) and isinstance(r.get("line"), str)
                    and isinstance(r.get("reason"), str)]
                if len(kept_row[field]) != len(rows):
                    changes.append((path, "dropped %d malformed row(s) from"
                                    % (len(rows) - len(kept_row[field]))))
            else:
                changes.append(("sanitized.%s.%s" % (name, field), "dropped"))
        for extra in sorted(set(row) - set(_SANITIZED_ROW)):
            changes.append(("sanitized.%s.%s" % (name, extra),
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
    changes = []
    out = {}
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append(("network", "dropped: not an object"))
        value = {}
    for name, posture in _bounded(
            sorted(value.items(), key=lambda kv: str(kv[0])), "network", changes):
        if not isinstance(name, str):
            changes.append(("network[%r]" % (name,), "dropped: name is not a string"))
            continue
        if len(name) > NAME_MAX:
            changes.append(("network.%s..." % name[:40],
                            "dropped: name is longer than %d characters in"
                            % NAME_MAX))
            continue
        if not isinstance(posture, str):
            changes.append(("network.%s" % name, "dropped: not a string"))
            continue
        out[name] = _cut(posture, "network.%s" % name, changes)
    warn_repairs("tools-manifest.json", changes, warn)
    return out
