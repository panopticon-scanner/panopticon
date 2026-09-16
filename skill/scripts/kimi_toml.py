"""The TOML writer the Kimi runner's per-run config.toml goes out through.

Stdlib has `tomllib` for reading and no writer, and the file this produces is
where Kimi's whole confinement lives -- the two `[[hooks]]` entries and
`tools.disabled` -- regenerated from whatever the operator's own
`~/.kimi-code/config.toml` holds. So it has to emit every shape a real config
can carry, not just the ones panopticon adds: C2 was two bugs here (an
array-of-tables header written as its PARENT's path, and headers emitted from
inside the scalar loop) that made any nested `[[mcp.servers]]` unloadable, and
a datetime aborting the run.

It lives beside runners/kimi.py rather than inside it because it is a
self-contained stdlib concern with no knowledge of the runner, and because
that module is at the layout ceiling. One owner, one patch target. #1640 put
the `[mcp]` scrub here for both halves of that reason: it is a fact about the
per-run config FILE, with no knowledge of the runner beyond the block it
names, and the runner had no room left for it.
"""
import datetime
import json


# #1640 (run-13 AGT-3297306866). The per-run home mediates what it can guard,
# and MCP is outside that: `tools.disabled` names the CLI's own built-in
# vocabulary, and the two PreToolUse hooks adjudicate calls to those same
# native tools by name. An MCP server's tools are supplied at runtime by
# ANOTHER PROCESS -- names neither list has heard, reaching the filesystem and
# the network through that process, not through a tool call this hook sees.
# Carrying the operator's `[[mcp.servers]]` into the armed home therefore
# handed every reviewer a surface the home exists to close, and a hostile
# target that steered a reviewer at one was outside the whole control.
#
# The block-level switch, not a per-server one: it is ONE fact to arm and one
# to refute (the guard probes read two keys), where disabling servers
# individually is a list to keep correct as the operator's config changes.
MCP = "mcp"
# What every per-run config carries, and what the guard probes must FIND in the
# armed file (fix round 1, F2). One definition, so the runner and the probe
# cannot drift about what "MCP is off in this home" looks like -- and so the
# probe can demand the block EXPLICITLY rather than reading an absent or
# unparseable one as "nothing live here", which is the absence of evidence.
INERT_MCP = {"enabled": False, "servers": []}
# One line, and a COUNT rather than the names: this shares the operator's
# stderr with the run's own progress output, so a disclosure that grew with
# their config would crowd out the thing they are watching.
MCP_DISCLOSURE = "driver loop: %d operator MCP servers disabled in the per-run home"


def mediated_mcp(source=None, disclose=None):
    """The `[mcp]` block every per-run config carries -- inert, always.

    CONSTRUCTED, never filtered: `enabled = false` with an empty `servers`
    array says the same thing whatever the operator's config holds, including
    shapes this writer would refuse to emit and per-server flags it would have
    to understand.

    `source` is the operator's config and `disclose` a stream; given both, the
    number of `[[mcp.servers]]` being dropped is announced on it when there is
    one (and nothing is said when there is not -- a line printed on every run
    teaches its reader to skip the ones that matter).
    """
    block = source.get(MCP) if isinstance(source, dict) else None
    servers = block.get("servers") if isinstance(block, dict) else None
    dropped = len(servers) if isinstance(servers, list) else 0
    if dropped and disclose is not None:
        print(MCP_DISCLOSURE % dropped, file=disclose, flush=True)
    return {"enabled": False, "servers": []}


def _toml_key(key):
    if key and all(c.isalnum() or c in "_-" for c in key):
        return key
    return json.dumps(key)


def _toml_value(value, key=None):
    """One TOML scalar. `key` is carried so a value this writer cannot emit
    names the key it came from: a bare "cannot emit TOML for None" in the
    middle of `prepare` names no config line."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    # datetime BEFORE date: every datetime is also a date (C2). tomllib hands
    # these back for any TOML date-time, and a CLI config that carries one
    # (`last_update_check`, an install stamp) used to abort the whole run.
    if isinstance(value, datetime.datetime):
        return value.isoformat()               # offset or local date-time
    if isinstance(value, datetime.date):
        return value.isoformat()               # local date
    if isinstance(value, datetime.time):
        return value.isoformat()               # local time
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[%s]" % ", ".join(_toml_value(v, key) for v in value)
    raise TypeError("cannot emit TOML for the value at %r: %r"
                    % (key if key is not None else "<root>", value))


def _split(table):
    """(scalars, arrays_of_tables, tables) -- separated so the emitter can
    order them. TOML binds every bare `key = value` to the LAST header above
    it, so a parent's scalars must precede any header of its own."""
    scalars, arrays, tables = {}, {}, {}
    for key, value in table.items():
        if isinstance(value, dict):
            tables[key] = value
        elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            arrays[key] = value
        else:
            scalars[key] = value
    return scalars, arrays, tables


def _emit_table(lines, table, path):
    """Emit one table's body under `path` (a dotted key path, already quoted)."""
    scalars, arrays, tables = _split(table)
    for key, value in scalars.items():
        lines.append("%s = %s" % (_toml_key(key), _toml_value(value, key)))
    for key, items in arrays.items():
        # C2: the header is the array's OWN path -- `[[mcp.servers]]`, not the
        # parent's `[[mcp]]` -- and it comes after the parent's scalars.
        subpath = "%s.%s" % (path, _toml_key(key)) if path else _toml_key(key)
        for item in items:
            lines.append("\n[[%s]]" % subpath)
            _emit_table(lines, item, subpath)
    for key, sub in tables.items():
        subpath = "%s.%s" % (path, _toml_key(key)) if path else _toml_key(key)
        lines.append("\n[%s]" % subpath)
        _emit_table(lines, sub, subpath)


def dump_toml(config):
    """Serialize a tomllib-produced dict back to TOML text."""
    lines = []
    _emit_table(lines, config, "")
    return "\n".join(lines) + "\n"
