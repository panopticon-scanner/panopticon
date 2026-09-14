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
that module is at the layout ceiling. One owner, one patch target.
"""
import datetime
import json


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
