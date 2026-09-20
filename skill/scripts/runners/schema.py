"""The output-schema argv rules (D10 ruling 3), split out of `runners/base.py`.

A cohesive piece with one subject: the ONE value on a launch's argv that did
not come from this process's own constants. `output_schema` travels on an
entry through `.panopticon/dispatch-request.json`, which lives INSIDE the
reviewed tree, so every rule about it -- may this path be read at all, does
this CLI take the file or its text, how big may that text be -- belongs
together rather than beside the pool and the process bookkeeping.

Moved here unchanged (#1732) because `base.py` sat at 695 of the 700-line
package ceiling and `RunResult.stderr` had to fit. No behaviour change: the
four names are the same four, with the same docstrings, and `base` does not
re-export them (layout rule 4 -- one name, one module, one patch target), so
every caller names this module instead.
"""
import json
import os

import scripts._version as version


def published_schema(path):
    """`path` resolved, when it is one of the JSON Schemas panopticon PUBLISHES
    under `skill/reference/`; None for anything else.

    The containment rule for the one argv value a target could otherwise
    choose. An entry travels through `.panopticon/dispatch-request.json`, which
    lives inside the reviewed tree, so `output_schema` is the only path on a
    launch's argv that did not come from this process's own constants. Only a
    published schema is ever handed to a host CLI: a file that does not exist,
    or one outside that directory, reads as no schema at all rather than as an
    argument. `codex_host.validate_command` re-applies this to the FINISHED
    argv -- one rule, two places it has to hold.
    """
    if not isinstance(path, str) or not path:
        return None
    root = os.path.realpath(version.reference_path())
    real = os.path.realpath(path)
    if not real.startswith(root + os.sep) or not os.path.isfile(real):
        return None
    return real


# The largest token `inline_schema` will put on an argv. Linux caps a single
# argv string at MAX_ARG_STRLEN (128 KiB) and `execve` answers E2BIG, which
# the runner reports as a failed entry -- three burned launches per entry,
# the exact failure this helper exists to prevent. `skill/reference/` also
# publishes `ocrdb-0.5.0.json` (176 KB compacted), and a rewritten
# `dispatch-request.json` can name any published file,
# so the cap is what keeps "published" from meaning "launchable". Half the
# kernel limit, well above every schema stamped on an entry today (the
# largest, report-schema.json, compacts to ~40 KB).
INLINE_SCHEMA_MAX = 65536


def inline_schema(path):
    """The published schema at `path` as one line of JSON, for a CLI that takes
    the schema TEXT on its argv; None when `path` is not a published schema
    (`published_schema` is applied HERE, not only by the caller: a helper that
    opened whatever it was handed would turn the one target-chosen argv value
    into an arbitrary-file read that reaches the CLI), when the file is not a
    JSON object, or when the text exceeds `INLINE_SCHEMA_MAX`.

    Two CLIs, two shapes, one helper that used to know only one of them:
    codex's `--output-schema <FILE>` takes a path, claude's `--json-schema
    <schema>` takes the JSON itself. MEASURED 2026-09-20 on claude 2.1.276:
    the path form is refused ("--json-schema is not valid JSON: JSON Parse
    error: Unrecognized token '/'"), exit 1 in ~120 ms with no envelope -- so
    every return_json entry of every checkpoint burned its three launches, and
    run 14's tool-verify round (103 entries) stopped the driver. The `--help`
    probe that marks the flag `advertised` reads the flag's NAME and cannot
    see its shape; this is where the shape lives, and `probes/shape.py` is
    where it is now MEASURED once per run rather than assumed.

    None, not a raise, for a file that does not parse: the persist layer
    validates the reply against the same schema on receipt, so a launch
    without the flag is the fail-safe and a launch the CLI refuses is not."""
    path = published_schema(path)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    text = json.dumps(data, separators=(",", ":"))
    if len(text) > INLINE_SCHEMA_MAX:
        return None
    return text


def schema_argv(flag, entry, inline=False):
    """The two argv tokens that constrain one launch's output, or [] (D10
    ruling 3). Empty whenever the family declares no flag, the entry names no
    schema, or the path it names is not published -- so a caller can append the
    result unconditionally. `inline=True` hands the CLI the schema's JSON text
    instead of its path (`inline_schema`); the containment rule is the same
    either way, only a published file is ever read."""
    schema = published_schema(entry.get("output_schema") if isinstance(entry, dict) else None)
    if not (flag and schema):
        return []
    if inline:
        schema = inline_schema(schema)
        if schema is None:
            return []
    return [*flag, schema]
