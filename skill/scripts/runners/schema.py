"""The output-schema argv rules (D10 ruling 3), split out of `runners/base.py`.

A cohesive piece with one subject: the ONE value on a launch's argv that did
not come from this process's own constants. `output_schema` travels on an
entry through `.panopticon/dispatch-request.json`, which lives INSIDE the
reviewed tree, so every rule about it -- may this path be read at all, does
this CLI take the file or its text, how big may that text be -- belongs
together rather than beside the pool and the process bookkeeping.

Moved here unchanged (#1732) because `base.py` sat at 695 of the 700-line
package ceiling and `RunResult.stderr` had to fit. The original four names
keep that contract; #2923 adds the Codex strict-subset gate here beside the
path rule it narrows. `base` does not re-export them (layout rule 4 -- one
name, one module, one patch target), so every caller names this module instead.
"""
import json
import os

import scripts._version as version


_STRICT_MAX_PROPERTIES = 5000
_STRICT_MAX_DEPTH = 10
_STRICT_MAX_TEXT = 120000
_STRICT_MAX_ENUM_VALUES = 1000
_STRICT_LARGE_ENUM_COUNT = 250
_STRICT_LARGE_ENUM_TEXT = 15000
_STRICT_DIALECT = "http://json-schema.org/draft-07/schema#"


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


def strict_output_schema(path):
    """Return a published schema only when it is strict-output compatible.

    Codex/OpenAI strict structured output requires an object root, every
    object's properties to be required, and ``additionalProperties: false``.
    It accepts nested ``anyOf`` and local ``$defs``, but not an ``anyOf`` root,
    draft-07 ``definitions``, external references, or the unsupported
    composition keywords below.
    Check those rules, the JSON Schema vocabulary, and the provider's size
    limits before a schema path reaches ``codex exec --output-schema``.
    ``None`` is the fail-safe answer: the controller still validates the
    returned reply against the entry's schema, while the host launches without
    a flag it would reject (#2923).
    """
    import jsonschema

    path = published_schema(path)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return None
    if (not isinstance(body, dict) or body.get("$schema") != _STRICT_DIALECT):
        return None
    try:
        jsonschema.validators.validator_for(body).check_schema(body)
    except (jsonschema.exceptions.SchemaError, TypeError, ValueError):
        return None

    unsupported = frozenset(("allOf", "oneOf", "not", "dependentRequired",
                             "dependentSchemas", "if", "then", "else"))
    supported = frozenset((
        "$schema", "$defs", "$ref", "title", "description", "type", "enum",
        "const", "anyOf", "properties", "required", "additionalProperties",
        "items", "minItems", "maxItems", "minLength", "maxLength", "pattern",
        "format", "multipleOf", "minimum", "maximum", "exclusiveMinimum",
        "exclusiveMaximum",
    ))
    kinds = frozenset(("string", "number", "boolean", "integer", "object",
                       "array", "null"))
    formats = frozenset(("date-time", "time", "date", "duration", "email",
                         "hostname", "ipv4", "ipv6", "uuid"))
    string_rules = frozenset(("minLength", "maxLength", "pattern", "format"))
    number_rules = frozenset(("multipleOf", "minimum", "maximum",
                              "exclusiveMinimum", "exclusiveMaximum"))
    array_rules = frozenset(("minItems", "maxItems", "items"))
    counts = {"properties": 0, "text": 0, "enum": 0}

    def value_text(value):
        if isinstance(value, str):
            return len(value)
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    def within_limits():
        return (counts["properties"] <= _STRICT_MAX_PROPERTIES
                and counts["text"] <= _STRICT_MAX_TEXT
                and counts["enum"] <= _STRICT_MAX_ENUM_VALUES)

    def local_reference(ref):
        if ref == "#":
            return isinstance(body, dict)
        target = body
        for raw in ref[2:].split("/"):
            if "%" in raw or "~" in raw.replace("~0", "").replace("~1", ""):
                return False
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or token not in target:
                return False
            target = target[token]
        return isinstance(target, dict)

    def compatible(node, *, root=False, depth=1):
        if (not isinstance(node, dict) or unsupported.intersection(node)
                or set(node).difference(supported) or depth > _STRICT_MAX_DEPTH):
            return False
        kind = node.get("type")
        if "type" in node:
            declared = [kind] if isinstance(kind, str) else kind
            if (not isinstance(declared, list)
                    or not declared
                    or any(item not in kinds for item in declared)
                    or len(set(declared)) != len(declared)):
                return False
        else:
            declared = []
        if not declared and "$ref" not in node and "anyOf" not in node:
            return False
        if root and (kind != "object" or "anyOf" in node):
            return False
        if "$schema" in node and not root:
            return False

        declared_set = set(declared)
        if (string_rules.intersection(node) and "string" not in declared_set
                or number_rules.intersection(node)
                and not declared_set.intersection(("number", "integer"))
                or array_rules.intersection(node) and "array" not in declared_set
                or "format" in node and node["format"] not in formats):
            return False

        ref = node.get("$ref")
        if "$ref" in node and (not isinstance(ref, str)
                                or (ref != "#" and not ref.startswith("#/"))
                                or not local_reference(ref)):
            return False

        properties = node.get("properties")
        is_object = "object" in declared
        if properties is not None and not is_object:
            return False
        if is_object:
            required = node.get("required")
            if (not isinstance(properties, dict)
                    or not isinstance(required, list)
                    or any(not isinstance(name, str) for name in required)
                    or len(required) != len(properties)
                    or set(required) != set(properties)
                    or node.get("additionalProperties") is not False):
                return False
            counts["properties"] += len(properties)
            counts["text"] += sum(len(name) for name in properties)
            if (not within_limits()
                    or not all(compatible(value, depth=depth + 1)
                               for value in properties.values())):
                return False
        elif "required" in node or "additionalProperties" in node:
            return False

        if "$defs" in node:
            definitions = node["$defs"]
            if not isinstance(definitions, dict):
                return False
            counts["text"] += sum(len(name) for name in definitions)
            if (not within_limits()
                    or not all(compatible(value, depth=depth + 1)
                               for value in definitions.values())):
                return False

        if "enum" in node:
            values = node["enum"]
            enum_text = sum(value_text(value) for value in values)
            counts["enum"] += len(values)
            counts["text"] += enum_text
            if (not within_limits()
                    or (len(values) > _STRICT_LARGE_ENUM_COUNT
                        and enum_text > _STRICT_LARGE_ENUM_TEXT)):
                return False
        if "const" in node:
            counts["text"] += value_text(node["const"])
            if not within_limits():
                return False

        if "anyOf" in node:
            alternatives = node["anyOf"]
            if (not isinstance(alternatives, list) or not alternatives
                    or not all(compatible(value, depth=depth + 1)
                               for value in alternatives)):
                return False

        is_array = "array" in declared
        if is_array and "items" not in node:
            return False
        if "items" in node:
            if not is_array or not compatible(node["items"], depth=depth + 1):
                return False
        return True

    return path if compatible(body, root=True) else None


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
