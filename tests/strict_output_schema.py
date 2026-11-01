"""CI-only Codex strict-output compatibility screen (#3272 cut 15).

Runtime confines schema argv paths to panopticon's published reference tree.
Compatibility of the finite generation-schema set we ship is a build property,
so this deliberately lives in tests and never runs once per model launch.
"""
import json

from scripts.runners.schema import published_schema


_STRICT_MAX_PROPERTIES = 5000
_STRICT_MAX_DEPTH = 10
_STRICT_MAX_TEXT = 120000
_STRICT_MAX_ENUM_VALUES = 1000
_STRICT_LARGE_ENUM_COUNT = 250
_STRICT_LARGE_ENUM_TEXT = 15000
_STRICT_DIALECT = "http://json-schema.org/draft-07/schema#"


def strict_output_schema(path):
    """Return a published schema only when it is strict-output compatible.

    Codex/OpenAI strict structured output requires an object root, every
    object's properties to be required, and ``additionalProperties: false``.
    It accepts nested ``anyOf`` and local ``$defs``, but not an ``anyOf`` root,
    draft-07 ``definitions``, external references, or the unsupported
    composition keywords below.
    Check those rules, the JSON Schema vocabulary, and the provider's size
    limits as a CI assertion over every production generation schema. Runtime
    confines the argv path but deliberately does not repeat this parse.
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
