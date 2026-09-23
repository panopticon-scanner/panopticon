"""Small TOML key and value encoder shared by the host config writers."""

import datetime
import json
import re


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+\Z")


def _check_unicode(value):
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError("cannot emit TOML with a lone Unicode surrogate")


def bare_key(key):
    """Whether a key is safe in both TOML and Codex CLI dotted paths."""
    if not isinstance(key, str):
        raise TypeError("TOML keys must be strings")
    _check_unicode(key)
    return _BARE_KEY.fullmatch(key) is not None


def _string(value):
    _check_unicode(value)
    # JSON and TOML share these basic-string escapes, but JSON's default
    # ASCII mode emits non-BMP characters as surrogate pairs, invalid in TOML.
    # DEL is a control character too, so give it an explicit TOML escape.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def key(name):
    return name if bare_key(name) else _string(name)


def value(item, name=None):
    """Encode a TOML value, including inline tables needed by CLI overrides."""
    if isinstance(item, bool):
        return "true" if item else "false"
    if isinstance(item, str):
        return _string(item)
    if isinstance(item, (datetime.datetime, datetime.date, datetime.time)):
        return item.isoformat()
    if isinstance(item, (int, float)):
        return repr(item)
    if isinstance(item, list):
        return "[%s]" % ", ".join(value(child, name) for child in item)
    if isinstance(item, dict):
        return "{%s}" % ", ".join(
            "%s = %s" % (key(child_key), value(child, child_key))
            for child_key, child in item.items()
        )
    raise TypeError("cannot emit TOML for the value at %r: %r"
                    % (name if name is not None else "<root>", item))
