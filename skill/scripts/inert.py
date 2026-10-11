"""Shared code-point policy for inert text rendering.

Kept outside ``scripts.tools`` so the driver can use the same policy without
importing the adapter registry. The set covers C0, DEL/C1, the Unicode line and
paragraph separators, the bidi controls named by #2118 item 1 / #2712, and the
surrogate block (#2951).
"""
import re
from typing import Any


# A lone surrogate (#2951) is not text: no encoder of text takes one, so a string
# holding one raises where it is first hashed or written as text -- `json.dump`
# alone writes it, as the escape it was read from. `json.load` hands one over for
# a lone `\udXXX` escape -- a PAIR decodes to its character and holds none.
SURROGATES = range(0xD800, 0xE000)

INERT_ESCAPE_CODE_POINTS = frozenset(
    (*range(0x0000, 0x0020),
     0x007F,
     *range(0x0080, 0x00A0),
     0x061C,
     0x200E, 0x200F,
     0x2028, 0x2029,
     *range(0x202A, 0x202F),
     *range(0x2066, 0x206A),
     *SURROGATES)
)

_SURROGATE = re.compile("[%c-%c]" % (SURROGATES[0], SURROGATES[-1]))


def spelled(code_point: int) -> str:
    r"""The ONE spelling of an inert code point: `\xNN` below U+0100 and `\uNNNN`
    above it, as ever -- and `U+NNNN` for a surrogate, with NO backslash (#2951
    round 2). A surrogate is what an undecodable byte in a file name becomes, and
    `evidence.norm_path` reads a backslash as a separator: spelled with one, a
    root-level `docs<byte>x.py` read as `docs/udce9x.py`, in the doc tree, and the
    doc policy took a HIGH on it down to INFO. Six characters either way."""
    if code_point in SURROGATES:
        return "U+%04X" % code_point
    return "\\x%02x" % code_point if code_point < 0x100 else "\\u%04x" % code_point


def escape_surrogates(text: str) -> str:
    """`text` with each lone surrogate as this policy spells one (`spelled`), and
    every other character as it is -- for text whose other characters are not
    this caller's to change."""
    return _SURROGATE.sub(lambda found: spelled(ord(found.group())), text)


def _holds_one(document):
    """Whether any string of `document` -- a key or a value, at any depth -- holds
    a lone surrogate. Nothing is built, and a string that is ASCII is not read:
    this pass is all a document holding none costs."""
    if isinstance(document, str):
        return _SURROGATE.search(document) is not None
    todo: list[Any] = [document] if isinstance(document, (dict, list)) else []
    while todo:
        node = todo.pop()
        if isinstance(node, dict):
            for key in node:
                if isinstance(key, str) and not key.isascii() and _SURROGATE.search(key):
                    return True
            node = node.values()
        for value in node:
            if isinstance(value, str):
                if not value.isascii() and _SURROGATE.search(value):
                    return True
            elif isinstance(value, (dict, list)):
                todo.append(value)
    return False


def surrogate_free(document):
    """`document` -- what `json.load` returned -- with no lone surrogate in any
    string of it: a key, a value, a list member, at any depth, each as
    `escape_surrogates` spells it.

    A document holding none comes back ITSELF, so nothing about it moves; one
    holding any comes back as a copy at every depth, the original untouched. No
    recursion: the nesting is its author's to choose, and `json.load` accepts
    more of it than a caller's stack has left."""
    if not _holds_one(document):
        return document
    copy: list[Any] = [None]
    todo: list[tuple[Any, Any]] = [([document], copy)]
    while todo:
        source, made = todo.pop()
        for key, value in (source.items() if isinstance(source, dict) else enumerate(source)):
            if isinstance(value, str):
                value = escape_surrogates(value)
            elif isinstance(value, (dict, list)):
                nested = {} if isinstance(value, dict) else [None] * len(value)
                todo.append((value, nested))
                value = nested
            made[escape_surrogates(key) if isinstance(key, str) else key] = value
    return copy[0]
