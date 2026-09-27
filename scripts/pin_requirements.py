"""Pure parsing and hash-block rewriting for pinned requirements files.

The caller obtains verified artifact hashes; this module only preserves the
requirement clause, comments, and non-pin physical lines while replacing hash
options. Parsing and rewriting share one logical-line matcher so continued
extras and versions are handled consistently.
"""
from __future__ import annotations

import re


_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[A-Za-z0-9._,\s-]+\])?"
                  r"\s*==(?P<version>[^\s;\\]+)")
_REQUIREMENT_PART = re.compile(
    r'''"[^"]*"|'[^']*'|(?P<comment>(?<!\S)\#.*$)|(?P<hash>(?<!\S)--hash(?:=|\s+)\S+)''')


def _requirement_clause(joined: str) -> tuple[str, str]:
    """Remove hash options, keeping quoted marker values and trailing prose."""
    comment = ""

    def keep(match):
        nonlocal comment
        if match.group("comment"):
            comment = match.group()
            return ""
        return "" if match.group("hash") else match.group()

    return _REQUIREMENT_PART.sub(keep, joined).rstrip(), comment


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """[(lineno, joined)] with `\\`-continuations folded in. lineno is where the
    logical line STARTS."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = None
    for n, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = n
        stripped = line.strip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1].strip())
            continue
        buf.append(stripped)
        out.append((start, " ".join(p for p in buf if p)))
        buf, start = [], None
    if buf:
        out.append((start or 1, " ".join(p for p in buf if p)))
    return out


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """[(name, version)] for every `name==version` pin in a requirements file."""
    pins = []
    for _n, joined in _logical_lines(text):
        if joined.startswith("#"):
            continue
        m = _PIN.match(joined)
        if m:
            pins.append((m.group("name"), m.group("version")))
    return pins


def rewrite_requirements(text: str, hashes: dict[tuple[str, str], list[str]]) -> str:
    """Requirements text with every pin's hash block regenerated.

    Pure, and total in both directions: a pin with no hashes raises, and so does
    a set of hashes with no pin to attach them to. Extras and markers stay in
    the requirement clause; trailing comments follow the final hash. Standalone
    comments and blank lines stay where they were.
    """
    lines = text.splitlines()
    out: list[str] = []
    written = set()
    i = 0
    while i < len(lines):
        if not lines[i].strip():
            out.append(lines[i])
            i += 1
            continue
        start = i
        while i < len(lines) - 1 and lines[i].rstrip().endswith("\\"):
            i += 1
        i += 1
        joined = _logical_lines("\n".join(lines[start:i]))[0][1]
        m = None if joined.startswith("#") else _PIN.match(joined)
        if not m:
            out.extend(lines[start:i])
            continue
        clause, comment = _requirement_clause(joined)
        key = (m.group("name"), m.group("version"))
        digests = hashes.get(key)
        if not digests:
            raise RuntimeError("no verified hashes for %s==%s" % key)
        out.append(clause + " \\")
        for n, digest in enumerate(digests):
            suffix = " \\" if n < len(digests) - 1 else ("  " + comment if comment else "")
            out.append("    --hash=sha256:%s%s"
                       % (digest, suffix))
        written.add(key)
    unused = sorted(set(hashes) - written)
    if unused:
        raise RuntimeError("hashes for pins this file does not carry: %s"
                           % ", ".join("%s==%s" % k for k in unused))
    return "\n".join(out) + "\n"
