#!/usr/bin/env python3
"""The words a shell parse hands back, and the markers that say what was lifted out of them.

Split out of `scripts/shell_reader.py` (#2628) at that module's size, byte
for byte: `_Parse` mints the markers a parse puts in place of the text it
lifts -- a substitution, a redirection, a heredoc, a group, a `case` arm --
and `_Token` is the word that carries its own markers back to a reader, so
`readable`, `is_marker`, `has_substitution` and `yields_words` can answer for
exactly the text that was lifted and never for a lookalike the target repo
wrote. `derived` carries that provenance through a substring a caller takes.
The reader imports every name back under its own, so nothing that read
`shell_reader.readable` or `shell_reader.derived` moved.
"""

import re
import secrets

from shell_text import Process
from shell_wrappers import Rewritten


class _Token(str):
    """String-compatible shell word with capabilities from its own parse.

    String operations deliberately discard provenance. Consumers deriving a
    path must use `derived` to retain only the markers actually in that path.
    Re-parsing a word starts a fresh context, never reuses these capabilities.
    """
    def __new__(cls, text, markers):
        token = super().__new__(cls, text)
        token.markers = markers
        return token

    markers: dict[str, tuple[str, object]]
    kept: bool                  # set by `kept`; read with a default by `shell_reader._optional`


class _Expanded(_Token, Rewritten):
    """A word bash expands as a pattern (#2294), lifted text in it or not;
    `covers` knows one by its `lead`: may it begin with `-` (`leads`)."""


def _markers(text):
    return text.markers if isinstance(text, _Token) else {}


def kept(word):
    """`word` as a token bash keeps as its command (#2472): every `$` of it
    quoted (`shell_reader._stage`), or the step's own table resolving it to a
    literal that is no wrapper (`workflow_annotate._mark`) -- so the reader does
    not drop it in front of a known name as it drops an empty or unset `$SUDO`
    (`shell_reader._optional`)."""
    token = _Token(str(word), _markers(word))
    token.kept = True
    return token


def derived(text, *sources):
    """Carry provenance through an explicit substring/path transformation."""
    markers = {key: value for source in sources
               for key, value in _markers(source).items() if key in text}
    return _Token(text, markers) if markers else text


# The shape of every marker `_Parse.new` mints: its prefix, then a count and `@@`.
_MARK = re.compile(r"@@shell-[0-9a-f]+-x*[0-9]+@@")


def spelled(text, source):
    """`derived(text, source)` in one pass over `text`: the markers of `source` that `text` spells,
    found by their shape rather than by trying each against `text`, so a word cut into n pieces
    costs the pieces, not the pieces times its n markers (#2856 round 12, the round-11 B3)."""
    markers = _markers(source)
    found = {key: markers[key] for key in _MARK.findall(text) if key in markers} if markers else {}
    return _Token(text, found) if found else text


class _Parse:
    def __init__(self, source):
        # No source spelling can collide, even if a nonce source is replaced
        # in a test. No global registry: tokens retain only their own entries.
        self.prefix = "@@shell-" + secrets.token_hex(16) + "-"
        while self.prefix in source:
            self.prefix += "x"
        self.source = source            # the text parsed (`shell_command._sets`)
        self.entries: dict[str, tuple[str, object]] = {}
        self.pattern = re.compile(re.escape(self.prefix) + r"\d+@@")

    def new(self, kind, value=None):
        marker = self.prefix + str(len(self.entries)) + "@@"
        self.entries[marker] = (kind, value)
        return marker

    def token(self, text):
        markers = {m: self.entries[m] for m in self.pattern.findall(text)
                   if m in self.entries}
        return _Token(text, markers) if markers else text

    def restore_arithmetic(self, text):
        """Put opaque arithmetic text back after shell structure is split."""
        def restore(match):
            marker = match.group()
            kind, value = self.entries[marker]
            return value if kind == "arithmetic" else marker

        return self.pattern.sub(restore, text)


def is_arm(token):
    return any(kind == "arm" and token.startswith(key)
               for key, (kind, _value) in _markers(token).items())


def readable(text):
    """Render only this token's genuine lifted substitutions for diagnostics."""
    for key, (kind, _value) in _markers(text).items():
        if kind == "subst":
            text = text.replace(key, "$(...)")
    return text


def is_marker(token):
    """True only for actual lifted text, never a target-authored lookalike."""
    return bool(_markers(token))


def has_substitution(token):
    """Whether a word/path depends on a substitution generated by its parse."""
    return any(kind == "subst" for kind, _value in _markers(token).values())


def yields_words(token):
    """Whether a `$(...)` or backquote in this word hands on its OUTPUT as
    words; a `<(...)` or `>(...)` (`shell_text.Process`) hands a file."""
    return any(kind == "subst" and not isinstance(value, Process)
               for kind, value in _markers(token).values())
