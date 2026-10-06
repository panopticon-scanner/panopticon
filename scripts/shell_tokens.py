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
    """Carry provenance through an explicit substring/path transformation -- and a word's two
    readings (`readings`, #2856): a destination's whole `${…}` word through a value cut from the
    end of its glued option (`--output-document=${D:-tool`) or a directory joined in front of it,
    and `main`'s pieces through a value cut from the end of a word read whole (`F=${D:-tool }`'s
    `${D:-tool }` keeps `${D:-tool`, which `main` assigned)."""
    markers = {key: value for source in sources
               for key, value in _markers(source).items() if key in text}
    made = _Token(text, markers) if markers else text
    for source in sources:
        whole, pieces, cut = getattr(source, "whole", None), getattr(source, "pieces", None), len(str(source)) - len(text)
        if whole is not None and (str(source).endswith(text) or text.endswith(str(source))):
            made = made if isinstance(made, _Token) else _Token(made, {})
            setattr(made, "whole", whole[cut:] if cut >= 0 else text[:-cut] + whole)
        elif pieces and 0 < cut < len(pieces[0]) and str(source).endswith(text) and str(source)[:cut] == pieces[0][:cut]:
            made = made if isinstance(made, _Token) else _Token(made, {})
            setattr(made, "pieces", [pieces[0][cut:], *pieces[1:]])
    return made


def readings(word):
    """The spelling a word holding a bare blank has besides its own (#2856): the whole `${…}`
    word a destination read as `main` read it was split from, or `main`'s first piece of a word
    read whole -- so a destination and a use meet whichever way each was read."""
    pieces = getattr(word, "pieces", None)
    other = getattr(word, "whole", None) or (pieces[0] if pieces else None)
    return {other} if other is not None else set()


def argv_readings(argv):
    """`argv`, and beside it the argv `main` read where a word holds a bare-blank `${…}`: each such
    word as the pieces `main` split it into. The coordinator's union (#2856 round 7): at every
    comparison `main`'s reading stays a candidate, and the whole reading only adds matches."""
    split = [piece for word in argv for piece in (getattr(word, "pieces", None) or [word])]
    return [argv, split] if len(split) != len(argv) else [argv]


def stage_readings(stage):
    """`stage`, and its twin holding `main`'s argv where that differs (`argv_readings`)."""
    return [stage._replace(argv=argv) for argv in argv_readings(stage.argv)]


def statement_readings(statement):
    """`statement`, and its twin with every stage read as `main` read it (`stage_readings`)."""
    twin = statement._replace(stages=[stage_readings(stage)[-1] for stage in statement.stages])
    return [statement, twin] if twin != statement else [statement]


class _Parse:
    def __init__(self, source):
        # No source spelling can collide, even if a nonce source is replaced
        # in a test. No global registry: tokens retain only their own entries.
        self.prefix = "@@shell-" + secrets.token_hex(16) + "-"
        while self.prefix in source:
            self.prefix += "x"
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
