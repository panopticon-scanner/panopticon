#!/usr/bin/env python3
"""The step's own literal values, read as bounded value facts (#2425, #2489).

The guard binds a download to its later uses by NAME, and a step that keeps
that name in a variable it assigns itself hid the use: `T=cuda_1.run; sh
"$T"`, `p=./cuda_*.run; sh $p`, `declare -a a=(sh tool); "${a[@]}"`, and the
#2581 rows `./cuda_$X.run`, `${X:-*}` and `${a[0]}`. This is the table that
reads them: `Values` holds, per name, the CANDIDATE texts a scalar may hold
and the CANDIDATE word-lists of the array literals it may hold. Split out of
`scripts/workflow_uses.py` at that module's size, it imports nothing from it,
and `workflow_uses` re-exports `Values`, `assigned`, `record`, `valued` and
`valued_argvs` beside `static_values`, the table live at one statement.

    who assigns     a statement that only assigns, a declaration's operands
                    (`export T=x`, `declare -a a=(sh tool)`) and a literal
                    `for NAME in WORDS` header -- never a PREFIX assignment
                    (`T=x sh "$T"`), which bash makes after it expands the
                    command's words and which does not outlive the command
    held, emptied   a value is held wherever a statement assigns it, and
                    replaced or emptied only where the caller says the shell
                    surely runs the statement; one it may not run adds its
                    value to the name's candidates, and a name it may leave
                    unset gains the empty candidate, `""` or `[]`, over
                    which a default stands (beside `""` under `-` and `=`)
    resolved        in the words of the stage that USES a value
                    (`valued_argvs`), so a relative value is read from the
                    directory of its use, bash's rule, and a text bash globs
                    is a live pattern for `covers`

What `valued_argvs` leaves to its caller: re-reading each argv it makes with
`shell_reader.command()` before asking `use()` what it runs, and splitting a
resolved scalar text that holds blanks on them, as bash splits an unquoted
expansion -- the quoted twin over-reports, as it does for a pattern. It drops
the empty words itself.

The prices: the reader's words have lost their quotes, so `sh "$p"` after
`p=./cuda_*.run` reads as the glob, a single-quoted `'$T'`, which bash does
not expand, as `"$T"`, and the quoted twin `"" sh x` of an empty `$SUDO`
dropped from `$SUDO sh x` as `sh x`; the empty candidate cannot say whether
the name was unset or set empty, so a `-` or `=` default stands beside it
and the set-but-null twin (`X=; sh "${X-d}"`, where bash gives `""`)
over-reports; a literal folded behind a declaration is re-split on blanks; a
subshell's empty prefix assignment `( T= sh tool )` reads as the literal
`T=(sh tool)`; a `for` header whose words the table cannot hold keeps the
name's old candidates; and `a[1]=x`, `mapfile` and `readarray`, the
assignment `${T:=d}` makes, and the attributes of `local -n` and `declare
-i` are not read. `$a` is read as `${a[0]}`, bash's rule.

Stdlib only, like everything under it.
"""
from dataclasses import dataclass, field
import itertools
import os
import re

import shell_reader
from shell_reader import _DECLARATIONS, command
from workflow_operands import live_pattern


# `_LITERAL` is an assignment word (`NAME=text`, `NAME+=text`), `_ARRAY` one
# holding a literal the reader folded in (`NAME=(words)`), `_OPENER` an empty
# one, which an UNFOLDED literal's words follow; `_VALUE` a reference -- `$T`,
# `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}`, `${T=d}`; `_ELEMENT` a whole `${a[0]}`,
# `${a[@]}` or `${a[*]}`; `_SPLAT` a whole `$@` or `$*`, any number of words;
# `_GLOB` what bash globs a value by.
_LITERAL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.S)
_ARRAY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=\((.*)\)$", re.S)
_OPENER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=$")
_VALUE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)"
                    r"|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=])([^{}]*))?\})")
_ELEMENT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\[([0-9]+|[@*])\]\}$")
_SPLAT = re.compile(r"^\$(?:[@*]|\{[@*]\})$")
_GLOB = re.compile(r"[*?\[]")
# A name holds the LAST `_CANDIDATES` candidates assigned, a word resolves to
# the first as many, and no text built is longer than `_LONGEST`: a value
# doubling itself (`T=$T$T`, line after line) in a TARGET repo's `run:` block
# would grow without bound.
_CANDIDATES = 8
_LONGEST = 4096


@dataclass
class Values:
    """The step's literal values at one statement: per name, the CANDIDATE texts
    a scalar may hold -- the reader's words, quotes gone, a lifted `$(...)` kept
    as its marker -- and the CANDIDATE word-lists of its array literals."""

    scalars: dict[str, list[str]] = field(default_factory=dict)
    arrays: dict[str, list[list[str]]] = field(default_factory=dict)


def _for_parts(stage):
    """A literal `for NAME in WORD...` header, or (None, [])."""
    raw = list(stage.argv)
    try:
        start = raw.index("for")
    except ValueError:
        return None, []
    if start + 2 >= len(raw) or raw[start + 2] != "in":
        return None, []
    return str(raw[start + 1]), raw[start + 3:]


def assigned(stage):
    """What this stage assigns in the step's shell (#2425, #2489): `({name:
    (append, text)}, {name: (append, words)})`, `append` for a `+=`.

    A statement that only assigns assigns, and so do a declaration's operands
    (`export T=x`, `declare -a a=(sh tool)`); not a bare `export T`, nor a
    PREFIX assignment (`T=x sh "$T"`: bash expands the command's words first,
    and the value does not outlive the command), nor one behind a wrapper
    other than `command` (`env T=x`). A text is `derived`: a lifted `$(...)`
    stays its marker. A literal is read only where the stage opened a group,
    as the reader counts its parentheses -- folded into its word behind a
    declaration, else handed UNFOLDED (`["a=", "sh", "tool"]`, #2348): an
    empty `NAME=` and the words up to the next one while groups remain. Two
    prices: a folded literal is re-split on blanks, and a subshell's empty
    prefix assignment `( T= sh tool )` reads as `T=(sh tool)`. A `for`
    header is `record`'s.
    """
    scalars, arrays, _count = _assignments(stage)
    return scalars, arrays


def _literals(stage):
    """How many array literals this stage assigns. The reader counts each one's
    parentheses as a group; to bash they are the rest of the literal's word."""
    return _assignments(stage)[2]


def _assignments(stage):
    """`assigned`'s reading, and the number of array literals it read."""
    scalars: dict[str, tuple[bool, str]] = {}
    arrays: dict[str, tuple[bool, list[str]]] = {}
    argv = command(stage.argv)
    if any(word != "command" for word in shell_reader.wrapper_words(stage.argv)):
        return scalars, arrays, 0
    if argv and os.path.basename(argv[0]) in _DECLARATIONS:
        words = list(argv[1:])
    else:
        lead = stage.argv[:len(stage.argv) - len(argv)]
        if argv and not (stage.group_open and any(_OPENER.match(str(word)) for word in lead)):
            return scalars, arrays, 0       # a prefix assignment, or none at all
        words = list(stage.argv)
    literals, unfolded = 0, None
    for word in words:
        room = literals < stage.group_open
        folded = _ARRAY.match(str(word)) if room else None
        match = folded or _LITERAL.match(str(word))
        if match and (folded or room and not match[3]):
            literals += 1
            parts = ([shell_reader.derived(part, word) for part in match[3].split()]
                     if folded else [])
            arrays[match[1]] = (bool(match[2]), parts)
            unfolded = None if folded else parts
        elif unfolded is not None:
            unfolded.append(word)
        elif match:
            scalars[match[1]] = (bool(match[2]), shell_reader.derived(match[3], word))
    return scalars, arrays, literals


def record(table, stage, certain):
    """Write what this stage assigns into `table` (#2425, #2489), each name's
    candidates as `_update` keeps them, as sure as `certain`.

    A scalar's text resolves through the table as it is assigned (`valued`,
    bash's rule for `T=$U`), else is held as written; `T+=x` appends to each
    candidate, and on a name not held it holds `x` alone, the known suffix: a
    price. A `certain` append that could only build a text over `_LONGEST`
    leaves the name unread. An array literal is one candidate word-list, and
    `+=` extends each candidate. A literal `for NAME in WORDS` header gives
    NAME every word, each resolved as a value is: a whole `${a[@]}` the
    words of each candidate, `$@` or a lone `$(...)` none at all. With none
    left NAME keeps its candidates; where no word is written out, the loop
    may not run, so the words join them, as an uncertain assignment's do.
    """
    scalars, arrays = assigned(stage)
    for name, (append, text) in scalars.items():
        new = valued(text, table) or [text]
        if append:
            new = [shell_reader.derived(head + tail, head, tail)
                   for head in table.scalars.get(name) or [""] for tail in new
                   if len(head) + len(tail) <= _LONGEST]
        _update(table.scalars, name, new, certain, "")
    for name, (append, words) in arrays.items():
        lists = [held + words for held in table.arrays.get(name) or [[]]] if append else [words]
        _update(table.arrays, name, lists, certain, [])
    variable, words = _for_parts(stage)
    argv = command(stage.argv)
    if variable and stage.argv[:len(stage.argv) - len(argv)][-1:] == ["for"]:
        texts, written = _looped(words, table)
        if texts:
            _update(table.scalars, variable, texts, certain and written, "")


def _looped(words, table):
    """The texts a `for` header's words give its NAME, and whether one of the
    words is written out, with no `$` or `$(...)`: bash surely runs the loop."""
    texts, written = [], False
    for word in words:
        element = _ELEMENT.match(str(word))
        if element and element[2] in ("@", "*"):
            texts += [part for parts in table.arrays.get(element[1], []) for part in parts]
        elif not (_SPLAT.match(str(word)) or str(word) in getattr(word, "markers", {})):
            texts += valued(word, table) or [shell_reader.derived(str(word), word)]
            written = written or "$" not in word and not shell_reader.has_substitution(word)
    return [text for text in texts if text], written


def _update(candidates, name, new, certain, empty):
    """A name's candidates after it is assigned `new`: replaced where `certain`;
    else added to, and followed by `empty`, the "maybe unset" candidate, where
    the name was not held. The last `_CANDIDATES` are kept; with none, the
    name is unread."""
    held = candidates.get(name)
    if not certain:
        new = (held or []) + new + ([] if held is not None else [empty])
    kept = _deduped(new)[-_CANDIDATES:]
    if kept:
        candidates[name] = kept
    else:
        candidates.pop(name, None)


def emptied(table, name, certain):
    """A command that empties `name` -- `unset`, `read`, a bare `local`: its
    candidates go where `certain`; else, where the table holds the name, it
    gains the "maybe unset" candidate, `""` or `[]`."""
    for candidates, empty in ((table.scalars, ""), (table.arrays, [])):
        if certain:
            candidates.pop(name, None)
        elif name in candidates:
            candidates[name] = _deduped(candidates[name] + [empty])[-_CANDIDATES:]


def _deduped(candidates):
    """`candidates` without a repeat, the first of each kept; a word-list is
    compared by its words."""
    unique: dict[object, object] = {}
    for candidate in candidates:
        unique.setdefault(tuple(candidate) if isinstance(candidate, list) else candidate,
                          candidate)
    return list(unique.values())


def valued(word, table):
    """The candidate texts ONE word resolves to through `table`, or [] where
    nothing in it does (#2425, #2489; #2581's `./cuda_$X.run`, `${X:-*}`, `${a[0]}`).

    Each `$T`, `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}` or `${T=d}`, whole or
    embedded, stands for a held name's candidates, left to right; the texts
    are the first `_CANDIDATES` of their product, less any over `_LONGEST`.
    A name that holds an array and no scalar stands for word 0 of each
    candidate, and is unset where one has none. A default stands where its
    name is unset, and for a held empty value under `:-` or `:=`, as bash
    reads one; under `-` or `=` a held empty value stands for itself AND the
    default, as it may be the mark of a name left unset: the set-but-null
    twin (`X=; sh "${X-d}"`, where bash gives `""`) over-reports, a price.
    An unheld name with no default, and every other
    `${T...}` form (`${T:+d}`, `${T#x}`, `${T%x}`, `${T//a/b}`, `${T:0:3}`,
    `${#T}`, `${!T}`), stays as written; a lifted `$(...)` holds no `$` to
    match. A whole `${a[N]}` is word N of each candidate that has one, and
    `${a[@]}` or `${a[*]}` each candidate joined by blanks (`valued_argvs`
    splices them). The texts carry the markers of the word and of its values,
    and are otherwise plain: the caller decides what kind of word each is.
    """
    text = str(word)
    if element := _ELEMENT.match(text):
        return _element(element[1], element[2], table)
    factors: list[list[str]] = []
    start = 0
    for match in _VALUE.finditer(text):
        if held := _held(match, table):
            factors += [[text[start:match.start()]], held]
            start = match.end()
    if not factors:
        return []
    factors.append([text[start:]])
    combinations = itertools.islice(itertools.product(*factors), _CANDIDATES)
    return [shell_reader.derived("".join(parts), word, *parts) for parts in combinations
            if sum(map(len, parts)) <= _LONGEST]


def _held(match, table):
    """What one `_VALUE` reference stands for, or [] where it stays as written:
    each candidate, `None` where the name is unset -- not held, or an array
    candidate without word 0 -- and the default where it stands."""
    name, operator, default = match[1] or match[2], match[3], match[4]
    held: list[str | None]
    if name in table.scalars:
        held = list(table.scalars[name])
    elif name in table.arrays:
        held = [words[0] if words else None for words in table.arrays[name]]
    else:
        held = [None]
    texts: list[str] = []
    for text in held:
        if text is None:
            texts += [default] if operator else []
        elif text or not operator:
            texts.append(text)
        else:
            texts += [default] if ":" in operator else ["", default]
    return _deduped(texts)


def _element(name, key, table):
    """A whole `${name[key]}` through `table`: word `key` of each candidate that
    has one, or for `@` and `*` each candidate joined by blanks."""
    candidates = table.arrays.get(name)
    if candidates is None:
        return []
    if key in ("@", "*"):
        return _deduped([shell_reader.derived(" ".join(words), *words) for words in candidates])
    # A subscript is arithmetic: a leading 0 is octal, so it, and a long one, stay unread.
    if len(key) > 9 or key.startswith("0") and key != "0":
        return []
    return _deduped([words[int(key)] for words in candidates if int(key) < len(words)])


def valued_argvs(argv, table):
    """The argvs `use()` must weigh for one stage's words (#2425, #2489, #2581):
    `[argv]` where no word resolves, else the first `_CANDIDATES` of the
    product of each word's `valued` texts (or the word itself), a whole
    `${a[@]}` or `${a[*]}` SPLICED as each candidate's words. An empty text is
    dropped, as bash drops an unquoted empty expansion, and an argv left empty
    is not made. A text with `*`, `?` or `[`, or from a word bash expands as a
    pattern (`{$T,x}`), is a `live_pattern`, as bash globs an unquoted `$p`
    and a literal's words.
    """
    choices: list[list[list[str]]] = []
    resolved = False
    for word in argv:
        element = _ELEMENT.match(str(word))
        if element and element[2] in ("@", "*") and element[1] in table.arrays:
            choices.append([[_as_word(text, word) for text in words if text]
                            for words in table.arrays[element[1]]])
        elif texts := valued(word, table):
            choices.append([[_as_word(text, word)] if text else [] for text in texts])
        else:
            choices.append([[word]])
            continue
        resolved = True
    if not resolved:
        return [argv]
    combinations = itertools.islice(itertools.product(*choices), _CANDIDATES)
    made = ([part for words in combination for part in words] for combination in combinations)
    return [words for words in made if words]


def _as_word(text, word):
    """A substituted text as an argv word: a live pattern where bash globs it."""
    if _GLOB.search(text) or getattr(word, "lead", None) is not None:
        return live_pattern(text)
    return text
