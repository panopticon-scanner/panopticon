#!/usr/bin/env python3
"""What a word is worth, read through the step's value table.

Split out of `scripts/workflow_values.py` at that module's size (699 of its
700 lines, with the lane's values fixes still to come), byte for byte: the
reading half of the table -- `valued`, the candidate texts a word resolves to
through the table, and `valued_argvs`, an argv's candidate argvs -- with the
helpers only they share (`_held`, `_element`, `_joined`, `_unknown`,
`_as_word`, `_glued`, `_lists`, `_deduped`), the reference spellings they
match (`_VALUE`, `_ELEMENT`, `_REFERENCES`, `_TAIL`, `_GLOB`) and the two
bounds (`_CANDIDATES`, `_LONGEST`). The writing half -- `record` and what it
calls -- stays in `workflow_values`, which imports every name back under its
own, so nothing that read `workflow_values.valued` moved; this module imports
nothing from it, so the layers still run one way.

Stdlib only, like everything under it.
"""
import itertools
import re

import shell_reader
from workflow_operands import live_pattern


_VALUE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)"
                    r"|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=])([^{}]*))?\})")
_ELEMENT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\[([0-9]+|[@*])\]\}$")
_REFERENCES = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]|\{[^{}]*\})")
_TAIL = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)$")
_GLOB = re.compile(r"[*?\[]|[@+!]\(")
# A name holds at most `_CANDIDATES` candidates, and past them its stand-in
# alone, the guard's reading without the table; a word resolves to the first
# `_CANDIDATES` of its product; and no text built is longer than `_LONGEST`: a
# value doubling itself (`T=$T$T`, line after line) in a TARGET repo's `run:`
# block would grow without bound. Each bound can lose a candidate: a price.
_CANDIDATES = 8
_LONGEST = 4096


def _deduped(candidates):
    """`candidates` without a repeat, the first of each kept; a word-list is
    compared by its words."""
    unique: dict[object, object] = {}
    for candidate in candidates:
        unique.setdefault(tuple(candidate) if isinstance(candidate, list) else candidate,
                          candidate)
    return list(unique.values())


def _lists(table, name):
    """Every word-list `name` may hold: its array candidates, and each scalar
    candidate as a one-word list, the one variable bash keeps."""
    return table.arrays.get(name, []) + [[text] for text in table.scalars.get(name, [])]


def _glued(head, tail):
    """`head` then `tail`, a `$NAME` ending `head` braced where `tail` would
    lengthen the name: the stand-in `$T` and `x` make `${T}x`, not `$Tx`."""
    if re.match(r"[A-Za-z0-9_]", tail):
        head = _TAIL.sub(r"${\1}", head)
    return head + tail


def valued(word, table):
    """The candidate texts ONE word resolves to through `table`, or [] where
    nothing in it does (#2425, #2489; #2581's `./cuda_$X.run`, `${X:-*}`, `${a[0]}`).

    Each `$T`, `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}` or `${T=d}`, whole or
    embedded, stands for a held name's candidates, left to right; the texts
    are the first `_CANDIDATES` of their product, less any over `_LONGEST`.
    A name stands for every scalar candidate and word 0 of every word-list,
    and is unset in a word-list without one. A default stands where its name
    is unset, and for a held empty value under `:-` or `:=`, as bash reads
    one; under `-` or `=` a held empty value stands for itself AND the
    default, as it may be the mark of a name left unset: the set-but-null
    twin (`X=; sh "${X-d}"`, where bash gives `""`) over-reports, a price. A
    value the table cannot see -- the stand-in, a text of references alone --
    may be null, so every default stands beside it. An unheld name with no
    default, and every other `${T...}` form (`${T:+d}`, `${T#x}`, `${T%x}`,
    `${T//a/b}`, `${T:0:3}`, `${#T}`, `${!T}`), stays as written; a lifted
    `$(...)` holds no `$` to match. A whole `${a[N]}` is word N of each
    word-list that has one, and `${a[@]}` or `${a[*]}` each joined by blanks
    (`valued_argvs` splices them), a scalar candidate as one word where the
    name holds an array. The texts carry the markers of the word and of its
    values, and are otherwise plain: the caller decides what kind of word
    each is."""
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
    return [shell_reader.derived(_joined(parts), word, *parts) for parts in combinations
            if sum(map(len, parts)) <= _LONGEST]


def _joined(parts):
    """`parts` side by side, each `_glued` to the text before it."""
    text = ""
    for part in parts:
        text = _glued(text, part)
    return text


def _held(match, table):
    """What one `_VALUE` reference stands for, or [] where it stays as written:
    each candidate, `None` where the name is unset -- not held, or a word-list
    without word 0 -- and the default where it stands."""
    name, operator, default = match[1] or match[2], match[3], match[4]
    held: list[str | None] = [None]
    if name in table.scalars or name in table.arrays:
        held = [*table.scalars.get(name, []),
                *(words[0] if words else None for words in table.arrays.get(name, []))]
    texts: list[str] = []
    for text in held:
        if text is None:
            texts += [default] if operator else []
        elif not operator:
            texts.append(text)
        elif not text:
            texts += [default] if ":" in operator else ["", default]
        else:
            texts += [text, default] if _unknown(text) else [text]
    return _deduped(texts)


def _unknown(text):
    """Whether `text` is references and lifted `$(...)`s alone -- the stand-in,
    or a `$U` held as written: a value the table cannot see, which may be
    null."""
    rest = str(text)
    for key in getattr(text, "markers", {}):
        rest = rest.replace(key, "")
    return not _REFERENCES.sub("", rest)


def _element(name, key, table):
    """A whole `${name[key]}` through `table`, where `name` holds an array: word
    `key` of each word-list that has one, or for `@` and `*` each word-list
    joined by blanks. A candidate that cannot say its words past the first --
    the stand-in a maybe `read -ra`, `mapfile`, `arr[1]=$(...)` or `eval`
    gives, or a literal's lone `$(...)` -- has no word past 0, so beside
    `arr=(x y)` a `${arr[1]}` reads `y` alone, without the stand-in (a limit:
    the caller weighs the use as written first)."""
    if name not in table.arrays:
        return []
    candidates = _lists(table, name)
    if key in ("@", "*"):
        return _deduped([shell_reader.derived(" ".join(words), *words) for words in candidates])
    # A subscript is arithmetic: a leading 0 is octal, so it, and a long one, stay unread.
    if len(key) > 9 or key.startswith("0") and key != "0":
        return []
    return _deduped([words[int(key)] for words in candidates if int(key) < len(words)])


def valued_argvs(argv, table):
    """The argvs `use()` must weigh BESIDE the stage's words as written
    (#2425, #2489, #2581): `[argv]` where no word resolves, else the first
    `_CANDIDATES` of the product of each word's `valued` texts (or the word
    itself), a whole `${a[@]}` or `${a[*]}` SPLICED as each word-list's words.
    An empty text is dropped, as bash drops an unquoted empty expansion, and
    an argv left empty is not made. A text with `*`, `?`, `[` or an extglob
    group outside its references, or from a word bash expands as a pattern
    (`{$T,x}`), is a `live_pattern`, as bash globs an unquoted `$p` and a
    literal's words."""
    choices: list[list[list[str]]] = []
    resolved = False
    for word in argv:
        element = _ELEMENT.match(str(word))
        if element and element[2] in ("@", "*") and element[1] in table.arrays:
            choices.append([[_as_word(text, word) for text in words if text]
                            for words in _lists(table, element[1])])
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
    """A substituted text as an argv word: a live pattern where bash globs its
    text outside its references (a held `${OTHER##*/}` is a plain word)."""
    if _GLOB.search(_REFERENCES.sub("", text)) or getattr(word, "lead", None) is not None:
        return live_pattern(text)
    return text
