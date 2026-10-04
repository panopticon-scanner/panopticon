#!/usr/bin/env python3
r"""The step's own literal values, read as bounded value facts (#2425, #2489).

The guard binds a download to its later uses by NAME, and a step that keeps
that name in a variable it assigns itself hid the use: `T=cuda_1.run; sh
"$T"`, `p=./cuda_*.run; sh $p`, `declare -a a=(sh tool); "${a[@]}"`, and the
#2581 rows `./cuda_$X.run`, `${X:-*}` and `${a[0]}`. This is the table that
reads them: `Values` holds, per name, the CANDIDATE texts a scalar may hold
and the CANDIDATE word-lists of the array literals it may hold -- views of
ONE variable, as bash keeps one per name: `$a` reads every scalar candidate
and word 0 of every word-list, and `${a[@]}` every word-list and each scalar
candidate as one word. Split out of `scripts/workflow_uses.py` at that
module's size, it imports nothing from it, and `workflow_uses` re-exports
`Values`, `assigned`, `record`, `valued` and `valued_argvs` beside
`static_values`, the table live at one statement.

    who assigns     a statement that only assigns, a declaration's operands
                    (`export T=x`, `declare -a a=(sh tool)`), either behind
                    `command`, `builtin` or `time`, the words a `coproc`'s
                    `{ }` or `( )` opens with (`coproc { T=x; }`, which the
                    coprocess assigns), and a literal `for NAME` header --
                    never a PREFIX assignment (`T=x sh "$T"`), which bash
                    makes after it expands the command's words and which
                    does not outlive the command
    held, emptied   a value is held wherever a statement assigns it, and
                    replaced or emptied only where the caller says the shell
                    surely runs the statement; one it may not run adds its
                    value to the name's candidates, and a name it may leave
                    unset gains the empty candidate, `""` or `[]`, over
                    which a default stands (beside `""` under `-` and `=`)
    unseen          a value the table cannot see -- `read` (`REPLY` without
                    a name), `printf -v`, `getopts` (its `OPTARG` and
                    `OPTIND` too), `mapfile`, `readarray` and `select`, bare
                    or behind `builtin`, an element's assignment or unset
                    (`a[1]=x`, `declare a[1]=x`, `unset 'a[1]'`), a `for`
                    header's `"$@"` or `$(...)`, a subscripted literal, a
                    literal left open at its line's end (`a=(`), a
                    declaration with `-l`, `-u`, `-i`, `-A` or `-n`, more
                    than `_CANDIDATES` candidates -- is the name's own
                    reference `$NAME`, the STAND-IN: the reading the guard
                    makes without the table, never a claim, beside which a
                    default stands too; after `eval`, `source` or `.`, or a
                    name taken from a value (`read "$n"`, `export "$k=$v"`,
                    `export $(cat .env)`), every held name gains its
                    stand-in
    resolved        in the words of the stage that USES a value
                    (`valued_argvs`), so a relative value is read from the
                    directory of its use, bash's rule, and a text bash globs
                    is a live pattern for `covers`

What `valued_argvs` leaves to its caller: weighing the stage's words AS
WRITTEN too, and first -- the guard names a download by the words its fetch
wrote (`-o "$TMP"`), which only the use as written still spells; re-reading
each argv it makes with `shell_reader.command()` before asking `use()` what
it runs; and splitting on its blanks a word that is ONE whole reference
(`$T`, `${T}`) whose value holds blanks, as bash splits an unquoted
expansion -- the quoted twin over-reports, as it does for a pattern; a word
with other text around a reference keeps its own blanks (`sh -c 'sh "$T"'`).
It drops the empty words itself.

The prices. Quoting: the reader's words have lost their quotes, so `sh "$p"`
after `p=./cuda_*.run` reads as the glob, a single-quoted `'$T'`, which bash
does not expand, as `"$T"`, the quoted twin `"" sh x` of an empty `$SUDO`
dropped from `$SUDO sh x` as `sh x`, a literal's quoted word
(`a=('./cuda_*.run')`) as live, a quoted brace word in a literal as expanded,
and a quoted `"${a[*]}"`, one word to bash, as spliced; a literal `@(x)`
value is live too. The shell's own settings are not read: the default `IFS`
and globbing are assumed, so a step's `IFS=`, `IFS=$'\n'` or `set -f`
over-reports a split or a pattern, and `IFS=:` misses one. Null: the empty
candidate cannot say whether the name was unset or set empty, so a `-` or
`=` default stands beside it and the set-but-null twin (`X=; sh "${X-d}"`,
where bash gives `""`) over-reports.
Literals: one folded behind a declaration is re-split on blanks, which
shifts the words after a quoted blank too (`declare -a a=("my file" x)`
reads `${a[1]}` as `file`; a reader-lane follow-up would keep a literal's
words on its token); a subshell's empty prefix assignment `( T= sh tool )`
and its quoted value `( T='(x y)' )` read as the literal `T=(...)`, and both
REPLACE the outer value; and a `NAME=text` word inside an open unfolded
literal is read as a scalar the statement may assign as well, which
over-reports where it was an element, and a `NAME[N]=text` one gives NAME
its stand-in. A statement that only assigns an array literal is read as
running its words, as main reads it, and the table resolves those words too:
`X=_1; a=(cuda$X.run)` alone over-reports.
Walks: after a loop that ran to its end bash holds its last
word and the table every word; a literal's glob is matched at the use, not
where bash matched it; a header that may not run keeps the old candidates
beside its stand-in. Caps: a name with more than `_CANDIDATES` candidates
holds its stand-in alone, a word resolves to the first `_CANDIDATES` of its
product, and a text over `_LONGEST` is dropped, both of which can lose a
candidate; a brace word the table cannot expand -- past 64 words, or with a
reference inside a group (`{a,$X}`) or a braced one beside it (`{a,b}${X}`)
-- gives its name the stand-in, a limit, not a price. Not read: the
assignment `${T:=d}` makes, an operator expansion's value (`NAME=${URL##*/}`
holds its own text, a plain word), an attribute an earlier declaration set
rewriting a later assignment, a call's own assignments, a name bash sets
itself (`cd`'s `PWD`, `BASH_REMATCH`, the numbers of a redirection's `{fd}`,
`wait -p` and `coproc`), held only where the step assigned it too, and
arithmetic -- `let T=5`, `((T++))` and an arithmetic `for`'s updates are not
read, and `((T=x+1))` is read as its text beside the old value -- so a name
built from a number the arithmetic changed holds the old number
(`i=0; ((i++)); T=cuda_$i.run` holds `cuda_0.run`): a download named by the
new number is missed, one named by the old over-reports.

Stdlib only, like everything under it.
"""
from dataclasses import dataclass, field
import itertools
import os
import re

import shell_reader
from shell_reader import _DECLARATIONS, command
from workflow_operands import _brace_patterns, live_pattern


# `_LITERAL` is an assignment word (`NAME=text`, `NAME+=text`), `_ARRAY` one
# holding a literal the reader folded in (`NAME=(words)`), `_OPENER` an empty
# one, which an UNFOLDED literal's words follow, `_SUBSCRIPT` a literal's
# `[key]=word`, `_SUBSCRIPTED` an element's assignment (`a[1]=x`, `a[$i]+=x`);
# `_VALUE` a reference -- `$T`, `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}`,
# `${T=d}`; `_ELEMENT` a whole `${a[0]}`, `${a[@]}` or `${a[*]}`; `_SPLAT` a
# whole `$@` or `$*`, any number of words; `_REFERENCES` any reference at all,
# `_TAIL` an unbraced one ending a text, `_NAME` a name; `_GLOB` what bash
# globs a value by, an extglob group too.
_LITERAL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.S)
_ARRAY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=\((.*)\)$", re.S)
_OPENER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=$")
_SUBSCRIPT = re.compile(r"^\[[^]]*\]\+?=")
_SUBSCRIPTED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[.*\]\+?=", re.S)
_VALUE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)"
                    r"|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=])([^{}]*))?\})")
_ELEMENT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\[([0-9]+|[@*])\]\}$")
_SPLAT = re.compile(r"^\$(?:[@*]|\{[@*]\})$")
_REFERENCES = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]|\{[^{}]*\})")
_TAIL = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GLOB = re.compile(r"[*?\[]|[@+!]\(")
# The attributes that rewrite the value a declaration assigns: case, integer,
# associative keys, and -- not behind `export`, where it un-exports -- a name
# reference.
_REWRITING = frozenset("luiA")
# The options that take an argument: `read`'s (`-p prompt`; `-a` names an
# array), and `mapfile`'s and `readarray`'s (`-u 3`).
_READING = frozenset("adinNptu")
_MAPPING = frozenset("dnOsuCc")
# A name holds at most `_CANDIDATES` candidates, and past them its stand-in
# alone, the guard's reading without the table; a word resolves to the first
# `_CANDIDATES` of its product; and no text built is longer than `_LONGEST`: a
# value doubling itself (`T=$T$T`, line after line) in a TARGET repo's `run:`
# block would grow without bound. Each bound can lose a candidate: a price.
_CANDIDATES = 8
_LONGEST = 4096


@dataclass
class Values:
    """The step's literal values at one statement: per name, the CANDIDATE texts
    a scalar may hold -- the reader's words, quotes gone, a lifted `$(...)` kept
    as its marker -- and the CANDIDATE word-lists of its array literals."""

    scalars: dict[str, list[str]] = field(default_factory=dict)
    arrays: dict[str, list[list[str]]] = field(default_factory=dict)

    def copy(self):
        """A copy whose lists are its own (`static_values`' `start`), made by hand, as
        `copy.deepcopy` cannot rebuild a marked text (`shell_reader.derived`'s)."""
        return Values({name: list(texts) for name, texts in self.scalars.items()},
                      {name: [list(words) for words in lists]
                       for name, lists in self.arrays.items()})


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
    (`export T=x`, `declare -a a=(sh tool)`), behind `command`, `builtin` or
    `time` as without, and the words after `coproc [NAME] {` or `(`, read as
    a lead `{`'s (the coprocess is a child: the caller weighs that, and a
    NAME before `(` may be a command, whose words then over-report); not a
    bare `export T`, nor a PREFIX assignment (`T=x sh "$T"`: bash expands the
    command's words first, and the value does not outlive the command), nor
    one behind any other wrapper (`env T=x`). A text is `derived`: a lifted
    `$(...)` stays its marker. A literal is read only where the stage opened
    a group, as the reader counts its parentheses -- folded into its word
    behind a declaration, else handed UNFOLDED (`["a=", "sh", "tool"]`,
    #2348): an empty `NAME=` and the words up to the next one while groups
    remain -- and its brace words are expanded, as bash expands them before
    it assigns (`a=({x,y}.run)` holds `x.run y.run`). A name set to
    a value the table cannot see -- a subscripted literal (`a=([1]=x)`), a
    literal still open where the stage ends (its later lines' words are not
    gathered), an element's assignment (`a[1]=x`, `declare a[1]=x`), a
    declaration with `-l`, `-u`, `-i`, `-A` or, not behind `export`, `-n` --
    and a scalar the statement only may assign are `record`'s. The prices: a
    folded literal is re-split on blanks; a quoted brace word is expanded; a
    subshell's empty prefix assignment `( T= sh tool )` and its quoted value
    `( T='(x y)' )` read as literals; and a `NAME=text` element of an open
    unfolded literal is read as a scalar too, a `NAME[N]=text` one as an
    element's assignment. A `for` header is `record`'s.
    """
    scalars, arrays = _assignments(stage)[:2]
    return scalars, arrays


def _literals(stage):
    """How many array literals this stage assigns. The reader counts each one's
    parentheses as a group; to bash they are the rest of the literal's word."""
    return _assignments(stage)[2]


def _assignments(stage):
    """`assigned`'s reading, the number of array literals it read, the scalars
    the statement only may assign, and the names it sets to a value the table
    cannot see."""
    scalars: dict[str, tuple[bool, str]] = {}
    arrays: dict[str, tuple[bool, list[str]]] = {}
    maybe: dict[str, tuple[bool, str]] = {}
    unseen: set[str] = set()
    if any(word not in ("command", "time") for word in shell_reader.wrapper_words(stage.argv)):
        return scalars, arrays, 0, maybe, unseen
    argv = command(stage.argv)
    # A coprocess's `{ }` or `( )` (a `(` is a group no literal opened): its words
    # read as a lead `{`'s, past `coproc` and a NAME (`coproc W {`, `coproc W (`).
    if argv[:1] == ["coproc"] and ("{" in argv[1:3] or stage.group_open > sum(
            1 for word in argv if _OPENER.match(str(word)))):
        named = argv[2:3] == ["{"] or argv[1:2] != ["{"] and argv[2:] and _NAME.match(argv[1])
        stage = stage._replace(argv=argv[2 if named else 1:])
        argv = command(stage.argv)
    if argv[:1] == ["builtin"] and argv[1:2] and os.path.basename(argv[1]) in _DECLARATIONS:
        argv = argv[1:]
    builtin = os.path.basename(argv[0]) if argv else ""
    rewriting = False
    if builtin in _DECLARATIONS:
        words = list(argv[1:])
        letters = {letter for word in words if str(word).startswith("-")
                   for letter in str(word)[1:]}
        rewriting = bool(letters & _REWRITING) or "n" in letters and builtin != "export"
    else:
        before = stage.argv[:len(stage.argv) - len(argv)]
        if argv and not (stage.group_open and any(_OPENER.match(str(word)) for word in before)):
            return scalars, arrays, 0, maybe, unseen      # a prefix assignment, or none at all
        words = list(stage.argv)
    literals, unfolded, opened = 0, None, ""
    for word in words:
        room = literals < stage.group_open
        folded = _ARRAY.match(str(word)) if room else None
        match = folded or _LITERAL.match(str(word))
        element = _SUBSCRIPTED.match(str(word))
        if match and (folded or room and not match[3]):
            literals += 1
            braced = [_braced(part) for part in match[3].split()] if folded else []
            parts = [shell_reader.derived(text, word) for texts in braced for text in texts or []]
            arrays[match[1]] = (bool(match[2]), parts)
            unfolded, opened = (None, "") if folded else (parts, match[1])
            if None in braced or folded and any(map(_SUBSCRIPT.match, match[3].split())):
                unseen.add(match[1])
        elif unfolded is not None:
            texts = _braced(str(word))
            if texts is None or _SUBSCRIPT.match(str(word)):
                unseen.add(opened)
            unfolded.extend(shell_reader.derived(text, word) for text in texts or [])
            if match and match[3]:
                maybe[match[1]] = (bool(match[2]), shell_reader.derived(match[3], word))
            elif element:
                unseen.add(element[1])
        elif match:
            scalars[match[1]] = (bool(match[2]), shell_reader.derived(match[3], word))
        elif element or rewriting and _NAME.match(str(word)):
            unseen.add(element[1] if element else str(word))
    if unfolded is not None and stage.group_close < literals:
        unseen.add(opened)              # a literal its later lines continue
    if rewriting:
        unseen.update(scalars, arrays)
    for name in unseen:
        scalars.pop(name, None)
        arrays.pop(name, None)
    return scalars, arrays, literals, maybe, unseen


def _braced(text):
    """The words bash makes of `text`'s brace groups (`{cuda_1,x}.run`), or
    `text` alone where it has none -- or None where it has one the table
    cannot expand: past 64 words, a reference inside a group (`{a,$X}`) or a
    braced one beside it (`{a,b}${X}`)."""
    words = _brace_patterns(text)
    if words is None and re.search(r"(?<!\$)\{[^{}]*(?:,|\.\.)[^{}]*\}", text):
        return None
    return words or [text]


def record(table, stage, certain):
    """Write what this stage assigns into `table` (#2425, #2489), each name's
    candidates as `_update` keeps them, as sure as `certain`.

    A scalar's text resolves through the table as it is assigned (`valued`,
    bash's rule for `T=$U`), else is held as written; `T+=x` appends to each
    candidate, and on a name not held it holds `x` alone, the known suffix: a
    price. On a name that holds an array it is element 0 (`arr=s` is
    `arr[0]=s`). An array literal is one candidate word-list -- a certain one
    ends the name's scalar candidates -- and `+=` extends each candidate, a
    scalar one as a one-word list. A scalar the statement only may assign is
    added; a name set to a value the table cannot see holds its stand-in
    (`emptied`). A literal `for NAME [in WORDS]` header gives NAME every word,
    each resolved as a value is: a brace word expanded, a whole `${a[@]}` the
    words of each candidate, and `$@`, `$*`, a lone `$(...)` or an array the
    table does not hold the stand-in; without `in` it walks `"$@"`. Where no
    word is written out, the loop may not run, so the words join the old
    candidates, as an uncertain assignment's do. `printf -v NAME`, `getopts
    OPTSTRING NAME`, `mapfile` and `readarray` are read as `read NAME`, a
    `read` or `unset` behind `builtin` as the bare one (`_unread`), and after
    `eval`, `source` or `.`, or a name taken from a value (`read "$n"`,
    `export "$k=$v"`), every held name gains its stand-in, kept beside its
    old candidates even where the statement is certain.
    """
    scalars, arrays, _count, maybe, unseen = _assignments(stage)
    for name, (append, text) in scalars.items():
        _assign(table, name, append, text, certain)
    for name, (append, text) in maybe.items():
        _assign(table, name, append, text, False)
    for name, (append, words) in arrays.items():
        lists = [old + words for old in _lists(table, name) or [[]]] if append else [words]
        if certain:
            table.scalars.pop(name, None)       # a literal makes the name an array
        _update(table, name, lists, certain, True)
    for name in unseen:
        emptied(table, name, certain, True)
    argv = command(stage.argv)
    variable, operands = _header(stage, argv)
    if variable:
        texts, written, unknown = _looped(operands, table)
        if unknown:
            texts.append("$" + variable)
        _update(table, variable, texts, certain and written)
    _unread(table, argv, certain)


def _assign(table, name, append, text, certain):
    """`NAME=text`, or `NAME+=text`, as bash assigns it: to the scalar
    candidates, and to word 0 of each word-list where the name holds an array."""
    new = valued(text, table) or [text]
    if name in table.arrays:
        scalar = name in table.scalars
        lists = [[shell_reader.derived(_glued(head, tail), head, tail)] + words[1:]
                 for words in table.arrays[name]
                 for head in ((words[:1] or [""]) if append else [""])
                 for tail in new if len(head) + len(tail) <= _LONGEST]
        _update(table, name, lists, certain, True)
        if not scalar or name not in table.arrays:
            return              # word 0 written, or the name is past the table
    if append:
        new = [shell_reader.derived(_glued(head, tail), head, tail)
               for head in table.scalars.get(name) or [""] for tail in new
               if len(head) + len(tail) <= _LONGEST]
    _update(table, name, new, certain)


def _header(stage, argv):
    """A `for NAME [in WORDS]` header where the stage's command would stand
    (`echo for T in x` is none): NAME and the words it walks -- `"$@"`
    without `in` -- or (None, [])."""
    if stage.argv[:len(stage.argv) - len(argv)][-1:] != ["for"]:
        return None, []
    variable, operands = _for_parts(stage)
    if variable is None and len(argv) == 1 and _NAME.match(str(argv[0])):
        return str(argv[0]), ["$@"]
    return variable, operands


def _looped(words, table):
    """The texts a `for` header's words give its NAME; whether one of the words
    is written out, with no `$` or `$(...)`, so bash surely runs the loop; and
    whether one is a value the table cannot see -- `$@`, `$*`, a lone
    `$(...)`, an array the table does not hold, a brace word `_braced` cannot
    expand, which is not written out either."""
    texts, written, unknown = [], False, False
    for word in words:
        element = _ELEMENT.match(str(word))
        if element and element[2] in ("@", "*"):
            if element[1] in table.arrays:
                texts += [part for parts in _lists(table, element[1]) for part in parts]
            else:
                unknown = True
        elif _SPLAT.match(str(word)) or str(word) in getattr(word, "markers", {}):
            unknown = True
        else:
            held = valued(word, table) or [shell_reader.derived(str(word), word)]
            if getattr(word, "lead", None) is not None:     # bash expands its braces first
                braced = [_braced(str(part)) for part in held]
                if None in braced:
                    unknown = True
                    continue
                held = [shell_reader.derived(text, part)
                        for part, parts in zip(held, braced) for text in parts]
            texts += held
            written = written or "$" not in word and not shell_reader.has_substitution(word)
    return [text for text in texts if text], written, unknown


def _unread(table, argv, certain):
    """The commands that set a name the reader never reads the value of:
    `printf -v NAME`, `getopts OPTSTRING NAME` with its `OPTARG` and `OPTIND`,
    `select NAME` with its `REPLY`, `mapfile` and `readarray`, as `read NAME`
    does -- `REPLY` or `MAPFILE` where they name none; an element's
    assignment the reader takes for a command (`a[${#a[@]}]=x`); `eval`,
    `source` and `.`, and a command taking a name it sets from a value
    (`_dynamic`), which may set any name at all; and, behind `builtin`, the
    `read` and `unset` `_cleared` reads bare -- for the table alone, as the
    bindings stay `_cleared`'s."""
    builtin = argv[:1] == ["builtin"]
    argv = argv[1:] if builtin else argv
    head = os.path.basename(str(argv[0])) if argv else ""
    named = _naming(head, argv)
    if head in ("eval", "source", ".") or any(_dynamic(word) for word in named):
        for name in list(dict.fromkeys([*table.scalars, *table.arrays])):
            _update(table, name, ["$" + name], False)
    names: list[str] = []
    if head in ("printf", "getopts", "select", "mapfile", "readarray"):
        names = [str(word) for word in named]
        names += {"getopts": ["OPTARG", "OPTIND"], "select": ["REPLY"]}.get(head, [])
    elif argv and (element := _SUBSCRIPTED.match(str(argv[0]))):
        names = [element[1]]
    elif builtin and (head == "read" or head == "unset" and "-f" not in argv):
        for word in argv[1:]:
            if not str(word).startswith("-"):
                emptied(table, str(word), certain, head == "read")
    if not named and head in ("read", "mapfile", "readarray"):     # bash's default name
        names = ["REPLY" if head == "read" else "MAPFILE"]
    for name in names:
        emptied(table, name, certain, True)


def _naming(head, argv):
    """The words of command `head` that name what it sets, or []: `read`'s
    and `mapfile`'s (`_operands`), `unset`'s but not `unset -f`'s, a
    declaration's operands, `printf -v NAME` (`-vNAME` too), `getopts
    OPTSTRING NAME` and `select NAME`."""
    if head == "read":
        return _operands(argv, _READING, "a")
    if head in ("mapfile", "readarray"):
        return _operands(argv, _MAPPING)
    if head == "printf" and argv[1:] and str(argv[1]).startswith("-v"):
        return _operands(argv, "v", "v")[:1]
    if head in ("getopts", "select"):
        return argv[2:3] if head == "getopts" else argv[1:2]
    if head in _DECLARATIONS or head == "unset" and "-f" not in argv:
        return [word for word in argv[1:] if not str(word).startswith(("-", "+"))]
    return []


def _operands(argv, takes, naming=""):
    """The words after a command's options -- an option of `takes` takes the
    next word unless joined (`-u 3`, `-u3`) -- and the argument of an option
    of `naming`, which names what it sets (`read -a NAME`)."""
    words = list(argv[1:])
    at = 0
    named: list[str] = []
    while at < len(words) and str(words[at]).startswith("-") and words[at] != "-":
        option, at = str(words[at])[1:], at + 1
        if option == "-":
            break
        for place, letter in enumerate(option, 1):
            if letter in takes:
                if place < len(option):         # joined to its option
                    argument = [shell_reader.derived(option[place:], words[at - 1])]
                else:
                    argument, at = words[at:at + 1], at + 1
                named += argument if letter in naming else []
                break
    return named + words[at:]


def _dynamic(word):
    """Whether a word naming what a command sets takes the name from a value:
    a `$` or a lifted `$(...)` before its `=` or subscript (`"$n"`,
    `"$k=$v"`, `$(cat .env)`), which may name any variable at all."""
    head = re.split(r"[=\[]", str(word), maxsplit=1)[0]
    return "$" in head or any(key in head for key in getattr(word, "markers", {}))


def _update(table, name, new, certain, array=False):
    """`name`'s scalar candidates -- or, `array`, its word-lists -- after it is
    assigned `new`: replaced where `certain`; else added to, with the "maybe
    unset" candidate, `""` or `[]`, where the name was not held at all. Past
    `_CANDIDATES` candidates, or with none, the name holds its stand-in."""
    candidates = table.arrays if array else table.scalars
    if not certain:
        held = name in table.scalars or name in table.arrays
        new = candidates.get(name, []) + new + ([] if held else [[] if array else ""])
    kept = _deduped(new)
    if 0 < len(kept) <= _CANDIDATES:
        candidates[name] = kept
    else:
        _unseen(table, name)


def _unseen(table, name):
    """`name` set to a value the table cannot see: it holds its own reference,
    `$NAME`, alone -- the reading the guard makes without the table."""
    table.scalars[name] = ["$" + name]
    table.arrays.pop(name, None)


def emptied(table, name, certain, unknown=False):
    """A command that empties `name` -- `unset`, a bare `local` -- or, with
    `unknown`, sets it to a value the table cannot see -- `read`: where
    `certain` the name goes, or holds its stand-in alone; else, where held,
    it gains the "maybe unset" candidate, `""` or `[]`, or the stand-in, held
    or not. An element (`unset 'a[0]'`, `read 'a[1]'`) leaves its array's
    value unseen."""
    base, bracket, _key = name.partition("[")
    if bracket:
        name, unknown = base, True
    if not _NAME.match(name):
        return
    if unknown:
        if certain:
            _unseen(table, name)
        else:
            _update(table, name, ["$" + name], False)
        return
    for array, empty in ((False, ""), (True, [])):
        candidates = table.arrays if array else table.scalars
        if certain:
            candidates.pop(name, None)
        elif name in candidates:
            _update(table, name, [empty], False, array)


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
