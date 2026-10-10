#!/usr/bin/env python3
"""The program a command hands a shell as a STRING: `eval "..."`, `sh -c "..."`.

Split out of `scripts/workflow_programs.py` at that module's size (700 of its 700 lines; #3011), byte
for byte: `scripts`, the scripts a command is handed as a string, with `Opaque` for one a `$(...)`
among its text prints part of; `candidates`, the words that may be the program where a value stands
in a shell's options; `dynamic_program`, the program word that is all expansion; and the readers and
tables the three ask -- `_main_scripts`, `_added_strings`, `_program_words`, `_joined`, `_script`,
`_after_dash_c`, `_candidates`, `_all_expansion`, `_SHELL_STRING`, `_EDGE`, `_NAME`.
`workflow_programs` imports every name back under its own, so nothing that read
`workflow_programs.scripts` or `workflow_programs._SHELL_STRING` moved; this module imports nothing
from it, so the layers still run one way: the option tables and the printers below it, the program
on standard input above.

Stdlib only, like everything under it.
"""
import os
import re

import shell_lex
import shell_reader
from shell_text import Process
from workflow_options import (VALUE_OPTIONS, Handed, _MAINS, _before_operand, _dash_c_strings,
                              _may_spell_option, _past_options, _shell_candidates, _sure_string, _value)
from workflow_printers import rendered



# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`. The text is shell and
# this module reads shell, so the quotes are not a grammar it lacks -- only one it was not looking
# through. `python3 -c` and `perl -e` are NOT here: that text is another language, and the gap list
# says so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


class Opaque(str):
    """A script `scripts` hands on from a string holding a lifted `$(...)` or backquote among text
    of its own, as `rendered` writes it: `sh $(...)` (#2486), or `sh tool` where one printer prints
    `tool` (#2487). Bash reads what the substitution PRINTS as part of the script, word-split where
    unquoted (the reader drops quotes), so `workflow_forms.flattened` reads it in place and counts
    no check in it: `bash -ec "$(echo 'true ||') <check>"` never runs the check."""


def scripts(argv):
    """The shell scripts this command is handed as a string, in order, each the text bash hands the
    shell: a double-quoted `\\$` or `` \\` `` without its backslash (`shell_reader._stage`'s
    `spelled`, #2342).

    A word that is all expansion as `rendered` writes it -- one lifted `$(...)` or backquote, or
    several beside `$` words (`$P$(...)`) -- is never one: it spells no command, and
    `dynamic_program` reports it (#2483, #2486). Nor is a word holding a heredoc, a `<(...)` or any
    other marker: each stands for text held in the parse it came from, and the guard's `_walk`
    already credits what is inside it. A `$(...)` or backquote among text of the word's own does not
    make it none (#2486): `eval "sh $(cat f)"` hands on `sh $(...)`, `Opaque`, whose `sh` is weighed
    as `sh $(cat f)`'s is, and `eval "sh $(echo tool)"` `sh tool`, what its one printer prints
    (#2487) -- the substitution's own text still read where `_walk` reads it, and no marker of this
    parse left to reach another. A text so rendered that the reader refuses is none, as before
    #2486: `eval "cat <<$(a b) …"` takes its delimiter from what `a b` prints, and `cat <<$(...)` is
    no spelling to end the body at, so the string is unread and the rest of the step read.

    `main`'s strings first, a check in one counted where the shell surely runs it (else `Handed`,
    reader `()`), then this walk's own (`_added_strings`, #2858) -- `main`'s alone in the main pass."""
    if _MAINS.get():
        return shell_reader.unsure(argv, _main_scripts(argv))
    shell = bool(argv) and os.path.basename(argv[0]) in _SHELL_STRING
    out = [Handed(script, ()) if shell and not isinstance(script, Opaque) and not _sure_string(argv, word) else script
           for word, script in ((word, _script(word)) for word in _program_words(argv)) if script is not None]
    return shell_reader.unsure(argv, out + [Handed(script) for script in map(_script, _added_strings(argv)) if script is not None])


def _main_scripts(argv):
    """`scripts`' answer as `main` reads it (7e9223e6), word for word: `main`'s strings alone."""
    return [script for script in map(_script, _program_words(argv)) if script is not None]


def _added_strings(argv):
    """A shell's `-c` strings this walk reads (`_dash_c_strings`, #2858) that `main`'s does not."""
    shell, mains = bool(argv) and os.path.basename(argv[0]) in _SHELL_STRING, _program_words(argv)
    return [word for word in _dash_c_strings(argv) if not any(word is seen for seen in mains)] if shell else []


def _program_words(argv):
    """The words where a program stands: `eval`'s -- joined as the ONE word bash runs where a
    statement is split across them (`_joined`), else one by one as before -- or a shell's `-c`
    operand."""
    name = os.path.basename(argv[0]) if argv else ""
    if name == "eval":
        joined = _joined(argv)
        return [joined] if joined is not None else [t for t in argv[1:] if not t.startswith("-")]
    return _after_dash_c(argv) if name in _SHELL_STRING else []


# A word of `eval`'s that begins or ends with a control or redirection operator, or is one: the
# statement it belongs to continues in the word beside it, which bash sees once it has joined
# them and a reading of the words one by one never does (#2673).
_EDGE = re.compile(r"^(?:\|\||&&|[|&;<>(){}])|(?:\|\||&&|[|&;<>(){}])$")


def _joined(argv):
    """`eval`'s words as the ONE text bash runs, where reading them one by one would miss a
    statement split across two of them (#2673: `eval 'curl … |' 'sh'`, `'…' '|' 'sh'`,
    `'sh -c "$(curl …' ')"'`): any word `_EDGE` matches makes the join -- a space between the
    words after a leading `--`, where bash ends `eval`'s own options (dash runs `--` as a
    command and nothing after it: fail-closed where a step's `sh` is dash). The join keeps every
    word's lifted text (`shell_reader._Token`) and its `spelled` form, so `_script` reads it as
    one word: `Opaque` where a `$(...)` stands among text, none where it is all expansion. None
    where no word is such an edge: the words then read one by one, as they did, each a script
    whose operands `workflow_operands` re-parses with its quoting kept."""
    words = argv[1:]
    if words and getattr(words[0], "spelled", words[0]) == "--":
        words = words[1:]
    if len(words) < 2 or not any(_EDGE.search(str(word)) for word in words):
        return None
    markers = {key: value for word in words for key, value in getattr(word, "markers", {}).items()}
    joined = shell_reader._Token(" ".join(words), markers) if markers else " ".join(words)
    if any(hasattr(word, "spelled") for word in words):
        joined = joined if markers else shell_reader._Token(joined, {})
        setattr(joined, "spelled", " ".join(getattr(word, "spelled", word) for word in words))
    return joined


def _script(word):
    """`word` as `scripts` hands it on, or None where it is no script. A plain text, `eval`'s join
    among them, is handed on as it is; a word holding lifted text is `rendered`, and is no script
    where it is all expansion or holds a marker that is neither a substitution handing on words nor
    a `<(...)`/`>(...)` handing a FILE (#2684: `sh $(...) <(...)` reads as `sh` handed a word that
    may vanish and a file operand, not as nothing)."""
    keys = getattr(word, "markers", {})
    if not keys:
        return getattr(word, "spelled", word)
    text = rendered(word)
    if _all_expansion(text) or not all(
            shell_reader.yields_words(shell_reader.derived(key, word))
            or isinstance(keys[key][1], Process) for key in keys):
        return None
    try:
        shell_reader.statements(text)
    except shell_lex.Unreadable:
        return None
    return Opaque(text)


def _after_dash_c(argv):
    """The script operand of a shell's `-c`, wherever the flag was clustered.

    `sh -ec`, `bash -lc`, `bash -euc` are the ordinary CI idiom, not an
    obfuscation, and a short-option cluster carrying a lowercase `c` IS `-c`:
    no shell spells anything else that way. Requiring `-c` as its own token
    let every clustered spelling through. The script is the first operand
    after the options, which need not be the next word: `_past_options`.
    """
    for position, token in enumerate(argv[1:], start=1):
        if token == "--":
            break
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return _past_options(argv, position)
    return []


def candidates(argv):
    """(the value, [the words it may make the program]) for a shell handed a value where it reads
    its options (`_VALUE`, #2344): `X=-c; sh $X 'curl … | sh'` runs that string, as
    `sh $(echo -c) '…'` and `echo -c | xargs -I{} sh {} '…'` do. This module follows no value, so a
    word after it may be the program, a dynamic one too (`"$Y"`, `"$(…)"`, a pattern), which
    `unread_program` weighs too (review N2 of #2331) -- up to the FIRST OPERAND, the first word that
    can be none of an option word, an option's value (`_BARE`) or anything once expanded
    (`_before_operand`), with the option words before it weighed, harmlessly, as `-c` strings. Where
    the value spells `-c`, the words after that operand are positional parameters (#2484). A value
    ending in `o` or `O` makes the next word an option name, which the shell refuses where it is not
    bare: `X=-cO; bash $X 'echo hi' '…'` runs nothing. But the operand may be an option's own value
    (`X=--rcfile; bash $X /dev/null …`), and the shell then reads on: its program can follow only
    (i) in a literal `-c` cluster, which `scripts` reads wherever it stands, (ii) behind a word that
    expands to one, or (iii) as a script file, which the operand reader reads, or on stdin, which
    `stdin_program` keeps possible past a value (#2605); a literal long option remains #2616. So
    spell an option once expanded (`_may_spell_option`: `$Y`, `-$Y`, `$(echo -c)`) re-opens every
    word after it, though not itself, which is `$0`, an option word or a script's file name, never a
    `-c` string, unless brace expansion spells one (`{-c,…}`, a `Rewritten` word nothing weighs).
    The price: a value that was `-c` after all has a later program-like parameter weighed again, as
    before #2484 (`X=-c; sh $X 'echo hi' "$Y" '…'` runs only `echo hi`). (None, []) where the
    options end first, at a program, a `-c` whose string `scripts` reads, or a `-` or `--`. A value
    that is the command word, handed a `-c` cluster, may be a shell itself (#2337,
    `CMD=sh; $CMD -c '…'`): the program after the options is the candidate. A `$(…)` or backquote
    value with no word after it is its own: bash makes the shell's words of its output, the program
    among them (`sh $(echo tool)`), where a `<(…)` hands it a file (`shell_reader.yields_words`).

    `main`'s answer (`_candidates`), then the words this walk adds (`_shell_candidates`, #2858)."""
    value, words = _candidates(argv)
    shell = bool(argv) and not _MAINS.get() and os.path.basename(argv[0]) in _SHELL_STRING
    more, added = _shell_candidates(argv) if shell else (None, [])
    seen = set(map(id, words))
    return (more if value is None else value), words + [word for word in added if id(word) not in seen]


def _candidates(argv):
    """`candidates`' answer as `main` reads it (7e9223e6), word for word."""
    if argv[1:] and _value(argv[0]) and argv[1][:1] == "-" != argv[1][1:2] and "c" in argv[1]:
        return argv[0], _past_options(argv, 1)
    if not argv or os.path.basename(argv[0]) not in _SHELL_STRING:
        return None, []
    owed = 0
    for at, word in enumerate(argv[1:], start=1):
        if owed:
            owed -= 1
        elif _value(word):
            rest = argv[at + 1:]
            end = next((k for k, after in enumerate(rest, 1) if not _before_operand(after)), len(rest))
            more = next((k for k in range(end, len(rest)) if _may_spell_option(rest[k])), len(rest))
            return word, rest[:end] + rest[more + 1:] or (
                [word] if shell_reader.yields_words(word) else [])
        elif word in ("-", "--") or word[:1] not in ("-", "+") or word[:2] != "--" and "c" in word:
            break
        elif word[:2] != "--":
            owed = sum(letter in VALUE_OPTIONS for letter in word[1:])
    return None, []


# What a `$` may carry without braces: a name, or the positional SET `$@` or
# `$*`, three spellings of one thing (review r0 finding 2). Not the bare `$-`,
# `$#`, `$$` or `$?` (their braced forms ARE matched): a program named by one
# of those is a path the fetch-and-exec rule or #2294 already reports.
_NAME = re.compile(r"\w+|[@*]")


def _all_expansion(text):
    """Whether `text` is nothing but expansion -- `$P`, `${P}`, `"$P"` as the reader hands it on
    with its quotes dropped, `$P$Q`, `$@`, a nest of any depth (`${A:-${B:-${C}}}`, r0 finding 3),
    and a lifted `$(...)` or backquote as `shell_reader.readable` renders it (`$P$(...)`, #2486) --
    and so spells no command at all for `flattened` to read (#2483). `${A}x`, `echo $X` and an
    unbalanced `${A` are not: they hold text of their own. Blanks around it and a trailing `;` are
    no text of its own: `sh -c "$(cat f) "`, the `run: |` spelling. Braces are counted rather than
    matched by pattern, because no regular expression can balance them. A `<(...)` renders as
    `$(...)` too, so whether each hands on words is the caller's to ask of the token."""
    at, text = 0, text.strip(" \t\n").removesuffix(";").rstrip(" \t\n")
    while at < len(text):
        if text.startswith("$(...)", at):       # a lifted substitution, rendered
            at += 6
            continue
        if text[at] != "$" or at + 1 >= len(text):
            return False
        if text[at + 1] == "{":
            depth, at = 1, at + 2
            while at < len(text) and depth:
                depth += (text[at] == "{") - (text[at] == "}")
                at += 1
            if depth:
                return False                # `${A`: no closing brace, no expansion
            continue
        name = _NAME.match(text, at + 1)
        if not name:
            return False
        at = name.end()
    return at > 0                           # `sh -c ""` hands over no program


def dynamic_program(argv):
    """(how this command hands a shell a program, the word it hands it) where that word is ENTIRELY
    expansion, else (None, None).

    `sh -c "$P"`, `bash -c "${P}"`, `sh -ec "$P"`, `eval "$P"`, `sh -c "$@"` and `${X:-sh} -c "$P"`,
    whose command word the reader rewrites to its default, so the shell is literal by the time it
    arrives here (`_all_expansion`). `flattened` reads such a word as no command at all, which left
    the program UNREAD wherever a literal shell took one while the `$CMD -c "$P"` twin `candidates`
    finds was reported: `unread_program` now says it of both. So is a word of lifted `$(...)` or
    backquote substitutions that hand on words, `$` words beside them or not (`sh -c "$(cat f)"`,
    `eval sh "$(cat f)"`, `sh -c "$P$(cat f)"`, #2486), asked here as `readable` writes it: bash
    runs what they print, a catch-all even where one printer spells it (`rendered`, #2487). The
    price is #2483's: beside an unverified download, `sh -c "$(date)"` and `eval "$(ssh-agent -s)"`
    are reported though they run none of it. A `<(...)` or `>(...)` hands a file, not words
    (`shell_reader.yields_words`), and is not one; nor is a string that MIXES literal text with an
    expansion (`sh -c "echo $X"`), which is read as written (`Opaque` where a `$(...)` is among its
    text). `set -- "$P"` IS one, and `eval set -- "$OPTS"` runs nothing of the value as a command:
    an accepted over-report, because a `;` in that value does run (r0 finding 4)."""
    name = os.path.basename(argv[0]) if argv else ""
    for word in _program_words(argv) + ([] if _MAINS.get() else _added_strings(argv)):
        keys = getattr(word, "markers", {})
        text = shell_reader.readable(getattr(word, "spelled", word))
        if _all_expansion(text) and all(
                shell_reader.yields_words(shell_reader.derived(key, word)) for key in keys):
            return (name if name == "eval" else name + " -c"), (word if keys else text)
    return None, None
