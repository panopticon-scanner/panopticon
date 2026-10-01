#!/usr/bin/env python3
"""Which program a command hands a shell, read off its argv and its stage.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups) the way
`scripts/workflow_operands.py` and `scripts/workflow_gating.py` were: that
module had 51 lines of room left, fewer than the third batch of those
follow-ups adds to these readers. What is here answers one question of one
command -- which program it hands a shell -- and reads no statement around it,
only, for a program piped into it, the stage in front of it (#2333):

    `scripts`         the script handed to `eval` or `sh -c` as a STRING,
                      which is the same act one quote away from a substitution
    `stdin_program`   whether an interpreter's program arrives on its standard
                      input instead, which is the same act one REDIRECTION
                      away (`bash -s <<'EOF'`), and in what language
    `stdin_scripts`   the quoted body that program is, where it is shell, or
                      the text an `echo` or `printf` pipes in (`printed`)
    `unprinted`       the printer piping one in whose text `printed` cannot
                      spell out, for `unread_program` to weigh
    `candidates`      the words that may be the program, where a value this
                      module does not follow stands in a shell's options

`workflow_forms` imports all five: its `flattened` reads each script found
here in place of the command handed it, its `unread_program` weighs the
candidates and the unprinted, and the guard takes `stdin_program` and
`SHELL_PROGRAM` through it.

Stdlib only, like everything under it.
"""
import os
import re

import shell_reader


# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`.
# The text is shell and this module reads shell, so the quotes are not a
# grammar it lacks -- only one it was not looking through. `python3 -c` and
# `perl -e` are NOT here: that text is another language, and the gap list says
# so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


def scripts(argv):
    """The shell scripts this command is handed as a string, in order, each
    the text bash hands the shell: a double-quoted `\\$` or `` \\` `` without
    its backslash (`shell_reader._stage`'s `spelled`, #2342).

    A lifted `$(...)` or heredoc marker is never one: it stands for text held
    in the parse it came from, and the guard's `_walk` already credits what
    is inside it.
    """
    if not argv:
        return []
    name, found = os.path.basename(argv[0]), []
    if name == "eval":
        found = [t for t in argv[1:] if not t.startswith("-")]
    elif name in _SHELL_STRING:
        found = _after_dash_c(argv)
    return [getattr(t, "spelled", t) for t in found if not shell_reader.is_marker(t)]


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


def _past_options(argv, at):
    """The first operand after `argv[at]`, the cluster that carries `-c`.

    Bash and dash read on through the option words after `-c` (#2332): `sh
    -c -e P`, `bash -c -x P` and `sh -c +x P` all run `P`. Each `o` or `O`
    in a word takes the next word as its value (`-c -o pipefail P`, `-co
    pipefail P`); a `-` or `--` ends the options, and the word after it is
    the program even if it begins with `-`; a `--long` word after `-c` is
    one both shells refuse, and nothing runs. Option letters are not
    checked: one both shells refuse (`sh -c -K P`) is read on to `P`,
    fail-closed, though nothing runs.
    """
    while True:
        at += 1 + sum(letter in _VALUE_OPTIONS for letter in argv[at][1:])
        if at >= len(argv) or argv[at].startswith("--") and argv[at] != "--":
            return []
        if argv[at] in ("-", "--"):
            return argv[at + 1:at + 2]
        if not argv[at].startswith(("-", "+")):
            return [argv[at]]


# A word bash expands, where a shell reads its options, that may spell one
# (#2344): past the `$NAME`, `${...}` or `$(...)` it begins with, nothing but
# letters -- `$X`, `"${X:--c}"`, `$(echo -c)`, `${X}c`, not `$X/x.sh` -- a
# `$'…'` the reader leaves undecoded (`shell_lex.ansi_c`) whose text BEGINS
# with an escape, `$'\x2dc'` but not `$'-\x63'` (a residual), or a word
# xargs puts a line of its input in (`{}`).
_VALUE = re.compile(r"(?:\$(?:\{[^{}]*\}|\w+|\(\.\.\.\)|[^\w{(\\]))+[A-Za-z]*|\$\\.*", re.S)


def _value(word):
    """Whether `word` is such a value; a pattern is `leads`'s to read."""
    if isinstance(word, shell_reader.Rewritten):
        return getattr(word, "lead", None) is None
    return bool(_VALUE.fullmatch(shell_reader.readable(word)))


def candidates(argv):
    """(the value, [the words it may make the program]) for a shell handed a
    value where it reads its options (`_VALUE`, #2344): `X=-c; sh $X 'curl
    … | sh'` runs that string, as `sh $(echo -c) '…'` and `echo -c | xargs
    -I{} sh {} '…'` do. This module follows no value, so every word after it
    may be the program, a dynamic one too (`"$Y"`, `"$(…)"`, a pattern),
    which `unread_program` weighs too (review N2 of #2331); (None, []) where
    the options end first, at a program, a `-c` whose string `scripts` reads,
    or a `-` or `--`. A value that is the command word, handed a `-c` cluster,
    may be a shell itself (#2337, `CMD=sh; $CMD -c '…'`): the program after
    the options is the candidate. A `$(…)` or backquote value with no word
    after it is its own: bash makes the shell's words of its output, the
    program among them (`sh $(echo tool)`), where a `<(…)` hands it a file
    (`shell_reader.yields_words`).
    """
    if argv[1:] and _value(argv[0]) and argv[1][:1] == "-" != argv[1][1:2] and "c" in argv[1]:
        return argv[0], _past_options(argv, 1)
    if not argv or os.path.basename(argv[0]) not in _SHELL_STRING:
        return None, []
    owed = 0
    for at, word in enumerate(argv[1:], start=1):
        if owed:
            owed -= 1
        elif _value(word):
            return word, argv[at + 1:] or ([word] if shell_reader.yields_words(word) else [])
        elif word in ("-", "--") or word[:1] not in ("-", "+") or word[:2] != "--" and "c" in word:
            break
        elif word[:2] != "--":
            owed = sum(letter in _VALUE_OPTIONS for letter in word[1:])
    return None, []


# An interpreter given no program to run reads one from its STANDARD INPUT, and
# a heredoc is the shortest way a `run:` step writes one down: `bash -s <<'EOF'`
# hands over a script exactly as `sh -c '<script>'` does, one redirection away
# (#1839, run-14 SEC-3915165799). Three answers, because the guard needs three.
SHELL_PROGRAM = "shell"        # the body is shell, which this module reads
FOREIGN_PROGRAM = "foreign"    # a program in a language it has no grammar for
# The interpreters of the second kind. `python3 -c` and `perl -e` are already
# ruled another language by `scripts` above, and a heredoc is the same text one
# redirection over.
_FOREIGN = ("python", "python3", "perl", "ruby", "node", "php", "pwsh")
# The operands that ARE standard input, and the only options a shell a `run:`
# step writes spells with a separate value (`-o pipefail`, bash's `-O shopt`).
_STDIN_OPERANDS = ("-", "/dev/stdin", "/dev/fd/0")
_VALUE_OPTIONS = "oO"


def stdin_program(argv):
    """Whether this command's PROGRAM is its standard input, and in what.

    `SHELL_PROGRAM` for a shell reading a script from stdin (`bash -s`, a bare
    `sh`, `dash -`), `FOREIGN_PROGRAM` for a program in a language this module
    does not read (`python3 -`), and None when the program is somewhere else --
    a file (`bash x.sh`), a `-c` string, a `-m` module -- which makes stdin that
    program's input DATA and not an act of this job's own.

    Read as OPERANDS rather than as a full option grammar: an interpreter's
    first word that is not an option is its program, and a shell's `-s` says
    every word after it is a positional parameter instead. See the guard's gap
    list for the spelling that leaves behind.

    A `-c` string or `eval`'s is ordinarily such a FILE-like place too (the
    `-c` string itself, not stdin, is the program) -- UNLESS that string is
    itself one statement whose own command is a stdin-reading shell (#2500):
    `eval 'bash -s'` and `bash -c 'sh'` then answer SHELL_PROGRAM for the
    ENCLOSING command, so its heredoc, here-string or pipe is `bash -s`'s or
    `sh`'s program, not `eval`'s or `-c`'s. `eval 'echo hi'` and `bash -c
    'cat'` are not stdin-reading shells, so they are unaffected.

    For a SHELL, a value form or a word that may vanish (`_value`) does not
    END the walk there either (#2485): `X=-s; sh $X <<'EOF'` runs the
    heredoc in bash 3.2.57, 5.2.21 and dash alike, as `bash <<'EOF' $(true)`
    and `sh $X` with `X` unset do, where `$X`'s empty expansion drops the
    word outright. Read IN PLACE rather than weighed, fail-closed: `X` may
    just as well spell a FILE (`X=script.sh`), so this over-reports there --
    see the guard's gap list, which names it. A `<(...)`/`>(...)` is NOT
    such a word, though `_value` matches its marker too: it always
    substitutes a real path, never empty, so `bash <(curl ...)` keeps
    reading as the FILE it is (`yields_words` tells a process substitution
    from a command substitution, whose OUTPUT may vanish instead) -- true
    only where EVERY substitution in the word is a process one; a MIXED word
    (`$(true)<(...)`) still reads as may-vanish even though bash always
    substitutes a real path for it too -- an over-report the guard's gap
    list does not separately name, beside the one it does (`X=script.sh`).

    A value-form COMMAND word (`$CMD`, `"$CMD"`, `${CMD}`) with stdin on it
    answers FOREIGN, not SHELL (#2473): a name this module has no table for
    gives it no SHELL to stand behind either, and guessing SHELL would read
    another language's program as though it were one -- `$PYTHON - <<'EOF'`
    running a Python download once read CLEAN this way, while the literal
    `python3 - <<'EOF'` was always FLAGGED (review I-2). `_unread_stdin`'s
    existing FOREIGN sentence already reports every body behind a program it
    cannot parse, read or EXPANDING alike, clean or not -- so `CMD=sh; $CMD
    <<'EOF'` is caught exactly as `python3 - <<'EOF'` is, fail-closed and
    over-reporting an innocuous body too (the reader cannot tell `$CMD` will
    turn out to hold a shell from one that will not).
    """
    if not argv:
        return None
    found = scripts(argv)
    if found:
        # bash's `eval` joins ALL of its own words -- `-`-prefixed ones too
        # -- into ONE string before running it (`eval bash -s x.sh` is
        # `bash -s x.sh`, still reading stdin, not `bash x.sh` alone); a
        # shell's `-c` STRING is already one word, `_after_dash_c`'s own.
        # `scripts()`'s OWN join drops `-`-words for its literal-text
        # callers, a filter wrong for this join (review R1-I2) -- re-join
        # eval's words here instead of using `scripts()`'s filtered list. A
        # leading `--` is dropped first: bash's `eval` ends its own options
        # there (`eval -- bash -s` reads stdin), but dash's runs `--` as a
        # command and nothing runs -- fail-closed where a step's `sh` is dash.
        is_eval = os.path.basename(argv[0]) == "eval"
        words = [t for t in (argv[1:] if is_eval else found) if not shell_reader.is_marker(t)]
        if is_eval and words and getattr(words[0], "spelled", words[0]) == "--":
            words = words[1:]
        text = " ".join(getattr(t, "spelled", t) for t in words)
        parsed = shell_reader.statements(text)
        if (len(parsed) == 1 and len(parsed[0].stages) == 1
                and stdin_program(shell_reader.command(parsed[0].stages[0].argv)) == SHELL_PROGRAM):
            return SHELL_PROGRAM
    name = os.path.basename(argv[0])
    shell = name in _SHELL_STRING
    foreign = name in _FOREIGN
    # `<(...)`/`>(...)` are a `_value`-matching marker too (`readable` renders
    # every substitution alike), but they never vanish -- a process
    # substitution always substitutes a real path, never empty, never word-
    # split away, unlike `$(...)`/backticks, whose OUTPUT may be (#2485's
    # `$(true)`). `yields_words` is the one already here that tells them apart.
    if not shell and not foreign and _value(argv[0]) and (
            not shell_reader.has_substitution(argv[0]) or shell_reader.yields_words(argv[0])):
        foreign = True            # a `$` command word's language is unknown
    if not shell and not foreign:
        return None
    answer = SHELL_PROGRAM if shell else FOREIGN_PROGRAM
    rest = iter(argv[1:])
    for token in rest:
        if token in _STDIN_OPERANDS:
            return answer
        if not token.startswith(("-", "+")):
            if shell and _value(token) and (
                    not shell_reader.has_substitution(token) or shell_reader.yields_words(token)):
                continue                    # the walk goes on as if absent
            return None                     # the program is this file
        letters = "" if token[:2] in ("--", "++") else token[1:]
        if shell and "c" in letters:
            return None                     # the program is the `-c` string
        if shell and "s" in letters:
            return answer                   # the words after `-s` are parameters
        # A shell's option word takes a value for each `o` or `O` in it (#2344,
        # `bash -oe pipefail`); another interpreter's, one where it ends so.
        owed = (sum(letter in _VALUE_OPTIONS for letter in letters) if shell
                else int(bool(letters) and letters[-1] in _VALUE_OPTIONS))
        for _ in range(owed):
            next(rest, None)                # an option's value is not a program
    return answer


def stdin_scripts(argv, stage, before=None):
    """The QUOTED heredoc script this stage hands an interpreter, if it does.

    `bash -s <<'EOF' … EOF` is `sh -c '<script>'` one redirection away: with a
    quoted delimiter the interpreter reads the body as the text it was written
    as, so reading it here is exactly as sound as reading that string -- and a
    `curl … | sh` inside it is the same defect it is at the top level; so is
    `sh <<< '…'` (#2293). What EXPANDS is read nowhere: the guard's
    `_unread_stdin`. Read here too is the text an `echo` or `printf` in front
    of it (`before`) pipes in, where `printed` spells it out (#2333): `echo
    'sh tool' | sh`; where it does not, `unprinted` has the printer.
    """
    here = stage.stdin_heredoc
    if here is None and _piped(stage, before):
        text = printed(shell_reader.command(before.argv))
        here = None if text is None else (text, False)
    if here is None or here[1] or stdin_program(argv) != SHELL_PROGRAM:
        return []
    return [here[0]]


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


# The commands whose output is the text of their words (#2333).
_PRINTERS = ("echo", "printf")


def printed(argv):
    """The text this `echo` or `printf` writes where its words spell it out,
    or None: `echo` of words no expansion changes (a `spelled` one's, #2342),
    after the `-n`, `-e` and `-E` bash's `echo` takes, or `printf` of such a
    format with no `%`, or of `%s`, `%s\\n` or `%b` and one such word. A
    backslash is left unspelled where the printer may read it as an escape
    (dash's `echo` does), but a format's `\\n`."""
    if not argv or os.path.basename(argv[0]) not in _PRINTERS or any(
            shell_reader.dynamic(w, shell_reader.has_substitution) and not hasattr(w, "spelled")
            for w in argv[1:]):
        return None
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if os.path.basename(argv[0]) == "echo":
        options = 0
        while options < len(words) and re.fullmatch("-[neE]+", words[options]):
            options += 1
        end = "" if any("n" in word for word in words[:options]) else "\n"
        text = " ".join(words[options:])
        return None if "\\" in text else text + end
    words = words[1:] if words[:1] == ["--"] else words
    if not words or words[0][:1] == "-":
        return None
    if words[0] in ("%s", "%s\\n") and len(words) == 2:
        return words[1] + words[0][2:].replace("\\n", "\n")
    if "%" in words[0] and not (words[0] == "%b" and len(words) == 2):
        return None
    text = (words[1] if "%" in words[0] else words[0]).replace("\\n", "\n")
    return None if "\\" in text else text


def unprinted(argv, stage, before):
    """The `echo` or `printf` in front of this shell piping it its program
    where `printed` does not spell that text out (`echo "$X" | sh`, #2333),
    or []."""
    producer = (shell_reader.command(before.argv)
                if stage.stdin_heredoc is None and _piped(stage, before) else [])
    if (not producer or os.path.basename(producer[0]) not in _PRINTERS
            or printed(producer) is not None or stdin_program(argv) != SHELL_PROGRAM):
        return []
    return producer
