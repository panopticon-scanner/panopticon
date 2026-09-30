#!/usr/bin/env python3
"""Which program a command hands a shell, read off its argv and its stage.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups) the way
`scripts/workflow_operands.py` and `scripts/workflow_gating.py` were: that
module had 51 lines of room left, fewer than the third batch of those
follow-ups adds to these readers. What is here answers one question of one
command -- which program it hands a shell -- and reads no statement around it:

    `scripts`         the script handed to `eval` or `sh -c` as a STRING,
                      which is the same act one quote away from a substitution
    `stdin_program`   whether an interpreter's program arrives on its standard
                      input instead, which is the same act one REDIRECTION
                      away (`bash -s <<'EOF'`), and in what language
    `stdin_scripts`   the quoted body that program is, where it is shell

`workflow_forms` imports all three: its `flattened` reads each script found
here in place of the command handed it, and the guard takes `stdin_program`
and `SHELL_PROGRAM` through it.

Stdlib only, like everything under it.
"""
import os

import shell_reader


# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`.
# The text is shell and this module reads shell, so the quotes are not a
# grammar it lacks -- only one it was not looking through. `python3 -c` and
# `perl -e` are NOT here: that text is another language, and the gap list says
# so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


def scripts(argv):
    """The shell scripts this command is handed as a string, in order.

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
    return [t for t in found if not shell_reader.is_marker(t)]


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
    one both shells refuse, and nothing runs.
    """
    while True:
        at += 1 + sum(letter in _VALUE_OPTIONS for letter in argv[at][1:])
        if at >= len(argv) or argv[at].startswith("--") and argv[at] != "--":
            return []
        if argv[at] in ("-", "--"):
            return argv[at + 1:at + 2]
        if not argv[at].startswith(("-", "+")):
            return [argv[at]]


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
    """
    if not argv:
        return None
    name = os.path.basename(argv[0])
    shell = name in _SHELL_STRING
    if not shell and name not in _FOREIGN:
        return None
    answer = SHELL_PROGRAM if shell else FOREIGN_PROGRAM
    rest = iter(argv[1:])
    for token in rest:
        if token in _STDIN_OPERANDS:
            return answer
        if not token.startswith(("-", "+")):
            return None                     # the program is this file
        letters = "" if token[:2] in ("--", "++") else token[1:]
        if shell and "c" in letters:
            return None                     # the program is the `-c` string
        if shell and "s" in letters:
            return answer                   # the words after `-s` are parameters
        if letters and letters[-1] in _VALUE_OPTIONS:
            next(rest, None)                # an option's value is not a program
    return answer


def stdin_scripts(argv, stage):
    """The QUOTED heredoc script this stage hands an interpreter, if it does.

    `bash -s <<'EOF' … EOF` is `sh -c '<script>'` one redirection away: with a
    quoted delimiter the interpreter reads the body as the text it was written
    as, so reading it here is exactly as sound as reading that string -- and a
    `curl … | sh` inside it is the same defect it is at the top level; so is
    `sh <<< '…'` (#2293). What EXPANDS is read nowhere: the guard's
    `_unread_stdin`.
    """
    here = stage.stdin_heredoc
    if here is None or here[1] or stdin_program(argv) != SHELL_PROGRAM:
        return []
    return [here[0]]
