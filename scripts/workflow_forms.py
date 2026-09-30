#!/usr/bin/env python3
"""#1697: the argv SHAPES a workflow `run:` step writes, with no rule on top.

Split out of `scripts/workflow_guard.py` the way `scripts/shell_reader.py` was
(#1647 fix round 1), and for the same reason: closing four of that module's
documented gaps pushed it past the house's module size, and the part that came
out is a layer, not a slice. `shell_reader` turns text into statements and
argv; this module answers the argv questions that have nothing to do with
supply chains, and `workflow_guard` asks the two that do.

Three questions live here, each one a shape a step writes down:

    what a fetcher was told    compatibility imports from workflow_fetch,
                               the single owner of bounded transfer parsing
    what an operand stands for compatibility imports from workflow_operands
                               (`same_file`, `names_file`, `covers`, `may_run`,
                               `described`, `chmod_targets`), split out when
                               this module reached its size
    where a script hides       `scripts` finds the shell handed to `eval` or
                               `sh -c` as a STRING, which is the same act one
                               quote away from a substitution; `stdin_program`
                               the interpreter whose program arrives on standard
                               input instead, which is the same act one
                               REDIRECTION away (`bash -s <<'EOF'`), whose
                               quoted body is `stdin_scripts`; `flattened`
                               reads both in place of the command handed them;
                               `within` the scripts a statement's command
                               substitutions run, where a use may be (#2345);
                               and `in_container` the operand a `docker run`
                               hands to a shell on the far side of a bind mount
    whether a failure matters  `regions` reads the branch bodies a command was
                               written inside, `_errexit_states` the `-e` and
                               `pipefail` each statement runs under as a `set`
                               moves them, and `step_credit` the step's own
                               answer from both; the rest are compatibility
                               imports from workflow_gating (`swallowed`,
                               `seed`, `Reach`, `clears`, `Inlined`), split out
                               when this module reached its size again

The layers run one way: `workflow_gating` sits below this module and imports
nothing from it, `step_credit` lives here because it is the one gating answer
that needs this module's readers, and `workflow_guard` sits on top of both,
importing the gating names through this one.

Stdlib only, like everything under it.
"""
import os

import shell_reader
from shell_reader import command, statements


# Compatibility bindings share the single fetch owner with existing callers,
# the operand questions with theirs, and the gating ones with theirs.
from workflow_fetch import (FETCHERS as FETCHERS, STDOUT as STDOUT, Fetch as Fetch,
                            parse_fetch as parse_fetch, streamed_fetch as streamed_fetch)
from workflow_gating import (Inlined as Inlined, Reach as Reach, _LOST, _NO_E, _NO_PIPEFAIL,
                             _SET_E, _errexit, _stops_step, clears as clears, seed as seed,
                             swallowed as swallowed)
from workflow_operands import (BIN_DIRS as BIN_DIRS, PATH_DIRS as PATH_DIRS,
                               chmod_executable as chmod_executable,
                               chmod_targets as chmod_targets, covers as covers,
                               described as described, may_run as may_run,
                               names_file as names_file, same_file as same_file)


# The shell words that open a body which MAY NOT RUN, and the ones that close
# it. The reader is flat -- statements, not a tree -- but these words arrive as
# the first token of the statement they introduce, which is enough to say
# whether something was written INSIDE a branch.
_BRANCH_OPEN = ("then", "do", "case")
_BRANCH_ALTERNATE = ("else", "elif")
_BRANCH_CLOSE = ("fi", "done", "esac")


def _arm(statement):
    """Does this statement open a `case` arm?

    The `;;` that ends an arm does not survive the statement split (it is two
    empty separators), but the PATTERN that starts the next one does, as the
    first word where a command was expected: `a)`, `*)`, `(a)`, and -- because
    the split cuts on `|` -- the `b)` of an `a|b)` alternation, which is why
    every stage is asked and not only the first.
    """
    return any(stage.argv and shell_reader.is_arm(stage.argv[0])
               for stage in statement.stages)


def regions(stmts):
    """{statement index: the branch body it sits in}, absent = it always runs.

    `if c; then A; fi` runs A only when c held, so a `sha256sum -c` written in
    A cannot clear a use written outside it -- the shell twin of an `if:` on a
    step, refused for the same reason. Bodies nest, so the value is the whole
    stack: two statements share a branch only when they share every enclosing
    one, and `else`/`elif` end the body before them rather than nesting inside
    it, which is what makes two arms of one `if` different answers.

    A `case` arm is a body of exactly that kind, and it is the one the reader
    has to be told about: `esac` is the only word that closes anything, so
    without the arm patterns every arm of one `case` shares a region and a
    checksum in `a)` clears a use in `b)` -- the last spelling left that bought
    the credit `if`/`else` had just stopped giving.

    Read at the head of the statement only. A keyword is a keyword where a
    command was expected; `echo then` is an argument, and counting it would
    open a body that never closes. A statement of a script handed to a shell
    (`Inlined`) sits in the body of the command running it and in its own
    script's bodies: that script's keywords never touch these (review I-3).
    """
    where = {}
    stack: list[tuple[int, str]] = []
    opened, inlined = 0, []
    for index, statement in enumerate(stmts):
        if isinstance(statement, Inlined):          # placed with its carrier's body
            inlined.append((index, statement.region))
            continue
        head = statement.stages[0].argv if statement.stages else []
        token = head[0] if head else None
        if token in _BRANCH_CLOSE:
            while stack and stack[-1][1] == "arm":
                stack.pop()                     # `esac` ends the open arm too
            if stack:
                stack.pop()
        elif token in _BRANCH_ALTERNATE:
            if stack:
                stack.pop()
            if token == "else":
                opened += 1
                stack.append((opened, "branch"))
        elif token in _BRANCH_OPEN:
            opened += 1
            stack.append((opened, "case" if token == "case" else "branch"))
        elif stack and stack[-1][1] in ("case", "arm") and _arm(statement):
            if stack[-1][1] == "arm":
                stack.pop()                     # this pattern ends the last arm
            opened += 1
            stack.append((opened, "arm"))
        here = tuple(identity for identity, _kind in stack)
        for at, region in inlined + [(index, ())]:
            if here + region:
                where[at] = here + region
        inlined = []
    return where


# --- where a script hides ----------------------------------------------------

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
    no shell spells anything else that way, and `-c` consumes the next word
    whatever else rides along with it. Requiring `-c` as its own token let
    every clustered spelling through.
    """
    for position, token in enumerate(argv[1:], start=1):
        if token == "--":
            break
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return argv[position + 1:][:1]
    return []


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


# Why a checksum in a script handed to a shell clears nothing, as `flattened`
# finds it for the `credit` of each `Inlined` statement.
_RUNS_ON = ("is inside the script `%s` runs, where no `-e` holds and it is not "
            "the last command, so the script carries on past its failure")
_UNGATED = "is inside the script `%s` runs, and the step does not stop when that script fails"
_PIPED = "is inside the script `%s` runs, piped into a command whose status the pipeline takes"


def flattened(stmts, stops=True, errexit=None, pipefail=True, shell=None, outer=(), key=()):
    """`eval "<script>"` expanded, in place, into the statements it runs.

    In place and in ORDER, rather than harvested separately, so the fetch, the
    checksum and the `chmod` written inside one quoted script are read as the
    sequence they are: a step hardened inside its own string must come out
    hardened, not unread. The wrapper is kept -- its redirections and the stage
    it pipes into are still the wrapper's.

    Hardened means the checksum's failure stops the STEP (review I-2 of #1793):
    it stops the script (`-e` holds, or it is the last command) and every
    command running a script around it passes that on, up to the command the
    step's own shell runs, whose failure `swallowed` and `step_credit` judge
    as they judge a check written there -- where one ahead of `&&` reaches
    only the rest of its list (#2334). A child shell has `-e` only from its
    options or a `set`, and `pipefail` so too (re-review N-D); the step's own
    shell has what its `shell:` starts it with (`seed`, #2338) as a `set`
    moves it (#2335), and `eval` keeps that, but not `-e` ahead of `||`/`&&`,
    where the shell suspends it.
    `stops`: this script's failure reaches the step's own shell; `errexit`:
    `-e` at its top (None: this is the step's own shell); `pipefail`: a
    pipeline there fails on any of its commands; `shell`: the script's
    runner, and at the step's own top its `shell:` (None: the default);
    `outer`: the bodies of the command running it, below the step's own, and
    `key` a name for the script, unique in the step, for its own bodies.
    """
    out, last, where, top = [], len(stmts) - 1, regions(stmts), errexit is None
    errexit, pipefail = seed(shell) if top else (errexit, pipefail)
    inner = {} if top else where                # a step's own: `regions` over its read
    on = _errexit_states(stmts, errexit, where, shell=shell)
    fails = _errexit_states(stmts, pipefail, where, "pipefail", shell)
    for index, statement in enumerate(stmts):
        region, ordinal = outer + tuple((key, n) for n in inner.get(index, ())), 0
        for stage in statement.stages:
            argv = command(stage.argv)
            for text in scripts(argv) + stdin_scripts(argv, stage):
                name, ordinal = os.path.basename(argv[0]), ordinal + 1
                gates = (stops and swallowed(stmts, index, statement, stage) is None
                         and (top or on[index] or index == last)
                         and (fails[index] or stage is statement.stages[-1]))
                own = name == "eval"            # runs in this shell, with its `-e`
                out.extend(flattened(statements(text), gates, on[index] and statement.separator
                                     not in ("&&", "||") if own else _errexit(argv[1:]),
                                     fails[index] if own else _errexit(argv[1:], False, "pipefail"),
                                     name, region, key + ((index, ordinal),)))
        if top:
            out.append(statement)
            continue
        why = (_UNGATED % shell if not stops
               else None if on[index] or index == last else _RUNS_ON % shell)
        out.append(Inlined(statement.stages, statement.separator, region,
                           (why, why or (None if fails[index] else _PIPED % shell))))
    return out


# The words a `set` this module reads may stand behind: `builtin` and `eval`
# run it in this shell, as `command` does, in either order.
_SETTERS = ("builtin", "command", "eval", "set", "shopt")


def _as_set(argv):
    """`shopt -s -o NAME...` or `shopt -u -o NAME...` (`-so`, `-uo`, `-os`) as
    the `set -o NAME...` or `set +o NAME...` it spells; any other argv as it
    is. Without `-o` shopt names options of its own, and without `-s` or
    `-u` it only reports them."""
    if argv[:1] != ["shopt"]:
        return argv
    flags, rest = "", argv[1:]
    while rest and rest[0][:1] == "-" and rest[0] != "--":
        flags, rest = flags + rest[0][1:], rest[1:]
    if "o" not in flags or ("s" in flags) == ("u" in flags):
        return argv
    sign = "-o" if "s" in flags else "+o"
    rest = rest[1:] if rest[:1] == ["--"] else rest
    return ["set"] + [word for option in rest for word in (sign, option)]


def _errexit_states(stmts, state, where, name="errexit", shell=None):
    """Whether `-e` (or `-o name`) holds as each of `stmts` runs, from `state`
    at the top, and after the last, in `shell` (a step's `shell:`, None for
    the default, or the name of a script's runner).

    A `set` turns it on only as a plain statement outside every branch
    (`where`, their `regions`), group, list and background job, and off
    wherever it is. `shopt -s -o` and `shopt -u -o` are the `set -o` and
    `set +o` they spell (`_as_set`, #2335, #2338), and a plain `shopt` turns
    an option on only where the shell is bash: dash has no `shopt`. A `set`
    or `shopt` behind `builtin`, `command` or `eval` runs in this shell too,
    and so does a `set` in the script `eval` runs, read in the same `shell`
    (#2335, review N-6); this guard reads all of them as able only to turn
    an option off, a fail-closed choice -- bash itself turns it on through
    each of them."""
    depth, states = 0, []
    bash = os.path.basename((shell or "bash").split()[0]) == "bash"
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            argv = command(stage.argv)
            while len(argv) > 1 and argv[0] in ("builtin", "eval") and argv[1] in _SETTERS:
                argv = command(argv[1:])        # `builtin set`, `eval set`, either way round
            argv = _as_set(argv)
            if argv and argv[0] == "set":
                plain = (not depth and not stage.group_open and index not in where
                         and (stage.argv[0] == "set" or bash and stage.argv[0] == "shopt")
                         and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = (_errexit(argv[1:], state, name) if plain
                         else state and _errexit(argv[1:], state, name))
            for text in scripts(argv) if argv[:1] == ["eval"] else ():
                inner = statements(text)
                state = state and _errexit_states(inner, state, regions(inner), name, shell)[-1]
            depth = max(0, depth + stage.group_open + stage.argv.count("{")
                        - stage.group_close - stage.argv.count("}"))
    return states + [state]


def step_credit(flat, shell=None):
    """{index: (why, why piped)} for the statements of one step's `read` in
    which a failing check does not stop the step, in `Inlined.credit`'s shape
    (the second answer is a check's with a command piped after it); a step
    whose `shell:` is `shell`. `swallowed` reads it last.

    `flattened` credits a script handed on only as far as the command that
    runs it, and the step's own shell decides the rest: its `-e`, for that
    command and for a check written at the top alike, and its pipefail, for
    a check piped at the top (`flattened` asks it of the command) -- each as
    the `shell:` starts it (`seed`) and a `set` moves it, read the way
    `_errexit_states` reads a child script. Without pipefail a piped check's
    status is lost to the command after it. Where `-e` is off, a failure
    stops the step only in its last command or through an `||` branch that
    exits. Ahead of `&&` the shell suspends `-e`, so a failure there stops
    only the rest of its list, a `Reach` of that many statements -- or,
    where the reader lost the list's end, only the rest of its own command,
    a `Reach` in `_LOST`'s words; a check that ends a group answers as the
    group does (`_stops_step`).

    The guard has no model of an exit status or a trap, so four readings
    here are fail-closed, and bash stops the step on each (review N-1): with
    `-e` off, a check the step then tests through `$?` (`rc=$?; if [ $rc -ne
    0 ]; then exit 1; fi`), or through `[ $rc -eq 0 ] || exit 1`, or that
    `trap 'exit 1' ERR` guards, is still refused; and so is `CHECK && [[ -f a
    || -f b ]] || exit 1`, whose rescue is lost where the reader splits the
    `[[ ]]` at its inner `||`.
    """
    at = [index for index, statement in enumerate(flat) if not isinstance(statement, Inlined)]
    stmts = [flat[index] for index in at]
    (errexit, pipefail), where, start = seed(shell), regions(stmts), 0
    on, fails = _errexit_states(stmts, errexit, where, shell=shell), _errexit_states(
        stmts, pipefail, where, "pipefail", shell)
    credit: dict[int, tuple] = {}
    for position, index in enumerate(at):
        stops = _stops_step(stmts, position, on, fails)
        for inner in range(start, index + 1):
            why = (Reach(index - inner, _LOST) if stops is _LOST
                   else stops if stops is None or isinstance(stops, str)
                   else Reach(at[stops] - inner) if stops >= 0
                   else _SET_E if errexit else _NO_E % shell)
            piped = why if inner < index or fails[position] else _NO_PIPEFAIL
            if why or piped:
                credit[inner] = (why, piped)
        start = index + 1
    return credit


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


class Idle(str):
    """An unread reason `kept` keeps only where there are downloads: see
    `substitution_script`."""


def substitution_script(argv, stage, walk):
    """Why the script this stage hands a shell goes unread in a command
    substitution, which `flattened` does not reach (review I-4), or None.

    `walk` is the guard's own walk (`workflow_guard._walk`), over the script
    flattened as a step's is -- which reads each script handed on inside it
    in place, once. A script it finds a fetch or an unread form in is
    reported; any other is `Idle` (re-review N-A of #1793's follow-ups).
    `VERSION=$(bash -c 'echo 1')` has nothing a checksum must precede, but
    the guard follows no download into a substitution, where a script may
    still run one the job fetched: `curl -o t.sh …; x=$(sh -c 'bash t.sh')`.
    """
    handed = scripts(argv) + stdin_scripts(argv, stage)
    if not handed:
        return None
    why = ("hands a script to `%s` inside a command substitution, where this guard "
           "follows no download -- it cannot say whether that script fetches or runs "
           "one unchecked; run it outside the substitution, or exempt the step with a "
           "reason" % os.path.basename(argv[0]))
    live = [walk(flattened(statements(text))) for text in handed]
    return why if any(found or any(not isinstance(w, Idle) for _i, w in unread)  # an inner Idle is not unread
                      for found, unread in live) else Idle(why)


INSIDE = " inside a command substitution"


def within(statement, where=""):
    """(statement, position, stage, where) for each stage of `statement` and,
    under each, of the scripts it runs in a command substitution -- `$(...)`,
    backquotes, `<(...)` -- read as scripts of their own (#2345), as the
    guard's `_walk` reads them for what they fetch; `where` is `INSIDE` for
    those. A script handed to a shell there as a string (`sh -c '...'`) is
    not read: `substitution_script` reports it where the job downloads."""
    for position, stage in enumerate(statement.stages):
        yield statement, position, stage, where
        for text in stage.substitutions:
            for inner in statements(text):
                yield from within(inner, INSIDE)


def kept(unread, fetched):
    """The `(index, why)` of `unread` that stand where `fetched` are the
    downloads: an `Idle` one only if there are any."""
    return [(index, why) for index, why in unread if fetched or not isinstance(why, Idle)]


# The container runners, and the subcommands of theirs that run a command. The
# image itself is not pinned -- this fleet runs the tools image from a mutable
# tag by decision (`workflow_guard`'s gap list, and DEVELOPMENT.md's "One
# residual to know about"); what is read here is the argv after it.
CONTAINERS = ("docker", "podman", "nerdctl")
_CONTAINER_RUN = ("run", "exec", "create")


def in_container(argv, dest, interpreters):
    """The interpreter a container command hands `dest` to, or None.

    Mounts are NOT modelled -- `-v /tmp:/w` renames a whole tree, and reading
    another executor's argv, its mounts and its entrypoint is a second guard's
    job -- so the binding is by BASENAME, and only inside a container argv.
    Everywhere else a basename match is exactly the unbound checksum this rule
    refuses, because the directory is real and a different one is a different
    file; on the far side of a bind mount the directory is the container's,
    and `docker run … -v /tmp:/w img bash /w/x.sh` runs the bytes this job
    downloaded to /tmp/x.sh under a path no step ever wrote.
    """
    base = os.path.basename(dest)
    if not base or len(argv) < 2 or argv[1] not in _CONTAINER_RUN:
        return None
    for position, token in enumerate(argv[2:], start=2):
        if os.path.basename(token) not in interpreters:
            continue
        for operand in argv[position + 1:]:
            if not operand.startswith("-") and os.path.basename(operand) == base:
                return os.path.basename(token)
    return None
