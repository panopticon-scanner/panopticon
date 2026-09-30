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
                               and `in_container` the operand a `docker run`
                               hands to a shell on the far side of a bind mount
    whether a failure matters  `swallowed` reads the separator, the `!` and
                               the `if`/`while` around a command, and `regions`
                               the branch bodies it was written inside -- the
                               two ways the shell says an exit status will not
                               stop the script -- and `step_credit` the step's
                               own `-e` and `pipefail`, which its `shell:`
                               starts (`seed`) and a `set` moves, and how far
                               a check ahead of `&&` reaches (`Reach`)

Stdlib only, like everything under it.
"""
import collections
import os
import re

import shell_reader
from shell_reader import command, conditional, negated, statements


# Compatibility bindings share the single fetch owner with existing callers,
# and the operand questions with theirs.
from workflow_fetch import (FETCHERS as FETCHERS, STDOUT as STDOUT, Fetch as Fetch,
                            parse_fetch as parse_fetch, streamed_fetch as streamed_fetch)
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


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")
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
    where bash suspends it.
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
    on = _errexit_states(stmts, errexit, where)
    fails = _errexit_states(stmts, pipefail, where, "pipefail")
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


def _errexit(words, state=False, name="errexit"):
    """Whether these shell or `set` options leave `-e` on, from `state` -- or
    the option `-o name` sets, for `pipefail`, which no letter spells."""
    words = iter(words)
    for word in words:
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            break
        if word[:2] != "--":                    # bash's long options carry none
            if "e" in word[1:] and name == "errexit":
                state = word[0] == "-"
            if "o" in word[1:] and next(words, None) == name:
                state = word[0] == "-"
    return state


def seed(shell):
    """(`-e`, `pipefail`) as a step whose `shell:` is `shell` starts (#2338).

    GitHub runs a step with no `shell:` as `bash -e {0}` (`sh -e {0}` where
    bash is missing) and `shell: sh` as `sh -e {0}`: `-e` and no pipefail.
    Only `shell: bash` adds it (`bash --noprofile --norc -eo pipefail {0}`),
    and a template (`bash {0}`, `bash -eo pipefail {0}`) runs with exactly
    the options it writes.
    """
    words = (shell or "").split()
    if len(words) < 2:
        return True, words == ["bash"]
    return _errexit(words[1:]), _errexit(words[1:], False, "pipefail")


def _errexit_states(stmts, state, where, name="errexit"):
    """Whether `-e` (or `-o name`) holds as each of `stmts` runs, from `state`
    at the top, and after the last: a `set` turns it on only as a plain
    statement outside every branch (`where`, their `regions`), group, list
    and background job, and off wherever it is -- `eval`'s too (#2335), which
    runs in this shell: `eval set +e`, and a `set` in the script it runs."""
    depth, states = 0, []
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            argv = command(stage.argv)
            argv = argv[1:] if argv[:2] == ["eval", "set"] else argv
            if argv and argv[0] == "set":
                plain = (not depth and not stage.group_open and stage.argv[0] == "set"
                         and index not in where and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = (_errexit(argv[1:], state, name) if plain
                         else state and _errexit(argv[1:], state, name))
            for text in scripts(argv) if argv[:1] == ["eval"] else ():
                inner = statements(text)
                state = state and _errexit_states(inner, state, regions(inner), name)[-1]
            depth = max(0, depth + stage.group_open + stage.argv.count("{")
                        - stage.group_close - stage.argv.count("}"))
    return states + [state]


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


def kept(unread, fetched):
    """The `(index, why)` of `unread` that stand where `fetched` are the
    downloads: an `Idle` one only if there are any."""
    return [(index, why) for index, why in unread if fetched or not isinstance(why, Idle)]


# --- whether a command's failure is allowed to matter -------------------------

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


# A check whose non-zero exit nobody sees is not a check. A step with no
# `shell:` runs `bash -e {0}`, and that `-e` is what makes `sha256sum -c` a
# GATE -- and the shell around the command decides whether that survives. `&`
# detaches it; `||` hands the failure to a branch, which rescues it ONLY if
# that branch ends the job; `if`/`while`/`!` make it a test, and errexit never
# applies to a test; a `set +e` ahead of it turns errexit off; and a command
# piped after it takes the pipeline's status unless `pipefail` holds, which
# only `shell: bash` or a `set -o pipefail` gives a step (`step_credit`).
# The `|| ...` branches that keep a check a check: they fail the step, which
# is exactly what errexit would have done.
_GROUP_OPEN = ("{", "(")


def _known_status(argv, inherited):
    """Known exit status, or None when this command's result is not proved."""
    if not argv:
        return inherited
    name = os.path.basename(argv[0])
    if name in ("exit", "return"):
        if len(argv) == 1 or argv[1] == "$?":
            return inherited
        if len(argv) != 2 or not re.fullmatch(r"[+-]?[0-9]+", argv[1]):
            return None
        return int(argv[1]) % 256
    if name == "false" and len(argv) == 1:
        return 1
    if name == "true" and len(argv) == 1:
        return 0
    return None


def _stops_the_job(stmts, index, errexit=True):
    """True if the `||` branch after `stmts[index]` fails the step.

    `sha256sum -c - || exit 1` and `... || { echo "::error::"; exit 1; }` are
    gates, not swallows -- and they are the cheap hardened spellings, so
    refusing them would push authors toward the exemption list instead.
    Where `errexit` is off a branch that only FAILS stops nothing (`|| false`
    sets a status the step carries on past), so there it has to `exit`.
    """
    following = stmts[index + 1:index + 11]
    if not following:
        return False
    first_stage = following[0].stages[0] if following[0].stages else None
    first = first_stage.argv if first_stage else []
    grouped = bool(first_stage and (first_stage.group_open or
                                    (first and first[0] in _GROUP_OPEN)))
    status = 1  # The rescue is entered only after the checksum fails.
    depth = subshell_depth = 0
    exited_subshell = None
    stopped_job = exited = False
    for statement in following:
        if (statement.separator == "&" or len(statement.stages) != 1 or
                any(negated(stage.argv) for stage in statement.stages)):
            return False
        for stage in statement.stages:
            depth += stage.group_open + stage.argv.count("{")
            subshell_depth += stage.group_open
            if exited_subshell is None and not stopped_job:
                # The bounded status walk does not evaluate conditional arms.
                if any(t in ("if", "then", "elif", "else", "fi", "while",
                             "until", "do", "done", "case", "esac", "for")
                       for t in stage.argv):
                    return False
                argv = command(stage.argv)
                if argv:
                    name = os.path.basename(argv[0])
                    status = _known_status(argv, status)
                    if name in ("exit", "return"):
                        if subshell_depth:
                            if name == "return":
                                return False
                            exited_subshell = subshell_depth
                        else:
                            stopped_job, exited = True, name == "exit"
            depth -= stage.group_close + stage.argv.count("}")
            subshell_depth -= stage.group_close
            if depth < 0 or subshell_depth < 0:
                return False
            if exited_subshell is not None and subshell_depth < exited_subshell:
                exited_subshell = None
        if not grouped or depth == 0:
            if statement.separator in ("&&", "||") and not stopped_job:
                return False
            break
        if statement.separator in ("&&", "||"):
            return False
    return ((not grouped or depth == 0) and status is not None and status != 0
            and (errexit or exited))


def swallowed(stmts, index, statement, stage, credit=None):
    """Why this check's failure would go nowhere, or None.

    Phrased to follow "the checksum that names <file>", because that is the
    sentence a reader gets when the check they wrote did not clear the fetch
    they wrote it for. What is read here is the shell right around the check
    -- an `Inlined` statement's `credit` first, then its separator, `!` and
    `if` -- and `credit` is the step's own answer for the statement, read
    last: `step_credit`'s, or None where it has none. A `Reach` answer is a
    check ahead of `&&`, which still stops what its list runs (`clears`).
    """
    if isinstance(statement, Inlined) and statement.credit[stage is not statement.stages[-1]]:
        return statement.credit[stage is not statement.stages[-1]]
    if statement.separator == "&":
        return "is detached with `&`"
    if statement.separator == "||" and not _stops_the_job(stmts, index):
        return "hands its failure to a `||` branch that does not fail the step"
    # `if`, `while` and `!` govern the PIPELINE, and they sit on its head:
    # in `if echo "<sha>  x" | sha256sum -c -; then` -- the spelling this
    # module's own remedy text recommends -- the checksum is the second stage
    # and its own argv says nothing about the test wrapped around it. Ask the
    # head as well as the stage, because a one-stage statement is both.
    head = statement.stages[0].argv if statement.stages else stage.argv
    if negated(head) or negated(stage.argv):
        return "is negated, so the failing path is the THEN branch"
    if conditional(head) or conditional(stage.argv):
        return "is an `if`/`while` test, which errexit does not apply to"
    return credit[stage is not statement.stages[-1]] if credit else None


# Why a check the step's own shell runs does not stop the step, as
# `step_credit` finds it.
_SET_E = ("runs after a `set +e` (or `set +o errexit`) turned errexit off and is not in "
          "the step's last command, so the step carries on past its failure")
_NO_E = ("runs under `shell: %s`, which starts without errexit, and is not in the step's "
         "last command, so the step carries on past its failure")
_NO_PIPEFAIL = ("is piped into another command where `pipefail` is off, so the pipeline "
                "takes that command's status and the step carries on past its failure "
                "(`shell: bash`, or `set -o pipefail` before it, turns pipefail on)")
_AHEAD = ("runs ahead of `&&`, where bash suspends `-e`, so its failure skips only the rest "
          "of that list and the step carries on past it")


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
    exits. Ahead of `&&` bash suspends `-e`, so a failure there stops only
    the rest of its list (`_stops_step`), a `Reach` of that many statements.
    """
    at = [index for index, statement in enumerate(flat) if not isinstance(statement, Inlined)]
    stmts = [flat[index] for index in at]
    (errexit, pipefail), where, start = seed(shell), regions(stmts), 0
    on, fails = _errexit_states(stmts, errexit, where), _errexit_states(
        stmts, pipefail, where, "pipefail")
    credit: dict[int, tuple] = {}
    for position, index in enumerate(at):
        stops = _stops_step(stmts, position, on, fails)
        for inner in range(start, index + 1):
            why = (None if stops is None else Reach(at[stops] - inner) if stops >= 0
                   else _SET_E if errexit else _NO_E % shell)
            piped = why if inner < index or fails[position] else _NO_PIPEFAIL
            if why or piped:
                credit[inner] = (why, piped)
        start = index + 1
    return credit


class Reach(str):
    """A check's refusal that still clears the `span` statements after it:
    the rest of the `&&` list its failure skips (`step_credit`, `clears`)."""

    span: int

    def __new__(cls, span):
        reach = str.__new__(cls, _AHEAD)
        reach.span = span
        return reach


def clears(why, check, use):
    """Whether a check at statement `check`, refused for `why` (None: it
    stops the step), stops the use at statement `use`."""
    return check < use and (why is None or isinstance(why, Reach) and use - check <= why.span)


# The keywords that open a compound command, and the ones that close it.
_OPENS, _CLOSES = ("if", "while", "until", "for", "case", "{"), ("fi", "done", "esac", "}")


def _nesting(statement):
    """The compound commands this statement opens, less those it closes: its
    subshell parentheses, and the keywords that lead its commands."""
    depth = 0
    for stage in statement.stages:
        depth += stage.group_open - stage.group_close
        for token in stage.argv:
            if token not in shell_reader.KEYWORDS:
                break
            depth += (token in _OPENS) - (token in _CLOSES)
    return depth


def _stops_step(stmts, position, on, fails):
    """How much of the step a failure in its top-level statement `position`
    stops: None for all of it, -1 for none of it, else the index of the last
    statement it still stops. Ahead of `&&` that is the end of its list -- the
    first `||` or the list's own end, a compound command in it taken whole --
    or of the `( )` or `{ }` group the list ends, whose status is the list's.
    That status still stops the step as the step's last command, through an
    `||` branch that stops the step, or as a subshell's where `-e` holds --
    never a `{ ...; }` group's, which `-e` lets pass -- and not from a group
    detached with `&`, or piped where pipefail is off (`fails`)."""
    last, separator = len(stmts) - 1, stmts[position].separator
    if separator != "&&":
        stops = (on[position] or position == last or
                 separator == "||" and _stops_the_job(stmts, position, False))
        return None if stops else -1
    end, depth = position, 0
    while end < last and (depth > 0 or not depth and stmts[end].separator == "&&"):
        end += 1
        depth += _nesting(stmts[end])
    if not depth and end < last and stmts[end].separator not in ("&", "||") and [
            stage.argv for stage in stmts[end + 1].stages[:1]] == [["}"]]:
        end, depth = end + 1, -1                # the list ends its `{ ...; }` group
    here = stmts[end]
    if depth < 0 and (here.separator == "&" or len(here.stages) > 1 and not fails[end]):
        return end                              # the group's failure goes nowhere
    if depth < 0 and here.separator == "&&":
        return _stops_step(stmts, end, on, fails)   # the group heads a list of its own
    if here.separator == "||":
        return None if _stops_the_job(stmts, end, all(on[position:end + 2])) else end
    subshell = depth < 0 and on[end] and any(stage.group_close for stage in here.stages)
    return None if subshell or end == last and here.separator != "&" else end
