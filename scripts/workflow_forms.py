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
    what an operand stands for `same_file`, `names_file` and `covers`: exactly,
                               by a glob, by the directory a recursive command
                               walks; `may_run`, a command word bash expands
                               that ends in a download's basename (#2310), or
                               a bare name a download written into a directory
                               on PATH answers to (#2308); and
                               `described`, for the operands handed over by
                               `find -exec` or `xargs`. The guard binds a use
                               to a download by NAME, and shell has several
                               ways to designate a file without ever writing
                               its name
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
                               stop the script

Stdlib only, like everything under it.
"""
import collections
import fnmatch
import os
import re

import shell_reader
from shell_reader import command, conditional, negated, statements
from shell_wrappers import dynamic


# Compatibility bindings share the single fetch owner with existing callers.
from workflow_fetch import (FETCHERS as FETCHERS, STDOUT as STDOUT, Fetch as Fetch,
                            parse_fetch as parse_fetch, streamed_fetch as streamed_fetch)


# --- what an operand stands for ----------------------------------------------

def _chmod_operands(argv):
    """Separate the mode from the file operands after chmod's leading options."""
    rest = iter(argv[1:])
    for mode in rest:
        if mode == "--":
            mode = next(rest, "")
            break
        if mode.startswith("--reference"):
            return "", []
        if mode in ("--recursive", "--verbose", "--changes", "--silent", "--quiet",
                    "--preserve-root", "--no-preserve-root") or re.fullmatch(r"-[Rvcf]+", mode):
            continue
        break
    else:
        return "", []
    return mode, list(rest)


def chmod_targets(argv):
    """Files chmod changes; the mode itself must never count as a target."""
    return _chmod_operands(argv)[1]


def chmod_executable(argv):
    """Whether chmod's MODE operand can set an execute bit, including X.

    Only the mode operand counts; a later filename called `u+x` is not a mode.
    Reference-file modes are unresolved here, as before; they are not symbolic.
    """
    mode, _targets = _chmod_operands(argv)
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return any(int(digit) % 2 for digit in mode[-3:])
    if not re.fullmatch(r"[ugoa]*[+=-][rwxXstugo]*(?:[+=-][rwxXstugo]*)*"
                        r"(?:,[ugoa]*[+=-][rwxXstugo]*(?:[+=-][rwxXstugo]*)*)*", mode):
        return False
    return any(op in "+=" and any(bit in permissions for bit in "xX")
               for op, permissions in re.findall(r"([+=-])([rwxXstugo]*)", mode))


def same_file(token, path):
    return os.path.normpath(token) == os.path.normpath(path)


# `mv`/`cp` of a fetched file into one of these is what makes it runnable by
# name for the rest of the job.
BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin",
            "/opt/bin", "/bin", "/sbin")
# Where `may_run` looks a bare command name up (#2308): those, and the runner
# user's `~/.local/bin` in the three spellings a step writes it. A directory
# a step puts on PATH itself (`PATH=…`, `$GITHUB_PATH`) is not read.
PATH_DIRS = BIN_DIRS + ("$HOME/.local/bin", "${HOME}/.local/bin", "~/.local/bin")


def may_run(word, dest):
    """Does running this COMMAND word run `dest`? By its spelling; by its
    basename where bash expands the word first (#2310); by PATH, for a bare
    name (#2308).

    `"$PWD/tool"` and `"$(pwd)/tool"` run the `tool` a step just fetched, and
    the guard does not evaluate the shell to learn where they point: so a
    word `shell_wrappers.dynamic` calls dynamic -- a `$`, a `$(...)` or
    backquotes, a `Rewritten` word -- that ends in the download's basename is
    read as running it, wherever the fetch put it. Loose on the side that
    RUNS only: a checksum still binds by its exact spelling (`names_file`), or
    one of `$OTHER/tool` would clear a `./tool` it never read. A word whose
    LAST part expands (`"$T"`) matches only a download whose basename is that
    same text -- refusing it outright needs a command position the reader
    does not have, where `case "$1" in` reads as the command `$1`.

    A bare name (`tool`) is looked up on PATH, so it is read as running a
    download written into one of `PATH_DIRS` under that name (`curl -o
    /usr/local/bin/tool`), whether or not a builtin or an earlier directory
    answers to it first. The run side only, again: a checksum of the bare
    `tool` reads `./tool`, so it does not clear `/usr/local/bin/tool`.
    """
    name = os.path.basename(os.path.normpath(dest))
    return same_file(word, dest) or (
        dynamic(word, shell_reader.has_substitution)
        and os.path.basename(os.path.normpath(word)) == name) or (
        word == name and os.path.dirname(os.path.normpath(dest)) in PATH_DIRS)


def names_file(content, dest):
    """Does this checked text name `dest`?

    Word-exact against the path, and NEVER a substring match: `/tmp/payload-old`
    must not clear `/tmp/payload`. A checksum list legitimately carries bare
    names, so a BARE dest may also be matched by its basename -- but only a
    bare one: with a directory in the dest, `x.sh` is a different file, and
    accepting it is the unbound checksum this rule exists to refuse, wearing a
    shorter path.
    """
    base = os.path.basename(dest)
    bare = not os.path.dirname(dest)
    return any(same_file(word, dest)
               or (bare and base and same_file(word, base))
               for word in content.split())


# An operand that carries a glob metacharacter DESCRIBES files rather than
# naming one, which is the whole of what `chmod +x *.sh` had over the rule.
_GLOB = re.compile(r"[*?\[]")
# `find`'s ways of running a command over what it walked. The operand is `{}`,
# which names nothing at all.
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")
_RECURSIVE = ("-R", "-r", "--recursive")


def covers(token, dest, recursive=False):
    """Does this operand stand for `dest`, even without naming it?

    Three spellings, and the guard binds by NAME, so each one hid a use:
    exactly (`chmod +x /tmp/payload`), by a glob (`chmod +x /tmp/*.sh`), and by
    the directory a recursive command walks (`chmod -R +x /tmp`). A glob is
    matched against the whole path and, for a bare dest, its basename -- the
    same asymmetry `names_file` draws, and for the same reason.
    """
    if same_file(token, dest):
        return True
    if _GLOB.search(token):
        return (fnmatch.fnmatch(dest, token)
                or (not os.path.dirname(dest)
                    and fnmatch.fnmatch(os.path.basename(dest), token)))
    if recursive and not token.startswith("-"):
        prefix = os.path.normpath(token)
        if prefix == ".":
            return not os.path.isabs(dest)
        if prefix == os.sep:
            # `normpath("/")` is `/`, so the plain prefix test would ask
            # whether the path starts with `//`: the widest walk of all bound
            # nothing at all.
            return os.path.isabs(dest)
        return os.path.normpath(dest).startswith(prefix + os.sep)
    return False


# `find [-H|-L|-P] [-D <opts>] [-O<n>] <starting-point...> <expression>`: the
# options in front of the starting points are not predicates, and reading one
# as "the roots end here" leaves the binding with nothing.
_FIND_LEADING = ("-H", "-L", "-P")


def _walked(argv):
    """The roots a `find` walks: its starting points, or `.` when it has none.

    The two spellings a maintainer writes without thinking -- `find -L /tmp …`
    and `find -name x …` -- both used to yield no roots at all, which is how a
    closed form quietly reopens.
    """
    i = 1
    while i < len(argv):
        if argv[i] in _FIND_LEADING or argv[i].startswith("-O"):
            i += 1
            continue
        if argv[i] == "-D":
            i += 2
            continue
        break
    roots = []
    for token in argv[i:]:
        if token.startswith("-") or token in ("(", "!"):
            break
        roots.append(token)
    return roots or ["."]


def _recursive(argv):
    return any(token in _RECURSIVE for token in argv[1:])


def described(statement, position, stage, argv):
    r"""(the command that really runs, the operands it is handed, does it walk).

    Two shapes give a command its operands without writing them down, and both
    made a download runnable with no use this rule could read: `find <roots>
    ... -exec chmod +x {} \;` substitutes each hit for `{}`, and `... | xargs
    chmod +x` reads them off the pipe -- where `command()` strips `xargs` as a
    wrapper, leaving a `chmod +x` with no operands at all. The roots stand in
    for what was walked, and a walk binds like a recursive flag.
    """
    for predicate in _FIND_EXEC:
        if os.path.basename(argv[0]) == "find" and predicate in argv:
            inner = [t for t in argv[argv.index(predicate) + 1:]
                     if t not in ("{}", ";", "+")]
            if inner:
                return inner, _walked(argv), True
    # `command()` strips what stands in FRONT of the command, and `argv` is
    # what it left: so the wrappers are the prefix, and an `xargs` anywhere
    # else is an operand -- a file that happens to be called `xargs` hands
    # nothing over.
    lead = stage.argv[:len(stage.argv) - len(argv)]
    if position and any(os.path.basename(t) == "xargs" for t in lead):
        previous = command(statement.stages[position - 1].argv)
        if previous and os.path.basename(previous[0]) == "find":
            return argv, _walked(previous), True
        return argv, previous[1:] if previous else [], _recursive(argv)
    return argv, [], _recursive(argv)


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
    open a body that never closes.
    """
    where = {}
    stack: list[tuple[int, str]] = []
    opened = 0
    for index, statement in enumerate(stmts):
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
        if stack:
            where[index] = tuple(identity for identity, _kind in stack)
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
# why a checksum there clears nothing: as its pipeline's last command, and as
# an earlier one (None: it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator credit")
_RUNS_ON = ("is inside the script `%s` runs, where no `-e` holds and it is not "
            "the last command, so the script carries on past its failure")
_UNGATED = "is inside the script `%s` runs, and the step does not stop when that script fails"
_PIPED = "is inside the script `%s` runs, piped into a command whose status the pipeline takes"


def flattened(stmts, stops=True, errexit=None, pipefail=True, shell=None):
    """`eval "<script>"` expanded, in place, into the statements it runs.

    In place and in ORDER, rather than harvested separately, so the fetch, the
    checksum and the `chmod` written inside one quoted script are read as the
    sequence they are: a step hardened inside its own string must come out
    hardened, not unread. The wrapper is kept -- its redirections and the stage
    it pipes into are still the wrapper's.

    Hardened means the checksum's failure stops the STEP (review I-2 of #1793):
    it stops the script (`-e` holds, or it is the last command) and every
    command running a script around it passes that on, up to the step's own
    shell, where `swallowed` decides. A child shell has `-e` only from its
    options or a `set`; `eval` keeps the step's, but not ahead of `||`/`&&`,
    where bash suspends it. `stops`: this script's failure stops the step;
    `errexit`: `-e` at its top (None: the step's own shell); `pipefail`: a
    pipeline fails on any of its commands; `shell`: the script's runner.
    """
    out, last = [], len(stmts) - 1
    on = [True] * len(stmts) if errexit is None else _errexit_states(stmts, errexit)
    for index, statement in enumerate(stmts):
        for stage in statement.stages:
            argv = command(stage.argv)
            for text in scripts(argv) + stdin_scripts(argv, stage):
                name = os.path.basename(argv[0])
                gates = (stops and swallowed(stmts, index, statement, stage) is None
                         and (on[index] or index == last)
                         and (pipefail or stage is statement.stages[-1]))
                own = name == "eval"            # runs in this shell, with its `-e`
                out.extend(flattened(statements(text), gates, on[index] and statement.separator
                                     not in ("&&", "||") if own else _errexit(argv[1:]),
                                     pipefail and own, name))
        if errexit is None:
            out.append(statement)
            continue
        why = _UNGATED % shell if not stops else None if on[index] or index == last else _RUNS_ON % shell
        out.append(Inlined(statement.stages, statement.separator,
                           (why, why or (None if pipefail else _PIPED % shell))))
    return out


def _errexit(words, state=False):
    """Whether these shell or `set` options leave `-e` on, from `state`."""
    words = iter(words)
    for word in words:
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            break
        if word[:2] != "--":                    # bash's long options carry none
            if "e" in word[1:]:
                state = word[0] == "-"
            if "o" in word[1:] and next(words, None) == "errexit":
                state = word[0] == "-"
    return state


def _errexit_states(stmts, state):
    """Whether `-e` holds as each of `stmts` runs, from `state` at the top: a
    `set` turns it on only as a plain statement outside every branch, group,
    list and background job, and off wherever it is written."""
    where, depth, states = regions(stmts), 0, []
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            argv = command(stage.argv)
            if argv and argv[0] == "set":
                plain = (not depth and not stage.group_open and stage.argv[0] == "set"
                         and index not in where and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = _errexit(argv[1:], state) if plain else state and _errexit(argv[1:], state)
            depth = max(0, depth + stage.group_open + stage.argv.count("{")
                        - stage.group_close - stage.argv.count("}"))
    return states


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


# A check whose non-zero exit nobody sees is not a check. Runners default to
# `bash -e -o pipefail`, which is what makes `sha256sum -c` a GATE -- and the
# shell around the command decides whether that survives. `&` detaches it;
# `||` hands the failure to a branch, which rescues it ONLY if that branch
# ends the job; `if`/`while`/`!` make it a test, and errexit never applies to
# a test.
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


def _stops_the_job(stmts, index):
    """True if the `||` branch after `stmts[index]` fails the step.

    `sha256sum -c - || exit 1` and `... || { echo "::error::"; exit 1; }` are
    gates, not swallows -- and they are the cheap hardened spellings, so
    refusing them would push authors toward the exemption list instead.
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
    stopped_job = False
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
                            stopped_job = True
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
    return (not grouped or depth == 0) and status is not None and status != 0


def swallowed(stmts, index, statement, stage):
    """Why this check's failure would go nowhere, or None.

    Phrased to follow "the checksum that names <file>", because that is the
    sentence a reader gets when the check they wrote did not clear the fetch
    they wrote it for.
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
    return None
