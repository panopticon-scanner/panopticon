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
    where a script hides       `flattened` reads in place of the command handed
                               them the scripts workflow_programs finds: the
                               shell handed to `eval` or `sh -c` as a STRING
                               (`scripts`), and the program an interpreter reads
                               on standard input (`stdin_program`,
                               `stdin_scripts`, a printer's among them, #2333),
                               each under its READER's `-e`, if any (`Stdin`)
                               -- compatibility imports split out when this
                               module ran short of room a third time;
                               `unread_program` reports the programs it cannot
                               read in place (`candidates`, `unprinted`,
                               `dynamic_program`);
                               `within` the scripts a statement's command
                               substitutions run, where a use may be (#2345);
                               `carried` a download a step keeps in a variable
                               and hands to a shell (#2341);
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
import re

import shell_reader
from shell_reader import command, statements


# Compatibility bindings share the single fetch owner with existing callers,
# the operand questions with theirs, and the gating ones with theirs.
from workflow_fetch import (FETCHERS as FETCHERS, STDOUT as STDOUT, Fetch as Fetch,
                            parse_fetch as parse_fetch, stdout_fetch as stdout_fetch,
                            stream_consumer as stream_consumer, streamed_fetch as streamed_fetch)
from workflow_gating import (Inlined as Inlined, Reach as Reach, _LOST, _NO_E, _NO_PIPEFAIL, _SET_E,
                             _errexit, _stops_step, clears as clears, conditional_contexts as paths,
                             conditional_reach as reach, seed as seed, swallowed as swallowed)
from workflow_operands import (BIN_DIRS as BIN_DIRS, PATH_DIRS as PATH_DIRS,
                               at_directory as at_directory, chmod_executable as chmod_executable,
                               chmod_targets as chmod_targets, covers as covers,
                               described as described, located as located, may_run as may_run,
                               names_file as names_file, same_file as same_file,
                               working_directories as working_directories)
from workflow_programs import (SHELL_PROGRAM as SHELL_PROGRAM, VALUE_PROGRAM, Opaque, candidates,
                               dynamic_program, scripts, stdin_program as stdin_program,
                               stdin_reader, stdin_scripts, runs_under, unprinted as unprinted)


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

# Why a checksum in a script handed to a shell clears nothing, as `flattened`
# finds it for the `credit` of each `Inlined` statement.
_RUNS_ON = ("is inside the script `%s` runs, where no `-e` holds and it is not "
            "the last command, so the script carries on past its failure")
_UNGATED = "is inside the script `%s` runs, and the step does not stop when that script fails"
_PIPED = "is inside the script `%s` runs, piped into a command whose status the pipeline takes"
_OPAQUE = "is inside the script `%s` runs with what a `$(...)` prints, which may skip the check"


class Unsure(Inlined):
    """An `Inlined` statement of a script no shell is sure to read (`workflow_programs.Stdin`), or
    of one inside such a script: read for what it fetches and runs, never the step's own."""
    __slots__ = ()


def flattened(stmts, stops=True, errexit=None, pipefail=True, shell=None, outer=(), key=()):
    """`eval "<script>"` expanded, in place, into the statements it runs.

    In place and in ORDER, rather than harvested separately, so the fetch, the checksum and the
    `chmod` written inside one quoted script are read as the sequence they are: a step hardened
    inside its own string must come out hardened, not unread. The wrapper is kept -- its
    redirections and the stage it pipes into are still the wrapper's.

    Hardened means the checksum's failure stops the STEP (review I-2 of #1793): it stops the script
    (`-e` holds, or it is the last command) and every command running a script around it passes that
    on, up to the command the step's own shell runs, whose failure `swallowed` and `step_credit`
    judge as they judge a check written there -- where one ahead of `&&` reaches only the rest of
    its list (#2334). A child shell has `-e` only from its options or a `set`, and `pipefail` so too
    (re-review N-D), read off the COMMAND LINE they are, where `-O shopt` takes a value (#2444) -- a
    stdin script's READER's (`workflow_programs.Stdin`), without which no check in it counts; the
    step's own shell has what `shell:` starts it with (`seed`, #2338) as a `set` moves it (#2335),
    and `eval` keeps that, but not `-e` ahead of `||`/`&&`, where the shell suspends it. `stops`:
    this script's failure reaches the step's own shell, None where no shell is sure to read it
    (`Unsure`), never true for an `Opaque` one (None in an `Unsure` one), whose statements, nested
    ones too, say why (`_OPAQUE`, #2486); `errexit`: `-e` at its top (None: this is the step's own
    shell); `pipefail`: a pipeline there fails on any of its commands; `shell`: the script's runner,
    and at the step's own top its `shell:` (None: the default) -- a `Named` one where the holder's
    string names it (`runs_under`); `outer`: the bodies of the command running it, below the step's
    own, and `key` a name for the script, unique in the step, for its own bodies.
    """
    out, last, where, top = [], len(stmts) - 1, regions(stmts), errexit is None
    errexit, pipefail = seed(shell) if top else (errexit, pipefail)
    inner = {} if top else where                # a step's own: `regions` over its read
    on = _errexit_states(stmts, errexit, where, shell=shell)
    fails = _errexit_states(stmts, pipefail, where, "pipefail", shell)
    for index, statement in enumerate(stmts):
        region, ordinal = outer + tuple((key, n) for n in inner.get(index, ())), 0
        for position, stage in enumerate(statement.stages):
            argv, before = command(stage.argv), statement.stages[:position]
            # Asked once per stage, not per script it hands on (an `eval` chain was cubic, #2500).
            name = _runner(argv) if argv else ""
            for text in scripts(argv) + stdin_scripts(argv, stage, before, shell):
                ordinal += 1
                who = getattr(text, "reader", argv)     # a stdin text's READER, `()` or None
                gates = None if who is None or stops is None else not isinstance(text, Opaque) and (
                    bool(who) and stops and swallowed(stmts, index, statement, stage) is None
                    and (top or on[index] or index == last)
                    and (fails[index] or stage is statement.stages[-1]))
                runner, who = runs_under(argv, who, name), who or argv
                own = name == "eval" and who is argv    # runs in this shell, with its `-e`
                read = flattened(
                    statements(text), gates,
                    on[index] and statement.separator not in ("&&", "||") if own
                    else _errexit(who[1:], invocation=True),
                    fails[index] if own else _errexit(who[1:], False, "pipefail", True),
                    runner, region,
                    key + ((index, ordinal),))
                if isinstance(text, Opaque):    # what its `$(...)` prints is read nowhere
                    read = [s._replace(credit=(_OPAQUE % name,) * 2) for s in read]
                out.extend(read)
        if top:
            out.append(statement)
            continue
        why = (_UNGATED % shell if not stops
               else None if on[index] or index == last else _RUNS_ON % shell)
        out.append((Unsure if stops is None else Inlined)(
            statement.stages, statement.separator, region,
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

    A `set` turns an option on only as a plain statement outside a branch,
    group, list or background job, and off within its current subshell; visible
    `( )` restores caller state. `shopt -s -o` and `shopt -u -o` become `set`
    forms (`_as_set`, #2335, #2338); plain `shopt` turns on only under bash. A
    setter behind `builtin`, `command` or `eval`, including an `eval` script
    (#2335, review N-6), runs in this shell. The guard reads those as able only
    to turn off, a fail-closed choice, though bash can turn them on."""
    depth, states, subshells = 0, [], []
    bash = os.path.basename((shell or "bash").split()[0]) == "bash"
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            subshells.extend([state] * stage.group_open)
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
            for _close in range(min(stage.group_close, len(subshells))):
                state = subshells.pop()
    return states + [state]


def step_credit(flat, shell=None):
    """{index: (why, why piped)} for the statements of one step's `read` in
    which a failing check does not stop the step, in `Inlined.credit`'s shape
    (the second answer is a check's with a command piped after it); a step
    whose `shell:` is `shell`. An explicit `(None, None)` retains pipefail-on
    state for enclosing status walks. `swallowed` reads the pair last.

    `flattened` credits a script handed on only as far as the command that
    runs it, and the step's own shell decides the rest: its `-e`, for that
    command and for a check written at the top alike, and its pipefail, for
    a check piped at the top (`flattened` asks it of the command) -- each as
    the `shell:` starts it (`seed`) and a `set` moves it, read the way
    `_errexit_states` reads a child script. Without pipefail a piped check's
    status is lost to the command after it. Where `-e` is off, a failure
    stops the step only in its last command or through an `||` branch that
    exits. Ahead of `&&`, failure reaches only its list; `Reach` bounds that
    list, `_LOST` bounds an unread list to its command, and
    `conditional_reach` bounds a skipped conditional check to paths that
    require it. A check ending a group answers as `_stops_step` says.

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
    path_map = paths(stmts)
    credit: dict[int, tuple] = {}
    for position, index in enumerate(at):
        stops = _stops_step(stmts, position, on, fails)
        for inner in range(start, index + 1):
            why = (Reach(index - inner, _LOST) if stops is _LOST
                   else stops if stops is None or isinstance(stops, str)
                   else Reach(at[stops] - inner) if stops >= 0
                   else _SET_E if errexit else _NO_E % shell)
            why = reach(why, stmts, path_map.get(position, ()), at, index, inner, on, fails)
            piped = why if inner < index or fails[position] else _NO_PIPEFAIL
            if why or piped or fails[position]:
                credit[inner] = (why, piped)
        start = index + 1
    return credit


class Idle(str):
    """An unread reason `kept` keeps only where the job holds a fetch the
    guard REPORTS (#2481): see `substitution_script`, `unread_program` and
    `workflow_guard._unread_stdin`'s foreign-language program (#2499)."""


class _Quiet(Idle):
    """An `Idle` `kept` keeps only where no other reason reports its statement:
    `unread_program`'s for a printer whose words it cannot spell out (#2333)
    and for a dynamic program word (#2483, #2486), both of which `carried` says
    louder where a variable carries the download -- `echo "$x" | sh` and
    `sh -c "$x"` are its own."""


def _runner(argv):
    """A script's runner as `flattened` names it: a `$` word as written (#2473), else a basename."""
    return (shell_reader.readable(argv[0]) if stdin_program(argv) == VALUE_PROGRAM
            else os.path.basename(argv[0]))


def substitution_script(argv, stage, walk, before=None, shell=None):
    """Why the script this stage hands a shell goes unread in a command
    substitution, which `flattened` does not reach (review I-4), or None.

    `walk` is the guard's own walk (`workflow_guard._walk`), over the script flattened as a step's
    is -- which reads each script handed on inside it in place, once. A script it finds a fetch or
    an unread form in is reported; any other is `Idle` (re-review N-A of #1793's follow-ups).
    `VERSION=$(bash -c 'echo 1')` has nothing a checksum must precede, but the guard follows no
    download into a substitution, where a script may still run one the job fetched:
    `curl -o t.sh …; x=$(sh -c 'bash t.sh')`. `before` is the stages in front of this one in its
    pipeline, whose printer may pipe it a program under `shell` (`stdin_scripts`, #2476, #2478).
    """
    handed = scripts(argv) + stdin_scripts(argv, stage, before, shell)
    if not handed:
        return None
    return _weighed("hands a script to `%s` inside a command substitution, where this guard "
                    "follows no download -- it cannot say whether that script fetches or runs "
                    "one unchecked; run it outside the substitution, or exempt the step with a "
                    "reason" % _runner(argv), handed, walk)


def _weighed(why, texts, walk, idle=Idle):
    """`why` where a script among `texts`, flattened and walked, fetches or holds an unread form,
    and `idle(why)` where none does. A foreign stdin program there is `Idle`, so it is not an unread
    form and the reason that hands the script is `Idle` too: #2499's predicate governs both (r0)."""
    live = [walk(flattened(statements(text))) for text in texts]
    return why if any(found or any(not isinstance(w, Idle) for _i, w in unread)  # an inner Idle is not unread
                      for found, unread in live) else idle(why)


def unread_program(argv, stage, walk, inside, before=None, shell=None):
    """Why a program this stage hands a shell goes unread, or None: a script handed to one `inside`
    a command substitution (`substitution_script`), the words a value where it reads its options may
    make its program (`candidates`, #2344, #2337), or those of the stage piping it one no printer
    spells out (`unprinted`, `before` the stages in front of this one in its pipeline, its text
    spelled under `shell`, #2333, #2476, #2478), weighed alike -- so `X=-c; sh $X 'echo hi'` and
    `echo "$X" | sh` are `Idle`, and `sh $X`, with no word after the value, hands none. A candidate
    is read as `scripts` reads a `-c` string, so `sh $X "$Y"` alone is `Idle` too, but not one
    `Rewritten`. A lifted `$(…)` stays opaque while the text around it is read, and `_walk` reads
    its inner script separately (#2482). A command the guard reports unresolved (`sudo $CMD -c …`)
    is not read again here. The handed script or the printer speaks before the value's reason where
    a shell reads that stdin (`Stdin.reader` the argv or `()`), where a `-c` or `eval` string is
    handed and the handed answer is LOUD, or where that reason is absent or `Idle`; an answer
    resting only on a stdin no shell is sure to read (`Stdin.reader` None, as past a value, #2485)
    never speaks before that reason where it is LOUD: `X=-c; echo "$Y" | sh $X -s 'curl … | sh'`
    runs the word whatever the stdin holds. LAST, where none of those speaks, the same word with the
    SHELL spelled out (`dynamic_program`, #2483, #2486): one rule for a dynamic program wherever a
    shell takes one, said where nothing louder (`carried`'s, a stream's) reports its statement. Last
    because a value in the options answers for the whole statement and `_weighed` makes that answer
    LOUD where a word after it fetches (`sh $X -c "$P" 'curl … | sh'`, review r0 finding 1), which
    this rule's droppable `_Quiet` would have replaced."""
    handed = inside and substitution_script(argv, stage, walk, before, shell)
    (value, words), printer = candidates(argv), unprinted(argv, stage, before, shell)
    how, bare = (None, None) if handed else dynamic_program(argv)
    if shell_reader.unresolved_wrapper(stage.argv) or not (handed or words or printer or bare):
        return handed or None           # an unresolved command is reported whole
    said = words and _weighed((
        "runs `%s` with `-c`, a command word this guard does not follow -- if it is a shell, "
        "the word after its options is a program that may fetch or run a download unchecked; "
        "name the command, or exempt the step with a reason" % shell_reader.readable(value)
        if value is argv[0] else
        "passes `%s` `%s` where it reads its options, a value this guard does not follow -- "
        "any word after it may be the program the shell runs, and one here may fetch or run a "
        "download unchecked; write the options out, or exempt the step with a reason"
        % (os.path.basename(argv[0]), shell_reader.readable(value))),
        [str(getattr(w, "spelled", w)) for w in words
         if not isinstance(w, shell_reader.Rewritten)
         and (not shell_reader.is_marker(w) or shell_reader.has_substitution(w))], walk)
    if (handed or printer) and (not said or isinstance(said, Idle) or stdin_reader(argv) is not None
                                or handed and scripts(argv) and not isinstance(handed, Idle)):
        return handed or _weighed(_PRINTED % (os.path.basename(argv[0]), os.path.basename(
            shell_reader.readable(printer[0]))), [" ".join(printer[1:])], walk, _Quiet)
    return said or _Quiet(              # the LAST resort (r0 finding 1)
        _DYNAMIC % (how, shell_reader.readable(bare).strip()))


_DYNAMIC = ("runs `%s` on `%s`, a program this guard does not follow -- the word spells no "
            "command it can read, and what it expands to may fetch or run a download unchecked; "
            "write the program out, or exempt the step with a reason")
_PRINTED = ("pipes `%s` its program from `%s`, whose words this guard does not spell out -- it "
            "cannot say whether that program fetches or runs a download unchecked; print literal "
            "text or write it in a quoted heredoc, or exempt the step with a reason")
INSIDE = " inside a command substitution"


def within(statement, where="", directory=".", scope=0):
    """Each stage and cwd, recursively through command substitutions.

    A substitution inherits and restores its caller's cwd. A shell string is
    reported by `kept`, not read; checks inside stay unread and fail closed
    (#2345)."""
    for position, stage in enumerate(statement.stages):
        yield statement, position, stage, where, directory
        for nested, text in enumerate(stage.substitutions):
            inner = list(statements(text))
            child_scope = "%sS%d_%d" % (scope, position, nested)
            working = working_directories(inner, regions(inner), child_scope,
                                           step_credit(inner, "bash {0}"), directory)
            for index, child in enumerate(inner):
                yield from within(child, INSIDE, working[index], "%sI%d" % (child_scope, index))


# A download a step keeps in a variable and hands a shell as its script
# (#2341): `x=$(curl -fsSL URL)`, then `eval "$x"`, `sh -c "$x"` or `echo "$x"
# | sh`. No file ever holds it, so no checksum clears it, as none clears
# `eval "$(curl URL)"`; the sentence names the variable.
_CARRIES = ("carries %s in `$%s` and hands it to `%s`%s, so there is no file to check -- "
            "download it to a file, `sha256sum -c` that file, then run it")
_NAMED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
_WHOLE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
_DECLARES = ("export", "local", "declare", "typeset", "readonly")


def _held(word):
    """The name of the variable `word` is whole (`$x`, `${x}`), or ''."""
    match = _WHOLE.fullmatch(word)
    return (match[1] or match[2]) if match else ""


def _prints(stage):
    """The words an `echo` or `printf` stage writes to its standard output."""
    argv = command(stage.argv)
    return argv[1:] if argv and os.path.basename(argv[0]) in ("echo", "printf") else []


def _assigned(stage, held):
    """{name: the download it now holds, or None} for what this stage assigns,
    in whatever shell runs it (`carried` weighs that). A bare assignment or a
    declaration's (`export x=...`) holds one when its value is the stage's one
    substitution and that is one fetch to standard output (`stdout_fetch`), or
    is a variable that holds one, whole (`y="$x"`); `unset` empties one,
    `unset -f` a function."""
    argv = command(stage.argv)
    name = os.path.basename(argv[0]) if argv else ""
    if name == "unset":
        return {} if "-f" in argv else dict.fromkeys((w for w in argv[1:] if w[:1] != "-"), None)
    now = {}
    for word in argv[1:] if name in _DECLARES else [] if argv else stage.argv:
        match = _NAMED.match(word)
        if match:
            value = shell_reader.derived(word[match.end():], word)
            whole = (len(stage.substitutions) == 1 and shell_reader.has_substitution(value)
                     and shell_reader.readable(value) == "$(...)")
            now[match[1]] = (stdout_fetch(stage.substitutions[0]) if whole
                             else held.get(_held(value)))
    return now


def carried(stmts, executors):
    """[(statement index, why)] for each download a step keeps in a variable and hands whole to a
    shell as its script (#2341): the word `$x` or `${x}` as what `eval` or a shell's `-c` runs
    (`scripts`) or as a word a value in its options or a `$` command word's `-c` may make the
    program (`candidates`, #2479) -- except at a command the reader reports unresolved
    (`unresolved_wrapper`) -- or printed by `echo` or `printf` down a pipe to one of `executors`
    (`stream_consumer`) or from a substitution one of them is handed (`bash <(echo "$x")`) -- in the
    statement or in a script its substitutions run (`within`), where `x` was assigned it before that
    statement and not since (`_assigned`). A step is a shell of its own, so the guard asks of each
    step's statements apart, and of each script a substitution runs for what it assigns itself.

    A download is held wherever a statement of its own assigns it. A reassignment empties the name
    only where the step's own shell always runs it, in the step's own scope (review I-1, I-2): not
    in a script `flattened` inlined, which `sh -c 'x=1'` runs in a child shell; not in a branch
    (`regions`) or behind `&&` or `||`, which bash may skip; not in a pipeline or a background job
    (`&`), which run in subshells; and not in a `( )` or `{ }` group or a function body, read as
    `_errexit_states` reads them: a subshell, or a body that runs only when called, with its `local`
    in a scope of its own. Where bash does empty it before the use, the name stays held, which is
    fail-closed: `eval 'x=:'`, `{ x=1; }`, a called `f() { x=1; }`, a use inside the same `( )` as
    its reassignment (`(x=1; eval "$x")`), bash's arithmetic `((x=1))` (dash runs it as two
    subshells), and any reassignment after an argument `{` (`echo {`). A line holding only `(` or
    `)` is a stage the reader keeps (#2420), so a subshell opened or closed on its own line reads
    as the `( )` it is.

    More readings fail closed. The reader drops quotes, so `eval '$x'` and `sh -c '$x'` read as
    `"$x"`: bash runs the first as one command made of the payload's words -- a true positive -- and
    the second runs nothing unless `x` is exported. These are reported where bash need not run the
    download: `sh -c 'x=$(curl ...)'` then `eval "$x"`, as `flattened` inlines the child's
    assignment; `local x`, `read -r x` or `for x in ...` in between, which leave the name held; a
    printing substitution anywhere in an executor's argv (`bash other.sh "$(echo "$x")"`, read as
    `bash other.sh "$(curl ...)"` is); and a pipe into `eval "<string>"`, `sh -c '...'` or
    `sh file`, read as `curl ... | sh x.sh` is.

    Not followed, beside the gap list's cut, command output and file (`echo "$x" > f; sh f`,
    `| tee f; sh f`): a substitution holding more than the fetch (`x=$(curl ... || true)`,
    `x=$(curl ... | tr ...)`) or not alone in its stage (`x=$(curl ...) y=$(date)`),
    `x+=$(curl ...)`, a printer other than echo or printf (`cat <<< "$x" | sh`, a heredoc naming
    `$x` piped to `sh`), a printer inside a `{ }` group or a multi-line subshell whose closing line
    is piped (`{ echo "$x"; } | sh`), which the stream walk does not read for a fetch either, and
    `$x` inside a longer word (`eval "echo $x"`)."""
    held: dict[str, Fetch | None] = {}
    out, branches, depth = [], regions(stmts), 0
    for index, statement in enumerate(stmts):
        for inner, position, stage, where, _directory in within(statement):
            argv = command(stage.argv)
            to = (stream_consumer(inner.stages[position + 1:], executors)
                  if _prints(stage) and stage.stdout_to_pipe else None)
            words = scripts(argv) + (_prints(stage) if to else []) + (
                [] if shell_reader.unresolved_wrapper(stage.argv) else candidates(argv)[1])
            if argv and os.path.basename(argv[0]) in executors:
                words += [w for text in stage.substitutions for inside in statements(text)
                          for w in _prints(inside.stages[-1])]
            for word in words:
                fetch = held.get(_held(word))
                if fetch:
                    consumer = to or [w for w in argv if getattr(w, "spelled", w) is not word
                                      and not shell_reader.is_marker(w)]
                    out.append((index, _CARRIES % (
                        shell_reader.readable(fetch.url), _held(word),
                        " ".join(shell_reader.readable(w) for w in consumer), where)))
                    break
        if len(statement.stages) == 1:
            stage = statement.stages[0]
            now = _assigned(stage, held)
            sure = not (isinstance(statement, Inlined) or branches.get(index) or depth
                        or stage.group_open or "{" in stage.argv or statement.separator == "&"
                        or index and stmts[index - 1].separator in ("&&", "||"))
            held.update(now if sure else {k: v for k, v in now.items() if v})
        for stage in statement.stages:              # a `( )` or `{ }` group, as `_errexit_states`
            depth = max(0, depth + stage.group_open + stage.argv.count("{")
                        - stage.group_close - stage.argv.count("}"))
    return out


# A stage that writes on the bytes it READS, where the fetcher named no file
# of its own: the stdout sink of a stage BEHIND the fetcher (`> f`) and the
# writers that name the file in their argv. An ADJACENT `tee` is bound to its
# file by `parse_fetch`, which reads `piped_to` -- the next stage only -- so it
# never arrives here; one behind any reader (`| cat | tee t`) is bound by
# nothing (review r1 finding 9). The unpackers are reported as streams into an
# executor whatever stands in front of them, so they stay out.
_WRITERS = ("dd", "sponge", "tee")


def _written_on(statement):
    """Whether a stage of this statement writes the bytes it reads to a FILE:
    the stdout SINK of a real one (`> f`, and not `> /dev/null`), or a writer
    that names it in its argv. The fetcher's own stage is never asked -- its
    `2> err.log` holds a log and its `-o /dev/null -w ... > code.txt` three
    digits, and neither of those is the download (review r1 finding 10)."""
    for stage in statement.stages:
        argv = command(stage.argv)
        if argv and os.path.basename(argv[0]) in FETCHERS:
            continue
        if [name for name in stage.stdout_writes if name not in STDOUT]:
            return True
        if argv and os.path.basename(argv[0]) in _WRITERS:
            return True
    return False


def unbound(stmts, fetched, unread):
    """Whether this job holds a download NO checksum could ever clear.

    A fetch to standard output leaves no file the guard can bind a checksum
    to, so `kept`'s predicate counts it as a fetch the guard reports (#2481)
    wherever its bytes can still reach a program. Three ways they can:

        a variable KEEPS it      `_assigned`'s own answer for the statement --
                                 no chain is followed, because the statement
                                 that first holds the download answers already,
                                 and so does every one `carried` reports
        the statement is itself  the words of a statement a reason reports
        reported unread          unread hold it, as `_Quiet`'s
                                 `echo "$(curl ...)" | sh` does
        the PIPELINE writes it   `curl ... | cat > f`, `| tr ... > f`,
                                 `| dd of=f`, `| sponge f`, `| cat | tee t`
                                 -- the write is on a LATER stage, so
                                 `parse_fetch` binds no destination and no
                                 checksum in the job can name the file
                                 (`_written_on`, review r0 and r1)

    One nothing keeps is read and gone -- `curl ... | jq`,
    `curl -o /dev/null -w ...` -- and keeps no unread reason standing. A
    reader that writes the bytes on is weighed whatever it wrote, so
    `curl ... | jq -r .url > f` counts too: a URL list, not a payload, and the
    over-report this rule takes to fail closed. Its real-workflow face is
    `curl ... | jq -r .tag >> "$GITHUB_OUTPUT"` (review r1 finding 11): beside
    an unread program that is reported, and is meant to be."""
    at = {index for index, fetch in fetched if fetch.dest is None}
    return (any(any(_assigned(statement.stages[0], {}).values())
                for statement in stmts if len(statement.stages) == 1)
            or bool(at & {index for index, _why in unread})
            or any(index in at and _written_on(statement)
                   for index, statement in enumerate(stmts)))


def kept(unread, found, unverified):
    """`unread`'s `(index, why)` that stand, as `(index, why, why)`, then the fetch defects `found`,
    each `(index, why, its Fetch)`: every loud one, and an `Idle` one only where `unverified` says
    the job holds a fetch this guard REPORTS -- a download no checksum clears, a stream handed to a
    shell, an unresolved transfer (#2481, #2499) -- and no loud reason of either reports its
    statement (`carried`'s, a stream's, a reported fetch's, #2490)."""
    loud = {index for index, why in unread if not isinstance(why, Idle)}
    loud |= {index for index, _why, _fetch in found}
    return [(index, why, why) for index, why in unread
            if not isinstance(why, Idle) or unverified and index not in loud] + found


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
