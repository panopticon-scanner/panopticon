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
                               compatibility imports from workflow_carried,
                               split when this module reached 700 lines, provide
                               `within` for scripts a command substitution runs
                               (#2345) and `carried` for a download a step keeps
                               in a variable and hands to a shell (#2341);
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

The layers run one way: `workflow_gating` sits below `workflow_step_credit`,
which owns the branch and shell-option state readers this module uses;
`workflow_guard` sits on top and keeps importing their compatibility bindings
through this module.

Stdlib only, like everything under it.
"""
import os

import shell_reader
from shell_reader import command, statements

from workflow_step_credit import (_BRANCH_ALTERNATE as _BRANCH_ALTERNATE,
                                  _BRANCH_CLOSE as _BRANCH_CLOSE,
                                  _BRANCH_OPEN as _BRANCH_OPEN, _SETTERS as _SETTERS,
                                  _LOST as _LOST, _NO_E as _NO_E,
                                  _NO_PIPEFAIL as _NO_PIPEFAIL, _SET_E as _SET_E,
                                  _stops_step as _stops_step,
                                  _arm as _arm, _arm_pattern as _arm_pattern,
                                  _as_set as _as_set, _body_words as _body_words,
                                  _case_match as _case_match,
                                  _case_subject as _case_subject,
                                  _errexit_states as _errexit_states,
                                  _literal_for as _literal_for,
                                  _plain_stage as _plain_stage,
                                  _proved_branch_statements as _proved_branch_statements,
                                  _safe_case_literal as _safe_case_literal,
                                  _same_shell_setter as _same_shell_setter,
                                  _static as _static, _static_eval as _static_eval,
                                  paths as paths, reach as reach, regions as regions,
                                  step_credit as step_credit)

# Compatibility bindings share the fetch, operand and gating owners with existing callers.
from workflow_carried import (_assigned as _assigned, _held as _held,
                              carried as carried,
                              may_carry_fetch as may_carry_fetch,
                              prefix_expanded_program as prefix_expanded_program,
                              prefix_handoff as prefix_handoff)
from workflow_fetch import (FETCHERS as FETCHERS, STDOUT as STDOUT, Fetch as Fetch,
                            compound_stream_consumer as compound_stream_consumer,
                            parse_fetch as parse_fetch, stdout_fetch as stdout_fetch,
                            stream_consumer as stream_consumer, streamed_fetch as streamed_fetch)
from workflow_gating import (Inlined as Inlined, Reach as Reach, _errexit,
                             clears as clears, inlined_reaches, inlined_stops,
                             seed as seed, statement_analysis,
                             swallowed as swallowed)
from workflow_operands import (BIN_DIRS as BIN_DIRS, PATH_DIRS as PATH_DIRS,
                               at_directory as at_directory,
                               chmod_conditional_executable as chmod_conditional_executable,
                               chmod_executable as chmod_executable,
                               chmod_targets as chmod_targets, covers as covers,
                               described as described, located as located, may_run as may_run,
                               names_file as names_file, same_file as same_file,
                               working_directories as working_directories)
from workflow_programs import (SHELL_PROGRAM as SHELL_PROGRAM, VALUE_PROGRAM, Named, Opaque,
                               candidates, dynamic_program, file_program_files, file_stdin_files,
                               scripts, stdin_program as stdin_program, stdin_reader, stdin_scripts,
                               runs_under, unprinted as unprinted, worded)
from workflow_printers import StatementFront
from workflow_stdin import BoundStdin, bound_stdin as bound_stdin, mark_stdin


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
    and `eval`, `source` and `.` keep that, but not `-e` ahead of `||`/`&&`, where the shell
    suspends it. `stops`: this script's failure reaches the step's own shell, None where no shell is
    sure to read it (`Unsure`), never true for an `Opaque` one (None in an `Unsure` one), whose
    statements, nested ones too, say why (`_OPAQUE`, #2486); `errexit`: `-e` at its top (None: this
    is the step's own shell); `pipefail`: a pipeline there fails on any of its commands; `shell`:
    the script's runner, and at the step's own top its `shell:` (None: the default) -- a `Named` one
    where the holder's string names it (`runs_under`); `outer`: the bodies of the command running
    it, below the step's own, and `key` a name for the script, unique in the step, for its own
    bodies."""
    out, last, where, top, indexes, analysis = [], len(stmts) - 1, regions(stmts), errexit is None, [], statement_analysis(stmts)
    errexit, pipefail = seed(shell) if top else (errexit, pipefail)
    inner = {} if top else where                # a step's own: `regions` over its read
    on = _errexit_states(stmts, errexit, where, shell=shell)
    fails = _errexit_states(stmts, pipefail, where, "pipefail", shell)
    for index, statement in enumerate(stmts):
        region, ordinal = outer + tuple((key, n) for n in inner.get(index, ())), 0
        for position, stage in enumerate(statement.stages):
            argv, before = shell_reader.acted(stage.argv), statement.stages[:position]
            # Asked once per stage, not per script it hands on (an `eval` chain was cubic, #2500) --
            # as the runner is where the reader is the stage's own argv or none, which `runs_under`
            # asks only whether there is one, and a reader's `-e` and `pipefail` once a reader (#2889:
            # a word that holds an expansion may hand on every word after it, and each asked again
            # cost the square of the words).
            name, runners, postures = _runner(argv) if argv else "", {}, {}
            for text in scripts(argv) + stdin_scripts(
                    argv, stage, before, shell,
                    StatementFront(stmts, index) if before else None):
                ordinal += 1
                who = getattr(text, "reader", argv)     # a stdin text's READER, `()` or None
                gates = None if who is None or stops is None else not isinstance(text, Opaque) and (
                    bool(who) and stops and swallowed(stmts, index, statement, stage, analysis=analysis) is None
                    and (top or on[index] or index == last)
                    and (fails[index] or stage is statement.stages[-1]))
                if who and who is not argv:
                    runner = runs_under(argv, who, name)
                else:
                    if bool(who) not in runners:
                        runners[bool(who)] = runs_under(argv, who, name)
                    runner = runners[bool(who)]
                who = who or argv
                own = name in ("eval", "source", ".") and who is argv     # in this shell, its `-e`
                if not own and id(who) not in postures:
                    postures[id(who)] = _errexit(who[1:], invocation=True), _errexit(who[1:], False, "pipefail", True)
                read = flattened(
                    statements(text), gates,
                    on[index] and statement.separator not in ("&&", "||") if own else postures[id(who)][0],
                    fails[index] if own else postures[id(who)][1],
                    runner, region,
                    key + ((index, ordinal),))
                if isinstance(text, Opaque):    # a `$(...)` prints part of it: no check counts
                    read = [s._replace(credit=(_OPAQUE % name,) * 2) for s in read]
                read = mark_stdin(read, getattr(text, "bound", None), Unsure)
                out.extend(read)
        if top:
            out.append(statement)
            continue
        why = (Reach(None, _UNGATED % shell) if stops is False and inlined_stops(stmts, 0, len(stmts), index, on, fails)
               else _UNGATED % shell if not stops
               else _RUNS_ON % shell if not (on[index] or index == last)
               else None)
        indexes.append(len(out))
        out.append((Unsure if stops is None else Inlined)(
            statement.stages, statement.separator, region,
            (why, why if fails[index] or type(why) is str or len(statement.stages) == 1 and why is not None else _PIPED % shell)))
    return out if top else inlined_reaches(out, stmts, indexes, on, fails, analysis)


class Idle(str):
    """An unread reason `kept` keeps only where the job holds a fetch the guard REPORTS (#2481):
    see `substitution_script`, `unread_program` and
    `workflow_guard._unread_stdin`'s foreign-language program (#2499)."""


class _Quiet(Idle):
    """An `Idle` `kept` keeps only where no other reason reports its statement:
    `unread_program`'s for a printer whose words it cannot spell out (#2333) and for a dynamic
    program word (#2483, #2486), both of which `carried` says louder where a variable carries
    the download -- `echo "$x" | sh` and `sh -c "$x"` are its own. A grouped printer may carry
    `printer_statement`, the statement where its printer stands (#3095)."""

    program_variable: str | None = None
    printer_statement: int


class FileBound(_Quiet):
    """A catch-all whose dynamic text is bounded to the named reader files (#2428).

    The guard keeps it beside an exact source-bound use so adding that use cannot clear the
    generic verdict current main reports (#2856 r6). Its `_Quiet` base still limits it to jobs
    where the guard reports an unverified fetch; narrowing that existing over-report is #3059.
    """

    files: tuple[str, ...]

    def __new__(cls, text, files):
        reason = super().__new__(cls, text)
        reason.files = tuple(map(str, files))
        return reason


def file_bound_reasons(unread, _stmts, _working):
    """Keep the generic current-main verdict beside the new source-bound verdict (#2856 r6)."""
    return unread


def _runner(argv):
    """A script's runner as `flattened` names it: a `$` word as written (#2473), else a basename."""
    return (shell_reader.readable(argv[0]) if stdin_program(argv) == VALUE_PROGRAM
            else os.path.basename(argv[0]))


def substitution_script(argv, stage, walk, before=None, shell=None):
    """Why the script this stage hands a shell goes unread in a command
    substitution, which `flattened` does not reach (review I-4), or None.

    `walk` is the guard's own walk (`workflow_guard._walk`), over the script flattened as a
    `shell: bash` step's is, its `echo` read both ways (`Named`, #2728) -- which reads each script
    handed on inside it in place, once. A script it finds a fetch or an unread form in is reported;
    any other is `Idle` (re-review N-A of #1793's follow-ups). `VERSION=$(bash -c 'echo 1')` has
    nothing a checksum must precede, but the guard follows no download into a substitution, where a
    script may still run one the job fetched: `curl -o t.sh …; x=$(sh -c 'bash t.sh')`. `before` is
    the stages in front of this one in its pipeline, whose printer may pipe it a program under
    `shell` (`stdin_scripts`, #2476, #2478)."""
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
    live = [walk(flattened(statements(text), shell=Named("bash"))) for text in texts]
    return why if any(found or any(not isinstance(w, (Idle, BoundStdin)) for _i, w in unread)
                      for found, unread in live) else idle(why)


def unread_program(argv, stage, walk, inside, before=None, shell=None, statements=None):
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
    (value, words), printer = candidates(argv), unprinted(argv, stage, before, shell, statements)
    how, bare = (None, None) if handed else dynamic_program(argv)
    bare_files = file_program_files(bare)
    printer_files = file_stdin_files(stage, before) if printer else ()
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
        answer = handed or _weighed(_PRINTED % (os.path.basename(argv[0]), os.path.basename(
            shell_reader.readable(printer[0]))), list(printer[1:]), walk, _Quiet)
        answer = (FileBound(answer, printer_files)
                  if printer_files and isinstance(answer, _Quiet) else answer)
        if (isinstance(answer, _Quiet) and statements and before
                and (list(before[-1].argv) == ["}"] or before[-1].group_close)):
            for printer_statement in range(len(statements) - 1, -1, -1):
                statement = statements[printer_statement]
                if any(printer[0] is word for item in statement.stages for word in item.argv):
                    answer.printer_statement = printer_statement
                    break
        return answer
    answer = said or _weighed(          # the LAST resort (r0 finding 1), its printer weighed (#2955)
        _DYNAMIC % (how, shell_reader.readable(bare).strip()), worded(bare), walk, _Quiet)
    if not said and isinstance(answer, _Quiet) and (variable := _held(bare)):
        answer.program_variable = variable
    return FileBound(answer, bare_files) if bare_files and isinstance(answer, _Quiet) else answer


_DYNAMIC = ("runs `%s` on `%s`, a program this guard does not follow -- the word spells no "
            "command it can read, and what it expands to may fetch or run a download unchecked; "
            "write the program out, or exempt the step with a reason")
_PRINTED = ("pipes `%s` its program from `%s`, whose words this guard does not spell out -- it "
            "cannot say whether that program fetches or runs a download unchecked; print literal "
            "text or write it in a quoted heredoc, or exempt the step with a reason")
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
        if (argv and os.path.basename(argv[0]) in FETCHERS
                and parse_fetch(os.path.basename(argv[0]), argv[1:], stage, None) is not None):
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
    statement, or the statement its grouped printer stands in (`carried`'s, a stream's, a reported
    fetch's, #2490, #3095)."""
    loud = {index for index, why in unread if not isinstance(why, (Idle, BoundStdin))}
    loud |= {index for index, _why, _fetch in found}
    return [(index, why, why) for index, why in unread
            if not isinstance(why, (Idle, BoundStdin))
            or unverified and getattr(why, "printer_statement", index) not in loud] + found


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
