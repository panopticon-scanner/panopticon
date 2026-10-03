#!/usr/bin/env python3
r"""#1647 (ARC-F2C): what a workflow `run:` step FETCHES, and whether what it
then runs was checked against a digest bound to the file it downloaded.

The rule is #1529's: a workflow can step outside the supply chain that SHA-pinned `uses:` references
govern simply by curling a binary and running it, so nothing unverified may become executable. The
Dockerfile was hardened for exactly this act (ten artifact fetches, every one `sha256sum -c`'d) and
`tests/test_dockerfile.py` guards it; the same act spelled in shell inside a `run:` block was
guarded by two regexes, and run-13 found both failing OPEN:

* the fetch pattern required a whitespace-separated short `-o`/`-O` and excluded pipe characters, so
  `curl -fsSL https://... | sh`, `wget -qO- ... | bash` and every `--output` form yielded an EMPTY
  fetch set -- not "unverified", not seen as a download at all; and
* "verified" was the first `sha256sum`/`shasum` carrying `-c` anywhere earlier
  in the step, bound to no path and no digest, so an unrelated checksum of one
  artifact cleared a later `curl -o payload; chmod +x payload`.

A regex over shell text reports a clean pass on every form it cannot parse, which is the worst
answer a control can give -- so the guard parses the shell instead. `scripts/shell_reader.py` does
that half (comments, continuations, heredocs, substitutions, quoting, redirections, separators,
wrappers) and `scripts/workflow_forms.py` the argv shapes above it (what a fetcher was told, what an
operand stands for, where a script hides in a string); this module asks the two supply-chain
questions of the result: which statements FETCH, and which statements CHECK what a fetch wrote --
naming that path, carrying a digest, in a position where the check's failure still stops the job,
before the statement that first uses it.

The scope is the JOB, not the step (`job_defects`): steps in one job share the workspace, /tmp and
PATH, so a download in step A and the `chmod +x`/run in step B is one act split into two innocent
halves, and a `sha256sum -c` in a later step is a real check of an earlier step's file. A step whose
`shell:` is not bash/sh (pwsh, python, cmd) is reported UNREAD rather than clean -- the same act in
a grammar this module lacks; so is a heredoc handed to such an interpreter (`python3 - <<'EOF'`),
and a step the reader refuses to guess at (`shell_lex.Unreadable`), by its name.

Stdlib only, so the test suite imports it with no dependency. `main()` is the same rule at a shell:

    python3 scripts/workflow_guard.py .github/workflows/*.yml

CI gets NO separate lint step for it: `tests/test_workflow_pins.py` applies this module to every
`run:` step in the fleet and `ci.yml` runs the suite on every PR, so a second invocation would rot.

What it does not model. Within the shell it reads, the requirement is to fail CLOSED -- an unparsed
form must be REPORTED, not accepted (as the two regexes did not). `tests/test_workflow_guard.py`
states every form probed and found open before parsing. The classes below are accepted SILENT gaps.

#1697 ruled every entry by REACHABILITY -- can the form appear in a `run:` step of this fleet, or
does it need a construct the runners never use or a grammar this module does not have by design?
Four entries were reachable and left this list CLOSED rather than documented, each of them shell the
reader already produced and the rule simply did not look at: a `chmod` over a glob and over a walked
directory, the `{}` and `xargs` operands that describe a file instead of naming it, a fetch inside
an `eval`/`sh -c` STRING, and `continue-on-error: true`. What remains keeps its entry WITH its
reason, and `TestTheGapsTheGuardDocuments` or tests/test_workflow_guard_reader_forms.py runs each
live, so a change that catches one fails there and edits this list.

* fetchers that are not curl/wget -- `gh release download`, `aws s3 cp`,
  `python3 -c "...urlretrieve..."`, an action that downloads for you. Reporting every command that
  might reach the network would be noise, not a gate, and the `uses:` pin rule covers the action
  half. If one of these lands in a workflow, the fetch-and-exec rule will not see it.
  KEPT: every download this repo writes -- the fleet's two, the Dockerfiles' ten -- is curl. A
  second tool needs a second option grammar (`gh`'s `-O` is not curl's, and `aws s3 cp` copies
  locally too), and a fetch inside `python3 -c` needs another language entirely.
* variable expansion: `${VERSION}` and `$TMP` stay literal, because the guard tracks the NAME a step
  writes. A checksum naming the same variable binds; a path spelled differently at fetch and at use
  matches nothing, and no `cd` is followed (`curl -o d/x; cd d; sh x`) -- but the side that RUNS
  compares last parts where a `$` spells either directory (`may_run` #2310, `covers` #2345, its
  mirror #2442 with a literal basename; argv only), and for a glob where one spells the download's
  or the download is a bare name. A download kept in a variable is followed to a shell whole
  (`carried`, #2341), not through a cut (`${x//$'\r'/}`), a command's output (`y=$(echo "$x")`) or
  `> f`; `( x=1 )` empties it in neither spelling, the `(` alone on its line kept (#2420). A
  value in shell options (`sh $X '…'`) is not followed; later words are read as `-c` strings
  (`candidates`, #2344) to the first operand and past a later word that may expand to an option, as
  the operand may be an option's value (`--rcfile f $Y '…'`, #2484): `X=-c; sh $X tool '…'` and
  `sh $X 'echo hi' "$Y" '…'` over-report. In a candidate program word, substitutions stay opaque
  while outer text is read (#2482), as a `$(…)` among a `-c`/`eval` string's text is (#2486): what
  it prints is unread (#2487), no check there counts, `eval "sh $(curl …)"` reports the inner
  `sh $(...)` beside `eval`'s stream, and one the reader refuses so read is unread (`cat <<$(…)`).
  One alone or a `Rewritten` word stays unread beside a download. A `$` command's `${X:-sh}` default
  is read, as is a program after its `-c` (#2337); `$CMD --flag` is not, while `sh -c "$P"` and a
  word all substitution are reported beside a download (#2483, #2486), though they may run none of
  it (`eval "$(ssh-agent -s)"`); `carried` follows a download to a `$X` or `$CMD` candidate (#2479).
  A `-c`/`eval` string loses `\$` escapes only with no other `$` (#2342). An option letter the shell
  in hand refuses reads as that refusal after `-c` and in `set`: `sh -c -K '…'` runs nothing and
  `set -Z -e` sets nothing (#2443, #2475). Because zsh runs twenty of bash's refused letters and ksh
  runs `-G`, those read on; so does a word after a shell whose name is itself a word. KEPT: binding
  two spellings of one path means EVALUATING the shell, which the reader does not do by design; the
  fleet puts its variables in the URL and a literal in `-o` (`-o dc.zip`, `-o /tmp/hadolint`).
* directories on the runner's PATH not in `workflow_operands.PATH_DIRS` (#2308), `$HOME/.cargo/bin`
  and `/snap/bin` among them, or one a step puts there (`PATH=…`, `>> "$GITHUB_PATH"`): a bare name
  finds a download in neither, past the `$`-spelled paths #2442's mirror binds by their basename.
  KEPT: the first differ by image (review N-4); the other is a VALUE, which
  is evaluating the shell again. No workflow here touches PATH at all.
* a digest computed from the download itself: `SHA="$(sha256sum x | cut ...)"` and then
  `echo "$SHA  x" | sha256sum -c -` clears x with x's own bytes. KEPT: it is variable expansion
  wearing a checksum -- refusing it means following a variable's VALUE. Only this spelling is open:
  with the digest in a sums file the step wrote, what was recorded is the text `sha256sum x`, which
  carries no digest, so the check does not count and the fetch is already reported.
* what runs inside a container, BEYOND the one shape that is read: `docker run … -v /tmp:/w img bash
  /w/x.sh` binds by basename (`workflow_forms.in_container`), because on the far side of a bind
  mount the basename is the only name the bytes have. What is still unread is everything that needs
  the mount table itself -- a file renamed by the mount (`-v /tmp/x.sh:/w/y.sh`), an argument the
  image's ENTRYPOINT supplies, and whatever the image itself runs.
  KEPT: those need another executor's mounts and entrypoint modelled, which is reading a second
  program's configuration rather than this job's shell. The image the container came from is NOT
  pinned either, and that is a decided residual rather than an oversight: this fleet pulls the
  tools image by its mutable `:latest` tag -- the `IMAGE` env binding and the `docker pull` in
  each consumer: the "Pull or build panopticon-tools image" step of `security.yml` and of
  `security-fork.yml`, and both "Pull the nightly tools image" steps of `adapter-integration.yml`.
  DEVELOPMENT.md states the consequence in its own voice twice, in the "One residual to know
  about" paragraph under "Key design decisions" and in the "Weekly strict security backstop"
  paragraph ("the tools image remains unpinned"). The `uses:` rule pins ACTIONS by SHA and
  `tests/test_dockerfile.py` pins what the Dockerfile FETCHES
  (`test_all_fetched_binaries_are_checksum_verified`, `test_nvd_data_ref_default_is_digest`);
  neither governs a `docker pull` of a tag.
* an executor that reads the file by convention rather than by argument (`make`, `npm install`): the
  download is never an operand, so no use names it. KEPT: needs a construct this fleet does not have
  -- there is no Makefile and no package.json outside a test fixture, no `run:` step invokes either
  tool, and the repo builds with Python and Docker.
* a download the PIPELINE writes under a name `workflow_forms._WRITERS` does not carry: the `> f`
  redirect, `dd`, `sponge` and `tee` are weighed (`unbound`, r0/r1), `| busybox dd of=f` is not.
  KEPT: binding a dest-less fetch to its pipeline's file is a `parse_fetch` change, owed a round.
* bytes modified after a passing check: `sha256sum -c` then `sed -i` then run. OUT OF SCOPE:
  the rule is about what ARRIVED from outside, and a workflow editing its own downloaded file is
  author-deterministic -- that `sed` is in the repo under review.
* a heredoc body printed inside a command substitution for `eval` to run
  (`eval "$(cat <<'EOF' … EOF)"`). The OUTER parse lifts the body, and the substitution's text
  carries it back to its redirection (#2336): a shell reading a quoted one as its program is
  reported as `x=$(sh -c '…')` is (review I-4), but `cat` reads data, and what `eval` runs is
  unread. KEPT: reading it means teaching the reader that a heredoc `cat` reads in a substitution is
  a SCRIPT -- a second expansion model. The fleet writes one heredoc-ish form (a `<<<` here-string
  in docker-publish.yml) and no `cat <<EOF`. It no longer CRASHES, as it did until #1697's review.
  CLOSED outside a substitution for the OTHER heredoc spelling, the body handed to an interpreter as
  the PROGRAM it runs (`bash -s <<'EOF'`, `sh <<< '…'`, `python3 - <<'EOF'` -- #1839, #2293 and
  run-14 SEC-3915165799). Two facts already parsed decide it: whether a command's program is its
  stdin at all (`workflow_programs.stdin_program`, an operand walk -- a `-c` string, a `-m` module
  and a script FILE each put it elsewhere, the body then its input DATA), and which body descriptor
  0 finally reads, EXPANDED or not (`shell_reader`'s `Stage.stdin_heredoc`). A `-c`/`eval` string
  whose one statement is a stdin-reading shell answers for the ENCLOSING command (#2500): a check
  behind an `eval`/`-c` string counts for nothing; the body is still read
  (`workflow_programs._stdin`). That is fail-closed -- `eval 'bash -s'` around a check alone is
  REPORTED though the step stops -- since what the inner shell is, what it reads and what becomes of
  its failure are the step's to change (`sh() { :; }`, `< $F`, `( … ) || true`). Nothing else in
  such a body is the step's own either, unless the holder's own options read stdin
  (`bash -s -c 'sh'`): the job is read with the bodies no shell is sure to read and without them
  (`job_defects`), and a defect of either reading is reported, so no statement of one clears a job;
  `eval 'bash -s < f'` and `eval 'bash -s &'` still over-report a download no shell runs. Still
  open: a `}` (or `exit`, a call, a write) in a body a LITERAL shell reads is taken for the step's
  own, filed under #2608; and a statement of one unsure body still gives credit for a
  fetch only another unsure body holds, filed under #2608. `eval '(bash -s)'` answers so and
  `eval '{ bash -s; }'` (a group: two statements to the reader) does not, though both run the
  heredoc, and a pipeline whose FIRST stage reads stdin is never reached, both filed under #2331.
  Nor, for a SHELL, does a value or a word that may vanish end the walk at a FILE (#2485), and no
  check past one counts, fail-closed: `X=-s; sh $X` around a check alone is REPORTED though the step
  stops, as the guard cannot tell it from `X=/dev/null`; one naming a file or an option nothing runs
  under, or quoted and empty (`X=script.sh`, `X=-K`, `X=-n`), over-reports; `python3 $S`, S unset, a
  FOREIGN word, under-reports (python runs the body), filed under #2331. A quoted body reaches an
  interpreter as written, so `workflow_forms.flattened` catches a shell download there as it does
  at top level. A literal shell's EXPANDING body is REPORTED unread: values and `$(...)` output
  remain unseen. A foreign-language program is reported too. So is a hand-off to a `$` command
  word (#2473); since #2499, either is kept only beside a reported fetch. A value word's body is
  read as shell with no check counted; an expanding one masks substitutions as values (#2597).
  Inside a substitution, the body speaks before its hand-off (#2598); the price remains shell-like
  non-shell text. A nearer literal shell remains the consumer when a surrounding value word gets
  its output. A direct or carried stream into a `$` command reports (#2602), as does a fetched
  file redirected into it.
  `CMD=cat` is the fail-closed price. Still unread: an interpreter behind an option or stdin alias,
  one behind a TRANSPORT (`ssh`, `docker run`, `docker exec`), and an unknown basename such as
  `python3.11` or `busybox sh`. A printer's unspelled text is reported only where its words fetch
  or beside a reported fetch (#2333, #2481); `cat <<'EOF' | sh` is not read. A heredoc the step
  WRITES to a file and then runs (`cat <<'EOF' > x.sh` … `bash x.sh`) is not this rule's business:
  the script is text in the repo under review, the `sed -i` entry's author-deterministic ruling.
* distant function calls treat every `unset` as a barrier, including `unset FOO`, `unset -v FOO`
  and harmless `unset -f f`; this may over-report, but none of the fleet's 84 steps uses it (#2586).
* Under outer `f || exit 1`, `( CHECK || exit 1 ); return $?`, its quoted form, and
  `( CHECK || exit 1 ) && echo ok` stay reported; so does `|| kill $$`, though it stops the shell.
* `if:` conditions are compared as WRITTEN (`_binds`), which assumes the expression is stable
  between the check's step and the use's step. It is not when it reads `env.*` written through
  `$GITHUB_ENV` in between, or a forward `steps.<id>.*` reference.
  KEPT: deciding it means EVALUATING a GitHub expression against a context this module never sees.
  `continue-on-error: true` was the other half of this entry and is now read -- see `job_defects`.

`if` branches inside the shell are read flat for what they FETCH and what they RUN -- folding
those in can only report more. Not for what they CHECK: `workflow_forms.regions` reads the
`then`/`else`/`do` bodies -- and each arm of a `case` -- back out of the statement stream, and a
checksum written inside a branch clears only a use written inside the same branch (#1697 item 3),
which is `_binds` again in the shell's own grammar."""
import collections
import os
import re
import sys

import shell_lex
import shell_reader
from shell_reader import command, statements
from workflow_forms import (BIN_DIRS, CONTAINERS, FETCHERS, SHELL_PROGRAM, STDOUT, Idle, Reach,
                            Unsure, at_directory, carried, chmod_executable, chmod_targets, clears,
                            covers, described, flattened, in_container, kept, may_run, names_file,
                            located, parse_fetch, regions, same_file, stdin_program, step_credit,
                            streamed_fetch, swallowed, unbound, unread_program, within,
                            working_directories)
from workflow_programs import VALUE_PROGRAM


# One `run:` step: its name, its script, the shell it will run under, the `if:`
# that decides whether it runs at all, and whether its own failure stops the
# job -- `continue-on-error: true` is the YAML twin of `|| true`.
Step = collections.namedtuple("Step", "name script shell condition soft",
                              defaults=(None, None, False))

# The shells this module has a grammar for. Anything else is reported unread.
PARSED_SHELLS = ("bash", "sh")
UNNAMED = "<unnamed step>"
CHECKSUM_TOOLS = ("sha256sum", "sha512sum", "sha384sum", "shasum")
INTERPRETERS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3",
                "perl", "ruby", "node", "php", "pwsh", "eval", "source", ".")
# Unpacking a downloaded archive is executing it too: the bytes decide what
# lands on disk and under what name. `install` places a file into a directory
# with a mode; `tar`/`unzip` write whatever the archive says.
UNPACKERS = ("tar", "unzip", "install", "gunzip", "bsdtar")
EXECUTORS = INTERPRETERS + UNPACKERS
# An expected digest: a hex literal, or the variable a workflow pins one in (`${HADOLINT_SHA256}`,
# `$SHA`). Naming a file is not checking it -- something in the checked line has to BE the
# expectation -- and ANY expansion is not good enough either: `echo "$FILE  /tmp/payload" |
# sha256sum -c -` carries a path where the digest belongs, so the name has to say digest.
_DIGEST = re.compile(r"\b[0-9a-f]{40,128}\b"
                     r"|\$\{?\w*(?:SHA|SUM|DIGEST|HASH|CHECKSUM)\w*\}?", re.I)


# --- which statements fetch --------------------------------------------------

def _walk(stmts, stream_exec=False, inside=False, working=None, scopes=None, directory="."):
    """Fetches and unread forms, retaining nested cwd while attributing them to the outer line."""
    stmts = list(stmts)
    if working is None:
        credit = step_credit(stmts, "bash {0}" if inside else None)
        dirs = working_directories(stmts, regions(stmts), 0, credit, directory)
        working = dict(enumerate(dirs))
    scopes = scopes or range(len(stmts))
    found, unread = [], []
    for index, statement in enumerate(stmts):
        here = working.get(index, directory)
        for position, stage in enumerate(statement.stages):
            argv, before = command(stage.argv), statement.stages[position - 1] if position else None
            if argv and os.path.basename(argv[0]) in FETCHERS:
                following = statement.stages[position + 1:]
                piped_to = tuple(command(following[0].argv)) if following else None
                fetch = parse_fetch(os.path.basename(argv[0]), argv[1:], stage, piped_to)
                if fetch is not None:
                    if stream_exec:
                        stream = streamed_fetch(os.path.basename(argv[0]), argv[1:],
                                                stage, following, EXECUTORS)
                        fetch = stream or (fetch._replace(piped_to=None) if fetch.dest is None
                                           else fetch)
                    if fetch.dest is not None:
                        fetch = fetch._replace(dest=located(fetch.dest, here))
                    found.append((index, fetch))
            reason = shell_reader.unresolved_wrapper(stage.argv)
            if reason:
                behind = " behind wrapper" if shell_reader.wrapper_words(stage.argv) else ""
                unread.append((index, "cannot read command%s: %s; the guard cannot "
                               "determine what it runs" % (behind, reason)))
            program = unread_program(argv, stage, _walk, inside, before)
            reason = program if inside and program else _unread_stdin(stage) or program
            if reason:
                unread.append((index, reason))
            consumer = tuple(t for t in argv if not shell_reader.is_marker(t)) or None
            executes = consumer and os.path.basename(consumer[0]) in EXECUTORS
            for subno, text in enumerate(stage.substitutions):
                inner = list(statements(text))
                child_scope = "%sS%d_%d" % (scopes[index], position, subno)
                dirs = working_directories(inner, regions(inner), child_scope,
                                           step_credit(inner, "bash {0}"), here)
                fetched, nested = _walk(
                    inner, stream_exec, True, dict(enumerate(dirs)),
                    ["%sI%d" % (child_scope, i) for i in range(len(inner))], here)
                unread.extend((index, why) for _inner, why in nested)
                found.extend((index, fetch._replace(piped_to=consumer)
                              if executes or fetch.piped_to is None else fetch)
                             for _inner, fetch in fetched)
    return found, unread + (carried(stmts, EXECUTORS) if found else [])


def _fetch_records(stmts, stream_exec=False):
    """[(statement index, Fetch)] for every download in the script."""
    return _walk(stmts, stream_exec)[0]


def _unread_stdin(stage):
    """Why the program on this stage's STANDARD INPUT goes unread, or None.

    A heredoc body or here-string handed to an interpreter is a program, not data
    (`workflow_programs.stdin_program`). One in a language this module has no grammar for, and one
    handed to a `$` command word no table places (#2473), are `Idle`, which `kept` stands only
    beside a fetch this guard reports (#2499); an EXPANDING one handed to a shell by name -- a body
    whose `$(...)` were lifted into the outer parse's table before it reached here, or a here-string
    whose word bash expands first (#2293) -- is reported fetch or no fetch. A body handed to a `$`
    command word is READ as shell; a literal shell's is read only when quoted (`stdin_scripts`)."""
    argv = command(stage.argv)
    here = stage.stdin_heredoc
    kind = stdin_program(argv) if here else None
    if kind is None:
        return None
    name = shell_reader.readable(argv[0])
    if kind == VALUE_PROGRAM:
        return Idle("hands a heredoc body or here-string to `%s`, a command word this guard does "
                    "not follow -- its body is read as shell, which it may not be; name the "
                    "interpreter (`bash -s`, `python3 -`), or exempt the step with a reason" % name)
    name = os.path.basename(name)
    if kind != SHELL_PROGRAM:
        return Idle("hands a heredoc body or here-string to `%s` as the program "
                    "to run, which this guard does not parse -- it cannot say whether "
                    "that program downloads and executes anything; write it in "
                    "bash/sh, or exempt the step with a reason" % name)
    if here[1]:
        return ("hands an EXPANDING heredoc body or here-string to `%s` as the "
                "script to run: it runs what bash expands it to -- values and "
                "`$(...)` output this guard never sees -- so the guard cannot say "
                "what the script runs; quote it (`<<'EOF'`, `<<< '...'`) and it is "
                "read as written, pass job values as arguments instead "
                "(`%s -s -- \"$VALUE\" <<'EOF'`), or exempt the step with a "
                "reason (`EXEMPT_FETCHES` in tests/test_workflow_pins.py)"
                % (name, name))
    return None


def read(script, shell=None):
    """Every statement a `run:` script runs under `shell:` `shell`, quoted scripts expanded."""
    return flattened(statements(script), shell=shell)


def fetches(script):
    """Every download a `run:` script performs, in order."""
    return [fetch for _index, fetch in _fetch_records(read(script))]


# --- which statements check, and what they check -----------------------------

def _has_check_flag(argv):
    for token in argv[1:]:
        if token in ("-c", "--check"):
            return True
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return True
    return False


def _operands(argv):
    return [t for t in argv[1:] if not t.startswith("-")]


def _checked_text(statement, position, stage, argv, written, directory):
    """Text a checksum reads, bound to its heredoc, a locally written sums
    file, or the previous pipeline stage; None when no source ties it."""
    if stage.heredoc:
        return stage.heredoc
    files = [at_directory(f, directory) for f in _operands(argv) + stage.reads if f not in STDOUT]
    # `shasum -a 256 -c -`: the `256` is `-a`'s value, not a sums file.
    files = [f for f in files if not re.fullmatch(r"\d+", f)]
    if files:
        known = [written[f] for f in files if f in written]
        return "\n".join(known) if known else None
    if position:
        return " ".join(command(statement.stages[position - 1].argv))
    return None


def _record_writes(statement, written, directory):
    """What this statement leaves in each file it writes, so a later
    `sha256sum -c <file>` can be bound to it."""
    for position, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        text = " ".join(argv) + ("\n" + stage.heredoc if stage.heredoc else "")
        targets = list(stage.writes)
        if argv and os.path.basename(argv[0]) == "tee":
            targets += _operands(argv)
            if position:
                text = " ".join(command(statement.stages[position - 1].argv))
        for target in targets:
            written[at_directory(target, directory)] = text


# Why a checksum this job ran clears nothing. A refused check is KEPT with its reason rather than
# dropped, because "no checksum in the job names this file" and "the checksum that names it was
# handed to a `|| true`" are different sentences, and only one of them is true of any given step.
_SOFT_STEP = ("is in a step carrying `continue-on-error: true`, so the job "
              "carries on past its failure")
_NO_DIGEST = ("carries no digest, so it says which file to read and not what "
              "should have arrived")
_UNSHARED_IF = ("runs under an `if:` the use does not share, so it may be "
                "skipped while the use is not")
_UNSHARED_BRANCH = ("is written inside an `if`/`while` branch the use is not "
                    "in, so it may be skipped while the use runs")


def _unshared(conditions, check, use):
    """Which half of the check's condition the use does not share."""
    when = conditions.get(check) or (None, None)
    theirs = conditions.get(use) or (None, None)
    if when[1] and when[1] != theirs[1]:
        return _UNSHARED_BRANCH
    return _UNSHARED_IF


def _checks(stmts, credit=None, working=None):
    """[(statement index, checked text, why it clears nothing or None)]."""
    found = []
    written: dict[str, str] = {}
    working = working or {}
    for index, statement in enumerate(stmts):
        directory = working.get(index, ".")
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if not argv or os.path.basename(argv[0]) not in CHECKSUM_TOOLS:
                continue
            if not _has_check_flag(argv):
                continue
            text = _checked_text(statement, position, stage, argv, written, directory) or ""
            why = swallowed(stmts, index, statement, stage, (credit or {}).get(index))
            if (why is None or isinstance(why, Reach)) and not _DIGEST.search(text):
                why = _NO_DIGEST
            found.append((index, text, why))
        _record_writes(statement, written, directory)
    return found


# --- which statements execute what was fetched -------------------------------

def _copies(statement, names, directory):
    """New names this statement gives a known file through `cp`, `mv`, `ln`
    or `cat`: the alias inherits; the copy itself remains innocent."""
    new = set()
    for stage in statement.stages:
        argv = command(stage.argv)
        if not argv:
            continue
        name = os.path.basename(argv[0])
        operands = [at_directory(word, directory) for word in _operands(argv)]
        if name in ("cp", "mv", "ln") and len(operands) > 1:
            if any(same_file(o, n) for o in operands[:-1] for n in names):
                new.add(operands[-1])
        if name == "cat" and stage.writes:
            if any(same_file(o, n) for o in operands for n in names):
                new.update(at_directory(word, directory) for word in stage.writes)
    return new


def _uses(stmts, dest, after, working=None):
    """Names the file gains and its later uses, walking in order so aliases count after creation.
    A use in a statement's substitutions (`within`) belongs to that outer statement."""
    names, out = {dest}, []
    working = working or {}
    for index, statement in enumerate(stmts[after:], after):
        directory = working.get(index, ".")
        for inner, position, stage, where, here in within(
                statement, directory=directory, scope=index):
            argv, how = command(stage.argv), None
            for name in sorted(names):
                how = _use(inner, position, stage, argv, name, here)
                if how:
                    if not same_file(name, dest):
                        shown = re.sub(r"^\$CWD[^/]*/", "", name).replace("$UP", "..")
                        how += " (as `%s`, copied from it earlier)" % shown
                    break
            if how:
                out.append((index, how + where))
                break
        names |= _copies(statement, names, directory)
    return names, out


def _use(statement, position, stage, argv, dest, directory):
    if any(may_run(at_directory(word, directory, True), dest)
           for word in shell_reader.wrapper_words(stage.argv)):
        return "running it"  # `./flock 9` is read through as `flock`, but runs ./flock
    if not argv:
        return None
    argv, handed, recursive = described(statement, position, stage, argv)
    name, rest = os.path.basename(argv[0]), argv[1:]
    if name == "chmod":
        rest = chmod_targets(argv)
    rest = [at_directory(word, directory) for word in rest]
    handed = [at_directory(word, directory) for word in handed]
    mentions = [t for t in rest + handed if covers(t, dest, recursive)]
    if name in CONTAINERS:
        interpreter = in_container(argv, dest, INTERPRETERS)
        if interpreter:
            return "running it inside a container under `%s`" % interpreter
    if (name in INTERPRETERS or stdin_program(argv) == VALUE_PROGRAM) and any(
            same_file(at_directory(r, directory), dest) or (
                stage.stdin_heredoc is None
                and covers(at_directory(r, directory), dest)) for r in stage.reads):
        # File input is the shell's program even though argv carries no path.
        return "running it under `%s` from standard input" % name
    if name == "chmod" and mentions and chmod_executable(argv):
        return "making it executable"
    if may_run(at_directory(argv[0], directory, True), dest):
        return "running it"
    if not mentions:
        return None
    if name in INTERPRETERS:
        return "running it under `%s`" % name
    if name == "install":
        return "installing it"
    if name in UNPACKERS:
        return "unpacking it with `%s`" % name
    if name in ("mv", "cp", "ln") and any(
            t.startswith(BIN_DIRS) or "/bin/" in t for t in rest):
        # Including `ln -s`: a symlink on PATH runs the same bytes, and the
        # name it is then invoked by (`hadolint`) is nowhere in this script.
        return "putting it on PATH with `%s`" % name
    if name == "cat" and position + 1 < len(statement.stages):
        following = command(statement.stages[position + 1].argv)
        if following and os.path.basename(following[0]) in INTERPRETERS:
            return "piping it into `%s`" % os.path.basename(following[0])
    return None


# --- the rule ----------------------------------------------------------------

def _describe(fetch):
    return "%s -> %s" % (shell_reader.readable(fetch.url) or "an unparsed URL",
                         shell_reader.readable(fetch.dest))


def _remedy(dest):
    return ('verify it first: `echo "<sha256>  %s" | sha256sum -c -` between '
            "the download and that use" % shell_reader.readable(dest))


def _runs_after_failure(when):
    """True when a step `if:` runs even after an earlier step failed -- `always()`,
    `failure()` or `!cancelled()` (any expression holding one, whitespace and case
    aside). `success()`, a plain expression and no `if:` are skipped then, so stay gated."""
    cond = re.sub(r"\s+", "", when[0] or "").lower() if when else ""
    return any(call in cond for call in ("always()", "failure()", "!cancelled()"))


def _binds(conditions, check, use):
    """May a check at statement `check` clear a use at statement `use`?

    Only if the check runs whenever the use does. Its condition is two halves -- the step's `if:`
    and the `if`/`while` branch it sits in (`workflow_forms.regions`); a check binds where both
    match, as written (no evaluation): a check and use sharing one `if:` (fleet's shape -- fetch,
    checksum and `unzip`) bind; a different condition, or one the use lacks, does not. A use
    whose `if:` RUNS AFTER A FAILED step (`_runs_after_failure` -- `always()`, `failure()` or
    `!cancelled()`) is refused unless the check shares it, since it runs on even when an earlier
    step's checksum stopped. Residual (#2608): a same-`if:` match in another step still binds --
    conditions cannot tell it from a true same-step one; stability of the `if:` is assumed."""
    when = conditions.get(check)
    theirs = conditions.get(use)
    if _runs_after_failure(theirs) and when != theirs:
        return False
    return when is None or when == theirs


def _defect(fetch, index, stmts, checks, conditions=None, unread=(), working=None):
    """Why this fetch is unverified; unread forms add uses, never replace parsed uses."""
    if fetch.url is None and fetch.dest is None:
        # `wget -i list.txt`, an argv assembled in a variable, `xargs curl -O`: a download whose
        # target this guard cannot name is not a clean step, it is an unread one.
        return ("runs `%s` with unresolved transfers: no URL and no destination "
                "this guard could parse, so it cannot say what arrived or whether "
                "anything checked it -- use explicit single-download commands "
                "with named files (`-o <path>`) and `sha256sum -c` checks" % fetch.tool)
    if fetch.dest is None:
        if not fetch.piped_to:
            return None
        if stdin_program(fetch.piped_to[:1]) == VALUE_PROGRAM:
            return ("pipes a download into `%s`, a command word this guard does not follow -- "
                    "download it to a file, `sha256sum -c` that file, then run it"
                    % shell_reader.readable(fetch.piped_to[0]))
        if os.path.basename(fetch.piped_to[0]) not in EXECUTORS:
            return None
        # Nothing landed on disk, so no checksum anywhere in the step can be
        # about these bytes: the only fix is to stop streaming them into a
        # shell (`curl ... | sh`, `eval "$(curl ...)"`, `bash <(curl ...)`).
        return ("hands %s straight to `%s`, so there is no file to check -- "
                "download it to a file, `sha256sum -c` that file, then run it"
                % (shell_reader.readable(fetch.url) or "a download",
                   " ".join(shell_reader.readable(t) for t in fetch.piped_to)))
    if shell_reader.has_substitution(fetch.dest):
        return ("fetches %s to an unknown destination (%s) containing a shell "
                "substitution, so this guard cannot bind the downloaded file "
                "to a checksum or later use -- name a stable file and verify it"
                % (shell_reader.readable(fetch.url) or "a download",
                   shell_reader.readable(fetch.dest)))
    working = working or {}
    dest = at_directory(fetch.dest, getattr(fetch.dest, "directory", working.get(index, ".")))
    names, uses = _uses(stmts, dest, after=index, working=working)
    uses += [(i, "may be run by a form the guard cannot read") for i in unread if i >= index]
    if not uses:
        return None                             # fetched and only read: not this rule
    conditions = conditions or {}
    naming = [(i, why) for i, text, why in checks if i > index
              and any(names_file(text, name, working.get(i, ".")) for name in sorted(names))]
    first_use, how = next(((u, h) for u, h in uses if not any(  # the first use no check clears
        clears(why, i, u) and _binds(conditions, i, u) for i, why in naming)), (None, None))
    if first_use is None:
        return None
    naming = [(i, why.at_use(i, first_use) if hasattr(why, "at_use") else why) for i, why in naming]
    cleared = [i for i, why in naming if why is None and _binds(conditions, i, first_use)]
    if cleared:
        # Ordering is the substance: a checksum that runs after the bytes are
        # made runnable is theatre.
        return ("verifies %s only AFTER %s -- fetches %s, so %s"
                % (shell_reader.readable(fetch.dest), how, _describe(fetch),
                   _remedy(fetch.dest)))
    if naming:
        # It NAMED the file. Saying "does not name" here sends the author
        # hunting a spelling bug in a line that is spelled right.
        why = (next((w for _i, w in naming if w), None)
               or _unshared(conditions, naming[0][0], first_use))
        return ("fetches %s and %s; the checksum that names %s %s -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   why, _remedy(fetch.dest)))
    if [i for i, _text, why in checks if i > index
            and (why.at_use(i, first_use) if hasattr(why, "at_use") else why) is None]:
        return ("fetches %s and %s; no checksum in the job names %s, and a "
                "checksum of a different file verifies nothing -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   _remedy(fetch.dest)))
    return ("fetches %s and %s with nothing verifying what arrived -- %s"
            % (_describe(fetch), how, _remedy(fetch.dest)))


def _defects(stmts, conditions=None, credit=None, walked=None, working=None):
    """[(statement index, why, what: its `Fetch`)] for every unverified fetch in parsed shell.

    Conditions, failure credit and cwd bind checks and uses; `kept` weighs unread forms
    beside fetch defects (#2481, #2490)."""
    working, conditions = working or {}, conditions or {}
    checks = _checks(stmts, credit, working)
    fetched, unread = walked or _walk(stmts, stream_exec=True)
    found = [(index, why, fetch) for index, fetch in fetched
             if (why := _defect(fetch, index, stmts, checks, conditions, working=working))]
    unverified = bool(found or unread and (unbound(stmts, fetched, unread) or any(
            _defect(fetch, index, stmts, checks, conditions, [i for i, _w in unread], working)
            for index, fetch in fetched)))
    return kept(unread, found, unverified)


def fetch_exec_defects(script):
    """Every unverified fetch-and-execute in one `run:` script."""
    return [why for _name, why in job_defects([("", script)], strict=True)]


def fetch_exec_defect(script):
    """Why this `run:` script fetches and executes without verifying, or None."""
    return "; ".join(fetch_exec_defects(script)) or None


def job_defects(steps, strict=False):
    """Defects for a job: steps share files but start fresh shells and cwd.
    Conditions and failure gates bind checks. `Unsure` scripts get a second fold;
    `strict` rejects an unread step."""
    found, seen, steps = [], set(), list(steps)     # read twice: a one-shot iterable, once
    for sure in (False, True):              # the second fold leaves every `Unsure` statement out
        stmts: list[shell_reader.Statement] = []
        owner, conditions, credit, working, entries, fetched, unread = [], {}, {}, {}, [], [], []
        for number, item in enumerate(steps):
            step = item if isinstance(item, Step) else Step(*item)
            why = unparseable(step.shell)
            if not why:
                try:                # the one read of every text, substitutions too
                    here = read(step.script, step.shell)
                    back = [i for i, s in enumerate(here) if not (sure and isinstance(s, Unsure))]
                    here = [here[i] for i in back]
                    branches, own = regions(here), step_credit(here, step.shell)
                    directories = working_directories(here, branches, number, own)
                    offset = len(stmts)
                    walked = _walk(here, True, working=dict(enumerate(directories)),
                                   scopes=range(offset, offset + len(here)))
                except (() if strict else shell_lex.Unreadable) as error:
                    why = "cannot read this step: %s; nothing in it is accepted" % error
            if why:
                entries.append(((None, number), step.name, why))
                continue
            fetched += [(len(stmts) + i, fetch) for i, fetch in walked[0]]
            unread += [(len(stmts) + i, reason) for i, reason in walked[1]]
            # Per step, because each one is its own shell invocation: neither an
            # `if` left open nor a `set +e` in step A reaches step B.
            for local, statement in enumerate(here):
                when = (step.condition, branches.get(local))
                if any(when):
                    conditions[len(stmts)] = when
                answer = own.get(local)
                soft = Reach(len(here) - local - 1, _SOFT_STEP)
                credit[len(stmts)] = (tuple(why or soft for why in answer or (None, None))
                                      if step.soft else answer)
                working[len(stmts)] = directories[local]
                stmts.append(statement)
                owner.append((step.name, (number, back[local])))
        entries += [((owner[index][1], what), owner[index][0], why)
                    for index, why, what in _defects(
                        stmts, conditions, credit, (fetched, unread), working)]
        found += [entry for entry in entries if entry[0] not in seen]
        seen = {key for key, _name, _why in found}
        if not any(isinstance(statement, Unsure) for statement in stmts):
            break
    return [(name, why) for _key, name, why in found]


def unparseable(shell):
    """Why this step's shell is not one this guard reads, or None.

    A `pwsh`, `python` or `cmd` step is not CLEAN, it is UNREAD, and the two
    answers must not look alike: `Invoke-WebRequest x.exe; ./x.exe` is the same
    act in a shell this parser has no grammar for."""
    words = (shell or "").split()
    if not words or os.path.basename(words[0]) in PARSED_SHELLS:
        return None
    return ("runs under `%s`, which this guard does not parse -- it cannot say "
            "whether the step downloads and executes anything; write it in "
            "bash/sh, or exempt the step with a reason" % shell)


def _default_shell(node):
    """`defaults: {run: {shell: ...}}` on a workflow or a job, or None."""
    defaults = node.get("defaults") if isinstance(node, dict) else None
    run = defaults.get("run") if isinstance(defaults, dict) else None
    return run.get("shell") if isinstance(run, dict) else None


def run_jobs(doc):
    """[(job id, [Step, ...])] -- each job's `run:` steps, in order.

    The shell is resolved the way Actions resolves it: the step's own `shell:`,
    else the job's `defaults.run.shell`, else the workflow's, else the runner
    default (bash on Linux, which is what this guard parses)."""
    jobs = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        steps = []
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not step.get("run"):
                continue
            shell = step.get("shell") or _default_shell(job) or _default_shell(doc)
            # A job-level `if:` makes every one of its steps conditional, and
            # a job-level `continue-on-error` makes every one of them soft.
            condition = step.get("if") or job.get("if")
            soft = bool(step.get("continue-on-error") or job.get("continue-on-error"))
            steps.append(Step(step.get("name") or UNNAMED, step["run"], shell, condition, soft))
        if steps:
            jobs.append((name, steps))
    return jobs


def run_steps(doc):
    """Every `run:` step in a parsed workflow, in job order."""
    return [step for _job, steps in run_jobs(doc) for step in steps]


def main(argv=None, out=print):
    """`python3 scripts/workflow_guard.py [workflow.yml ...]` -> 0 or 1."""
    import yaml                                 # not needed to IMPORT the rule
    paths = list(argv if argv is not None else sys.argv[1:])
    if not paths:
        directory = os.path.join(".github", "workflows")
        paths = sorted(os.path.join(directory, n) for n in os.listdir(directory)
                       if n.endswith((".yml", ".yaml")))
    defects = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle.read()) or {}
        for job, steps in run_jobs(doc):
            for name, why in job_defects(steps):
                defects.append("%s / %s / %s -- %s" % (os.path.basename(path), job, name, why))
    for line in defects:
        out(line)
    if defects:
        out("%d defect(s): unverified fetch-and-exec, or code the guard cannot read; "
            "see scripts/workflow_guard.py" % len(defects))
    return 1 if defects else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
