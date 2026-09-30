#!/usr/bin/env python3
r"""#1647 (ARC-F2C): what a workflow `run:` step FETCHES, and whether what it
then runs was checked against a digest bound to the file it downloaded.

The rule is #1529's: a workflow can step outside the supply chain that
SHA-pinned `uses:` references govern simply by curling a binary and running
it, so nothing unverified may become executable. The Dockerfile was hardened
for exactly this act (ten artifact fetches, every one `sha256sum -c`'d) and
`tests/test_dockerfile.py` guards it; the same act spelled in shell inside a
`run:` block was guarded by two regexes, and run-13 found both failing OPEN:

* the fetch pattern required a whitespace-separated short `-o`/`-O` and
  excluded pipe characters, so `curl -fsSL https://... | sh`,
  `wget -qO- ... | bash` and every `--output` form yielded an EMPTY fetch set
  -- not "unverified", not seen as a download at all; and
* "verified" was the first `sha256sum`/`shasum` carrying `-c` anywhere earlier
  in the step, bound to no path and no digest, so an unrelated checksum of one
  artifact cleared a later `curl -o payload; chmod +x payload`.

A regex over shell text reports a clean pass on every form it cannot parse,
which is the worst answer a control can give -- so the guard parses the shell
instead. `scripts/shell_reader.py` does that half (comments, continuations,
heredocs, substitutions, quoting, redirections, separators, wrappers) and
`scripts/workflow_forms.py` the argv shapes above it (what a fetcher was told,
what an operand stands for, where a script hides in a string); this module
asks the two supply-chain questions of the result: which statements FETCH, and
which statements CHECK what a fetch wrote -- naming that path, carrying a
digest, in a position where the check's failure still stops the job, before
the statement that first uses it.

The scope is the JOB, not the step (`job_defects`): steps in one job share the
workspace, /tmp and PATH, so a download in step A and the `chmod +x`/run in
step B is one act split into two innocent halves, and a `sha256sum -c` in a
later step is a real check of an earlier step's file. A step whose `shell:` is
not bash/sh (pwsh, python, cmd) is reported UNREAD rather than clean -- the
same act in a grammar this module does not have, and so is a heredoc body
handed to such an interpreter as its program (`python3 - <<'EOF'`). So is a
step the reader refuses to guess at (`shell_lex.Unreadable`), by its name.

Stdlib only, so the test suite imports it with no dependency. `main()` reads
YAML and is the same rule for a human at a shell:

    python3 scripts/workflow_guard.py .github/workflows/*.yml

CI gets NO separate lint step for it: `tests/test_workflow_pins.py` applies
this module to every `run:` step in the fleet and `ci.yml` runs the suite on
every PR, so a second invocation would be the same assertion wearing a
different hat -- and one that can rot out of step with the first.

What it does not model. Within the shell it reads, the standing requirement is
to fail CLOSED -- an unparsed form must be REPORTED, not accepted, which is
precisely what the two regexes did not do, and `tests/test_workflow_guard.py`
states every form that was probed and found open before it was parsed. The
classes below fall outside that and are accepted SILENT gaps, deliberately.

#1697 ruled every entry by REACHABILITY -- can the form appear in a `run:`
step of this fleet, or does it need a construct the runners never use or a
grammar this module does not have by design? Four entries were reachable and
left this list CLOSED rather than documented, each of them shell the reader
already produced and the rule simply did not look at: a `chmod` over a glob
and over a walked directory, the `{}` and `xargs` operands that describe a
file instead of naming it, a fetch inside an `eval`/`sh -c` STRING, and
`continue-on-error: true`. What remains keeps its entry WITH its reason, and
`TestTheGapsTheGuardDocuments` runs all of them as live steps -- so a change
that starts catching one fails there, and this list is edited with it.

* fetchers that are not curl/wget -- `gh release download`, `aws s3 cp`,
  `python3 -c "...urlretrieve..."`, an action that downloads for you. Reporting
  every command that might reach the network would be noise, not a gate, and
  the `uses:` pin rule covers the action half. If one of these lands in a
  workflow, the fetch-and-exec rule will not see it.
  KEPT: every download this repo writes -- the fleet's two, the Dockerfiles'
  ten -- is curl. A second tool needs a second option grammar (`gh`'s `-O` is
  not curl's, and `aws s3 cp` copies locally too), and a fetch inside
  `python3 -c` needs another language entirely.
* variable expansion: `${VERSION}` and `$TMP` stay literal, because the guard
  tracks the NAME a step writes. A checksum naming the same variable binds; a
  path spelled differently at fetch and at use matches nothing, and no `cd` is
  followed (`curl -o d/x; cd d; sh x`) -- but the side that RUNS compares last parts
  where a `$` spells the use's directory (`may_run` #2310, `covers` #2345; argv only),
  and for a glob where one spells the download's or the download is a bare name.
  A download kept in a variable is followed to a shell whole (`carried`, #2341),
  not through a cut (`${x//$'\r'/}`), a command's output (`y=$(echo "$x")`) or `> f`,
  and `( x=1 )` empties it only with the `(` alone on its line, which the reader drops.
  KEPT: binding two spellings of one path means EVALUATING the shell, which
  the reader does not do by design; the fleet puts its variables in the URL
  and a literal in `-o` (`-o dc.zip`, `-o /tmp/hadolint`).
* directories on the runner's PATH not in `workflow_operands.PATH_DIRS` (#2308),
  `$HOME/.cargo/bin` and `/snap/bin` among them, or one a step puts there
  (`PATH=…`, `>> "$GITHUB_PATH"`): a bare name finds a download in neither.
  KEPT: the first differ by image (review N-4); the other is a VALUE, which
  is evaluating the shell again. No workflow here touches PATH at all.
* a digest computed from the download itself: `SHA="$(sha256sum x | cut ...)"`
  and then `echo "$SHA  x" | sha256sum -c -` clears x with x's own bytes.
  KEPT: it is variable expansion wearing a checksum -- refusing it means
  following a variable's VALUE. Only this spelling is open: with the digest in
  a sums file the step wrote, what was recorded is the text `sha256sum x`,
  which carries no digest, so the check does not count and the fetch is
  already reported.
* what runs inside a container, BEYOND the one shape that is read: `docker
  run … -v /tmp:/w img bash /w/x.sh` binds by basename (`workflow_forms.in_container`),
  because on the far side of a bind mount the basename is the only name the
  bytes have. What is still unread is everything that needs the mount table
  itself -- a file renamed by the mount (`-v /tmp/x.sh:/w/y.sh`), an argument
  the image's ENTRYPOINT supplies, and whatever the image itself runs.
  KEPT: those need another executor's mounts and entrypoint modelled, which is
  reading a second program's configuration rather than this job's shell. The
  image the container came from is NOT pinned either, and that is a decided
  residual rather than an oversight: this fleet pulls the tools image by its
  mutable `:latest` tag -- the `IMAGE` env binding and the `docker pull` in
  each consumer: the "Pull or build panopticon-tools image" step of
  `security.yml` and of `security-fork.yml`, and both "Pull the nightly tools
  image" steps of `adapter-integration.yml`. DEVELOPMENT.md states
  the consequence in its own voice twice, in the "One residual to know about"
  paragraph under "Key design decisions" and in the "Weekly strict security
  backstop" paragraph ("the tools image remains unpinned"). The `uses:`
  rule pins ACTIONS by SHA and `tests/test_dockerfile.py` pins what the
  Dockerfile FETCHES (`test_all_fetched_binaries_are_checksum_verified`,
  `test_nvd_data_ref_default_is_digest`); neither governs a `docker pull` of a
  tag.
* an executor that reads the file by convention rather than by argument
  (`make`, `npm install`): the download is never an operand, so no use names
  it.
  KEPT: needs a construct this fleet does not have -- there is no Makefile and
  no package.json outside a test fixture, no `run:` step invokes either tool,
  and the repo builds with Python and Docker.
* bytes modified after a passing check: `sha256sum -c` then `sed -i` then run.
  OUT OF SCOPE rather than unreached: the rule is about what ARRIVED from
  outside, and a workflow editing its own downloaded file is
  author-deterministic -- that `sed` is in the repo under review.
* a heredoc body read inside a command substitution, `EOF` and `)` each on a
  line (`eval "$(cat <<'EOF' … EOF)"`; `x=$(bash -s <<'EOF' … EOF)`, review
  I-4). The OUTER parse lifts the body and leaves a marker: a re-read sees a
  word meaning nothing to it, and what `eval` or `bash` runs is unread.
  KEPT: resolving it means handing one parse's tables to another, or teaching
  the reader that a heredoc read by `cat` inside a substitution is a SCRIPT --
  a second expansion model. The fleet writes one heredoc-ish construct (a
  `<<<` here-string in docker-publish.yml) and no `cat <<EOF` at all. It no
  longer CRASHES, which is what it did until #1697's review.
  CLOSED outside a substitution for the OTHER heredoc spelling, the body handed
  to an interpreter as the PROGRAM it runs (`bash -s <<'EOF'`, `sh <<< '…'`,
  `python3 - <<'EOF'` -- #1839, #2293 and run-14 SEC-3915165799).
  Two facts decide it and both are already parsed: whether a command's program
  is its standard input at all (`workflow_programs.stdin_program`, an operand walk
  -- a `-c` string, a `-m` module and a script FILE each put it elsewhere, and
  then the body is that program's input DATA), and which body descriptor 0
  finally reads, with the flag saying whether it EXPANDED
  (`shell_reader`'s `Stage.stdin_heredoc`). A QUOTED body reaches the
  interpreter as the text it was written as, so `workflow_forms.flattened`
  reads it exactly as it reads an `eval` string -- a `curl … | sh` inside it
  is the defect it is at the top level. An EXPANDING one is REPORTED unread
  (`_unread_stdin`): it runs what bash expands it to, and a body's `$(...)`
  were lifted into the enclosing parse's table before this text was reached
  -- this entry's own gap, one redirection over. A program in a language this
  module has no grammar for is reported too, the answer `unparseable` gives a
  `shell: python` step. What that leaves unread: an interpreter whose program
  is on stdin in a spelling the operand walk does not resolve -- behind an
  option it reads as a filename (`bash --rcfile f <<'EOF'`), since it knows
  only `-o`/`-O` as options taking a separate value, or named as a FILE by a
  builtin outside its table (`. /dev/stdin <<'EOF'`); an interpreter behind a
  TRANSPORT (`ssh host bash -s <<'EOF'`, `docker run -i img bash -s <<'EOF'`,
  `docker exec -i c sh <<'EOF'`), whose argv this walk reads as the transport's;
  and, as everywhere in this module, an interpreter under a name its tables do
  not carry (`python3.11 -`, `busybox sh`) -- the answer is keyed on the
  program's basename.
  A heredoc the step WRITES to a file and then runs
  (`cat <<'EOF' > x.sh` … `bash x.sh`) is not this rule's business at all: the
  script is text in the repo under review, which is the `sed -i` entry's
  author-deterministic ruling.
* `if:` conditions are compared as WRITTEN (`_binds`), which assumes the
  expression is stable between the check's step and the use's step. It is not
  when it reads `env.*` written through `$GITHUB_ENV` in between, or a forward
  `steps.<id>.*` reference.
  KEPT: deciding it means EVALUATING a GitHub expression against a context
  this module never sees. `continue-on-error: true` was the other half of this
  entry and is now read -- see `job_defects`.

`if` branches inside the shell are read flat for what they FETCH and what they
RUN -- folding those in can only report more. Not for what they CHECK:
`workflow_forms.regions` reads the `then`/`else`/`do` bodies -- and each arm of
a `case` -- back out of the statement stream, and a checksum written inside a
branch clears only a use written inside the same branch (#1697 item 3), which
is `_binds` again in the shell's own grammar.
"""
import collections
import os
import re
import sys

import shell_lex
import shell_reader
from shell_reader import command, statements
from workflow_forms import (BIN_DIRS, CONTAINERS, FETCHERS, SHELL_PROGRAM, STDOUT, Reach,
                            carried, chmod_executable, chmod_targets, clears, covers, described,
                            flattened, in_container, kept, may_run, names_file, parse_fetch,
                            regions, same_file, stdin_program, step_credit, streamed_fetch,
                            substitution_script, swallowed, within)


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
# An expected digest: a hex literal, or the variable a workflow pins one in
# (`${HADOLINT_SHA256}`, `$SHA`). Naming a file is not checking it -- something
# in the checked line has to BE the expectation -- and ANY expansion is not
# good enough either: `echo "$FILE  /tmp/payload" | sha256sum -c -` carries a
# path where the digest belongs, so the name has to say digest.
_DIGEST = re.compile(r"\b[0-9a-f]{40,128}\b"
                     r"|\$\{?\w*(?:SHA|SUM|DIGEST|HASH|CHECKSUM)\w*\}?", re.I)


# --- which statements fetch --------------------------------------------------

def _walk(stmts, stream_exec=False, inside=False):
    """([(statement index, Fetch)], [(statement index, why it is unread or carried)]).

    Every download in the script, and every command this module cannot read,
    asked of each stage in ONE walk -- the first read of each command
    substitution as a script of its own, so a caller that walks inside a
    catch (`job_defects`) has read every text anything here reads.

    A fetch in a substitution is credited to the command that CONSUMES it --
    `eval`, `sh -c`, `bash <(...)` -- because that is what decides whether
    the downloaded bytes become behaviour, and so is one a variable carries
    (`carried`, where the walk found a fetch). Three forms are REPORTED unread:
    a command that cannot be resolved (`shell_reader.unresolved_wrapper`), a
    stdin program not readable as written (`_unread_stdin`) and, `inside` a
    substitution, a script handed to a shell (`substitution_script`), which `kept` weighs.
    """
    found, unread = [], []
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
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
                    found.append((index, fetch))
            reason = shell_reader.unresolved_wrapper(stage.argv)
            if reason:
                behind = " behind wrapper" if shell_reader.wrapper_words(stage.argv) else ""
                unread.append((index, "cannot read command%s: %s; the guard cannot "
                               "determine what it runs" % (behind, reason)))
            reason = _unread_stdin(stage) or inside and substitution_script(argv, stage, _walk)
            if reason:
                unread.append((index, reason))
            consumer = tuple(t for t in argv if not shell_reader.is_marker(t)) or None
            executes = consumer and os.path.basename(consumer[0]) in EXECUTORS
            for inner in stage.substitutions:
                fetched, nested = _walk(statements(inner), stream_exec, True)
                unread.extend((index, why) for _index, why in nested)
                found.extend((index, fetch._replace(piped_to=consumer)
                              if executes or fetch.piped_to is None else fetch)
                             for _index, fetch in fetched)
    return found, unread + (carried(stmts, EXECUTORS) if found else [])


def _fetch_records(stmts, stream_exec=False):
    """[(statement index, Fetch)] for every download in the script."""
    return _walk(stmts, stream_exec)[0]


def _unread_stdin(stage):
    """Why the program on this stage's STANDARD INPUT goes unread, or None.

    A heredoc body or here-string handed to an interpreter is a program, not
    data (`workflow_programs.stdin_program`), and two kinds of it cannot be read:
    one in a language this module has no grammar for, and one the shell would
    EXPAND -- a body whose `$(...)` were lifted into the enclosing parse's
    table before it reached here, a here-string whose word bash expands first
    (#2293) -- so what the interpreter runs is not the text this module holds.
    Quoted shell is the third kind and is READ, in `workflow_programs.stdin_scripts`.
    """
    argv = command(stage.argv)
    here = stage.stdin_heredoc
    kind = stdin_program(argv) if here else None
    if kind is None:
        return None
    name = os.path.basename(argv[0])
    if kind != SHELL_PROGRAM:
        return ("hands a heredoc body or here-string to `%s` as the program to "
                "run, which this guard does not parse -- it cannot say whether "
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


def _checked_text(statement, position, stage, argv, written):
    """The text a checksum stage reads, or None if nothing ties it to one.

    Three ways a step says what it expects, and each is BOUND to a source: a
    heredoc body, a sums file this same step wrote, or the previous pipeline
    stage (`echo "<sha>  <file>" | sha256sum -c -`). A `sha256sum -c` over a
    file nothing in the step produced ties this check to no download.
    """
    if stage.heredoc:
        return stage.heredoc
    files = [f for f in _operands(argv) + stage.reads if f not in STDOUT]
    # `shasum -a 256 -c -`: the `256` is `-a`'s value, not a sums file.
    files = [f for f in files if not re.fullmatch(r"\d+", f)]
    if files:
        known = [written[f] for f in files if f in written]
        return "\n".join(known) if known else None
    if position:
        return " ".join(command(statement.stages[position - 1].argv))
    return None


def _record_writes(statement, written):
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
            written[target] = text


# Why a checksum this job ran clears nothing. A refused check is KEPT with its
# reason rather than dropped, because "no checksum in the job names this file"
# and "the checksum that names it was handed to a `|| true`" are different
# sentences, and only one of them is true of any given step.
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


def _checks(stmts, credit=None):
    """[(statement index, checked text, why it clears nothing or None)]."""
    found = []
    written: dict[str, str] = {}
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if not argv or os.path.basename(argv[0]) not in CHECKSUM_TOOLS:
                continue
            if not _has_check_flag(argv):
                continue
            text = _checked_text(statement, position, stage, argv, written) or ""
            why = swallowed(stmts, index, statement, stage, (credit or {}).get(index))
            if (why is None or isinstance(why, Reach)) and not _DIGEST.search(text):
                why = _NO_DIGEST
            found.append((index, text, why))
        _record_writes(statement, written)
    return found


# --- which statements execute what was fetched -------------------------------

def _copies(statement, names):
    """The new names this statement gives a file it already knows.

    `cp payload alias`, `mv`, `ln -s`, `cat payload > alias`: renaming is not
    executing, but it LAUNDERS -- run `alias` and the bytes are the download's,
    under a name the guard never heard of. So the alias inherits, and the copy
    itself stays innocent (copying a fetched JSON is still just a copy).
    """
    new = set()
    for stage in statement.stages:
        argv = command(stage.argv)
        if not argv:
            continue
        name, operands = os.path.basename(argv[0]), _operands(argv)
        if name in ("cp", "mv", "ln") and len(operands) > 1:
            if any(same_file(o, n) for o in operands[:-1] for n in names):
                new.add(operands[-1])
        if name == "cat" and stage.writes:
            if any(same_file(o, n) for o in operands for n in names):
                new.update(stage.writes)
    return new


def _uses(stmts, dest, after):
    """(names the file goes by, [(statement index, what it does)]), walked in
    order from the fetch so a name only counts once the statement creating it
    has run; a use in a statement's substitutions (`within`) is that statement's."""
    names, out = {dest}, []
    for index, statement in enumerate(stmts[after:], after):
        for inner, position, stage, where in within(statement):
            argv, how = command(stage.argv), None
            for name in sorted(names):
                how = _use(inner, position, stage, argv, name)
                if how:
                    if not same_file(name, dest):
                        how += " (as `%s`, copied from it earlier)" % name
                    break
            if how:
                out.append((index, how + where))
                break
        names |= _copies(statement, names)
    return names, out


def _use(statement, position, stage, argv, dest):
    if any(may_run(word, dest) for word in shell_reader.wrapper_words(stage.argv)):
        return "running it"  # `./flock 9` is read through as `flock`, but runs ./flock
    if not argv:
        return None
    argv, handed, recursive = described(statement, position, stage, argv)
    name, rest = os.path.basename(argv[0]), argv[1:]
    if name == "chmod":
        rest = chmod_targets(argv)
    mentions = [t for t in rest + handed if covers(t, dest, recursive)]
    if name in CONTAINERS:
        interpreter = in_container(argv, dest, INTERPRETERS)
        if interpreter:
            return "running it inside a container under `%s`" % interpreter
    if name in INTERPRETERS and any(same_file(r, dest) for r in stage.reads):
        # `bash < payload`, `sh -s -- --yes < payload`: the file is never an
        # argument, so argv alone shows an interpreter with nothing after it.
        return "running it under `%s` from standard input" % name
    if name == "chmod" and mentions and chmod_executable(argv):
        return "making it executable"
    if may_run(argv[0], dest):
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


def _binds(conditions, check, use):
    """May a check at statement `check` clear a use at statement `use`?

    Only if the check runs whenever the use does. A step carrying an `if:` may
    be skipped, so its checksum cannot clear an execution that is not skipped
    with it -- crediting one is fail-open. The condition has two halves: the
    step's `if:`, and the `if`/`while` branch of the SHELL the statement was
    written inside (`workflow_forms.regions`) -- a check binds only where both
    match. Conditions are compared as written
    (no expression evaluation), so a check and a use in the same conditional
    step -- the shape the fleet actually has, where the fetch, the checksum and
    the `unzip` share one `if:` -- binds, and a check under a DIFFERENT
    condition (or under one at all, where the use has none) does not.

    Comparing as written assumes the expression is stable between the two
    steps; see the module docstring's gap list for the cases where it is not.
    """
    when = conditions.get(check)
    return when is None or when == conditions.get(use)


def _defect(fetch, index, stmts, checks, conditions=None):
    """Why this one fetch is unverified, or None."""
    if fetch.url is None and fetch.dest is None:
        # `wget -i list.txt`, an argv assembled in a variable, `xargs curl -O`:
        # a download whose target this guard cannot name is not a clean step,
        # it is an unread one.
        return ("runs `%s` with unresolved transfers: no URL and no destination "
                "this guard could parse, so it cannot say what arrived or whether "
                "anything checked it -- use explicit single-download commands "
                "with named files (`-o <path>`) and `sha256sum -c` checks" % fetch.tool)
    if fetch.dest is None:
        if not fetch.piped_to or os.path.basename(fetch.piped_to[0]) not in EXECUTORS:
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
    names, uses = _uses(stmts, fetch.dest, after=index)
    if not uses:
        return None                             # fetched and only read: not this rule
    # A checksum naming any name the file goes by is a checksum of this file.
    conditions = conditions or {}
    naming = [(i, why) for i, text, why in checks if i > index
              and any(names_file(text, name) for name in sorted(names))]
    first_use, how = next(((u, h) for u, h in uses if not any(  # the first use no check clears
        clears(why, i, u) and _binds(conditions, i, u) for i, why in naming)), (None, None))
    if first_use is None:
        return None
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
    if [i for i, _text, why in checks if i > index and why is None]:
        return ("fetches %s and %s; no checksum in the job names %s, and a "
                "checksum of a different file verifies nothing -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   _remedy(fetch.dest)))
    return ("fetches %s and %s with nothing verifying what arrived -- %s"
            % (_describe(fetch), how, _remedy(fetch.dest)))


def _defects(stmts, conditions=None, credit=None, walked=None):
    """[(statement index, why)] for every unverified fetch in parsed shell.

    `conditions` maps a statement index to the PAIR that decides whether it
    runs -- the `if:` of the step it came from, and the shell branch it was
    written inside (`workflow_forms.regions`); absent = unconditional on both
    counts. A check clears a use only where both halves match -- see `_binds`.
    `credit` maps an index to its step's own answer for a check there, which
    `workflow_gating.swallowed` reads last: `workflow_forms.step_credit`'s, or
    `_SOFT_STEP` where the step carries `continue-on-error: true`, whose
    checks clear nothing at all. `walked` is `_walk`'s answer for `stmts`,
    which `job_defects` has from each step's own read.
    """
    checks = _checks(stmts, credit)
    conditions = conditions or {}
    fetched, unread = walked or _walk(stmts, stream_exec=True)
    found = kept(unread, fetched)
    for index, fetch in fetched:
        why = _defect(fetch, index, stmts, checks, conditions)
        if why:
            found.append((index, why))
    return found


def fetch_exec_defects(script):
    """Every unverified fetch-and-execute in one `run:` script."""
    stmts = read(script)
    branches = regions(stmts)
    return [why for _index, why in
            _defects(stmts, {i: (None, b) for i, b in branches.items()}, step_credit(stmts))]


def fetch_exec_defect(script):
    """Why this `run:` script fetches and executes without verifying, or None."""
    return "; ".join(fetch_exec_defects(script)) or None


def job_defects(steps):
    """[(step name, why)] for one job's `run:` steps, folded in order.

    A step carrying an `if:` is folded for what it FETCHES and what it RUNS;
    its CHECK is credited only to a use that shares the same condition (see
    `_binds`), because a checksum that may be skipped cannot clear an
    execution that is not. A step carrying `continue-on-error: true` is folded
    the same way and its CHECK is credited to nothing: the job carries on past
    its failure, which is `|| true` spelled in YAML.

    THE SCOPE IS THE JOB, not the step. Steps in a job share the workspace,
    /tmp and PATH, so `curl -o /tmp/x` in step A and `chmod +x /tmp/x; /tmp/x`
    in step B is one fetch-and-exec written across two innocent-looking steps
    -- and a rule scoped to a single `run:` block sees neither half. The same
    sharing is what makes a `sha256sum -c` in a later step a real check of an
    earlier step's download, so the fold has to run both ways.

    Parsed STATEMENTS are concatenated, never the texts: each step is its own
    shell invocation, so one step's stray quote or unterminated heredoc must
    not reach into the next step's parse. Each defect is attributed to the step
    that performed the fetch.
    """
    stmts: list[shell_reader.Statement] = []
    owner = []
    conditions = {}
    credit = {}
    found, fetched, unread = [], [], []
    for item in steps:
        step = item if isinstance(item, Step) else Step(*item)
        why = unparseable(step.shell)
        if not why:
            try:                    # the one read of every text, substitutions too
                here = read(step.script, step.shell)
                walked = _walk(here, stream_exec=True)
            except shell_lex.Unreadable as error:
                why = "cannot read this step: %s; nothing in it is accepted" % error
        if why:
            found.append((step.name, why))
            continue
        fetched += [(len(stmts) + i, fetch) for i, fetch in walked[0]]
        unread += [(len(stmts) + i, reason) for i, reason in walked[1]]
        # Per step, because each one is its own shell invocation: neither an
        # `if` left open nor a `set +e` in step A reaches step B.
        branches, own = regions(here), step_credit(here, step.shell)
        for local, statement in enumerate(here):
            when = (step.condition, branches.get(local))
            if any(when):
                conditions[len(stmts)] = when
            credit[len(stmts)] = (_SOFT_STEP,) * 2 if step.soft else own.get(local)
            stmts.append(statement)
            owner.append(step.name)
    found.extend((owner[index], why)
                 for index, why in _defects(stmts, conditions, credit, (fetched, unread)))
    return found


def unparseable(shell):
    """Why this step's shell is not one this guard reads, or None.

    A `pwsh`, `python` or `cmd` step is not CLEAN, it is UNREAD, and the two
    answers must not look alike: `Invoke-WebRequest x.exe; ./x.exe` is the same
    act in a shell this parser has no grammar for.
    """
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
    default (bash on Linux, which is what this guard parses).
    """
    jobs = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        steps = []
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not step.get("run"):
                continue
            shell = (step.get("shell") or _default_shell(job)
                     or _default_shell(doc))
            # A job-level `if:` makes every one of its steps conditional, and
            # a job-level `continue-on-error` makes every one of them soft.
            condition = step.get("if") or job.get("if")
            soft = bool(step.get("continue-on-error")
                        or job.get("continue-on-error"))
            steps.append(Step(step.get("name") or UNNAMED, step["run"], shell,
                              condition, soft))
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
                defects.append("%s / %s / %s -- %s"
                               % (os.path.basename(path), job, name, why))
    for line in defects:
        out(line)
    if defects:
        out("%d defect(s): unverified fetch-and-exec, or code the guard cannot read; "
            "see scripts/workflow_guard.py" % len(defects))
    return 1 if defects else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
