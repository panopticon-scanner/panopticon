#!/usr/bin/env python3
"""#1647 (ARC-F2C): what a workflow `run:` step FETCHES, and whether what it
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
heredocs, substitutions, quoting, redirections, separators, wrappers); this
module asks the two supply-chain questions of the result: which statements
FETCH, and which statements CHECK what a fetch wrote -- naming that path,
carrying a digest, in a position where the check's failure still stops the
job, before the statement that first uses it.

The scope is the JOB, not the step (`job_defects`): steps in one job share the
workspace, /tmp and PATH, so a download in step A and the `chmod +x`/run in
step B is one act split into two innocent halves, and a `sha256sum -c` in a
later step is a real check of an earlier step's file. A step whose `shell:` is
not bash/sh (pwsh, python, cmd) is reported UNREAD rather than clean -- the
same act in a grammar this module does not have.

Stdlib only, so the test suite imports it with no dependency (`import
workflow_guard` -- repo-root `scripts/` is on the path via tests/conftest.py).
`main()` reads YAML and is the same rule for a human at a shell:

    python3 scripts/workflow_guard.py .github/workflows/*.yml

CI gets NO separate lint step for it: `tests/test_workflow_pins.py` applies
this module to every `run:` step in the fleet and `ci.yml` runs the suite on
every PR, so a second invocation would be the same assertion wearing a
different hat -- and one that can rot out of step with the first.

What it does not model. Within the shell it reads, the standing requirement is
to fail CLOSED -- an unparsed form must be REPORTED, not accepted, which is
precisely what the two regexes did not do, and `tests/test_workflow_guard.py`
states every form that was probed and found open before it was parsed. The
classes below fall outside that and are accepted SILENT gaps, deliberately:

* fetchers that are not curl/wget -- `gh release download`, `aws s3 cp`,
  `python3 -c "...urlretrieve..."`, an action that downloads for you. Reporting
  every command that might reach the network would be noise, not a gate, and
  the `uses:` pin rule covers the action half. If one of these lands in a
  workflow, the fetch-and-exec rule will not see it.
* variable expansion: `${VERSION}` and `$TMP` stay literal, because the guard
  tracks the NAME a step writes. A checksum naming the same variable binds; a
  path spelled differently at fetch and at use matches nothing, including its
  own use, so that download goes unseen.
* what runs inside a container: `docker run ... image bash /w/x.sh` (and
  `podman run`) is one command to this parser. Modelling another executor's
  argv, its mounts and its entrypoint is a second guard's job; the image the
  container came from is pinned by digest elsewhere (`tests/test_dockerfile.py`,
  the `uses:` pin rule).
* bytes modified after a passing check: `sha256sum -c` then `sed -i` then run.
  The rule is about what ARRIVED from outside, and a workflow editing its own
  downloaded file is author-deterministic, not an upstream vector.

* a `chmod` over a glob (`chmod +x *.sh`): the guard tracks names, a glob
  names nothing it can bind, so that use goes unseen.
* a fetch inside an `eval` STRING (`eval "curl -o x URL"`), an executor that
  reads the file by convention rather than by argument (`make`, `npm install`),
  a digest computed from the download itself, and `find -exec` / `xargs`
  operands: probed and found open on the last review pass, recorded in the
  follow-up issue rather than modelled here.
* `if:` conditions are compared as WRITTEN (`_binds`), which assumes the
  expression is stable between the check's step and the use's step. It is not
  when it reads `env.*` written through `$GITHUB_ENV` in between, or a forward
  `steps.<id>.*` reference, and `continue-on-error: true` on the check step is
  not read at all -- the YAML twin of `|| true`.

`if` branches inside the shell are read flat: a fetch inside one is a fetch,
and a check inside a `then` branch is credited although it may not run.
"""
import collections
import fnmatch
import os
import re
import sys

import shell_reader
from shell_reader import command, conditional, negated, statements

# A download: the tool that ran, the URL it was given, the file it lands in
# (None = standard output, which is the pipe-to-shell shape), and the argv of
# the next pipeline stage (None when the fetch ends the pipeline).
Fetch = collections.namedtuple("Fetch", "tool url dest piped_to")

# One `run:` step: its name, its script, the shell it will run under, the `if:`
# that decides whether it runs at all, and whether its own failure stops the
# job -- `continue-on-error: true` is the YAML twin of `|| true`.
Step = collections.namedtuple("Step", "name script shell condition soft",
                              defaults=(None, None, False))

FETCHERS = ("curl", "wget")
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
# `mv`/`cp` of a fetched file into one of these is what makes it runnable by
# name for the rest of the job.
BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin",
            "/opt/bin", "/bin", "/sbin")
# An expected digest: a hex literal, or the variable a workflow pins one in
# (`${HADOLINT_SHA256}`, `$SHA`). Naming a file is not checking it -- something
# in the checked line has to BE the expectation -- and ANY expansion is not
# good enough either: `echo "$FILE  /tmp/payload" | sha256sum -c -` carries a
# path where the digest belongs, so the name has to say digest.
_DIGEST = re.compile(r"\b[0-9a-f]{40,128}\b"
                     r"|\$\{?\w*(?:SHA|SUM|DIGEST|HASH|CHECKSUM)\w*\}?", re.I)

# curl and wget spell the same options differently, and the difference is
# load-bearing: curl's `-o` is the output file, wget's `-o` is the LOG file and
# its `-O` is the output document. One shared table writes a log path into the
# guard's dest field and then verifies the wrong thing.
# Short options that consume the next word, so it is not mistaken for the URL:
# curl's -A/-b/-c/-C/-d/-D/-e/-E/-F/-H/-K/-m/-o/-P/-Q/-r/-t/-T/-u/-U/-w/-x/-X/
# -y/-Y/-z, wget's -a/-o/-O/-i/-B/-t/-T/-w/-Q/-P/-D/-A/-R/-I/-X/-U/-e/-l.
_VALUE_SHORT = {"curl": set("AbcCdDeEFHKmoPQrtTuUwxXyYz"),
                "wget": set("aoOiBtTwQPDARIXUel")}
_VALUE_LONG = {
    "curl": {"output", "url", "connect-timeout", "max-time", "retry",
             "retry-delay", "retry-max-time", "header", "data", "data-raw",
             "data-binary", "data-urlencode", "user", "user-agent", "proxy",
             "proxy-user", "cacert", "capath", "cert", "key", "cookie",
             "cookie-jar", "referer", "request", "range", "write-out",
             "max-filesize", "limit-rate", "resolve", "form", "form-string",
             "oauth2-bearer", "unix-socket", "interface", "dump-header",
             "upload-file", "continue-at", "config", "location-trusted"},
    "wget": {"output-document", "output-file", "append-output",
             "directory-prefix", "timeout", "connect-timeout", "read-timeout",
             "dns-timeout", "tries", "waitretry", "wait", "user", "password",
             "user-agent", "header", "quota", "input-file", "base", "referer",
             "post-data", "post-file", "ca-certificate", "certificate",
             "private-key", "limit-rate", "bind-address"},
}
_DEST_SHORT = {"curl": "o", "wget": "O"}
_DEST_LONG = {"curl": ("output",), "wget": ("output-document",)}
# The directory the file lands in when it is not part of the destination:
# curl's `--output-dir` applies to `-o` and `-O` alike; wget's `-P` applies to
# the default name only (`-O` wins outright).
_DIR_LONG = {"curl": ("output-dir",), "wget": ("directory-prefix",)}
_DIR_SHORT = {"curl": "", "wget": "P"}
_STDOUT = ("-", "/dev/stdout", "/dev/fd/1", "/dev/null")
# `curl --version` in a diagnostics step downloads nothing; without this it
# parses as a fetch with no URL, which the rule now REPORTS rather than drops.
_INFORMATIONAL = ("--version", "-V", "--help", "-h", "--manual", "-M", "--usage")
_UNSET = object()


# --- which statements fetch --------------------------------------------------

def _basename(url):
    if not url:
        return None
    name = os.path.basename(url.split("?", 1)[0].split("#", 1)[0].rstrip("/"))
    return name or None


def _pick_url(operands):
    """The operand that is the URL. A scheme wins outright; a variable is the
    next best answer (`curl -o x "$URL"`); otherwise the first operand, which
    is where both tools take it."""
    for operand in operands:
        if "://" in operand:
            return operand
    for operand in operands:
        if operand.startswith("$"):
            return operand
    return operands[0] if operands else None


def _parse_fetch(tool, args, stage, piped_to):
    """One `curl`/`wget` argv -> the Fetch it performs."""
    value_short, value_long = _VALUE_SHORT[tool], _VALUE_LONG[tool]
    dest_short, dest_long = _DEST_SHORT[tool], _DEST_LONG[tool]
    dir_short, dir_long = _DIR_SHORT[tool], _DIR_LONG[tool]
    dest, remote_name, operands, i = _UNSET, False, [], 0
    directory = None
    while i < len(args):
        token, i = args[i], i + 1
        if token == "--":
            operands.extend(args[i:])
            break
        if token.startswith("--"):
            name, sep, inline = token[2:].partition("=")
            if name in dest_long:
                dest = inline if sep else (args[i] if i < len(args) else None)
                i += 0 if sep else 1
            elif name in dir_long:
                directory = inline if sep else (args[i] if i < len(args) else None)
                i += 0 if sep else 1
            elif name in value_long and not sep:
                i += 1
            continue
        if token.startswith("-") and len(token) > 1:
            j = 1
            while j < len(token):
                ch, j = token[j], j + 1
                if ch == dest_short:
                    dest = token[j:] if token[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if token[j:] else 1
                    break
                if tool == "curl" and ch == "O":
                    remote_name = True
                    continue
                if dir_short and ch == dir_short:
                    directory = token[j:] if token[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if token[j:] else 1
                    break
                if ch in value_short:
                    if not token[j:]:
                        i += 1
                    break
            continue
        operands.append(token)
    url = _pick_url(operands)
    if url is None and any(a in _INFORMATIONAL for a in args):
        return None                             # `curl --version`, `wget --help`
    named = dest is not _UNSET
    if not named:
        # wget writes the URL's basename by default; curl streams to stdout
        # unless asked for the remote name.
        dest = _basename(url) if (tool == "wget" or remote_name) else None
    if directory and dest and not os.path.isabs(dest) and (
            tool == "curl" or not named):
        dest = os.path.join(directory, dest)
    if stage.writes:
        dest = stage.writes[-1]                 # `curl ... > /tmp/x`
    if dest is None and piped_to and os.path.basename(piped_to[0]) == "tee":
        # `curl ... | sudo tee /usr/local/bin/tool`: the pipeline IS the
        # download's destination, and what tee wrote is what runs next.
        written = [t for t in piped_to[1:] if not t.startswith("-")]
        dest = written[0] if written else None
    if dest in _STDOUT:
        dest = None
    return Fetch(tool, url, dest, piped_to)


def _fetch_records(stmts):
    """[(statement index, Fetch)] for every download in the script."""
    found = []
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if argv and os.path.basename(argv[0]) in FETCHERS:
                following = statement.stages[position + 1:]
                piped_to = tuple(command(following[0].argv)) if following else None
                fetch = _parse_fetch(os.path.basename(argv[0]), argv[1:],
                                     stage, piped_to)
                if fetch is not None:
                    found.append((index, fetch))
            found.extend((index, f) for f in _substituted(argv, stage))
    return found


def _substituted(argv, stage):
    """Every fetch inside this stage's command substitutions, credited to the
    command that CONSUMES it -- `eval`, `sh -c`, `bash <(...)` -- because that
    is what decides whether the downloaded bytes become behaviour."""
    consumer = tuple(t for t in argv if not shell_reader.is_marker(t)) or None
    executes = consumer and os.path.basename(consumer[0]) in EXECUTORS
    found = []
    for inner in stage.substitutions:
        for _index, fetch in _fetch_records(statements(inner)):
            if fetch is None:
                continue
            if executes or fetch.piped_to is None:
                fetch = fetch._replace(piped_to=consumer)
            found.append(fetch)
    return found


# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`.
# The text is shell and this module reads shell, so the quotes are not a
# grammar it lacks -- only one it was not looking through. `python3 -c` and
# `perl -e` are NOT here: that text is another language, and the gap list says
# so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


def _scripts(argv):
    """The shell scripts this command is handed as a string, in order.

    A lifted `$(...)` or heredoc marker is never one: it stands for text held
    in the parse it came from, and `_substituted` already credits what is
    inside it.
    """
    if not argv:
        return []
    name, found = os.path.basename(argv[0]), []
    if name == "eval":
        found = [t for t in argv[1:] if not t.startswith("-")]
    elif name in _SHELL_STRING and "-c" in argv:
        found = argv[argv.index("-c") + 1:][:1]
    return [t for t in found if not shell_reader.is_marker(t)]


def _flattened(stmts):
    """`eval "<script>"` expanded, in place, into the statements it runs.

    In place and in ORDER, rather than harvested separately, so the fetch, the
    checksum and the `chmod` written inside one quoted script are read as the
    sequence they are: a step hardened inside its own string must come out
    hardened, not unread. The wrapper is kept -- its redirections and the stage
    it pipes into are still the wrapper's.
    """
    out = []
    for statement in stmts:
        for stage in statement.stages:
            for text in _scripts(command(stage.argv)):
                out.extend(_flattened(statements(text)))
        out.append(statement)
    return out


def read(script):
    """Every statement a `run:` script runs, quoted scripts expanded."""
    return _flattened(statements(script))


def fetches(script):
    """Every download a `run:` script performs, in order."""
    return [fetch for _index, fetch in _fetch_records(read(script))]


# --- which statements check, and what they check -----------------------------

def _same_file(token, path):
    return os.path.normpath(token) == os.path.normpath(path)


def _names(content, dest):
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
    return any(_same_file(word, dest)
               or (bare and base and _same_file(word, base))
               for word in content.split())


# A check whose non-zero exit nobody sees is not a check. Runners default to
# `bash -e -o pipefail`, which is what makes `sha256sum -c` a GATE -- and the
# shell around the command decides whether that survives. `&` detaches it;
# `||` hands the failure to a branch, which rescues it ONLY if that branch
# ends the job; `if`/`while`/`!` make it a test, and errexit never applies to
# a test.
_SWALLOWING = ("||", "&")
# The `|| ...` branches that keep a check a check: they fail the step, which
# is exactly what errexit would have done.
_FATAL = ("exit", "return", "false")
_GROUP_OPEN = ("{", "(")


def _stops_the_job(stmts, index):
    """True if the `||` branch after `stmts[index]` fails the step.

    `sha256sum -c - || exit 1` and `... || { echo "::error::"; exit 1; }` are
    gates, not swallows -- and they are the cheap hardened spellings, so
    refusing them would push authors toward the exemption list instead.
    """
    following = stmts[index + 1:index + 11]
    if not following:
        return False
    first = following[0].stages[0].argv if following[0].stages else []
    grouped = bool(first) and first[0] in _GROUP_OPEN
    for statement in following:
        for stage in statement.stages:
            argv = command(stage.argv)
            if argv and os.path.basename(argv[0]) in _FATAL:
                return True
        if not grouped or any("}" in t or ")" in t
                              for stage in statement.stages for t in stage.argv):
            break
    return False


def _swallowed(stmts, index, statement, stage):
    """Why this check's failure would go nowhere, or None."""
    if statement.separator == "&":
        return "detached with `&`"
    if statement.separator == "||" and not _stops_the_job(stmts, index):
        return "handed to a `||` branch that does not fail the step"
    if negated(stage.argv):
        return "negated, so the failing path is the THEN branch"
    if conditional(stage.argv):
        return "an `if`/`while` test, which errexit does not apply to"
    return None


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
    files = [f for f in _operands(argv) + stage.reads if f not in _STDOUT]
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


def _checks(stmts):
    """[(statement index, checked text)] for every bound checksum check."""
    found, written = [], {}
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if not argv or os.path.basename(argv[0]) not in CHECKSUM_TOOLS:
                continue
            if not _has_check_flag(argv):
                continue
            if _swallowed(stmts, index, statement, stage):
                continue                        # its failure goes nowhere
            text = _checked_text(statement, position, stage, argv, written)
            if text and _DIGEST.search(text):
                found.append((index, text))
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
            if any(_same_file(o, n) for o in operands[:-1] for n in names):
                new.add(operands[-1])
        if name == "cat" and stage.writes:
            if any(_same_file(o, n) for o in operands for n in names):
                new.update(stage.writes)
    return new


def _uses(stmts, dest, after):
    """(names the file goes by, [(statement index, what it does)]).

    Walked in order from the fetch, so a name only counts once the statement
    that created it has run.
    """
    names, out = {dest}, []
    for index, statement in enumerate(stmts):
        if index < after:
            continue
        for position, stage in enumerate(statement.stages):
            argv, how = command(stage.argv), None
            for name in sorted(names):
                how = _use(statement, position, stage, argv, name)
                if how:
                    if not _same_file(name, dest):
                        how += " (as `%s`, copied from it earlier)" % name
                    break
            if how:
                out.append((index, how))
                break
        names |= _copies(statement, names)
    return names, out


# An operand that carries a glob metacharacter DESCRIBES files rather than
# naming one, which is the whole of what `chmod +x *.sh` had over this rule.
_GLOB = re.compile(r"[*?\[]")
# `find`'s ways of running a command over what it walked. The operand is `{}`,
# which names nothing at all.
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")
_RECURSIVE = ("-R", "-r", "--recursive")


def _covers(token, dest, recursive=False):
    """Does this operand stand for `dest`, even without naming it?

    Three spellings, and the guard binds by NAME, so each one hid a use:
    exactly (`chmod +x /tmp/payload`), by a glob (`chmod +x /tmp/*.sh`), and by
    the directory a recursive command walks (`chmod -R +x /tmp`). A glob is
    matched against the whole path and, for a bare dest, its basename -- the
    same asymmetry `_names` draws, and for the same reason.
    """
    if _same_file(token, dest):
        return True
    if _GLOB.search(token):
        return (fnmatch.fnmatch(dest, token)
                or (not os.path.dirname(dest)
                    and fnmatch.fnmatch(os.path.basename(dest), token)))
    if recursive and not token.startswith("-"):
        prefix = os.path.normpath(token)
        if prefix == ".":
            return not os.path.isabs(dest)
        return os.path.normpath(dest).startswith(prefix + os.sep)
    return False


def _walked(argv):
    """The roots a `find` walks: its operands before the first predicate."""
    roots = []
    for token in argv[1:]:
        if token.startswith("-") or token in ("(", "!"):
            break
        roots.append(token)
    return roots


def _described(statement, position, stage, argv):
    r"""(the command that really runs, the operands it is handed, is it a walk).

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
        return argv, previous[1:] if previous else [], False
    return argv, [], False


def _use(statement, position, stage, argv, dest):
    if not argv:
        return None
    argv, handed, walk = _described(statement, position, stage, argv)
    name, rest = os.path.basename(argv[0]), argv[1:]
    recursive = walk or any(t in _RECURSIVE for t in rest)
    mentions = [t for t in rest + handed if _covers(t, dest, recursive)]
    if name in INTERPRETERS and any(_same_file(r, dest) for r in stage.reads):
        # `bash < payload`, `sh -s -- --yes < payload`: the file is never an
        # argument, so argv alone shows an interpreter with nothing after it.
        return "running it under `%s` from standard input" % name
    if name == "chmod" and mentions:
        modes = [t for t in rest if re.fullmatch(r"[0-7]{3,4}", t)]
        if any(t.startswith("+") and "x" in t for t in rest) or any(
                int(digit) % 2 for mode in modes for digit in mode[-3:]):
            return "making it executable"
    if _same_file(argv[0], dest):
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
    with it -- crediting one is fail-open. Conditions are compared as written
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
        return ("runs `%s` with no URL and no destination this guard could "
                "parse, so it cannot say what arrived or whether anything "
                "checked it -- name the file (`-o <path>`) and `sha256sum -c` "
                "it, or exempt the step with a reason" % fetch.tool)
    if fetch.dest is None:
        if not fetch.piped_to:
            return None
        target = os.path.basename(fetch.piped_to[0])
        if target not in EXECUTORS:
            return None
        # Nothing landed on disk, so no checksum anywhere in the step can be
        # about these bytes: the only fix is to stop streaming them into a
        # shell (`curl ... | sh`, `eval "$(curl ...)"`, `bash <(curl ...)`).
        return ("hands %s straight to `%s`, so there is no file to check -- "
                "download it to a file, `sha256sum -c` that file, then run it"
                % (shell_reader.readable(fetch.url) or "a download",
                   shell_reader.readable(" ".join(fetch.piped_to))))
    names, uses = _uses(stmts, fetch.dest, after=index)
    if not uses:
        return None                             # fetched and only read: not this rule
    first_use, how = uses[0]
    # A checksum naming any name the file goes by is a checksum of this file.
    conditions = conditions or {}
    naming = [i for i, text in checks if i > index
              and any(_names(text, name) for name in sorted(names))
              and _binds(conditions, i, first_use)]
    if any(i < first_use for i in naming):
        return None
    if naming:
        # Ordering is the substance: a checksum that runs after the bytes are
        # made runnable is theatre.
        return ("verifies %s only AFTER %s -- fetches %s, so %s"
                % (shell_reader.readable(fetch.dest), how, _describe(fetch),
                   _remedy(fetch.dest)))
    if [i for i, _text in checks if i > index]:
        return ("fetches %s and %s; the step's checksum does not name %s, and a "
                "checksum of a different file verifies nothing -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   _remedy(fetch.dest)))
    return ("fetches %s and %s with nothing verifying what arrived -- %s"
            % (_describe(fetch), how, _remedy(fetch.dest)))


def _defects(stmts, conditions=None, soft=()):
    """[(statement index, why)] for every unverified fetch in parsed shell.

    `conditions` maps a statement index to the `if:` of the step it came from
    (absent = unconditional), which decides whether a check is allowed to clear
    a use -- see `_binds`. `soft` holds the indexes whose step carries
    `continue-on-error: true`, whose checks clear nothing at all.
    """
    checks = [(index, text) for index, text in _checks(stmts)
              if index not in soft]
    conditions = conditions or {}
    found = []
    for index, fetch in _fetch_records(stmts):
        why = _defect(fetch, index, stmts, checks, conditions)
        if why:
            found.append((index, why))
    return found


def fetch_exec_defects(script):
    """Every unverified fetch-and-execute in one `run:` script."""
    return [why for _index, why in _defects(read(script))]


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
    stmts, owner, conditions, soft, found = [], [], {}, set(), []
    for item in steps:
        step = item if isinstance(item, Step) else Step(*item)
        why = unparseable(step.shell)
        if why:
            found.append((step.name, why))
            continue
        for statement in read(step.script):
            # An `if:` step may not run. Its FETCH still counts -- folding it in
            # can only report more -- but its CHECK counts only for a use that
            # is skipped with it (`_binds`): a checksum that may not run cannot
            # clear an execution that always does. A `continue-on-error` step
            # DOES run, and its failure is discarded, so its check counts for
            # nothing.
            if step.condition:
                conditions[len(stmts)] = step.condition
            if step.soft:
                soft.add(len(stmts))
            stmts.append(statement)
            owner.append(step.name)
    found.extend((owner[index], why)
                 for index, why in _defects(stmts, conditions, soft))
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
        out("%d unverified fetch-and-exec step(s); see scripts/workflow_guard.py"
            % len(defects))
    return 1 if defects else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
