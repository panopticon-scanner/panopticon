#!/usr/bin/env python3
"""#1697: the argv SHAPES a workflow `run:` step writes, with no rule on top.

Split out of `scripts/workflow_guard.py` the way `scripts/shell_reader.py` was
(#1647 fix round 1), and for the same reason: closing four of that module's
documented gaps pushed it past the house's module size, and the part that came
out is a layer, not a slice. `shell_reader` turns text into statements and
argv; this module answers the argv questions that have nothing to do with
supply chains, and `workflow_guard` asks the two that do.

Three questions live here, each one a shape a step writes down:

    what a fetcher was told    curl and wget spell the same options
                               differently, and `-o` means opposite things to
                               them -- `parse_fetch` reads one argv into the
                               download it performs
    what an operand stands for `same_file`, `names_file` and `covers`: exactly,
                               by a glob, by the directory a recursive command
                               walks; and `described`, for the operands handed
                               over by `find -exec` or `xargs`. The guard binds
                               a use to a download by NAME, and shell has
                               several ways to designate a file without ever
                               writing its name
    where a script hides       `scripts` finds the shell handed to `eval` or
                               `sh -c` as a STRING, which is the same act one
                               quote away from a substitution; `in_container`
                               the operand a `docker run` hands to a shell on
                               the far side of a bind mount
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
from shell_reader import command, conditional, negated


# A download: the tool that ran, the URL it was given, the file it lands in
# (None = standard output, which is the pipe-to-shell shape), and the argv of
# the next pipeline stage (None when the fetch ends the pipeline).
Fetch = collections.namedtuple("Fetch", "tool url dest piped_to")

FETCHERS = ("curl", "wget")

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
STDOUT = ("-", "/dev/stdout", "/dev/fd/1", "/dev/null")
# `curl --version` in a diagnostics step downloads nothing; without this it
# parses as a fetch with no URL, which the rule now REPORTS rather than drops.
_INFORMATIONAL = ("--version", "-V", "--help", "-h", "--manual", "-M", "--usage")
_UNSET = object()


# --- what a fetcher was told -------------------------------------------------

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


def parse_fetch(tool, args, stage, piped_to):
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
    if dest in STDOUT:
        dest = None
    return Fetch(tool, url, dest, piped_to)


# --- what an operand stands for ----------------------------------------------

def same_file(token, path):
    return os.path.normpath(token) == os.path.normpath(path)


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
_ARM = re.compile(r"^[^\s]*[^\s(]\)$")


def _arm(statement):
    """Does this statement open a `case` arm?

    The `;;` that ends an arm does not survive the statement split (it is two
    empty separators), but the PATTERN that starts the next one does, as the
    first word where a command was expected: `a)`, `*)`, `(a)`, and -- because
    the split cuts on `|` -- the `b)` of an `a|b)` alternation, which is why
    every stage is asked and not only the first.
    """
    return any(stage.argv and _ARM.match(stage.argv[0])
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
    where, stack, opened = {}, [], 0
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
    in the parse it came from, and `_substituted` already credits what is
    inside it.
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


# --- whether a command's failure is allowed to matter -------------------------

# The container runners, and the subcommands of theirs that run a command. The
# image itself is pinned by digest elsewhere; what is read here is the argv
# after it.
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


def swallowed(stmts, index, statement, stage):
    """Why this check's failure would go nowhere, or None.

    Phrased to follow "the checksum that names <file>", because that is the
    sentence a reader gets when the check they wrote did not clear the fetch
    they wrote it for.
    """
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
