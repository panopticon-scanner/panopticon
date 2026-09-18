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
                               quote away from a substitution

Stdlib only, like everything under it.
"""
import collections
import fnmatch
import os
import re

import shell_reader
from shell_reader import command


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
    elif name in _SHELL_STRING and "-c" in argv:
        found = argv[argv.index("-c") + 1:][:1]
    return [t for t in found if not shell_reader.is_marker(t)]
