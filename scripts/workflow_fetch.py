#!/usr/bin/env python3
"""Bounded curl/wget transfer shapes and descriptor-aware pipe consumption.

Single curl transfers are modeled; complex transfers remain explicitly unread.
This layer depends on shell_reader only. workflow_forms re-exports the public API.
"""
import collections
import os
import re
from typing import cast

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
             "upload-file", "continue-at", "config", "doh-url", "preproxy",
             "proxy-header", "request-target", "url-query", "connect-to", "json",
             "proto", "proto-default", "proto-redir",
             "max-redirs", "netrc-file", "stderr", "trace", "trace-ascii"},
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
# Only these destinations follow fd 1. Discarding a response in /dev/null
# is independent of stdout, although both are suppressed in the final result.
_STDOUT_DESTINATIONS = ("-", "/dev/stdout", "/dev/fd/1")
STDOUT = _STDOUT_DESTINATIONS + ("/dev/null",)
# `curl --version` in a diagnostics step downloads nothing; without this it
# parses as a fetch with no URL, which the rule now REPORTS rather than drops.
_INFORMATIONAL = ("--version", "-V", "--help", "-h", "--manual", "-M", "--usage")
_UNSET = object()

# Explicit no-operand curl options used in workflow downloads. Unmodeled options
# are unread rather than allowing a possible option value to masquerade as a URL.
_CURL_FLAGS = set("aBfgGIijklnNLpqRsSvZ046#")
_CURL_LONG_FLAGS = set("""
    fail fail-with-body fail-early silent show-error location location-trusted
    insecure compressed create-dirs retry-all-errors retry-connrefused verbose
    head include get ipv4 ipv6 http1.0 http1.1 http2 http2-prior-knowledge http3
    parallel parallel-immediate progress-bar no-progress-meter disable netrc
    netrc-optional tcp-nodelay no-buffer remove-on-error remote-time
""".split())


def _curl_glob(url):
    # Parameter-expansion braces are not curl's URL-list syntax. IPv6 literals
    # are also single URLs; ranges in brackets and brace lists are fanout.
    literal = re.sub(r"\$\{[^}]*\}", "", url)
    return bool(re.search(r"\{|\[[^]]*-[^]]*\]", literal))


# --- what a fetcher was told -------------------------------------------------

def _basename(url):
    if not url:
        return None
    name = os.path.basename(url.split("?", 1)[0].split("#", 1)[0].rstrip("/"))
    return shell_reader.derived(name, url) if name else None


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
    """A Fetch and whether its response still leaves on standard output."""
    value_short, value_long = _VALUE_SHORT[tool], _VALUE_LONG[tool]
    dest_short, dest_long = _DEST_SHORT[tool], _DEST_LONG[tool]
    dir_short, dir_long = _DIR_SHORT[tool], _DIR_LONG[tool]
    dest, remote_name, operands, i = _UNSET, False, [], 0
    directory = None
    unread, outputs, remote_all, header_name, globoff = False, 0, False, False, False
    while i < len(args):
        token, i = args[i], i + 1
        if token == "--":
            operands.extend(args[i:])
            break
        if token in _INFORMATIONAL:
            return None, False
        if token.startswith("--"):
            name, sep, inline = token[2:].partition("=")
            inline = shell_reader.derived(inline, token)
            if name in value_long or name in dir_long:
                value = inline if sep else (args[i] if i < len(args) else None)
                i += 0 if sep else 1
                unread |= value is None
                if name in dest_long:
                    dest = value
                    outputs += 1
                elif name in dir_long:
                    directory = value
                elif tool == "curl" and name == "url":
                    if value is not None:
                        operands.append(value)
                elif tool == "curl" and name == "config":
                    unread = True
            elif tool == "curl":
                if name in ("remote-name", "no-remote-name"):
                    if name == "no-remote-name" and not remote_all and not outputs and not operands:
                        continue  # No output slot exists to disable yet.
                    remote_name = name == "remote-name"
                    dest = _UNSET if remote_name else "-"
                    outputs += 1
                elif name in ("remote-name-all", "no-remote-name-all"):
                    # Older curl versions apply defaults when URL slots are
                    # created. A later toggle is version-dependent: leave unread.
                    unread |= bool(operands)
                    remote_all = name == "remote-name-all"
                elif name in ("remote-header-name", "no-remote-header-name"):
                    header_name = name == "remote-header-name"
                elif name in ("globoff", "no-globoff"):
                    globoff = name == "globoff"
                elif name not in _CURL_LONG_FLAGS:
                    unread = True  # Includes --next and unknown option arities.
                unread |= bool(sep)
            continue
        if token.startswith("-") and len(token) > 1:
            j = 1
            while j < len(token):
                ch, j = token[j], j + 1
                if tool == "curl" and ch in "hMV":
                    return None, False
                if ch in value_short or (dir_short and ch == dir_short):
                    value = shell_reader.derived(token[j:], token) if token[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if token[j:] else 1
                    unread |= value is None
                    if ch == dest_short:
                        dest = value
                        outputs += 1
                    elif ch == dir_short:
                        directory = value
                    elif tool == "curl" and ch == "K":
                        unread = True
                    break
                if tool == "curl":
                    if ch == "O":
                        remote_name, dest = True, _UNSET
                        outputs += 1
                    elif ch == "J":
                        header_name = True
                    elif ch == "g":
                        globoff = True
                    elif ch not in _CURL_FLAGS:
                        unread = True  # Includes -: / --next.
            continue
        operands.append(token)
    url = _pick_url(operands)
    if tool == "curl" and (unread or len(operands) > 1 or outputs > 1 or header_name
                           or (url and not globoff and _curl_glob(url))):
        return Fetch(tool, None, None, None), False
    remote_name |= remote_all and outputs == 0
    named = dest is not _UNSET
    if not named:
        # wget writes the URL's basename by default; curl streams to stdout
        # unless asked for the remote name.
        dest = _basename(url) if (tool == "wget" or remote_name) else None
    # The sentinel has been resolved; remaining destinations are paths or stdout.
    dest = cast(str | None, dest)
    # A remote basename of "-" is a filename, not the explicit output
    # option that requests stdout. Keep that origin through directory joining.
    to_stdout = dest is None or (named and dest in _STDOUT_DESTINATIONS)
    streams = to_stdout and stage.stdout_to_pipe
    if not to_stdout and directory and dest and not os.path.isabs(dest) and (
            tool == "curl" or not named):
        dest = shell_reader.derived(os.path.join(directory, dest), directory, dest)
    if stage.stdout_writes and to_stdout:
        dest = stage.stdout_writes[-1]           # `curl ... > /tmp/x`; a
        # Track stdout only when the fetcher actually writes there. An
        # explicit output file is independent of the shell stdout redirect.
        # `stage.writes` also carries other opened files; only the final fd 1
        # sink (including ordered fd copies) can receive this stream.
        if dest == "/dev/stderr":
            # A STDOUT redirect landing on `/dev/stderr` is also "nothing was
            # written" -- but only when a redirect put it there. `-o
            # /dev/stderr` (below, via `dest`/`named`) really did write it,
            # and STDOUT must not silence that explicit destination too
            # (round 1 NIT: it did, while this lived in the STDOUT tuple).
            dest = None
    if dest is None and piped_to and os.path.basename(piped_to[0]) == "tee":
        # `curl ... | sudo tee /usr/local/bin/tool`: the pipeline IS the
        # download's destination, and what tee wrote is what runs next.
        written = [t for t in piped_to[1:] if not t.startswith("-")]
        dest = written[0] if written else None
    # Suppress stream/discard outputs without discarding an inferred "-" file.
    if dest in STDOUT and (named or to_stdout):
        dest = None
    return Fetch(tool, url, dest, piped_to), streams


def parse_fetch(tool, args, stage, piped_to):
    """One `curl`/`wget` argv -> the four-field Fetch it performs."""
    return _parse_fetch(tool, args, stage, piped_to)[0]


def _may_read_pipe(argv, stage):
    """Use final descriptor origins for stdin and file-alias operands."""
    def connected(operand):
        if operand == "-":
            return stage.stdin_from_pipe
        source = shell_reader.input_alias_fd(operand)
        return source == "?" or source in stage.pipe_input_fds

    name = os.path.basename(argv[0])
    if name == "cat":
        operands = [t for t in argv[1:] if t == "-" or not t.startswith("-")]
        return any(map(connected, operands)) if operands else stage.stdin_from_pipe
    if name != "sed":
        # Unknown commands may consume either stdin or a named descriptor.
        return stage.stdin_from_pipe or any(map(connected, argv[1:]))
    if any(t.startswith(("-i", "--in-place")) for t in argv[1:]):
        return False
    # sed's first bare operand is the script unless -e/-f supplies it.
    scripted, i, operands = False, 1, []
    while i < len(argv):
        argument = argv[i]
        if argument in ("-e", "-f", "--expression", "--file"):
            scripted, i = True, i + 2
            continue
        if argument.startswith(("-e", "-f", "--expression=", "--file=")):
            scripted = True
        elif argument == "-" or not argument.startswith("-"):
            if scripted:
                operands.append(argument)
            scripted = True
        i += 1
    return any(map(connected, operands)) if operands else stage.stdin_from_pipe


def streamed_fetch(tool, args, stage, following, executors):
    """A direct stream-to-executor view, separate from the Fetch's file view.

    `tee` may both write the file named by parse_fetch and pass the same bytes
    onward. The ordinary Fetch keeps that destination; this view supplies a
    stdout-only record for the execution check.
    """
    fetch, streams = _parse_fetch(tool, args, stage, None)
    if not fetch or not streams:
        return None
    for next_stage in following:
        argv = command(next_stage.argv)
        if not argv or not _may_read_pipe(argv, next_stage):
            break
        name = os.path.basename(argv[0])
        if name in executors:
            return fetch._replace(dest=None, piped_to=tuple(argv))
        if not next_stage.stdout_to_pipe:
            break
    return None
