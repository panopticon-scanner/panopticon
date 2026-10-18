#!/usr/bin/env python3
"""Bounded download-command shapes and descriptor-aware pipe consumption.

Single transfers are modeled; complex transfers remain explicitly unread.
This layer uses shell_reader and the stdin-program classifier. workflow_forms re-exports its API.
"""
import collections
import os
import re
from typing import cast

import shell_reader
from workflow_compound_outputs import (_ForwardedTee, _InheritedOutput, _compound_delta,
                                       _inline_pipeline, _may_read_pipe, _stream_forwarded,
                                       compound_output as compound_output,
                                       stream_forwarded as stream_forwarded)
import workflow_fetch_adapters
from workflow_option_slots import _one_word, _value
from workflow_option_words import lifted, ruled, uncovered_argv
from workflow_programs import VALUE_PROGRAM, stdin_program


# A download: the tool that ran, the URL it was given, the file it lands in
# (None = standard output, which is the pipe-to-shell shape), and the argv of
# the next pipeline stage (None when the fetch ends the pipeline).
Fetch = collections.namedtuple("Fetch", "tool url dest piped_to")


FETCHERS = ("curl", "wget", *workflow_fetch_adapters.FETCHERS)

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
_DESCRIPTOR_STDOUT = ("/dev/stdout", "/dev/fd/1")
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


def _parse_curl_wget(tool, args, stage, piped_to, file_view=True):
    """A Fetch and whether its response still leaves on standard output: the transfer the words name
    (`_transfer`), or -- where a word's expansions in front of an option word may print nothing
    (`uncovered`, #3042: `wget $X-qO- URL | sh`, `wget $X-O f URL && sh f`) -- the one they name
    then, where it has a URL, its stream beside the first's. The guard's job keeps `main`'s reading
    of the words as written first and whole (`workflow_guard.job_defects`). ``file_view`` is #3034's,
    handed to both transfers."""
    fetch, streams = _transfer(tool, args, stage, piped_to, file_view)
    alt = uncovered_argv([tool, *args])
    other, more = _transfer(tool, alt[1:], stage, piped_to, file_view) if alt else (None, False)
    return (other, streams or more) if other is not None and other.url is not None else (fetch, streams)


def _transfer(tool, args, stage, piped_to, file_view=True):
    """A Fetch and whether its response still leaves on standard output.

    ``file_view`` is false for the separate #2889 stream reading, whose
    possible ``-O-`` must stay available even when #3034 cannot name a file.
    """
    value_short, value_long = _VALUE_SHORT[tool], _VALUE_LONG[tool]
    dest_short, dest_long = _DEST_SHORT[tool], _DEST_LONG[tool]
    dir_short, dir_long = _DIR_SHORT[tool], _DIR_LONG[tool]
    dest, remote_name, operands, i = _UNSET, False, [], 0
    directory = None
    unread, outputs, remote_all, header_name, globoff = False, 0, False, False, False
    while i < len(args):
        argument, i = args[i], i + 1
        if argument == "--":
            operands.extend(args[i:])
            break
        if argument in _INFORMATIONAL:
            return None, False
        if argument.startswith("--"):
            name, sep, inline = argument[2:].partition("=")
            if lifted(argument, 0, 2 + len(name)):
                return Fetch(tool, None, None, None), False     # a NAME no text spells: unread (#3023)
            inline = shell_reader.derived(inline, argument)
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
        if argument.startswith("-") and len(argument) > 1:
            j = 1
            while j < len(argument):
                # Lifted text where a letter is read (`curl -fsSL$(true) URL`): what it prints may be
                # any option, and its marker's text is none -- an `h` in it was `curl -h` (#3023).
                # Unread, as a `$X` there is; in an option's VALUE (`-o"$(mktemp)"`) it is a value.
                if lifted(argument, j, j + 1):
                    return Fetch(tool, None, None, None), False
                ch, j = argument[j], j + 1
                if tool == "curl" and ch in "hMV":
                    return None, False
                if ch in value_short or (dir_short and ch == dir_short):
                    value = shell_reader.derived(argument[j:], argument) if argument[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if argument[j:] else 1
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
        operands.append(argument)
    url = _pick_url(operands)
    if tool == "curl" and (unread or len(operands) > 1 or outputs > 1 or header_name
                           or (url and not globoff and _curl_glob(url))):
        return Fetch(tool, None, None, None), False
    # A whole-word expansion beside a written URL may be wget's destination
    # option and value (`X='-O tool'; wget $X URL`, #3034). Only this stage's
    # own pipe or redirect bounds the file view; an enclosing compound's route
    # says nothing about the destination the expansion may name. Stage-owned
    # output keeps its stream view under #3035's separate arm.
    may_name_destination = any(_value(operand) for operand in operands)
    has_written_url = any("://" in operand and not _value(operand)
                          for operand in operands)
    owns_output = ((bool(stage.stdout_writes) and not stage.group_close
                    and not isinstance(stage.stdout_writes, _InheritedOutput))
                   or (piped_to is not None
                       and not isinstance(piped_to, _InheritedOutput)))
    if ruled(file_view and tool == "wget" and may_name_destination and has_written_url
             and not owns_output):
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
    dest = shell_reader.stdout_named(dest, stage)       # any spelling of descriptor 1 is the listed one (#2744)
    to_stdout = dest is None or (named and dest in _STDOUT_DESTINATIONS)
    # wget writes a file unless told `-O-`, and a whole-word expansion among its words may tell it
    # (`wget $(echo -qO-) URL | sh`, `X=-qO-; wget "$X" URL | sh`; one unquoted and alone may be the
    # option and the URL both, #2889). So the response MAY leave on standard output: the stream view
    # is added where that is piped, BESIDE the file `main` reads the transfer into, which stays.
    may_stream = ruled(tool == "wget" and any(
        _value(operand) and (len(operands) > 1 or not _one_word(operand)) for operand in operands))
    streams = (to_stdout or may_stream) and stage.stdout_to_pipe
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
    # Resolve an explicitly named stdout before asking whether an adjacent
    # tee saves that stream (#2916). `/dev/null` is a discard, and an inferred
    # remote basename of `-` remains a file, so neither takes this path.
    if named and dest in _STDOUT_DESTINATIONS:
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


class _TreeDestination(str):
    """The root of a fetched tree; uses beneath it are unverified too."""

    tree = True


def _parse_adapter(tool, args, stage, piped_to):
    """One non-curl/wget adapter, with shell stdout routing applied."""
    transfer = workflow_fetch_adapters.parse(tool, args)
    if transfer is None:
        return None, False
    if transfer.unread:
        return Fetch(transfer.tool, None, None, None), False
    ambiguous = transfer.ambiguous
    dest = (shell_reader.stdout_named(transfer.dest, stage)
            if transfer.named and not transfer.tree else transfer.dest)
    # Only tools whose own grammar documents `-` as stdout set `stdout`.
    # `/dev/stdout` and `/dev/fd/1` are OS-level fd aliases for every tool;
    # aria2c and axel, by contrast, really open a file named `-` for `-o -`.
    to_stdout = transfer.stdout or transfer.named and dest in _DESCRIPTOR_STDOUT
    discarded = transfer.named and dest == "/dev/null"
    streams = bool(to_stdout and stage.stdout_to_pipe)
    if to_stdout and not stage.stdout_to_pipe:
        ambiguous = False
    redirected = False
    if to_stdout and stage.stdout_writes:
        redirected = True
        ambiguous = False
        dest = stage.stdout_writes[-1]
        if shell_reader.stdout_named(dest, stage) == "/dev/stdout" or dest in (
                "/dev/null", "/dev/stderr"):
            dest = None
    if not redirected and to_stdout and dest in _STDOUT_DESTINATIONS:
        dest = None
    if streams and dest is None and piped_to and os.path.basename(piped_to[0]) == "tee":
        written = [word for word in piped_to[1:] if not word.startswith("-")]
        dest = written[0] if written else None
    if discarded:
        dest = None
    if transfer.tree and dest is not None:
        dest = _TreeDestination(dest)
    if piped_to:
        ambiguous = False
    label = transfer.tool + (" --download" if ambiguous else "")
    return Fetch(label, transfer.url, dest, piped_to), streams


def _parse_fetch(tool, args, stage, piped_to, file_view=True):
    """One recognized fetcher argv and whether its response leaves on stdout."""
    if tool in ("curl", "wget"):
        return _parse_curl_wget(tool, args, stage, piped_to, file_view)
    return _parse_adapter(tool, args, stage, piped_to)


def parse_fetch(tool, args, stage, piped_to):
    """One recognized download argv -> the Fetch it performs."""
    return _parse_fetch(tool, args, stage, piped_to)[0]


def streams_to_executor(fetch, executors):
    """Whether a lent tee destination also reaches this outer consumer."""
    return bool(is_forwarded_tee(fetch) and (
        os.path.basename(fetch.piped_to[0]) in executors
        or stdin_program(fetch.piped_to[:1]) == VALUE_PROGRAM))


def is_forwarded_tee(fetch):
    """Whether a fetch keeps a compound tee's outward stream."""
    return isinstance(fetch.piped_to, _ForwardedTee)


def forwarded_consumer(fetch, consumer):
    """Keep a compound tee's outward stream when a substitution is consumed."""
    if is_forwarded_tee(fetch):
        return _ForwardedTee(consumer)
    return consumer


def _streamed_fetch(tool, args, stage, following, executors, compound=None):
    """A direct stream-to-executor view, separate from the Fetch's file view.

    `tee` may both write the file named by parse_fetch and pass the same bytes
    onward. The ordinary Fetch keeps that destination; this view supplies a
    stdout-only record for the execution check.
    """
    fetch, streams = _parse_fetch(tool, args, stage, None, file_view=False)
    consumer = stream_consumer(following, executors) if fetch and streams else None
    if (not consumer and fetch and streams and compound
            and (not following or _stream_forwarded(following))):
        consumer = compound
    return fetch._replace(dest=None, piped_to=consumer) if consumer else None


def streamed_fetch(tool, args, stage, following, executors):
    """The stdout download handed to a local pipeline executor, or None."""
    return _streamed_fetch(tool, args, stage, following, executors)


def compound_streamed_fetch(tool, args, stage, following, executors, compound):
    """A streamed fetch whose local stages may reach a compound consumer."""
    return _streamed_fetch(tool, args, stage, following, executors, compound)


def stdout_fetch(text):
    """The download a script is when it is one fetch to standard output and
    nothing else -- what `x=$(curl -fsSL URL)` holds (#2341) -- or None."""
    stmts = shell_reader.statements(text)
    stage = stmts[0].stages[0] if len(stmts) == 1 and len(stmts[0].stages) == 1 else None
    argv = shell_reader.acted(stage.argv) if stage else []
    tool = os.path.basename(argv[0]) if argv else ""
    fetch, streams = (_parse_fetch(tool, argv[1:], stage, None, file_view=False)
                      if tool in FETCHERS else (None, False))
    return fetch if fetch and streams and fetch.url else None


def stream_consumer(following, executors):
    """The argv of the first of `executors` the stages `following` one hand
    its standard output to, read through each stage that reads the pipe and
    writes on into it (`| tee f | sh`), or None: `streamed_fetch`'s walk, and
    `workflow_forms.carried`'s for a download a step prints (#2341)."""
    for next_stage in following:
        argv = shell_reader.acted(next_stage.argv)
        if not argv or not _may_read_pipe(argv, next_stage):
            break
        if (os.path.basename(argv[0]) in executors
                or stdin_program(argv[:1]) == VALUE_PROGRAM):
            return tuple(argv)
        if not next_stage.stdout_to_pipe:
            break
    return None


def _closing_stream(statement, executors):
    """The consumer or forwarding state at a compound-closing pipeline."""
    for position, stage in enumerate(statement.stages):
        one = shell_reader.Statement([stage], statement.separator)
        if _compound_delta(one) >= 0:
            continue
        following = statement.stages[position + 1:] or _inline_pipeline(stage)
        if not stage.stdout_to_pipe:
            return None, False
        consumer = stream_consumer(following, executors)
        if consumer:
            return consumer, True
        return None, _stream_forwarded(following) if following else True
    return None, True


def compound_stream_consumer(stmts, position, executors):
    """An executor piped from a compound containing statement `position`."""
    depth = sum(_compound_delta(statement) for statement in stmts[:position + 1])
    if depth <= 0:
        return None
    containing = depth
    for statement in stmts[position + 1:]:
        depth += _compound_delta(statement)
        if depth >= containing:
            continue
        consumer, forwarded = _closing_stream(statement, executors)
        if consumer:
            return consumer
        if not forwarded:
            return None
        containing = max(0, depth)
        if not containing:
            break
    return None


def _describe(fetch):
    return "%s -> %s" % (shell_reader.readable(fetch.url) or "an unparsed URL",
                         shell_reader.readable(fetch.dest))


def _remedy(dest):
    if getattr(dest, "tree", False):
        return ("use a pinned source archive instead, verify that file's sha256, then unpack it "
                "before that use")
    return ('verify it first: `echo "<sha256>  %s" | sha256sum -c -` between '
            "the download and that use" % shell_reader.readable(dest))
