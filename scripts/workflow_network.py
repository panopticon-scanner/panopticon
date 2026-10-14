#!/usr/bin/env python3
"""Raw network streams that are not downloads with a named destination.

``workflow_fetch`` owns programs with an output-file contract.  This smaller
layer covers the other half of #2829: a shell fed directly from a socket
pseudo-device, a connecting socket client, or a foreign one-liner that names
a network API.  It deliberately does not invent a file destination.  The
ordinary stream defect therefore speaks only when those bytes reach an
executor, directly or through a command/process substitution.

The recognizers are bounded allow-lists.  In particular, a netcat listener,
an OpenSSL subcommand other than ``s_client``, ordinary foreign code, and a
``socat`` pair without a network-to-stdio path are not network producers here.
"""
import os
import re

import shell_reader
from workflow_fetch import Fetch, stream_consumer, stream_forwarded
from workflow_programs import stdin_program


_SOCKET_PATH = re.compile(r"^/dev/(?:tcp|udp)/[^/]+/[^/]+/?$")
_NETCAT = frozenset(("nc", "ncat", "netcat"))
_SOCAT_NETWORK = re.compile(
    r"^(?:tcp[46]?|udp[46]?|openssl|socks[45]?a?|proxy)(?:-connect)?:",
    re.I,
)
_SOCAT_STDIO = re.compile(r"^(?:-|stdio|stdin|stdout|fd:[01])(?:,|$)", re.I)

# Only source text passed through an interpreter's one-line option is read.
# A filename containing "requests" and a program that merely prints "http"
# are controls: neither says the interpreter itself reads the network.
_ONE_LINE = {
    "python": ("-c",),
    "python3": ("-c",),
    "perl": ("-e", "-E"),
    "ruby": ("-e", "--eval"),
    "node": ("-e", "--eval", "-p", "--print"),
    "php": ("-r",),
    "pwsh": ("-c", "-command"),
}
_NETWORK_CODE = re.compile(
    r"\burllib(?:\.[A-Za-z_]\w*)?\b|"
    r"\brequests\b|"
    r"\bhttp(?:\.client|::[A-Za-z_]\w*)\b|"
    r"\bnet(?:::|/)http\b|"
    r"\brequire\s*\(\s*['\"]https?['\"]|"
    r"\bfetch\s*\(",
    re.I,
)


def _text(word):
    """A reader word as the source language sees it."""
    return shell_reader.readable(word)


def _listener(args):
    """Whether netcat's option prefix explicitly selects listener mode."""
    for word in map(_text, args):
        if word == "--":
            return False
        if word == "-" or not word.startswith("-"):
            return False
        if word == "--listen" or word.startswith("--listen="):
            return True
        if not word.startswith("--") and "l" in word[1:]:
            return True
    return False


def _netcat_connects(args):
    """Whether netcat names any connect operand after its option prefix."""
    operands = []
    options = True
    for word in map(_text, args):
        if options and word == "--":
            options = False
        elif options and word != "-" and word.startswith("-"):
            continue
        else:
            options = False
            operands.append(word)
    return bool(operands)


def _one_line(argv):
    """The literal source passed by one recognized interpreter option."""
    name = os.path.basename(_text(argv[0]))
    options = _ONE_LINE.get(name, ())
    if not options:
        return None
    at = 1
    while at < len(argv):
        word = _text(argv[at])
        if word == "--" or not word.startswith("-"):
            return None
        for option in options:
            if word == option:
                return _text(argv[at + 1]) if at + 1 < len(argv) else None
            if option.startswith("--") and word.startswith(option + "="):
                return word[len(option) + 1:]
            if len(option) == 2 and word.startswith(option) and len(word) > 2:
                return word[2:]
        at += 1
    return None


def _raw_source(stage):
    """The socket pseudo-device descriptor zero finally reads, if any."""
    return next((path for word in stage.stdin_reads
                 if _SOCKET_PATH.fullmatch(path := _text(word))), None)


def _command_source(argv):
    """A bounded command/network-API label, or None for an accepted control."""
    if not argv:
        return None
    name = os.path.basename(_text(argv[0]))
    if name in _NETCAT:
        return name if not _listener(argv[1:]) and _netcat_connects(argv[1:]) else None
    if name == "openssl":
        return name if len(argv) > 1 and _text(argv[1]) == "s_client" else None
    if name == "socat":
        operands = [_text(word) for word in argv[1:]
                    if _text(word) == "-" or not _text(word).startswith("-")]
        network = any(_SOCAT_NETWORK.match(word) for word in operands)
        stdio = any(_SOCAT_STDIO.match(word) for word in operands)
        return name if network and stdio else None
    source = _one_line(argv)
    return name if source is not None and _NETWORK_CODE.search(source) else None


def opens_socket(stage, argv):
    """The pseudo-device a descriptor-only ``exec`` opens, or None.

    ``shell_reader.Stage`` intentionally does not retain a descriptor number
    across statements.  It does retain the path that ``exec N<...`` or
    ``exec N<>...`` opens, under reads or writes respectively.  A later
    descriptor-fed ``cat`` is therefore paired conservatively with this open.
    """
    if not argv or os.path.basename(_text(argv[0])) != "exec":
        return None
    return next((path for word in (*stage.reads, *stage.writes)
                 if _SOCKET_PATH.fullmatch(path := _text(word))), None)


def _descriptor_cat(stage, argv):
    """Whether ``cat`` reads an unnamed descriptor rather than a file."""
    if not argv or os.path.basename(_text(argv[0])) != "cat":
        return False
    operands = [_text(word) for word in argv[1:]
                if _text(word) == "-" or not _text(word).startswith("-")]
    return (not stage.stdin_from_pipe and not stage.stdin_reads
            and stage.stdin_heredoc is None and all(word == "-" for word in operands))


def descriptor_network_fetch(stmts, index, executors):
    """A socket opened on one statement and copied to a later shell.

    This is the issue's ``exec 3<>/dev/tcp/...; cat <&3 | sh`` spelling.
    Descriptor numbers are absent from the flattened Stage contract, so the
    bounded pairing requires the later reader to be a descriptor-fed ``cat``
    with no file operand.  A close or reassignment the flattened reader cannot
    distinguish may over-report; it never turns a different input into a
    trusted download.
    """
    source = next((path for stage in stmts[index].stages
                   if (path := opens_socket(stage, shell_reader.command(stage.argv)))), None)
    if source is None:
        return None
    for statement in stmts[index + 1:]:
        for position, stage in enumerate(statement.stages):
            argv = shell_reader.command(stage.argv)
            if not _descriptor_cat(stage, argv) or not stage.stdout_to_pipe:
                continue
            consumer = stream_consumer(statement.stages[position + 1:], executors)
            if consumer is not None:
                label = "unmodeled network input from `%s`" % source
                return Fetch("network producer", label, None, consumer)
    return None


def network_fetch(argv, stage, following, executors, compound=None):
    """A destination-less Fetch for network bytes that can reach stdout.

    ``compound`` is the executor outside an enclosing ``{ ...; }`` / keyword
    compound.  Local stages must all forward the stream before it is used.
    Returning an unconsumed record is intentional: ``workflow_guard._walk``
    can then attach an enclosing command/process-substitution consumer exactly
    as it does for a named fetch.
    """
    raw = _raw_source(stage)
    command = _command_source(argv)
    if raw is None and command is None:
        return None
    own = tuple(argv) if raw is not None and stdin_program(argv) else None
    if own is None and not stage.stdout_to_pipe:
        return None
    consumer = own or stream_consumer(following, executors)
    if (consumer is None and compound is not None
            and (not following or stream_forwarded(following))):
        consumer = compound
    source = ("unmodeled network input from `%s`" % raw if raw is not None
              else "unmodeled network output from `%s`" % command)
    return Fetch("network producer", source, None, consumer)
