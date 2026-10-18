#!/usr/bin/env python3
"""Compound-output routes used by the workflow fetch analysis."""
import os
import re

import shell_reader
from shell_reader import command
from workflow_function_calls import _function_syntax
from workflow_values import _literals


class _InheritedOutput(tuple):
    """A pipe argv or redirect sink inherited from a compound close."""


class _ForwardedTee(_InheritedOutput):
    """A tee argv whose file output also continues to an outer reader."""


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


def _stream_forwarded(following):
    """Whether every local stage may carry its input to compound stdout."""
    if not following:
        return False
    for stage in following:
        argv = command(stage.argv)
        if not argv or not _may_read_pipe(argv, stage) or not stage.stdout_to_pipe:
            return False
    return True


def stream_forwarded(following):
    """Whether every local stage can carry a producer's stdout outward."""
    return _stream_forwarded(following)


_COMPOUND_OPEN = ("if", "while", "until", "for", "case", "{")
_COMPOUND_CLOSE = ("fi", "done", "esac", "}")


def _compound_delta(statement, groups=True):
    """The compound nesting change; `groups=False` keeps keyword compounds."""
    depth = 0
    for stage in statement.stages:
        if groups:
            depth += stage.group_open - stage.group_close
        name, _ = _function_syntax(stage.argv)
        header = 0
        while (header < len(stage.argv)
               and stage.argv[header] in shell_reader.KEYWORDS
               and stage.argv[header] != "function"):
            token = stage.argv[header]
            depth += (token in _COMPOUND_OPEN) - (token in _COMPOUND_CLOSE)
            header += 1
        if name is not None:
            # The command walk stops at `f()` / `function f`, but the reader
            # emits the body's closes later. Count every compound opener in
            # the header's statement, including an immediate `if` or loop
            # (#3069); a nested function header still stops this prefix.
            header += (
                2 if (stage.argv[header] == "function"
                      or stage.argv[header + 1:header + 2] == ["()"])
                else 1
            )
            for token in stage.argv[header:]:
                if token not in shell_reader.KEYWORDS:
                    break
                depth += (token in _COMPOUND_OPEN) - (token in _COMPOUND_CLOSE)
    return depth


_STDIN_REDIRECT = re.compile(r"^(?:0)?(?:<|<<|<<<|<&)")
_STDOUT_REDIRECT = re.compile(r"^(?:1)?(?:>|>>|>&)")


def _redirected(words, pattern):
    """Whether any word redirects the descriptor selected by ``pattern``."""
    return any(pattern.match(shell_reader.readable(word)) for word in words)


def _inline_pipeline(stage):
    """Stages spelled inline after a compound close's first pipe."""
    if "|" not in stage.argv:
        return []
    pipeline: list[list[str]] = []
    current: list[str] = []
    for word in stage.argv[stage.argv.index("|") + 1:]:
        if word == "|":
            pipeline.append(current)
            current = []
        else:
            current.append(word)
    pipeline.append(current)
    following = []
    for position, words in enumerate(pipeline):
        stdin = not _redirected(words, _STDIN_REDIRECT)
        stdout = position < len(pipeline) - 1 and not _redirected(
            words, _STDOUT_REDIRECT
        )
        following.append(stage._replace(
            argv=words,
            stdin_from_pipe=stdin,
            stdout_to_pipe=stdout,
            pipe_input_fds=("0",) if stdin else (),
        ))
    return following


def _closing_output(statement):
    """The first closing stage's file or forwarding-pipe route."""
    for position, close in enumerate(statement.stages):
        one = shell_reader.Statement([close], statement.separator)
        if _compound_delta(one) >= 0:
            continue
        following = statement.stages[position + 1:] or _inline_pipeline(close)
        next_argv = command(following[0].argv) if following else []
        piped_to = (tuple(next_argv) if close.stdout_to_pipe and next_argv
                    and _may_read_pipe(next_argv, following[0]) else None)
        if (piped_to and os.path.basename(piped_to[0]) == "tee"
                and _stream_forwarded(following)):
            piped_to = _ForwardedTee(piped_to)
        if close.stdout_writes or not close.stdout_to_pipe or following:
            return close, piped_to
    return None


def _compound_outputs(stmts):
    """Map stages to closing outputs, excluding array literals from depth."""
    levels, depth, literal_depth = {}, 0, 0
    for position, statement in enumerate(stmts):
        for number, stage in enumerate(statement.stages):
            before = depth
            literals = min(_literals(stage), stage.group_open)
            literal_depth += literals
            literal_closes = min(literal_depth, stage.group_close)
            literal_depth -= literal_closes
            groups = stage.group_open - literals - stage.group_close + literal_closes
            one = shell_reader.Statement([stage], statement.separator)
            # A function body's unmatched `}` must not make a follower nested.
            depth = max(0, depth + groups + _compound_delta(one, False))
            levels[position, number] = before, depth
    inherited: dict[int, tuple] = {}
    outputs: dict[tuple[int, int], tuple] = {}
    for position in range(len(stmts) - 1, -1, -1):
        statement = stmts[position]
        for number in range(len(statement.stages) - 1, -1, -1):
            before, after = levels[position, number]
            if after < before:
                suffix = statement._replace(stages=statement.stages[number:])
                output = _closing_output(suffix) or inherited.get(after)
                if output is not None:
                    for level in range(after + 1, before + 1):
                        inherited[level] = output
            level = max(before, after)
            if level in inherited:
                outputs[position, number] = inherited[level]
            if after > before:
                for level in range(before + 1, after + 1):
                    inherited.pop(level, None)
    return outputs


def _forwarded_output(stmts, mapped, locations, output):
    """Follow forwarding consumers to the output of their own compound."""
    piped_to = output[1]
    while output is not None and output[1] is not None:
        where = locations.get(id(output[0]))
        if where is None:
            break
        position, number = where
        following = stmts[position].stages[number + 1:]
        if not following or not _stream_forwarded(following):
            break
        output = mapped.get((position, number + 1))
    return (output[0], piped_to) if output is not None else None


def _contains_compound_forwarder(following):
    """Whether a forwarding pipeline enters a lexical compound command."""
    return any(_compound_delta(shell_reader.Statement([stage], "")) > 0
               for stage in following)


def _outer_brace_output(stmts, where):
    """The first redirected brace after consecutive unredirected closes."""
    position, number = where
    for current in range(position, len(stmts)):
        start = number + 1 if current == position else 0
        for stage in stmts[current].stages[start:]:
            if stage.argv != ["}"] or stage.group_close:
                return None
            if stage.redirected:
                return stage if stage.stdout_writes else None
    return None


def compound_output(stmts, outputs, position, stage, following):
    """The stage and next argv after its own or its compound's stdout."""
    if following:
        return stage, tuple(shell_reader.acted(following[0].argv))
    if not stage.stdout_to_pipe:
        return stage, None
    if outputs[0] is None:
        outputs[0] = _compound_outputs(stmts)
        depth = 0
        outputs.extend(({id(candidate): (p, n) for p, one in enumerate(stmts)
                         for n, candidate in enumerate(one.stages)},
                        [(depth := depth + _compound_delta(one, False)) for one in stmts]))
    number = next(number for number, candidate in enumerate(stmts[position].stages)
                  if candidate is stage)
    output = outputs[0].get((position, number))
    if output is None:
        return stage, None
    close, piped_to = output
    # A reader may combine nested subshell closes and both of their redirects
    # in one stage. The inner file still cuts the fetch off from the outer one.
    if close.group_close > 1 and close.writes != close.stdout_writes:
        return stage, None
    where = outputs[1].get(id(close))
    close_following = stmts[where[0]].stages[where[1] + 1:] if where else []
    depth = outputs[2][position]
    forwarded = _forwarded_output(stmts, outputs[0], outputs[1], output)
    if (forwarded is not None and forwarded[0] is not close and depth > 0 and
            (close.group_close or _contains_compound_forwarder(close_following)) and
            len(forwarded[0].writes) == len(forwarded[0].stdout_writes)):
        close = forwarded[0]
    elif (piped_to is None and where and number == 0 and depth > 0
          and close.group_close == 1 and close.redirected):
        outer = _outer_brace_output(stmts, where)
        if outer is not None:
            close = outer
    inherited_pipe = (piped_to if isinstance(piped_to, _InheritedOutput)
                      else _InheritedOutput(piped_to) if piped_to is not None else None)
    return stage._replace(stdout_writes=_InheritedOutput(close.stdout_writes)), inherited_pipe
