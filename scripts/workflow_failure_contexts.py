#!/usr/bin/env python3
"""Failure contexts around checks in workflow shell statements.

Split verbatim from ``workflow_gating`` so the gating layer stays below the
flat-module ceiling.  ``workflow_gating`` keeps compatibility imports for the
callers that already name these helpers there.
"""
import shell_reader
from shell_reader import command
from workflow_function_calls import _function_syntax, _known_status


def _structural_groups(stage):
    """Leading brace and subshell opens/closes carried by this stage."""
    braces = []
    for token in stage.argv:
        if token not in shell_reader.KEYWORDS:
            break
        if token in ("{", "}"):
            braces.append(token)
    return stage.group_open + braces.count("{"), stage.group_close + braces.count("}")


def conditional_contexts(stmts):
    """{statement: ((list head, carrier end), ...)} for conditional groups."""
    stack, active = [], []
    for index, statement in enumerate(stmts):
        opens = closes = 0
        for stage in statement.stages:
            opened, closed = _structural_groups(stage)
            opens, closes = opens + opened, closes + closed
        for _opening in range(opens):
            group = [index, None]
            stack.append(group)
        active.append(tuple(stack))
        for _closing in range(closes):
            if stack:
                stack.pop()[1] = index
    contexts = {}
    for position, groups in enumerate(active):
        ends: dict[int, list[int | None]] = {}
        for start, end in groups:
            if start and stmts[start - 1].separator in ("&&", "||"):
                ends.setdefault(start, []).append(end)
        found = [(start - 1, None if None in bounds
                  else max(end for end in bounds if end is not None))
                 for start, bounds in ends.items()]
        if (position and position not in ends
                and stmts[position - 1].separator in ("&&", "||")):
            found.append((position - 1, position))
        if found:
            contexts[position] = tuple(found)
    return contexts


def _negation_count(words):
    """Leading status inversions; assignments end the reserved-word prefix."""
    count = 0
    for word in words:
        if word == "!":
            count += 1
        elif word not in shell_reader.KEYWORDS:
            break
    return count


def _known_failure(statement):
    """Whether this one command certainly leaves a failing list status."""
    if len(statement.stages) != 1:
        return False
    stage = statement.stages[0]
    # Defining a function succeeds without running its body.  In particular,
    # `false || f() ( false ) || CHECK` skips CHECK; the body's known status
    # says nothing about the definition command that the `||` list sees.
    if _function_syntax(stage.argv)[0] is not None:
        return False
    status = _known_status(command(stage.argv), None)
    if status is None:
        return False
    return (status != 0) != bool(_negation_count(_failure_context(stage.argv)) % 2)


def _skippable_or(stmts, index):
    """Whether an earlier successful `||` path may skip this statement."""
    contexts = conditional_contexts(stmts)

    def skipped(position, seen=()):
        if position in seen:
            return False
        return any(stmts[source].separator == "||" and
                   (not _known_failure(stmts[source])
                    or skipped(source, seen + (position,)))
                   for source, _carrier in contexts.get(position, ()))

    return skipped(index)


def _function_body(words, bare=0):
    """Words after a function header, whatever compound opens its body."""
    name = _function_syntax(words)[0]
    start = 0
    while (start < len(words) and words[start] in shell_reader.KEYWORDS
           and words[start] != "function"):
        start += 1
    # Inside another function, or after `then` / a group opener, shell_reader
    # can retain only the bare name from `name() compound-command`.
    explicit = (start + 1 < len(words)
                and words[start + 1] in ("{", "(", "if", "while", "until", "for", "case"))
    if (name is None and start + 1 < len(words) and (explicit or bare)
            and (_function_syntax([words[start], "()"])[0] == words[start])):
        return words[start + 1:], not explicit
    if name is None:
        return None
    if words[start] == "function":
        end = start + 2
    elif words[start] == name + "()":
        end = start + 1
    else:                                           # `name () compound-command`
        end = start + 2
    if end < len(words) and words[end] == "()":
        end += 1
    return words[end:], False


def _failure_context(argv, plain_arm=False, structure=None):
    """Words around a status after its structural headers, to a fixed point."""
    # Parentheses lost from `name()` and a subshell body remain in stage counts.
    bare = (min(structure.group_close, max(structure.group_open - structure.group_close, 0))
            if structure is not None else 0)
    compound = bool(structure and structure.group_open > structure.group_close)
    words = argv
    while words:
        if shell_reader.is_arm(words[0]):
            words = words[1:]
            continue
        if (plain_arm and len(words) > 1 and
                (words[1] in shell_reader.KEYWORDS
                 or _function_syntax(words[1:])[0] is not None)):
            words, plain_arm = words[1:], False
            continue
        body = _function_body(words, bare)
        if body is not None:
            words, consumed = body
            bare -= consumed
            continue
        lead = next((at for at, word in enumerate(words)
                     if word not in shell_reader.KEYWORDS), len(words))
        if lead < len(words) and words[lead] in ("time", "coproc"):
            end = lead + 1
            if words[lead] == "time":
                while end < len(words) and words[end].startswith("-"):
                    end += 1
            elif (end < len(words) and (compound or
                  end + 1 < len(words) and words[end + 1] in ("{", "("))
                  and (_function_syntax([words[end], "()"])[0] == words[end])):
                end += 1
            # Bash 3.2 runs external `time` here, whose rejected `!` a leading
            # negation turns successful; Bash 5 instead reads both as reserved words.
            bash3_time = (words[lead] == "time" and _negation_count(words[:lead]) % 2
                          and _negation_count(words[end:]) % 2)
            words = words[:lead] + ["!"] * bool(bash3_time) + words[end:]
            continue
        if words[0] in ("{", "("):
            words = words[1:]
            continue
        # A function header before `case` makes shell_reader retain the arm as
        # plain words rather than an arm token: `case WORD in PATTERN command`.
        if len(words) >= 4 and words[0] == "case" and words[2] == "in":
            words = words[4:]
            continue
        return words
    return words


def _inside_unmarked_case(stmts, index):
    """Whether a prior statement opened a case whose arm markers were lost."""
    cases = []
    for statement in stmts[:index + 1]:
        for stage in statement.stages:
            for token in stage.argv:
                if token == "case":
                    cases.append(False)
                elif shell_reader.is_arm(token) and cases:
                    cases[-1] = True
                elif token == "esac" and cases:
                    cases.pop()
    return bool(cases and not cases[-1])


def _enclosing_failure_contexts(stmts, index):
    """Failure prefixes on structural groups enclosing this statement."""
    stack: list[list[str]] = []
    for statement in stmts[:index]:
        for stage in statement.stages:
            opens, closes = _structural_groups(stage)
            for _close in range(min(closes, len(stack))):
                stack.pop()
            if opens:
                context = _failure_context(stage.argv, structure=stage)
                stack.extend([context] + [[]] * (opens - 1))
    return stack
