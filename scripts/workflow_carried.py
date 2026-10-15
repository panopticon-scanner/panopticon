#!/usr/bin/env python3
"""Carried download values and their same-shell assignment state.

This is the variable-held program layer split from ``workflow_forms`` at its
700-line ceiling.  It follows a stdout fetch through scalar assignments to a
shell handoff, keeps child and uncertain scopes fail-closed, and proves the
narrow same-shell replacements that retire #2437's stale carried value and
generic dynamic-program fallback.
"""
import os
import re
from typing import cast

import shell_reader
from shell_reader import command, statements
from workflow_called import (_UNSURE, _possible_called_readonly, _reached, _skipped_call, _status_shadows,
                             _written)
from workflow_fetch import (FETCHERS, Fetch, compound_stream_consumer, parse_fetch,
                            stdout_fetch, stream_consumer)
from workflow_gating import (Inlined, _piped_group_stage, _structural_groups,
                             conditional_contexts)
from workflow_operands import working_directories
from workflow_programs import ANY, candidates, dynamic_program, scripts
from workflow_step_credit import _plain_stage, _static, regions, step_credit
from workflow_use_scopes import _forked, _function_ranges


INSIDE = " inside a command substitution"


def within(statement, where="", directory=".", scope=0):
    """Each stage and cwd, recursively through command substitutions.

    A substitution inherits and restores its caller's cwd. A shell string is
    reported by `kept`, not read; checks inside stay unread and fail closed
    (#2345)."""
    for position, stage in enumerate(statement.stages):
        yield statement, position, stage, where, directory
        for nested, text in enumerate(stage.substitutions):
            inner = list(statements(text))
            child_scope = "%sS%d_%d" % (scope, position, nested)
            working = working_directories(inner, regions(inner), child_scope,
                                           step_credit(inner, "bash {0}"), directory)
            for index, child in enumerate(inner):
                yield from within(child, INSIDE, working[index], "%sI%d" % (child_scope, index))


# A download a step keeps in a variable and hands a shell as its script
# (#2341): `x=$(curl -fsSL URL)`, then `eval "$x"`, `sh -c "$x"` or `echo "$x"
# | sh`. No file ever holds it, so no checksum clears it, as none clears
# `eval "$(curl URL)"`; the sentence names the variable.
_CARRIES = ("carries %s in `$%s` and hands it to `%s`%s, so there is no file to check -- "
            "download it to a file, `sha256sum -c` that file, then run it")
_READS_CARRIES = ("carries %s in `$%s` and hands it to `%s`%s in this guard's conservative "
                  "reading, so there is no file to check -- download it to a file, `sha256sum "
                  "-c` that file, then run it")
_NAMED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\+?)=")
_WHOLE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
_DECLARES = ("export", "local", "declare", "typeset", "readonly")
_OPAQUE_STATE = (".", "alias", "eval", "source", "trap", "unalias")
_WRITERS = ("declare", "export", "getopts", "local", "mapfile", "read", "readarray",
            "readonly", "select", "typeset", "unset", "wait")
# Prefix assignments before these builtins persist in dash and bash's POSIX mode.
_SPECIAL = (":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly",
            "return", "set", "shift", "times", "trap", "unset")


def _held(word, embedded=False, names=None):
    """The held variable named whole by `word`, or embedded in its program text."""
    matches = _WHOLE.finditer(word) if embedded else (_WHOLE.fullmatch(word),)
    for match in matches:
        if match is None:
            continue
        outside = word[:match.start()] + word[match.end():]
        if embedded and outside and not outside.strip():
            continue                    # padding alone keeps #2483's existing answer
        name = match[1] or match[2]
        if names is None or name in names:
            return name
    return ""


def _prints(stage):
    """The words a supported printer stage writes to its standard output."""
    argv = command(stage.argv)
    if (argv and os.path.basename(argv[0]) == "cat"
            and stage.stdin_heredoc is not None):
        return [stage.stdin_heredoc[0]]
    return argv[1:] if argv and os.path.basename(argv[0]) in ("echo", "printf") else []


def _assignment_fetch(value):
    """The stdout fetch held by one substitution assignment value, or None."""
    if not (shell_reader.has_substitution(value)
            and shell_reader.readable(value) == "$(...)"):
        return None
    substitutions = [text for kind, text in getattr(value, "markers", {}).values()
                     if kind == "subst"]
    if len(substitutions) != 1:
        return None
    text = substitutions[0]
    if fetch := stdout_fetch(text):
        return fetch
    inner = list(statements(text))
    first = inner[0] if inner and inner[0].separator == "||" else None
    stage = first.stages[0] if first and len(first.stages) == 1 else None
    argv = command(stage.argv) if stage else []
    tool = os.path.basename(argv[0]) if argv else ""
    fetch = parse_fetch(tool, argv[1:], stage, None) if tool in FETCHERS else None
    return (fetch if stage is not None and fetch and fetch.url and fetch.dest is None
            and stage.stdout_to_pipe else None)


def _assigned(stage, held):
    """{name: (download, certain), or None} for what this stage assigns,
    in whatever shell runs it (`carried` weighs that). A bare assignment or a
    declaration's (`export x=...`) holds one when its value is the stage's one
    substitution and that is one fetch to standard output (`_assignment_fetch`), or
    is a variable that holds one, whole (`y="$x"`); `+=` holds a fetch on its
    right side; `unset` empties one, `unset -f` a function."""
    argv = command(stage.argv)
    name = os.path.basename(argv[0]) if argv else ""
    words = argv[1:] if name in _DECLARES else [] if argv else stage.argv
    if name in _SPECIAL and not shell_reader.wrapper_words(stage.argv):
        _names, _substitutions, prefixes, _replaced = _prefix_assignments(stage)
        words = prefixes + list(words)
    now = {}
    for word in words:
        match = _NAMED.match(word)
        if match:
            value = shell_reader.derived(word[match.end():], word)
            fetch = _assignment_fetch(value)
            if fetch:
                now[match[1]] = (fetch, True)
            elif not match[2]:
                now[match[1]] = held.get(_held(value))
    if name == "unset" and "-f" not in argv:
        now.update(dict.fromkeys((w for w in argv[1:] if w[:1] != "-"), None))
    return now


def may_carry_fetch(stmts):
    """Whether the holder's own assignment predicate finds a streamed fetch."""
    return any(value for statement in stmts for stage in statement.stages
               for value in _assigned(stage, {}).values())


def _posix_prefix_shell(shell):
    """Whether a declared shell keeps special-builtin prefix assignments."""
    words = (shell or "bash").split()
    name = os.path.basename(words[0]) if words else ""
    return bool(name == "sh" or name == "bash" and (
        "--posix" in words or any(left == "-o" and right == "posix"
                                  for left, right in zip(words, words[1:]))
    ))


def _plain_assignments(stage, shell=None):
    """Names this stage certainly replaces with expansion-free text, or unsets."""
    if not _plain_stage(stage):
        return set()
    argv = command(stage.argv)
    name = os.path.basename(argv[0]) if argv else ""
    words = argv[1:] if name in ("export", "readonly") else [] if argv else stage.argv
    if name in ("export", "readonly") and any(
            str(word).startswith(("-", "+")) and str(word) != "--" for word in words):
        words = []
    wrappers = shell_reader.wrapper_words(stage.argv)
    if any(os.path.basename(str(word)) == "time" for word in wrappers):
        return set()
    if (name in _SPECIAL and _posix_prefix_shell(shell)
            and not wrappers):
        _names, _substitutions, prefixes, _replaced = _prefix_assignments(stage)
        words = prefixes + list(words)
    plain = set()
    for word in words:
        if (match := _NAMED.match(word)) and not match[2]:
            value = shell_reader.derived(word[match.end():], word)
            # The reader no longer distinguishes quoted/escaped `~` from a
            # live tilde. A live one may expand from HOME, which can itself
            # hold the download, so none proves an independent literal here.
            if _static(value) and "~" not in str(value):
                plain.add(match[1])
            else:
                plain.discard(match[1])
    if name == "unset" and all(str(word) in ("-v", "--")
                                for word in argv[1:] if str(word).startswith("-")):
        plain.update(str(word) for word in argv[1:] if not str(word).startswith("-"))
    return plain


def _dynamic_command(stage):
    written = shell_reader.command_as_written(stage.argv if hasattr(stage, "argv") else stage)
    return bool(written and shell_reader.dynamic(
        written[0], shell_reader.has_substitution
    ))


def _hidden_writer(stage):
    """Whether this command may write names hidden from ``_written``."""
    argv = command(stage.argv)
    wrappers = {os.path.basename(str(word)) for word in shell_reader.wrapper_words(stage.argv)}
    wrapped = bool(argv and "command" in wrappers
                   and os.path.basename(str(argv[0])) in _WRITERS)
    return _dynamic_command(stage) or wrapped


def _unseen_write(statement):
    """Whether this statement may write a name its direct assignment view misses."""
    texts = [str(text) for stage in statement.stages
             for text in (*stage.argv, *stage.writes, *stage.reads, stage.heredoc or "")]
    commands = [list(command(stage.argv)) for stage in statement.stages]
    return (any(map(_UNSURE.search, texts)) or "let" in texts
            or (not isinstance(statement, Inlined)
                and any(_hidden_writer(stage) for stage in statement.stages))
            or any(argv[:1] in (["trap"], ["coproc"])
                   or argv[:1] == ["wait"] and "-p" in argv[1:]
                   for argv in commands))


def _opaque_state(statement):
    """Whether this statement can install later writes or command dispatch."""
    for stage in statement.stages:
        argv = command(stage.argv)
        if argv and os.path.basename(str(argv[0])) in _OPAQUE_STATE:
            return True
    return False


def _bash(shell):
    """Whether Bash-only declaration attributes may take effect."""
    if shell == ANY:
        return True
    words = (shell or "bash").split()
    return bool(words and os.path.basename(words[0]) == "bash")


def _declaration_attributes(stage, shell):
    """(readonly names, nameref targets, unknown target) declared here."""
    argv = list(command(stage.argv if hasattr(stage, "argv") else stage))
    name = os.path.basename(str(argv[0])) if argv else ""
    if name not in ("declare", "local", "readonly", "typeset"):
        return set(), set(), False
    options = [str(word) for word in argv[1:] if str(word).startswith(("-", "+"))]
    minus = "".join(word[1:] for word in options if word.startswith("-") and word != "--")
    operands = [str(word) for word in argv[1:] if not str(word).startswith(("-", "+"))]
    readonly = name == "readonly" or name in ("declare", "typeset") and "r" in minus
    readonly_names = set()
    if readonly:
        readonly_names = {word.split("=", 1)[0] for word in operands
                          if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:=.*)?", word)}
    nameref = _bash(shell) and name in ("declare", "local", "typeset") and "n" in minus
    targets, unknown = set(), False
    if nameref:
        for word in operands:
            _holder, equals, target = word.partition("=")
            if equals and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                targets.add(target)
            else:
                unknown = True
    return readonly_names, targets, unknown


def _prefix_assignments(stage):
    """The scalar assignments before this simple command, and the substitutions each holds."""
    names: dict[str, str] = {}
    assignments: list[tuple[str, bool, str]] = []
    words: list[str] = []
    timed = False
    for word in stage.argv:
        if word in shell_reader.KEYWORDS or shell_reader.is_arm(word):
            continue
        if word == "time" and not names:
            timed = True
            continue
        if timed and word in ("-p", "--"):
            continue
        if not shell_reader._ASSIGNMENT.match(word) or getattr(word, "quoted", False):
            break
        if match := _NAMED.match(word):
            words.append(word)
            names[match[1]] = word
            assignments.append((match[1], bool(match[2]), word))
    substitutions: dict[int, tuple[str, bool]] = {}
    replaced: set[str] = set()
    for name, appended, word in reversed(assignments):
        active = name not in replaced
        substitutions.update((id(text), (name, active)) for kind, text in
                             getattr(word, "markers", {}).values() if kind == "subst")
        if not appended:
            replaced.add(name)
    return names, substitutions, words, replaced


def _after_prefix(word, name, argv):
    """Whether an executor re-reads `name` after prefixing: live references expand first;
    delayed literals are reread by `eval`/`-c`; ambiguous reader-built strings fail closed."""
    if not _held(word, embedded=True, names={name}):
        return False
    sources = [source for source in argv if source is word]
    if not sources:
        sources = [source for source in argv if str(source) == str(word)
                   or str(getattr(source, "spelled", "")) == str(word)]
    if not sources:
        return True
    return any(hasattr(source, "spelled") or getattr(source, "kept", False)
               and not getattr(source, "live_dollar", False) for source in sources)


def prefix_handoff(stage, substitution, argv):
    """Whether `substitution` can feed the executor in its own prefix-assigned command (#2433)."""
    _names, substitutions, _words, _replaced = _prefix_assignments(stage)
    binding = substitutions.get(id(substitution))
    if binding is None:
        return True
    name, active = binding
    if not active:
        return False
    programs = list(scripts(argv))
    if not shell_reader.unresolved_wrapper(stage.argv):
        programs += candidates(argv)[1]
    _how, dynamic = dynamic_program(argv)
    if dynamic is not None:
        programs.append(dynamic)
    if not programs:
        return bool(argv and os.path.basename(argv[0]) not in ("source", "."))
    return any(_after_prefix(word, name, argv) for word in programs)


def prefix_expanded_program(stage, argv):
    """Whether the unread program is a live reference expanded before its prefix is applied."""
    _how, word = dynamic_program(argv)
    names, _substitutions, _words, _replaced = _prefix_assignments(stage)
    name = word is not None and _held(word, names=set(names))
    return bool(name and not _after_prefix(word, name, argv))


def _outer_group_depths(stmts, occupied):
    """Structural and subshell depths around statements, excluding function bodies.

    A definition inside a subshell or brace compound may not exist in the
    caller's shell.  Function bodies are skipped because their own closing
    brace has no matching opener in ``_structural_groups``: the header keeps
    that opener behind the function name.
    """
    depth, subshell, out, subshells = 0, 0, [], []
    for index, statement in enumerate(stmts):
        out.append(depth)
        subshells.append(subshell)
        if index in occupied:
            continue
        for stage in statement.stages:
            opens, closes = _structural_groups(stage)
            depth = max(0, depth + opens - closes)
            subshell = max(0, subshell + stage.group_open - stage.group_close)
    return out, subshells


def _safe_enclosing_groups(stmts, occupied):
    """Whether each statement's structural groups have executable boundaries."""
    stack, active, frames = [], [], []
    for index, statement in enumerate(stmts):
        opens = closes = 0
        if index not in occupied:
            for stage in statement.stages:
                opened, closed = _structural_groups(stage)
                opens, closes = opens + opened, closes + closed
        for _opening in range(opens):
            frame = [index, None]
            frames.append(frame)
            stack.append(frame)
        active.append(tuple(stack))
        for _closing in range(closes):
            if stack:
                stack.pop()[1] = index

    safe = {}
    for frame in frames:
        start, close = frame
        safe[id(frame)] = bool(close is not None and all(
            _plain_stage(stage) for at in (start, close) for stage in stmts[at].stages
        ))
    return [all(safe[id(frame)] for frame in groups) for groups in active]


def _function_barrier(stmts, start, stop, name, starts):
    """Whether earlier code may replace/remove a definition or alter its call."""
    functions = {function for at, entries in starts.items() if at < stop
                 for function, _head, _close in entries}
    for statement in stmts[start:stop]:
        for stage in statement.stages:
            argv = list(command(stage.argv))
            while argv and os.path.basename(str(argv[0])) in ("builtin", "command"):
                argv = argv[1:]
                while argv and str(argv[0]).startswith("-"):
                    argv = argv[1:]
            if not argv:
                continue
            head = os.path.basename(str(argv[0]))
            if head in _OPAQUE_STATE or str(argv[0]) in functions:
                return True
            if head == "unset":
                function = any(str(word).startswith("-") and "f" in str(word)[1:]
                               for word in argv[1:])
                operands = [str(word) for word in argv[1:] if not str(word).startswith("-")]
                if function and (name in operands or any(
                        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", word)
                        for word in operands)):
                    return True
    return False


def _called_assignments(stmts, index, starts, held, branches, conditionals, outer, probe,
                        shell=None, bodies=None):
    """Certain caller-visible assignments and readonly names from one direct call."""
    bodies = _reached(stmts, index, starts) if bodies is None else bodies
    if len(bodies) != 1:
        return {}, set(), set()
    start, close = bodies[0]
    definitions = [(name, head, end) for entries in starts.values()
                   for name, head, end in entries if (head, end) == (start, close)]
    if len(definitions) != 1:
        return {}, set(), set()
    name = definitions[0][0]
    call_stage = stmts[index].stages[0]
    call = command(call_stage.argv)
    if (not call or str(call[0]) != name or not _plain_stage(call_stage)
            or outer[start] or branches.get(start)
            or conditionals.get(start) or _piped_group_stage(stmts, start) is not None
            or stmts[close].separator == "&"
            or _function_barrier(stmts, 0, index, name, starts)):
        return {}, set(), set()
    nested = {at for entries in _function_ranges(stmts)[0].values()
              for _name, head, end in entries if head > start
              for at in range(head, end + 1)}
    changed: dict[str, tuple[Fetch, bool] | None] = {}
    plain: set[str] = set()
    local: set[str] = set()
    readonly: set[str] = set()
    caller_readonly: set[str] = set()
    blocked: set[str] = set()
    block_all = False
    subshells, compounds, may_return = 0, 0, False
    for at in range(start, close + 1):
        statement = stmts[at]
        written = _written(statement, probe)
        if probe in written or _unseen_write(statement):
            changed.clear()
            plain.clear()
        else:
            for variable in written:
                changed.pop(variable, None)
                plain.discard(variable)
        for stage in statement.stages:
            argv = command(stage.argv)
            name = os.path.basename(argv[0]) if argv else ""
            words = argv[1:] if name in ("local", "declare", "typeset") else ()
            if words and not any(str(word).startswith(("-", "+")) and "g" in str(word)
                                 for word in words):
                local.update(str(word).split("=", 1)[0] for word in words
                             if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:=.*)?", str(word)))
            made_readonly, targets, unknown = _declaration_attributes(stage, shell)
            blocked.update(targets)
            plain.difference_update(targets)
            if unknown:
                block_all = True
                plain.clear()
            now = _assigned(stage, {**held, **changed})
            stage_plain = _plain_assignments(stage, shell) - readonly - blocked
            if block_all:
                stage_plain.clear()
            certain = (at not in nested and at not in branches and at not in conditionals
                       and not may_return and not subshells and not compounds
                       and not stage.group_open
                       and _piped_group_stage(stmts, at) is None
                       and len(statement.stages) == 1 and statement.separator != "&"
                       and not (at and stmts[at - 1].separator in ("&&", "||")))
            if certain:
                caller_readonly.update(made_readonly - local)
            for variable, value in now.items():
                if variable in local:
                    continue
                if certain:
                    changed[variable] = value
                    if value is None and variable in stage_plain:
                        plain.add(variable)
                    else:
                        plain.discard(variable)
                else:
                    changed.pop(variable, None)
                    plain.discard(variable)
            readonly.update(made_readonly)
            if name == "return":
                if certain:
                    return changed, plain, caller_readonly
                may_return = True
            subshells = max(0, subshells + stage.group_open - stage.group_close)
            opens, closes = _structural_groups(stage)
            compounds = max(0, compounds + opens - closes)
    return changed, plain, caller_readonly


def carried(stmts, executors, shell=None):
    """Reasons for a download held in a variable and handed whole to a shell (#2341).
    Follows `$x`/`${x}` through `eval`, `-c`, candidate programs, supported printers, piped
    compounds, and executor substitutions; each substitution has its own assignment state.
    Uncertain scope, status, or quote loss keeps a name held and identifies the guard's reading
    (#2424). Saved files and compound assignments are not followed."""
    held: dict[str, tuple[Fetch, bool] | None] = {}
    out, cleared, branches, subshells = [], set(), regions(stmts), 0
    # Names that held a fetch and were then certainly replaced with plain text.
    plain: set[str] = set()
    readonly: set[str] = set()
    blocked: set[str] = set()
    block_all = False
    starts, occupied = _function_ranges(stmts)
    status_shadows = _status_shadows(stmts, starts)
    conditionals = conditional_contexts(stmts)
    body_attributes = {
        (start, close): _possible_called_readonly(
            stmts, [(start, close)], branches, conditionals, shell,
            _declaration_attributes, _dynamic_command
        )
        for entries in starts.values() for _name, start, close in entries
    }
    stateful_bodies = {
        (start, close) for entries in starts.values()
        for _name, start, close in entries
        if any(body_attributes[(start, close)]) or any(
            _assigned(stage, {}) for statement in stmts[start:close + 1]
            for stage in statement.stages)
    }
    forked = _forked(stmts, len(stmts))
    outer, outer_subshells = _outer_group_depths(stmts, occupied)
    safe_groups = _safe_enclosing_groups(stmts, occupied)
    probe = "_" * (2 + max((len(str(word)) for statement in stmts
                             for stage in statement.stages for word in stage.argv), default=0))
    detached_definitions = {at for entries in starts.values()
                            for _name, start, close in entries if outer_subshells[start]
                            for at in range(start, close + 1)}
    child_values: dict[str, tuple[int | None, bool, bool]] = {}  # boundary, introduced, uncertain
    inlined_handoffs: set[str] = set()          # a flattened child owns its wrapper's same handoff
    opaque = False
    for index, statement in enumerate(stmts):
        escaped = {key for key, (boundary, _introduced, _uncertain) in child_values.items()
                   if boundary is None and not isinstance(statement, Inlined)
                   or boundary is not None and subshells < boundary}
        held.update({key: (cast(tuple[Fetch, bool], held[key])[0], False)
                     for key in escaped if child_values[key][1] and held.get(key)})
        child_values = {key: value for key, value in child_values.items()
                        if key not in escaped}
        for inner, position, stage, where, _directory in within(statement):
            argv = command(stage.argv)
            _prefixes, _substitutions, _words, replaced = _prefix_assignments(stage)
            printed, piped = _prints(stage), stage.stdout_to_pipe
            to = (stream_consumer(inner.stages[position + 1:], executors)
                  if printed and piped else None)
            if printed and piped and not to and not where and position == len(inner.stages) - 1:
                to = compound_stream_consumer(stmts, index, executors)
            words = [(word, getattr(word, "kept", False), True) for word in scripts(argv)]
            words += [(word, True, False) for word in printed if to]
            words += [(word, getattr(word, "kept", False), True) for word in (
                [] if shell_reader.unresolved_wrapper(stage.argv) else candidates(argv)[1])]
            if argv and os.path.basename(argv[0]) in executors:
                words += [(word, True, False) for text in stage.substitutions
                          for inside in statements(text) for word in _prints(inside.stages[-1])]
            for word, embedded, program in words:
                known = _held(word, embedded=embedded)
                if program and known in plain and not opaque:
                    cleared.add((index, known))
                available = {name for name, value in held.items() if value and (
                    isinstance(statement, Inlined) or name not in inlined_handoffs)}
                variable = _held(word, embedded=embedded, names=available)
                if program and variable in replaced and _after_prefix(word, variable, argv):
                    continue
                kept = held.get(variable)
                if kept:
                    fetch, certain = kept
                    consumer = to or [w for w in argv if getattr(w, "spelled", w) is not word
                                      and not shell_reader.is_marker(w)]
                    scope = child_values.get(variable)
                    certain = certain and not (scope and scope[2]) and "-c" not in consumer
                    out.append((index, (_CARRIES if certain else _READS_CARRIES) % (
                        shell_reader.readable(fetch.url), variable,
                        " ".join(shell_reader.readable(w) for w in consumer), where)))
                    if isinstance(statement, Inlined):
                        inlined_handoffs.add(variable)
                    break
        if len(statement.stages) == 1:
            stage = statement.stages[0]
            now = _assigned(stage, held)
            sure = not (isinstance(statement, Inlined) or branches.get(index)
                        or conditionals.get(index) or subshells or stage.group_open
                        or not safe_groups[index] or index in forked or statement.separator == "&"
                        or index and stmts[index - 1].separator in ("&&", "||"))
            if index in detached_definitions:
                now = {}
            elif index in occupied:
                now = {key: (cast(tuple[Fetch, bool], value or held[key])[0], False)
                       for key, value in now.items() if value or held.get(key)}
            inlined_child = (isinstance(statement, Inlined)
                             and "script `eval` runs" not in str(statement.credit))
            child = bool(statement.separator == "&" or stage.group_open or subshells
                         or inlined_child)
            stateful = not child and index not in occupied and index not in detached_definitions
            made_readonly, targets, unknown = _declaration_attributes(stage, shell)
            if stateful:
                blocked.update(targets)
                plain.difference_update(targets)
                if unknown or not isinstance(statement, Inlined) and _dynamic_command(stage):
                    block_all = True
                    plain.clear()
            if not child:
                written = _written(statement, probe)
                if probe in written or _unseen_write(statement):
                    plain.clear()
                else:
                    plain.difference_update(written)
            replaced_carry = {key for key in now if held.get(key) or key in plain}
            held.update(now if sure else {
                key: (cast(tuple[Fetch, bool], value or held[key])[0],
                      bool(value and (child or isinstance(statement, Inlined))))
                for key, value in now.items()
                if value or not child and held.get(key)})
            if sure:
                stage_plain = _plain_assignments(stage, shell) - readonly - blocked
                if block_all:
                    stage_plain.clear()
                plain.difference_update(now)
                plain.update(key for key, value in now.items()
                             if value is None and key in stage_plain and key in replaced_carry)
            else:
                plain.difference_update(now)
            if stateful:
                readonly.update(made_readonly)
            if child:
                boundary = None if inlined_child else max(1, subshells + stage.group_open)
                for key, value in now.items():
                    prior = child_values.get(key)
                    child_values[key] = (boundary, bool(value) or bool(prior and prior[1]),
                                         not bool(value))
            bodies = _reached(stmts, index, starts)
            if bodies and not child:
                # A refused or nested call may write any holder. Exact direct
                # calls add their proved plain replacements back below.
                plain.clear()
            # A body with no scalar assignment or declaration attribute cannot
            # alter either carried state. Avoid re-reading it at every call site:
            # large, repeatedly called bodies are a bounded-work contract (#2855).
            stateful_call = any(body in stateful_bodies for body in bodies)
            possible_readonly, possible_unknown = ((
                set().union(*(body_attributes[body][0] for body in bodies)),
                any(body_attributes[body][1] for body in bodies)
            ) if bodies and not child and stateful_call
                and not _skipped_call(stmts, index, branches, status_shadows) else (set(), False))
            if possible_unknown:
                block_all = True
                plain.clear()
            called_readonly: set[str] = set()
            if sure and stateful_call:
                called, called_plain, called_readonly = _called_assignments(
                    stmts, index, starts, held, branches, conditionals, outer, probe, shell, bodies
                )
                called_plain.difference_update(readonly | blocked)
                if block_all:
                    called_plain.clear()
                replaced_carry = {key for key in called_plain if held.get(key) or key in plain}
                held.update(called)
                plain.difference_update(called)
                plain.update(replaced_carry)
                readonly.update(called_readonly)
            blocked.update(possible_readonly - called_readonly)
        for stage in statement.stages:              # a `( )` or `{ }` group, as `_errexit_states`
            subshells = max(0, subshells + stage.group_open - stage.group_close)
        if not isinstance(statement, Inlined):
            inlined_handoffs.clear()
        opaque = opaque or _opaque_state(statement)
    return out, cleared
