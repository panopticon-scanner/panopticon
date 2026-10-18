#!/usr/bin/env python3
"""Downloaded-file use discovery for the workflow fetch-and-execute guard.

Shell patterns designate concrete files before a loop variable, positional
parameter, or function argument receives the resulting word. This module
keeps that bounded value fact long enough to recognize the later use, while
quoted and nonmatching patterns remain ordinary strings.

The step's own LITERAL values are a second kind of bounded value fact beside
those glob bindings (#2425, #2489), read by `scripts/workflow_values.py`;
`static_values` here is that table live at one statement, which `uses` reads
a stage through, and this module re-exports its `Values`, `assigned`,
`record`, `valued` and `valued_argvs`, so a caller reaches them with `uses`.
"""
from dataclasses import dataclass
import os
import re

import shell_reader
from shell_reader import command
from workflow_called import _carried, _writes, record_called, with_call_stdin
from workflow_checks import inside
from workflow_options import _MAINS
from workflow_forms import (BIN_DIRS, CONTAINERS, at_directory,
                            chmod_conditional_executable, chmod_executable, chmod_targets,
                            covers, described, in_container, may_run, same_file, stdin_program)
from workflow_programs import VALUE_PROGRAM, reader_files, redirection_handoffs
from workflow_printers import _cat_reads_stdin
from workflow_use_scopes import (_COMPOUNDS as _COMPOUNDS, _forked as _forked, _forked_index,
                                 _function_changes, _function_ranges as _function_ranges,
                                 _openers as _openers, _opens as _opens,
                                 _own_parens as _own_parens)
# Compatibility bindings: the value table moved to `workflow_values` with its
# names, and its callers keep reaching them here.
from workflow_values import (Values as Values, assigned as assigned, record as record,
                             valued as valued, valued_argvs as valued_argvs)
from workflow_values import PAST, _as_word as _as_word, _for_parts, _literals, emptied
# The command words a use is read through moved to `workflow_use_words` whole; its callers keep reaching them here.
from workflow_use_words import (EXECUTORS as EXECUTORS, INTERPRETERS as INTERPRETERS, UNPACKERS as UNPACKERS,
                                _WHOLE as _WHOLE, _copied, _first_operand, _resolved as _resolved,
                                _on_stdin as _on_stdin, _unvalued, _value_command as _value_command,
                                _value_stage)


_REFERENCE = re.compile(
    r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|([1-9][0-9]*)|([@*])|"
    r"\{([A-Za-z_][A-Za-z0-9_]*|[1-9][0-9]*|[@*])\})"
)
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=")
_DECLARATIONS = ("declare", "export", "local", "readonly", "typeset")


@dataclass(frozen=True)
class Binding:
    """A glob result and the directory where its relative spelling was made."""

    directory: str
    absolute: bool = False
    loop: bool = False


def _reference(word):
    """The name or positional number named by one whole expansion word."""
    match = _REFERENCE.fullmatch(str(word))
    return next((part for part in match.groups() if part), "") if match else ""


def _active(bindings, word, directory):
    """The binding this whole value still designates here, or None."""
    name = _reference(word)
    if name in ("@", "*"):
        numbered = sorted(
            ((int(key), binding) for key, binding in bindings.items() if key.isdecimal()),
        )
        binding = next((value for _number, value in numbered
                        if value.absolute or value.directory == directory), None)
    else:
        binding = bindings.get(name)
    return (binding if binding and (binding.absolute or binding.directory == directory)
            else None)


def _live(named, positional, directory):
    """Bound names that still designate the file in `directory`, and the name the cap's
    stand-in reads (`workflow_values.PAST`, #2871), which designates every download."""
    bound = {
        name for name, binding in {**named, **positional}.items()
        if binding.absolute or binding.directory == directory
    }
    if "1" in bound:
        bound.update(("@", "*"))
    return bound | {_reference(PAST)}


def _from_operand(word, dest, directory, bindings):
    """A binding made by a live matching pattern or another bound value."""
    name = _reference(word)
    if name and (binding := _active(bindings, word, directory)):
        return binding
    absolute = os.path.isabs(str(word))
    if (not absolute and directory.startswith("$CWD")
            or getattr(word, "lead", None) is None):
        return None
    if not covers(at_directory(word, directory), dest):
        return None
    return Binding(directory, absolute)


def _cleared(stage, named, positional, certain, direct_loop, table=None):
    """Drop value facts a command overwrites; it does not create new ones.

    With `table` (#2425, #2489), an `unset` or bare `local` empties the name's
    literal values too (`emptied`): they go where `certain` -- the table's
    answer, `static_values`' -- and gain the "maybe unset" candidate where
    not; a `read` sets the name to a value the table cannot see, its
    stand-in. Behind `builtin`, a `read` or `unset` is `record`'s, which reads
    it for the table alone. An assignment's are left to `record`, which
    replaces them where certain: dropping them here first would lose the
    value `T+=.run` appends to and the one `T=$T.run` reads."""
    def drop(name, valueless=True, unknown=False):
        binding = named.get(name)
        if binding and (certain or direct_loop and binding.loop):
            named.pop(name)
        if table is not None and valueless:
            emptied(table, name, certain, unknown)

    argv = command(stage.argv)
    raw = list(stage.argv)
    # A prefix assignment belongs to the command's environment and does not
    # replace the caller's shell value. An assignment-only command does.
    prefix = raw if not argv else []
    for word in prefix:
        if match := _ASSIGNMENT.match(str(word)):
            drop(match[1], False)
    name = os.path.basename(argv[0]) if argv else ""
    if name in _DECLARATIONS:
        for word in argv[1:]:
            if ("=" in str(word) or name == "local") and not str(word).startswith("-"):
                drop(str(word).split("=", 1)[0], "=" not in str(word))
    elif name == "read" or (name == "unset" and "-f" not in argv):
        for word in argv[1:]:
            if not str(word).startswith("-"):
                drop(str(word), True, name == "read")
    if certain and argv[:2] == ["set", "--"]:
        positional.clear()
    elif name == "shift":
        _shifted(positional, argv, certain)


def _shifted(positional, argv, certain):
    """Move known positional facts through a literal `shift [n]`."""
    operands = [str(word) for word in argv[1:]]
    if operands[:1] == ["--"]:
        operands = operands[1:]
    if len(operands) > 1 or operands and not operands[0].isdecimal():
        return
    amount = int(operands[0]) if operands else 1
    if not amount:
        return
    numbered = {int(key): value for key, value in positional.items() if key.isdecimal()}
    if not numbered:
        return
    shifted = {str(number - amount): binding for number, binding in numbered.items()
               if number > amount}
    if certain and amount <= max(numbered):
        positional.clear()
    positional.update(shifted)


def _bound_after(stage, dest, directory, named, positional, writable=True):
    """Record the values a loop header or `set --` establishes."""
    if not writable:
        return
    variable, operands = _for_parts(stage)
    if variable and operands:
        named.pop(variable, None)
        for word in operands:
            if binding := _from_operand(word, dest, directory, {**named, **positional}):
                named[variable] = Binding(binding.directory, binding.absolute, True)
                break
    argv = command(stage.argv)
    if argv[:2] == ["set", "--"]:
        positional.clear()
        bindings = {**named, **positional}
        for number, word in enumerate(argv[2:], 1):
            if binding := _from_operand(word, dest, directory, bindings):
                positional[str(number)] = Binding(binding.directory, binding.absolute)


def _control_kinds(stmts):
    """The active shell-body kinds at each flat statement."""
    states: list[tuple[str, ...]] = []
    stack: list[str] = []
    for statement in stmts:
        head = statement.stages[0].argv if statement.stages else []
        keyword = head[0] if head else None
        if keyword == "esac":
            while stack and stack[-1] == "arm":
                stack.pop()
            if stack:
                stack.pop()
        elif keyword in ("fi", "done"):
            if stack:
                stack.pop()
        elif keyword in ("else", "elif"):
            if stack:
                stack.pop()
            stack.append(str(keyword))
        elif keyword in ("then", "do", "case"):
            stack.append(str(keyword))
        elif (stack and stack[-1] in ("case", "arm") and
              any(stage.argv and shell_reader.is_arm(stage.argv[0])
                  for stage in statement.stages)):
            if stack[-1] == "arm":
                stack.pop()
            stack.append("arm")
        states.append(tuple(stack))
    return states


def _certainty(stmts, index, kinds):
    """Whether assignments here certainly update the caller or its direct loop."""
    statement = stmts[index]
    serial = (statement.separator != "&"
              and not (index and stmts[index - 1].separator in ("&&", "||"))
              and not any(stage.group_open or stage.group_close
                          for stage in statement.stages))
    active = kinds[index]
    return serial and not active, serial and active == ("do",)


def _table_certainty(stmts, index, kinds):
    """`_certainty` as the value table asks it (#2489): the parentheses of a
    stage's own array literals are the rest of their words, not a group, so
    `arr=(a b)` alone is as sure as `T=a`; `uses()` still asks `_certainty`."""
    statement = stmts[index]
    counts = [_literals(stage) for stage in statement.stages]
    if not any(counts):
        return _certainty(stmts, index, kinds)
    stages = [stage._replace(group_open=max(0, stage.group_open - count),
                             group_close=max(0, stage.group_close - count))
              for stage, count in zip(statement.stages, counts)]
    view = {index: statement._replace(stages=stages)}
    if index:
        view[index - 1] = stmts[index - 1]
    return _certainty(view, index, kinds)


def _operands(argv):
    return [word for word in argv[1:] if not word.startswith("-")]


def copies(statement, names, directory):
    """New names this statement gives a known file through a bounded copy."""
    new = set()
    for stage in statement.stages:
        argv = shell_reader.acted(stage.argv)
        if not argv:
            continue
        name = os.path.basename(argv[0])
        operands = [at_directory(word, directory) for word in _operands(argv)]
        if name in ("cp", "mv", "ln") and len(operands) > 1:
            for old in operands[:-1]:
                for known in names:
                    if (same_file(old, known)
                            or getattr(known, "tree", False) and covers(old, known)):
                        copied = operands[-1]
                        new.add(type(known)(copied) if getattr(known, "tree", False) else copied)
        if name == "cat" and stage.writes:
            if any(same_file(old, known) or (
                    getattr(known, "tree", False) and covers(old, known)
            ) for old in operands for known in names):
                new.update(at_directory(word, directory) for word in stage.writes)
    return new


def use(statement, position, stage, argv, dest, directory, bound=frozenset(), handoff=None, unresolved=None):
    """How this stage uses `dest`, including whole bound value words and program hand-offs. `unresolved`: the step's
    values table, where the guard's second walk weighs a value command word it gives no value at all (`uses`, #3143)."""
    # A clone into `.` makes every relative child part of the fetched tree;
    # the producing `git clone` argv is not itself an execution of that tree.
    if getattr(dest, "tree", False) and argv[:2] == ["git", "clone"]:
        return None
    wrappers = shell_reader.wrapper_words(stage.argv)
    if any(_reference(word) in bound or
           may_run(at_directory(word, directory, True), dest) for word in wrappers):
        return "running it"
    if not argv:
        if not handoff:
            return None
    for word, source in redirection_handoffs(argv, stage, statement.stages[:position]):
        if covers(at_directory(word, directory), dest):
            return "running it through a %s handed to `%s`" % (source.kind, source.runner)
    if handoff and any(covers(at_directory(word, directory), dest)
                       for word in reader_files(stage, argv)):
        return "running it through a %s handed to `%s`" % (handoff.kind, handoff.runner)
    if not argv:
        return None
    argv, handed, recursive = described(statement, position, stage, argv)
    name, rest = os.path.basename(argv[0]), argv[1:]
    if name == "chmod":
        rest = chmod_targets(argv)
    if name == "cat" and stage.stdout_to_pipe and _cat_reads_stdin(argv):
        rest += stage.stdin_reads
    rest = [at_directory(word, directory) for word in rest]
    handed = [at_directory(word, directory) for word in handed]
    mentions = [word for word in rest + handed
                if _reference(word) in bound or covers(word, dest, recursive)]
    if name in CONTAINERS:
        interpreter = in_container(argv, dest, INTERPRETERS)
        if interpreter:
            return "running it inside a container under `%s`" % interpreter
    if any(same_file(at_directory(read, directory), dest) or (
            stage.stdin_heredoc is None and covers(at_directory(read, directory), dest)
            ) for read in stage.reads) and (
            name in INTERPRETERS or stdin_program(argv) == VALUE_PROGRAM):
        return "running it under `%s` from standard input" % os.path.basename(shell_reader.readable(argv[0]))  # (#3156)
    if name == "chmod" and mentions and chmod_executable(argv):
        if getattr(dest, "tree", False) and chmod_conditional_executable(argv):
            return None
        return "making it executable"
    if _reference(argv[0]) in bound or may_run(at_directory(argv[0], directory, True), dest):
        return "running it"
    if not mentions:
        return None
    if name in INTERPRETERS:
        return "running it under `%s`" % name
    if unresolved is not None and _value_command(argv[0]) and _first_operand(rest) in mentions and _unvalued(
            argv, unresolved):                  # `$SHELL ./t`, `$RUN ./t` (#3143)
        return "running it under `%s`, a command word this guard cannot resolve" % name
    if name == "install":
        return "installing it"
    if name in UNPACKERS:
        return "unpacking it with `%s`" % name
    if name in ("mv", "cp", "ln") and any(
            word.startswith(BIN_DIRS) or "/bin/" in word for word in rest):
        return "putting it on PATH with `%s`" % name
    if name == "cat" and position + 1 < len(statement.stages):
        following = shell_reader.acted(statement.stages[position + 1].argv)
        if following and (os.path.basename(following[0]) in INTERPRETERS or unresolved is not None
                          and _value_command(following[0]) and _first_operand(following[1:]) is None
                          and _unvalued(following, unresolved)):
            return "piping it into `%s`" % os.path.basename(following[0])
    return None


def _function_use(stmts, definition, args, dest, directory, named, inherited, table, scopes,
                  indexed, call=None, literal=False):
    """A use reached by one direct call carrying a matching glob argument, or by a value of the
    caller's `table` (#2425, #2489), which the body's table starts from (`static_values`' `start`);
    only a binding call weighs a stage as written, as before. A call made inside a body is not
    followed (`f() { g; }` reads no table into `g`), as for a glob argument."""
    start, close = definition
    positional = {}
    for number, word in enumerate(args, 1):
        if binding := _from_operand(word, dest, directory, inherited):
            positional[str(number)] = binding
    called = bool(positional)
    local_named = dict(named)
    here = directory
    body = stmts[start:close + 1]
    kinds = _control_kinds(body)
    for index, statement in enumerate(body):
        for position, stage in enumerate(statement.stages):
            bound = _live(local_named if called else {}, positional, here)
            # Each stage as written where the walk never reads it: a body whose definition closes before
            # the fetch (`literal`, #2982), and a stage the call's own input changes (`f < t` runs the body's
            # `sh` on `t`, #2973) -- a body written after the fetch, or holding it, is read where it stands,
            # with its own order and checks, and not again here; a binding call weighs the bound words, as before.
            read = with_call_stdin(call, stage) if call is not None else stage
            argv = command(read.argv)
            if (called or literal or read is not stage) and (
                    answer := use(statement, position, read, argv, dest, here, bound)):
                return answer
            if any("$" in word for word in argv):
                values = (indexed.at(start + index, table) if indexed is not None
                          else static_values(stmts, start + index, scopes=scopes, start=table))
                for made in _resolved(argv, values):
                    if answer := use(statement, position, stage, made, dest, here, bound):
                        return answer
            certain, direct_loop = _certainty(body, index, kinds)
            _cleared(stage, local_named, positional, certain, direct_loop)
            _bound_after(
                stage, dest, here, local_named, positional, certain or direct_loop
            )
            if argv and os.path.basename(argv[0]) in ("cd", "pushd", "popd"):
                local_named = {key: value for key, value in local_named.items()
                               if value.absolute}
                positional = {key: value for key, value in positional.items()
                              if value.absolute}
                here = "$CWD-function"
    return None


def _functions_before(stmts, starts, kinds, scopes, after):
    """Functions certainly defined earlier in this same workflow-step shell."""
    functions: dict[str, tuple[int, int]] = {}
    target = scopes.get(after)
    for index in range(after):
        if scopes.get(index) != target:
            continue
        certain, direct_loop = _certainty(stmts, index, kinds)
        writable = certain or direct_loop
        if writable:
            for name, start, close in starts.get(index, []):
                functions[name] = (start, close)
        if len(stmts[index].stages) == 1:
            _function_changes(stmts[index].stages[0], functions, writable)
    return functions


class _StaticValues:
    """One step's values, switching to a shared forward walk only when asked twice (#3145)."""

    def __init__(self, stmts, scopes=None, kinds=None, first=None):
        self.stmts, self.scopes = stmts, scopes or {}
        self.kinds = kinds
        self.step = self.definitions = self.starts = self.occupied = self.forked = None
        self.tables, self.readonly = {}, None
        self.first, self.reuse = first, None

    def _structure(self):
        """Set up what the incremental path shares, after a second lookup asks for it."""
        if self.step is None:
            self.step = _carried(self.stmts)
            self.definitions = self.step.definitions(None)
            self.starts = self.definitions.starts
            self.occupied = self.step.ranges()[1]
            if self.kinds is None:
                self.kinds = _control_kinds(self.stmts)

    def _readonly_calls(self):
        """Whether every step-defined call leaves a value table unchanged."""
        self._structure()
        assert self.step is not None and self.occupied is not None
        if self.readonly is None:
            self.readonly = not any(
                _writes(self.stmts[position], self.step.probe)
                for position in self.occupied
            )
        return self.readonly

    def _compatible(self, index, start):
        """Whether this lookup can continue another top-level table."""
        if start is not None:
            return False
        self._structure()
        assert self.definitions is not None and self.kinds is not None
        first, _last = self.definitions.enclosing(index, len(self.stmts) - 1)
        loop = self.kinds[index] if index < len(self.stmts) else ()
        head = self.stmts[index].stages[0].argv if index < len(self.stmts) and self.stmts[index].stages else []
        return (first < 0 and "do" not in loop
                and not {"while", "until"} & set(head[:len(head) - len(command(head))]))

    def _shared_at(self, index):
        """Extend a compatible table through only the statements not already read."""
        stmts, scopes = self.stmts, self.scopes
        assert self.definitions is not None and self.forked is not None and self.kinds is not None and self.starts is not None
        definitions, kinds, starts = self.definitions, self.kinds, self.starts
        first, _last = definitions.enclosing(index, len(stmts) - 1)
        forked = self.forked.at(index)
        key = (scopes.get(index), forked.active)
        saved = self.tables.get(key)
        before, table = saved if saved is not None and saved[0] <= index else (max(first, 0), Values())

        def walk(positions, sure):
            for position in positions:
                stages = stmts[position].stages
                if (definitions.nested_found(position, first)
                        or scopes.get(position) != scopes.get(index) or not stages):
                    continue
                certain, direct_loop = _table_certainty(stmts, position, kinds)
                looped = direct_loop and index < len(stmts) and all(    # on the pass that reaches it
                    kind[:1] == ("do",) for kind in kinds[position:index + 1])
                certain = sure and (certain or looped) and position not in forked and len(stages) == 1
                _cleared(stages[-1], {}, {}, certain, direct_loop, table)
                record(table, stages[-1], certain)
                if len(stages) == 1 and position not in forked:
                    record_called(table, stmts, position, starts)

        walk(range(before, min(index, len(stmts))), True)
        if saved is None or saved[0] <= index:
            self.tables[key] = (index, table)
        return table

    def at(self, index, start=None):
        """The values at `index`; a second compatible lookup starts incremental reuse."""
        if self.reuse is True and self._compatible(index, start):
            return self._shared_at(index)
        if self.reuse is not None or start is not None:
            return static_values(self.stmts, index, scopes=self.scopes, start=start)
        if self.first is None:
            self.first = index
            return static_values(self.stmts, index, scopes=self.scopes)
        first, current = self._compatible(self.first, None), self._compatible(index, None)
        if first and current:
            self.reuse = self._readonly_calls()
            if self.reuse:
                self.forked = _forked_index(self.stmts)
                return self._shared_at(index)
        table = static_values(self.stmts, index, scopes=self.scopes)
        if not first:
            self.first = index if current else None
        return table


def static_values(stmts, index, working=None, scopes=None, start=None):
    """The step's literal values live at statement `index` (#2425, #2489):
    `_cleared`, then `record`, over each statement before it in its scope,
    walked as `_functions_before` walks, as sure as `_table_certainty` says
    -- and a serial statement directly in a top-level loop body is sure where
    the use follows it in that body (`direct_loop`), as bash surely ran it on
    the pass that reaches the use; one in a nested loop's body stays unsure
    (a limit) -- and never sure in a child the shell forks that the use is not
    in (`_forked`). A pipeline's stages run in subshells, but its last runs in
    the shell under `lastpipe`, so that stage's assignments are read unsure.
    Inside a loop, the body's statements after `index` are walked too,
    unsure: an earlier pass ran them; and so is the body after a
    `while`/`until` head's own command (`while ! sh "$T"; do`) -- a later
    command of the condition, or one on the lines after a bare `while`, is
    not found (a limit). At an index inside a function body only that body is
    walked, under its own control flow and from a copy of `start`, the
    caller's table at a call, which `_function_use` carries, or an empty one;
    a body is otherwise skipped, and a call to a function defined before it
    adds what the body may assign, unsure (`record_called`); a subshell body
    (`g() ( ... )`) ends where its parentheses close (`_body_end`). A
    function defined after `{`, `then` or `do` on the same line is not found
    (`_function_ranges`' limit), nor is the end of a body that is neither
    `{ }` nor `( )` (`g() if c; then T=y; fi`): such a body is walked as the
    code around it, never sure outside it (`_forked`), and a use inside it
    reads the code before it, not its caller's values (a limit). A one-line
    `function NAME { ... }` (or `function NAME() {`) after a `{` on its line
    is read to that group's `}` (`_function_ranges`' limit), so the group's
    own later assignments are not read (`{ function f { :; }; T=x; }`). A
    block or a function nested in the body of a one-line function inside a
    forked group is taken to close that body at its own `}`, so the group's
    later assignments read sure (`{ f() { { :; }; }; T=x; } &`, a limit). A
    `g ( )` header, a blank inside its parentheses, with its body on the next
    line is no definition to the reader (`( )` is an empty subshell), so
    that body is walked as sure code (a limit). `working` is accepted and
    unused: a value resolves at the directory of its USE, bash's rule for a
    relative path."""
    scopes = scopes or {}
    forked = _forked(stmts, index)
    definitions = _carried(stmts).definitions(None)         # the step's definitions, indexed once a step (#3124)
    starts = definitions.starts
    first, last = definitions.enclosing(index, len(stmts) - 1)
    table = start.copy() if start is not None and first >= 0 else Values()
    kinds = _control_kinds(stmts)
    # A body's own `then`/`do`/`case`: what wraps the definition wraps no call.
    outer = len(kinds[first]) if first >= 0 else 0
    kinds = [kind[outer:] for kind in kinds]

    def walk(positions, sure):
        for position in positions:
            stages = stmts[position].stages
            if definitions.nested_found(position, first) or scopes.get(position) != scopes.get(index) or not stages:
                continue
            certain, direct_loop = _table_certainty(stmts, position, kinds)
            looped = direct_loop and index < len(stmts) and all(    # on the pass that reaches it
                kind[:1] == ("do",) for kind in kinds[position:index + 1])
            certain = sure and (certain or looped) and position not in forked and len(stages) == 1
            _cleared(stages[-1], {}, {}, certain, direct_loop, table)
            record(table, stages[-1], certain)
            if len(stages) == 1 and position not in forked:
                record_called(table, stmts, position, starts)

    walk(range(max(first, 0), min(index, len(stmts))), True)
    loop = kinds[index] if index < len(stmts) else ()
    head = stmts[index].stages[0].argv if index < len(stmts) and stmts[index].stages else []
    if "do" in loop:
        depth = loop.index("do") + 1        # the outermost loop: it re-enters the inner ones
        after = index + 1
        while after <= last and kinds[after][:depth] == loop[:depth]:
            after += 1
        walk(range(index + 1, after), False)
    elif {"while", "until"} & set(head[:len(head) - len(command(head))]):
        body, after, entered = loop + ("do",), index + 1, False
        while after <= last:                # the rest of the condition, then the body
            inside = kinds[after][:len(body)] == body
            if not inside and (entered or kinds[after] != loop):
                break
            entered, after = entered or inside, after + 1
        walk(range(index + 1, after), False)
    return table


def uses(stmts, dest, after, working=None, scopes=None):
    """Names `dest` gains and its later uses, including bounded shell values and, where a
    stage as written names none, the step's own values at the use (`_resolved`, #2425). In the guard's second
    walk -- never its main pass, `main`'s answer -- a statement that names none may still hand the file to a value
    command word the table gives no value (`use`'s `unresolved`): that use follows every one `main` names (#3143)."""
    names, out, later = {dest}, [], []
    walked = not _MAINS.get()
    working, scopes = working or {}, scopes or {}
    starts, occupied = _carried(stmts).ranges()
    kinds = _control_kinds(stmts)
    indexed, first_value = None, None

    def values():
        """The step's values at `index`, read once a stage asks for them: the first lookup walks to its statement,
        the second shares one table forward (`_StaticValues`, #3145) -- the one lookup every reader here goes through,
        the second walk's value command word among them (#3143)."""
        nonlocal indexed, first_value
        if indexed is not None:
            return indexed.at(index)
        if first_value is None:
            first_value = index
            return static_values(stmts, index, working, scopes)
        indexed = _StaticValues(stmts, scopes, kinds, first_value)
        return indexed.at(index)

    functions = _functions_before(stmts, starts, kinds, scopes, after)
    named: dict[str, Binding] = {}
    positional: dict[str, Binding] = {}
    previous_scope = scopes.get(after)
    for index, statement in enumerate(stmts[after:], after):
        scope = scopes.get(index)
        if scope != previous_scope:
            functions.clear()
            named.clear()
            positional.clear()
        previous_scope = scope
        directory = working.get(index, ".")
        certain, direct_loop = _certainty(stmts, index, kinds)
        writable = certain or direct_loop
        if writable:
            for name, start, close in starts.get(index, []):
                functions[name] = (start, close)
        in_definition = index in occupied
        bound = set() if in_definition else _live(named, positional, directory)
        how, table, late = None, None, None
        for point, inner, position, stage, where, here, handoff in inside(
                statement, index, directory=directory, scope=index):
            argv = command(stage.argv)
            call = not in_definition and argv and argv[0] in functions
            for name in sorted(names):
                how = use(inner, position, stage, argv, name, here, bound, handoff)
                if not how and (call or any("$" in word for word in argv)):
                    if table is None:
                        table = values()
                    how = next(filter(None, (use(inner, position, stage, made, name, here, bound,
                                                  handoff)
                                             for made in _resolved(argv, table))), None)
                if not how and call:
                    how = _function_use(stmts, functions[argv[0]], argv[1:], name, here, named,
                                        {**named, **positional}, table, scopes, indexed, call=stage,
                                        literal=functions[argv[0]][1] < after)
                if not how and walked and late is None and _value_stage(inner, position, argv):
                    if table is None:
                        table = values()
                    if held := use(inner, position, stage, argv, name, here, bound, handoff, table):
                        late = (point, _copied(held, name, dest) + ("" if handoff else where))
                if how:
                    how = _copied(how, name, dest)
                    break
            if how:
                out.append((point, how + ("" if handoff else where)))
                break
        if not how and late:            # a use only a value command word makes, after every one `main` names (#3143)
            later.append(late)
        if not in_definition and len(statement.stages) == 1:
            stage = statement.stages[0]
            _cleared(stage, named, positional, certain, direct_loop)
            _bound_after(
                stage, dest, directory, named, positional, certain or direct_loop
            )
            _function_changes(stage, functions, writable)
        names |= copies(statement, names, directory)
    return names, out + later
