#!/usr/bin/env python3
"""Downloaded-file use discovery for the workflow fetch-and-execute guard.

Shell patterns designate concrete files before a loop variable, positional
parameter, or function argument receives the resulting word. This module
keeps that bounded value fact long enough to recognize the later use, while
quoted and nonmatching patterns remain ordinary strings.

The step's own LITERAL values are a second kind of bounded value fact beside
those glob bindings (#2425, #2489), read by `scripts/workflow_values.py`;
`static_values` here is that table live at one statement, and this module
re-exports its `Values`, `assigned`, `record`, `valued` and `valued_argvs`, so
a caller of this module reaches them where it reaches `uses`.
"""
from dataclasses import dataclass
import os
import re

import shell_reader
from shell_reader import command
from workflow_checks import inside
from workflow_forms import (BIN_DIRS, CONTAINERS, at_directory, chmod_executable,
                            chmod_targets, covers, described, in_container, may_run,
                            same_file, stdin_program)
from workflow_function_calls import _function_scope, _function_syntax
from workflow_programs import VALUE_PROGRAM
# Compatibility bindings: the value table moved to `workflow_values` with its
# names, and its callers keep reaching them here.
from workflow_values import (Values as Values, assigned as assigned, record as record,
                             valued as valued, valued_argvs as valued_argvs)
from workflow_values import _for_parts, _literals, emptied


INTERPRETERS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3",
                "perl", "ruby", "node", "php", "pwsh", "eval", "source", ".")
# Unpacking a downloaded archive executes its bytes too: they choose what
# lands on disk and under what name.
UNPACKERS = ("tar", "unzip", "install", "gunzip", "bsdtar")
EXECUTORS = INTERPRETERS + UNPACKERS
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
    """Bound names that still designate the file in `directory`."""
    bound = {
        name for name, binding in {**named, **positional}.items()
        if binding.absolute or binding.directory == directory
    }
    if "1" in bound:
        bound.update(("@", "*"))
    return bound


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
    stand-in. An assignment's are left to `record`, which replaces them where
    certain: dropping them here first would lose the value `T+=.run` appends
    to and the one `T=$T.run` reads.
    """
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
        argv = command(stage.argv)
        if not argv:
            continue
        name = os.path.basename(argv[0])
        operands = [at_directory(word, directory) for word in _operands(argv)]
        if name in ("cp", "mv", "ln") and len(operands) > 1:
            if any(same_file(old, known) for old in operands[:-1] for known in names):
                new.add(operands[-1])
        if name == "cat" and stage.writes:
            if any(same_file(old, known) for old in operands for known in names):
                new.update(at_directory(word, directory) for word in stage.writes)
    return new


def use(statement, position, stage, argv, dest, directory, bound=frozenset()):
    """How this stage uses `dest`, including whole bound value words."""
    wrappers = shell_reader.wrapper_words(stage.argv)
    if any(_reference(word) in bound or
           may_run(at_directory(word, directory, True), dest) for word in wrappers):
        return "running it"
    if not argv:
        return None
    argv, handed, recursive = described(statement, position, stage, argv)
    name, rest = os.path.basename(argv[0]), argv[1:]
    if name == "chmod":
        rest = chmod_targets(argv)
    rest = [at_directory(word, directory) for word in rest]
    handed = [at_directory(word, directory) for word in handed]
    mentions = [word for word in rest + handed
                if _reference(word) in bound or covers(word, dest, recursive)]
    if name in CONTAINERS:
        interpreter = in_container(argv, dest, INTERPRETERS)
        if interpreter:
            return "running it inside a container under `%s`" % interpreter
    if (name in INTERPRETERS or stdin_program(argv) == VALUE_PROGRAM) and any(
            same_file(at_directory(read, directory), dest) or (
                stage.stdin_heredoc is None and covers(at_directory(read, directory), dest)
            ) for read in stage.reads):
        return "running it under `%s` from standard input" % name
    if name == "chmod" and mentions and chmod_executable(argv):
        return "making it executable"
    if _reference(argv[0]) in bound or may_run(at_directory(argv[0], directory, True), dest):
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
            word.startswith(BIN_DIRS) or "/bin/" in word for word in rest):
        return "putting it on PATH with `%s`" % name
    if name == "cat" and position + 1 < len(statement.stages):
        following = command(statement.stages[position + 1].argv)
        if following and os.path.basename(following[0]) in INTERPRETERS:
            return "piping it into `%s`" % os.path.basename(following[0])
    return None


def _function_ranges(stmts):
    """Definition starts and the indices occupied by each function body."""
    starts: dict[int, list[tuple[str, int, int]]] = {}
    occupied: set[int] = set()
    for index, statement in enumerate(stmts):
        for stage in statement.stages:
            name = _function_syntax(stage.argv)[0]
            if name is None:
                continue
            scope = _function_scope(stmts, index)
            if scope is None:
                continue
            close = scope[1]
            starts.setdefault(index, []).append((name, index, close))
            occupied.update(range(index, close + 1))
    return starts, occupied


def _function_use(stmts, definition, args, dest, directory, named, inherited):
    """A use reached by one direct call carrying a matching glob argument."""
    start, close = definition
    positional = {}
    for number, word in enumerate(args, 1):
        if binding := _from_operand(word, dest, directory, inherited):
            positional[str(number)] = binding
    if not positional:
        return None
    local_named = dict(named)
    here = directory
    body = stmts[start:close + 1]
    kinds = _control_kinds(body)
    for index, statement in enumerate(body):
        for position, stage in enumerate(statement.stages):
            bound = _live(local_named, positional, here)
            argv = command(stage.argv)
            if answer := use(statement, position, stage, argv, dest, here, bound):
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


def _function_changes(stage, functions, writable):
    """Apply a certain `unset -f`; definitions are installed by their range."""
    if not writable:
        return
    argv = command(stage.argv)
    if argv[:1] == ["unset"] and "-f" in argv:
        for word in argv[1:]:
            if not str(word).startswith("-"):
                functions.pop(str(word), None)


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


def _forked(stmts):
    """The statements inside a group the step's shell forks (#2425): a `( ... )`
    subshell past its opening statement, and every statement of a `{ ...; }`
    piped into, piped on or sent to the background. Their assignments end
    with the child, as `working_directories` keeps a subshell's `cd`. An array
    literal's parentheses are no group (`_literals`), and a `{` or `}` is one
    only where the stage's command would stand."""
    forked: set[int] = set()
    opened: list[tuple[int, bool]] = []
    depth = 0
    for position, statement in enumerate(stmts):
        if depth:
            forked.add(position)
        last = len(statement.stages) - 1
        for number, stage in enumerate(statement.stages):
            count = _literals(stage)
            depth = max(0, depth + max(0, stage.group_open - count)
                        - max(0, stage.group_close - count))
            for word in stage.argv[:len(stage.argv) - len(command(stage.argv))]:
                if word == "{":
                    opened.append((position, number > 0))
                elif word == "}" and opened:
                    start, piped = opened.pop()
                    if piped or number < last or statement.separator == "&":
                        forked.update(range(start, position + 1))
    return forked


def static_values(stmts, index, working=None, scopes=None):
    """The step's literal values live at statement `index` (#2425, #2489):
    `_cleared`, then `record`, over each one-stage statement before it in its
    scope, walked as `_functions_before` walks, as sure as `_table_certainty`
    says and never sure inside a group the shell forks (`_forked`). A
    pipeline runs in subshells and records nothing. Inside a loop, the body's
    statements after `index` are walked too, unsure: an earlier pass ran
    them. At an index inside a function body only that body is walked, under
    its own control flow and from an empty table -- a call's values are its
    caller's at the call, which `_function_use` carries -- and a body is
    otherwise skipped, so a call's own assignments are not read (`f() { T=b;
    }; T=a; f` holds `a`, a price).
    `working` is accepted and unused: a value resolves at the directory of
    its USE, bash's rule for a relative path.
    """
    scopes = scopes or {}
    table = Values()
    forked = _forked(stmts)
    ranges = [(start, close) for entries in _function_ranges(stmts)[0].values()
              for _name, start, close in entries]
    first, last = max([(start, close) for start, close in ranges if start <= index <= close],
                      default=(-1, len(stmts) - 1))
    nested = {position for start, close in ranges if start > first
              for position in range(start, close + 1)}
    kinds = _control_kinds(stmts)
    # A body's own `then`/`do`/`case`: what wraps the definition wraps no call.
    outer = len(kinds[first]) if first >= 0 else 0
    kinds = [kind[outer:] for kind in kinds]

    def walk(positions, sure):
        for position in positions:
            stages = stmts[position].stages
            if (position in nested or scopes.get(position) != scopes.get(index)
                    or len(stages) != 1):
                continue
            certain, direct_loop = _table_certainty(stmts, position, kinds)
            certain = sure and certain and position not in forked
            _cleared(stages[0], {}, {}, certain, direct_loop, table)
            record(table, stages[0], certain)

    walk(range(max(first, 0), min(index, len(stmts))), True)
    loop = kinds[index] if index < len(stmts) else ()
    if "do" in loop:
        depth = loop.index("do") + 1        # the outermost loop: it re-enters the inner ones
        after = index + 1
        while after <= last and kinds[after][:depth] == loop[:depth]:
            after += 1
        walk(range(index + 1, after), False)
    return table


def uses(stmts, dest, after, working=None, scopes=None):
    """Names `dest` gains and its later uses, including bounded shell values."""
    names, out = {dest}, []
    working, scopes = working or {}, scopes or {}
    starts, occupied = _function_ranges(stmts)
    kinds = _control_kinds(stmts)
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
        how = None
        for point, inner, position, stage, where, here in inside(
                statement, index, directory=directory, scope=index):
            argv = command(stage.argv)
            for name in sorted(names):
                how = use(inner, position, stage, argv, name, here, bound)
                if not how and not in_definition and argv and argv[0] in functions:
                    how = _function_use(
                        stmts, functions[argv[0]], argv[1:], name, here, named,
                        {**named, **positional}
                    )
                if how:
                    if not same_file(name, dest):
                        shown = re.sub(r"^\$CWD[^/]*/", "", name).replace("$UP", "..")
                        how += " (as `%s`, copied from it earlier)" % shown
                    break
            if how:
                out.append((point, how + where))
                break
        if not in_definition and len(statement.stages) == 1:
            stage = statement.stages[0]
            _cleared(stage, named, positional, certain, direct_loop)
            _bound_after(
                stage, dest, directory, named, positional, certain or direct_loop
            )
            _function_changes(stage, functions, writable)
        names |= copies(statement, names, directory)
    return names, out
