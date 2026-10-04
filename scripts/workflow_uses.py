#!/usr/bin/env python3
"""Downloaded-file use discovery for the workflow fetch-and-execute guard.

Shell patterns designate concrete files before a loop variable, positional
parameter, or function argument receives the resulting word. This module
keeps that bounded value fact long enough to recognize the later use, while
quoted and nonmatching patterns remain ordinary strings.

The step's own LITERAL values are a second kind of bounded value fact beside
those glob bindings (#2425, #2489): `T=cuda_1.run`, `p=./cuda_*.run`, an array
literal `a=(sh tool)`. `static_values` keeps a scalar's CANDIDATE texts per
name, held wherever a statement assigns one and replaced or emptied only where
the shell surely runs the statement, and an array literal's words; and
`valued_argvs` substitutes both into a stage's words, so that what those
words stand for can be asked of `use()`.
"""
from dataclasses import dataclass, field
import itertools
import os
import re

import shell_reader
from shell_reader import command
from workflow_checks import inside
from workflow_forms import (BIN_DIRS, CONTAINERS, at_directory, chmod_executable,
                            chmod_targets, covers, described, in_container, may_run,
                            same_file, stdin_program)
from workflow_function_calls import _function_scope, _function_syntax
from workflow_operands import live_pattern
from workflow_programs import VALUE_PROGRAM


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
# The step's literal values (#2425, #2489): `_LITERAL` an assignment word
# (`NAME=text`, `NAME+=text`), `_ARRAY` one holding a literal the reader folded
# in (`NAME=(words)`), `_OPENER` an empty one, which an UNFOLDED literal's words
# follow; `_VALUE` a reference -- `$T`, `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}`,
# `${T=d}`; `_ELEMENT` a whole `${a[0]}`, `${a[@]}` or `${a[*]}`; `_GLOB` what
# bash globs a value by.
_LITERAL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.S)
_ARRAY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=\((.*)\)$", re.S)
_OPENER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=$")
_VALUE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)"
                    r"|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=])([^{}]*))?\})")
_ELEMENT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\[([0-9]+|[@*])\]\}$")
_GLOB = re.compile(r"[*?\[]")
# A name holds the LAST `_CANDIDATES` texts assigned, a word resolves to the
# first as many, and none built is longer than `_LONGEST`: a value doubling
# itself (`T=$T$T`, line after line) in a TARGET repo's `run:` block would grow
# without bound.
_CANDIDATES = 8
_LONGEST = 4096


@dataclass(frozen=True)
class Binding:
    """A glob result and the directory where its relative spelling was made."""

    directory: str
    absolute: bool = False
    loop: bool = False


@dataclass
class Values:
    """The step's literal values at one statement (#2425 scalars, #2489 arrays):
    a name's CANDIDATE texts -- the reader's words, quotes gone, a lifted
    `$(...)` kept as its marker -- and the words of the literal a name holds."""

    scalars: dict[str, list[str]] = field(default_factory=dict)
    arrays: dict[str, list[str]] = field(default_factory=dict)


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

    With `table` (#2425, #2489), a certain `unset`, `read` or bare `local` drops
    the name's literal values too. An assignment's are left to `record`, which
    replaces them where the statement is certain: dropping them here first
    would lose the value `T+=.run` appends to and the one `T=$T.run` reads.
    """
    def drop(name, valueless=True):
        binding = named.get(name)
        if binding and (certain or direct_loop and binding.loop):
            named.pop(name)
        if table is not None and certain and valueless:
            table.scalars.pop(name, None)
            table.arrays.pop(name, None)

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
                drop(str(word))
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


def _for_parts(stage):
    """A literal `for NAME in WORD...` header, or (None, [])."""
    raw = list(stage.argv)
    try:
        start = raw.index("for")
    except ValueError:
        return None, []
    if start + 2 >= len(raw) or raw[start + 2] != "in":
        return None, []
    return str(raw[start + 1]), raw[start + 3:]


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


def assigned(stage):
    """What this stage assigns in the step's shell (#2425, #2489): `({name:
    (append, text)}, {name: (append, words)})`, `append` for a `+=`.

    A statement that only assigns assigns, and so do a declaration's operands
    (`export T=x`, `declare -a a=(sh tool)`); not a bare `export T`, nor a
    PREFIX assignment (`T=x sh "$T"`: bash expands the command's words first,
    and the value does not outlive the command), nor one behind a wrapper
    other than `command` (`env T=x`). A text is `derived`: a lifted `$(...)`
    stays its marker. A literal is read only where the stage opened a group,
    as the reader counts its parentheses -- folded into its word behind a
    declaration, else handed UNFOLDED (`["a=", "sh", "tool"]`, #2348): an
    empty `NAME=` and the words up to the next one while groups remain. Two
    prices: a folded literal is re-split on blanks, and a subshell's empty
    prefix assignment `( T= sh tool )` reads as `T=(sh tool)`.
    """
    scalars: dict[str, tuple[bool, str]] = {}
    arrays: dict[str, tuple[bool, list[str]]] = {}
    argv = command(stage.argv)
    if any(word != "command" for word in shell_reader.wrapper_words(stage.argv)):
        return scalars, arrays
    if argv and os.path.basename(argv[0]) in _DECLARATIONS:
        words = list(argv[1:])
    else:
        lead = stage.argv[:len(stage.argv) - len(argv)]
        if argv and not (stage.group_open and any(_OPENER.match(str(word)) for word in lead)):
            return scalars, arrays          # a prefix assignment, or none at all
        words = list(stage.argv)
    literals, unfolded = 0, None
    for word in words:
        room = literals < stage.group_open
        folded = _ARRAY.match(str(word)) if room else None
        match = folded or _LITERAL.match(str(word))
        if match and (folded or room and not match[3]):
            literals += 1
            parts = ([shell_reader.derived(part, word) for part in match[3].split()]
                     if folded else [])
            arrays[match[1]] = (bool(match[2]), parts)
            unfolded = None if folded else parts
        elif unfolded is not None:
            unfolded.append(word)
        elif match:
            scalars[match[1]] = (bool(match[2]), shell_reader.derived(match[3], word))
    return scalars, arrays


def record(table, stage, certain):
    """Write what this stage assigns into `table` (#2425, #2489).

    A scalar's text resolves through the table as it is assigned (`valued`,
    bash's rule for `T=$U`), else is held as written. A `certain` assignment
    replaces the candidates and any other adds to them (`T=a; false && T=b`
    holds both); the last `_CANDIDATES` are kept. `T+=x` appends to each; on
    a name not held it holds `x` alone, the known suffix: a price. A
    `certain` append that could only build a text over `_LONGEST` leaves the
    name unread. A literal's words are held where the name holds none and
    replaced where `certain`, and `+=` extends them; one list is kept per
    name, so an uncertain literal over held words leaves them as they were.
    """
    scalars, arrays = assigned(stage)
    for name, (append, text) in scalars.items():
        new = valued(text, table) or [text]
        if append:
            new = [shell_reader.derived(head + tail, head, tail)
                   for head in table.scalars.get(name) or [""] for tail in new
                   if len(head) + len(tail) <= _LONGEST]
        kept = new if certain else list(dict.fromkeys(table.scalars.get(name, []) + new))
        if kept:
            table.scalars[name] = kept[-_CANDIDATES:]
        else:
            table.scalars.pop(name, None)
    for name, (append, words) in arrays.items():
        held = table.arrays.get(name)
        if append:
            table.arrays[name] = (held or []) + words
        elif certain or held is None:
            table.arrays[name] = words


def valued(word, table):
    """The candidate texts ONE word resolves to through `table`, or [] where
    nothing in it does (#2425, #2489; #2581's `./cuda_$X.run`, `${X:-*}`, `${a[0]}`).

    Each `$T`, `${T}`, `${T:-d}`, `${T-d}`, `${T:=d}` or `${T=d}`, whole or
    embedded, stands for a held name's candidates, left to right; the texts
    are the first `_CANDIDATES` of their product, less any over `_LONGEST`.
    A default stands where its name is not held, and for a held empty value
    under `:-` or `:=`, as bash reads one. An unheld name, and every other
    `${T...}` form (`${T:+d}`, `${T#x}`, `${T%x}`, `${T//a/b}`, `${T:0:3}`,
    `${#T}`, `${!T}`), stays as written; a lifted `$(...)` holds no `$` to
    match. A whole `${a[N]}` is the literal's word N or nothing, and `${a[@]}`
    or `${a[*]}` its words joined by blanks (`valued_argvs` splices them).
    The texts carry the markers of the word and of its values, and are
    otherwise plain: the caller decides what kind of word each is.
    """
    text = str(word)
    if element := _ELEMENT.match(text):
        return _element(element, table)
    factors: list[list[str]] = []
    start = 0
    for match in _VALUE.finditer(text):
        if held := _held(match, table):
            factors += [[text[start:match.start()]], held]
            start = match.end()
    if not factors:
        return []
    factors.append([text[start:]])
    combinations = itertools.islice(itertools.product(*factors), _CANDIDATES)
    return [shell_reader.derived("".join(parts), word, *parts) for parts in combinations
            if sum(map(len, parts)) <= _LONGEST]


def _held(match, table):
    """What one `_VALUE` reference stands for, or [] where it stays as written."""
    name, operator, default = match[1] or match[2], match[3], match[4]
    held = table.scalars.get(name)
    if held is None:
        return [default] if operator else []
    if operator in (":-", ":="):
        return list(dict.fromkeys(text or default for text in held))
    return held


def _element(element, table):
    """A whole `${a[N]}`, `${a[@]}` or `${a[*]}` read through `table`."""
    words, key = table.arrays.get(element[1]), element[2]
    if words is None:
        return []
    if key in ("@", "*"):
        return [shell_reader.derived(" ".join(words), *words)]
    # A subscript is arithmetic: a leading 0 is octal, so it, and a long one, stay unread.
    if len(key) > 9 or key.startswith("0") and key != "0" or int(key) >= len(words):
        return []
    return [words[int(key)]]


def valued_argvs(argv, table):
    """The argvs `use()` must weigh for one stage's words (#2425, #2489, #2581):
    `[argv]` where no word resolves, else the first `_CANDIDATES` of the
    product of each word's `valued` texts (or the word itself), a whole
    `${a[@]}` or `${a[*]}` SPLICED as the literal's words. A text with `*`,
    `?` or `[`, or from a word bash expands as a pattern (`{$T,x}`), is a
    `live_pattern`, as bash globs an unquoted `$p` and a literal's words.
    The quotes are gone, and two prices follow: `sh "$p"` after
    `p=./cuda_*.run` reads as the glob, and `'$T'`, which bash does not
    expand, as `"$T"`.
    """
    choices: list[list[list[str]]] = []
    resolved = False
    for word in argv:
        element = _ELEMENT.match(str(word))
        if element and element[2] in ("@", "*") and element[1] in table.arrays:
            choices.append([[_as_word(text, word) for text in table.arrays[element[1]]]])
        elif texts := valued(word, table):
            choices.append([[_as_word(text, word)] for text in texts])
        else:
            choices.append([[word]])
            continue
        resolved = True
    if not resolved:
        return [argv]
    combinations = itertools.islice(itertools.product(*choices), _CANDIDATES)
    return [[part for words in combination for part in words] for combination in combinations]


def _as_word(text, word):
    """A substituted text as an argv word: a live pattern where bash globs it."""
    if _GLOB.search(text) or getattr(word, "lead", None) is not None:
        return live_pattern(text)
    return text


def static_values(stmts, index, working=None, scopes=None):
    """The step's literal values live at statement `index` (#2425, #2489):
    `_cleared`, then `record`, over each one-stage statement before it in its
    scope, walked as `_functions_before` walks and as sure as `_certainty`
    says. A pipeline runs in subshells and records nothing; a function body
    is skipped, so a call's own assignments are not read (`f() { T=b; };
    T=a; f` holds `a`, a price). `working` is accepted and unused: a value
    resolves at the directory of its USE, bash's rule for a relative path.
    """
    scopes = scopes or {}
    table = Values()
    kinds = _control_kinds(stmts)
    occupied = _function_ranges(stmts)[1]
    for position in range(min(index, len(stmts))):
        stages = stmts[position].stages
        if position in occupied or scopes.get(position) != scopes.get(index) or len(stages) != 1:
            continue
        certain, direct_loop = _certainty(stmts, position, kinds)
        _cleared(stages[0], {}, {}, certain, direct_loop, table)
        record(table, stages[0], certain)
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
