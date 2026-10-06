#!/usr/bin/env python3
"""As much of the POSIX shell as a guard over `run:` blocks has to read.

Split out of `scripts/workflow_guard.py` (#1647 fix round 1), which asks two
questions of a workflow step -- what does it download, and what checks the
download -- and could answer neither while its input was a regex match over
shell TEXT. Both questions need the same thing first: the commands, in order,
with their arguments, their redirections, their heredocs and the commands
hidden inside their substitutions.

So this module reads shell, and nothing about supply chains lives here. The
reading is deliberately partial -- no expansion, no arithmetic, no control
flow -- and the rule on top is written to fail closed on what is missing (see
that module's docstring). What IS handled, because each one hid a download
from the guard until it was:

    comments        `# curl ... | sh` in the prose explaining the rule
    continuations   a fetch written across four lines
    heredocs        `sha256sum -c <<EOF ... EOF`, and `<<EOF` expands where
                    `<<'EOF'` does not
    substitutions   `eval "$(curl ...)"`, `bash <(curl ...)`, backticks
    quoting         a `|` or `;` inside '...' or "..." is text, not a pipeline
    redirections    `curl ... > file`, `bash < file`; `curl ... &>file` /
                    `>&file` (bash's combined-stream form) are real
                    destinations too; `2>&1`/`>&2`/`>&-` are neither, and
                    `2>file` is a write, but not to stdout
    separators      `&&`, `||`, `;`, `&` -- which is where a shell says whether
                    a command's exit status is allowed to matter
    wrappers        `sudo`, `env FOO=1`, `timeout 300`, and the keywords (`if`,
                    `do`) that stand in front of a command
    patterns        `{sh,-c}` and `[s]h` are not expanded but marked: bash makes
                    words of them, so no command they may start is resolved

The first three are settled on the TEXT, before any command is read, in the
one quote-aware pass `scripts/shell_lex.py` makes the way bash does (#1793),
and the substitutions are lifted out of it by `scripts/shell_text.py`.
The wrappers' table, and the option grammar each one is read with, are
`scripts/shell_wrappers.py`'s (#2227).
The words a parse hands back, and the markers in them that say what was
lifted out, are `scripts/shell_tokens.py`'s (#2628): split out at this
module's size and imported back here, so no caller moved.
The quote-aware pass that cuts the text into statements and pipeline stages,
and the marks it leaves for `_stage`, are `scripts/shell_split.py`'s: split
out at this module's size a second time, and imported back here likewise.

Stdlib only. `statements(script)` is the entry point; `command(argv)` strips
what stands in front of a command; `readable(text)` puts lifted substitutions
back for a human reading an error message.
"""
import collections
import os
import re
import shlex

from shell_lex import lex
from shell_patterns import (MARK, QUOTED, QUOTED_DOLLAR, _expansion_end as _expansion_end,
                            is_pattern, leads, patterned, shell_words as shell_words)
from shell_quote import ansi_c as ansi_c
from shell_text import (_lift_substitutions, join_continuations as join_continuations,
                        without_comments as without_comments)
from shell_tokens import (_Expanded as _Expanded, _Parse as _Parse, _Token as _Token,
                          _markers as _markers, derived as derived,
                          has_substitution as has_substitution, is_arm as is_arm,
                          is_marker as is_marker, kept as kept, readable as readable,
                          yields_words as yields_words)
from shell_wrappers import (WRAPPERS as WRAPPERS, Defaulted as Defaulted,
                            Rewritten as Rewritten, dynamic as dynamic, unwrap as unwrap)
from shell_command import (CONDITIONS as CONDITIONS, KEYWORDS as KEYWORDS,
                           OPTIONAL_NEXT as OPTIONAL_NEXT, _ASSIGNMENT as _ASSIGNMENT,
                           _DEFAULTS as _DEFAULTS, _ENVIRONMENT as _ENVIRONMENT,
                           _FETCHERS as _FETCHERS, _FUNCTION as _FUNCTION,
                           _INTERPRETERS as _INTERPRETERS, _NAME as _NAME, _OPTIONAL as _OPTIONAL,
                           _SHELLS as _SHELLS, _command_result as _command_result,
                           _optional as _optional, command as command,
                           command_as_written as command_as_written, conditional as conditional,
                           negated as negated, unresolved_wrapper as unresolved_wrapper,
                           wrapper_words as wrapper_words)
from shell_split import (_BLANK as _BLANK, _BRACED_HEADER as _BRACED_HEADER,
                         _ESCAPE_AT as _ESCAPE_AT, _ESCAPED as _ESCAPED, _HEADER as _HEADER,
                         _MARKS as _MARKS, _NESTED_CASE as _NESTED_CASE,
                         _QUOTE_END as _QUOTE_END, _QUOTED_AT as _QUOTED_AT,
                         _REDIRECT as _REDIRECT, _split as _split)

# One shell command: its argv, the files it redirects into / reads from, the
# heredoc body attached to it, the command substitutions inside it -- the
# `$(...)`, `<(...)` and backtick texts, which are commands in their own right
# and where `eval "$(curl ...)"` hides its download -- and stdout_writes, the
# final file sink of descriptor 1 after ordered redirects/duplications. `writes`
# also carries an explicit OTHER fd (`2>err.log`) so the guard's file-tracking
# stays correct; `stdout_writes` is the one a caller may call THE destination
# (#1733). `&>word`/`&>>word` and the UNNUMBERED `>&word` land there too --
# bash's `>word 2>&1` shorthand, a real file whatever `word` looks like. A
# target beginning with `&` whose remainder IS a duplication or close (`&1`,
# `&-`) -- `2>&1`, `>&2`, `>&-` -- lands in neither list.
# Parse-local subshell markers leave argv alone; counts retain their boundaries
# for the checksum handler without exposing marker tokens as commands.
# `heredoc` is the body a caller may quote back (a `sha256sum -c` sums list;
# of several, the one descriptor 0 reads if any -- `cat` and `-c` read stdin);
# `stdin_heredoc` is the body descriptor 0 FINALLY reads, with the flag that
# says whether it expanded -- `(body, expands)` or None. The two are different
# questions: `sh 3<<EOF` writes a body nothing reads on stdin, `sh <<EOF 0<&3`
# hands stdin somewhere else afterwards, and only the second question can say
# whether a heredoc is the SCRIPT of the interpreter in front of it (#1839).
# A here-string is a body the second question reads too (`sh <<< '...'`,
# #2293) -- expanding unless `lex` spelled its word -- and never the first's.
# `stderr_to_pipe` says descriptor 2 finally feeds the next stage (`2>&1` under a
# pipe), where `/dev/stderr` is the pipe's own mouth (#2744).
Stage = collections.namedtuple(
    "Stage", "argv writes reads heredoc substitutions stdout_writes "
             "group_open group_close stdin_from_pipe stdout_to_pipe pipe_input_fds "
             "stdin_heredoc stderr_to_pipe",
    defaults=(0, 0, True, True, ("0",), None, False))
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages in order,
# and the separator that FOLLOWS it -- which is where a shell says whether the
# command's exit status is allowed to matter (`... || true`, `... &`).
Statement = collections.namedtuple("Statement", "stages separator")


# The builtins whose words bash reads as assignments too: `declare -a a=(1 2)`.
_DECLARATIONS = ("declare", "typeset", "local", "export", "readonly")
class _StdoutAliases(tuple):
    """The spellings of this process's standard output, asked with `in`: the listed ones as
    written, and any spelling of them with repeated slashes collapsed (`//dev/stdout`,
    `/dev//fd/1`), as the kernel reads a path (#2744). `/dev/stderr` and its twins are not
    here: they are standard output only where the stage's own `2>&1` makes them so
    (`Stage.stderr_to_pipe`), which is the consumer's to ask."""

    def __contains__(self, word):
        return tuple.__contains__(self, re.sub(r"/{2,}", "/", str(word)))


_STDOUT_ALIASES = _StdoutAliases(("/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"))


# --- reading the shell -------------------------------------------------------

def _fd_or_close(word):
    """True for the historical ambiguity of the UNNUMBERED `>&word` form:
    real bash reads a word made only of digits, or exactly `-`, as a file
    descriptor to duplicate or close -- never a path -- and anything else as
    the file `>word 2>&1` would have named. Checked against bash 5 (round 1
    of #1733's fix): `>&2extra` writes a file called `2extra`; `>&2` does
    not. The `&>word` spelling carries no such ambiguity at all (`&>2` is
    always a file named `2`), so this is never consulted for it.
    """
    return word == "-" or (word.isascii() and word.isdigit())


def input_alias_fd(word):
    """Alias fd, ? for unresolved input, or None for a literal ordinary file."""
    if "$" in word or has_substitution(word):
        return "?"
    word = os.path.normpath(word)
    if word == "/dev/stdin":
        return "0"
    match = re.fullmatch(r"/dev/fd/([0-9]+)", word)
    if match:
        return match[1].lstrip("0") or "0"
    if word.startswith("/dev/fd/") or re.match(r"/proc/.*/fd/", word):
        return "?"
    return None


def _unmarked(head):
    """`head` with the quoting marks gone: the text shlex handed on."""
    for mark in _MARKS:
        head = head.replace(mark, "")
    return head


def _quoted_assignment(head):
    """Whether `head`, a token with `_QUOTED_AT` where its quotes opened and `_ESCAPE_AT` where
    its backslashes stood, spells an assignment whose name or operator was quoted or escaped
    (#2480): bash then runs a command of that name. A quoted VALUE (`X="1"`) is one still."""
    match = _ASSIGNMENT.match(_unmarked(head))
    seen = 0                                    # characters of the name and operator passed
    for ch in head if match else "":
        if ch in (_QUOTED_AT, _ESCAPE_AT):
            return True
        if ch == _QUOTE_END:
            continue
        seen += 1
        if seen >= match.end():                 # a quote opening the VALUE is not one
            break
    return False


def _quoted_spans(head):
    """The (start, end) ranges of the word's text, as shlex handed it on, that stood inside
    quotes or behind a backslash: what bash neither splits, globs nor drops."""
    spans, pos, start = [], 0, None
    for ch in head:
        if ch == _QUOTED_AT:
            start = pos
        elif ch == _QUOTE_END:
            spans.append((start if start is not None else pos, pos))
            start = None
        elif ch == _ESCAPE_AT:
            spans.append((pos, pos + 1))
        else:
            pos += 1
    return spans


def bare(word):
    """Whether `word` was written with no quote and no backslash anywhere that mattered: bash
    may split it, glob it, or drop it where it expands to nothing (`sh $X` with `X` unset
    vanishes, `sh "$X"` does not, #2593; `sh $p` globs, `sh "$p"` does not, #2769). A plainly
    quoted literal name (`"sh"`) carries no spans and reads bare, as its quotes change nothing."""
    return not getattr(word, "quoted_spans", None)


def quoted_marker(word, key):
    """Whether the lifted substitution `key` of `word` stood inside quotes, so its output is one
    field (`sh -c "$(…)"` hands the text on whole; `sh -c $(…)` takes its first field, #2747)."""
    at = str(word).find(key)
    return at >= 0 and any(start <= at and at + len(key) <= end
                           for start, end in getattr(word, "quoted_spans", ()))


def _assigns(words):
    """Whether bash reads the word after `words` as an assignment: behind
    keywords and assignments only, or among a declaration's words. After any
    other command word an array literal is a syntax error, read as before."""
    words = [word for word in words if word not in KEYWORDS and not _ASSIGNMENT.match(word)]
    return not words or words[0] in _DECLARATIONS


def _stage(text, context):
    """Read lexical redirect operators in order, copying fd sinks by value,
    and an array literal as part of the word that assigns it (#2348). A word
    with a double-quoted `\\$` or `` \\` `` in it carries the text bash makes
    of it, `spelled`, which is the program a shell handed it runs (#2342): the
    backslash of each gone, a live `$` word beside them kept as the value word
    it is (#2466), a lifted substitution as its marker; it reads as before."""
    try:
        tokens = shlex.split(patterned(text))
    except ValueError:                          # an unbalanced quote
        tokens = text.split()
    argv: list[str] = []
    writes, reads = [], []
    group_open = group_close = 0
    substitutions: list[str] = []
    heredoc = None
    # Missing and closed fds have no known file sink. A dup copies the current
    # sink; later opens/closes of the original fd cannot change that snapshot.
    sinks: dict[str, str | None] = {}
    # fd 0 initially receives the preceding pipeline stage. Like output
    # sinks, input origins are copied in lexical redirect order.
    pipe_inputs = {"0": True}
    # Which heredoc each descriptor reads, in that same order: a heredoc is an
    # input FILE opened on one descriptor, so a later open, copy or close of
    # that descriptor replaces it exactly as it replaces a pipe. A here-string
    # is one too; the third field says which, as only a heredoc is quoted back.
    bodies: dict[str, tuple[str, bool, bool]] = {}
    # fd 1 initially feeds the next pipeline stage. Opening its aliases copies
    # its CURRENT sink, so `>file >/dev/stdout` still writes to file.
    pipe_outputs = {"1": True}
    pending = None
    literal: int | None = None          # where an array literal's words start
    words: list[str] = []               # argv with no literal folded
    folds: list[tuple[int, list[str]]] = []     # each literal: its opener in `words`, its elements

    def take(word):
        substitutions.extend(value for kind, value in _markers(word).values()
                             if kind == "subst")

    def reads_body(number, body):
        """Descriptor `number` now reads this heredoc body, or none at all."""
        if body is None:
            bodies.pop(number, None)
        else:
            bodies[number] = body

    for raw in tokens:
        raw = raw.replace(_BLANK, " ")          # the blanks of one `${…}` word (#2731)
        head = raw.replace(MARK, "").replace(QUOTED, "").replace(QUOTED_DOLLAR, "")
        raw, quoted, spans = _unmarked(raw), _quoted_assignment(head), _quoted_spans(head)
        plain = context.restore_arithmetic(_unmarked(head))
        raw, word = raw.replace(_ESCAPED, "\\"), context.token(plain.replace(_ESCAPED, "\\"))
        if is_pattern(raw):             # bash expands it first (#2294)
            word = _Expanded(word, _markers(word))
            setattr(word, "lead", leads(context.pattern.sub("${}", raw).replace(QUOTED_DOLLAR, "")))
        elif _ESCAPED in plain:
            word = word if _markers(word) else _Token(word, {})
            setattr(word, "spelled", context.token(plain.replace(_ESCAPED, "")))
        elif raw.count(QUOTED_DOLLAR) == plain.count("$") > 0 and not _markers(word):
            word = kept(word)               # every `$` of it quoted: bash keeps the word (#2472)
        if quoted:                              # `"X=1"`, `"X"=1`, `A\+=x`: no assignment (#2480)
            word = word if isinstance(word, _Token) else _Token(word, {})
            setattr(word, "quoted", True)
        if spans and (_markers(word) or any(c in plain for c in "$ *?[{}")):
            # Quoting that changes bash's reading of the word travels with it (`quoted_spans`);
            # a plainly quoted literal name stays the `str` it always was.
            word = word if isinstance(word, _Token) else _Token(word, {})
            setattr(word, "quoted_spans", spans)
        entry = _markers(word).get(word)
        if entry and entry[0] == "group":
            if entry[1] == "(":
                group_open += 1
                # `a=(1 2)` is no subshell: bash reads an array literal as the
                # rest of the word that assigns it, so it is one here (#2348).
                literal = len(argv) if argv and _ASSIGNMENT.fullmatch(argv[-1]) and _assigns(
                    argv[:-1]) else None
            else:
                group_close += 1
                if literal is not None:
                    # The folded word carries its `elements`, the words as bash splits them
                    # (markers and quoting kept), beside the text it always read as; a word
                    # that only looks like a literal has none (the array-literal cluster).
                    folded = context.token("%s(%s)" % (argv[literal - 1], " ".join(argv[literal:])))
                    folded = folded if _markers(folded) else _Token(folded, {})
                    setattr(folded, "elements", list(argv[literal:]))
                    folds.append((len(words) - len(argv[literal:]) - 1, list(argv[literal:])))
                    argv[literal - 1:] = [folded]
                literal = None
            continue
        if entry and entry[0] == "redirect":
            pending = entry[1]
            continue
        if pending is not None:
            fd, op = pending
            pending = None
            take(word)
            number = (fd.lstrip("0") or "0") if fd else ("0" if op.startswith("<") else "1")
            if op in (">&", "<&"):
                if _fd_or_close(word):
                    source = word.lstrip("0") or "0"
                    sinks[number] = None if word == "-" else sinks.get(source)
                    pipe_inputs[number] = word != "-" and pipe_inputs.get(source, False)
                    pipe_outputs[number] = word != "-" and pipe_outputs.get(source, False)
                    reads_body(number, None if word == "-" else bodies.get(source))
                    continue
                if fd or op == "<&":
                    sinks[number] = None       # invalid/unresolved fd operand
                    pipe_inputs[number] = False
                    pipe_outputs[number] = False
                    reads_body(number, None)
                    continue
                op = "&>"                     # unnumbered >&file
            if op in ("<", "<>", "<<<"):    # `<>` opens the file for reading too (#2657)
                spelled = op == "<<<" and entry and entry[0] == "heredoc"
                word = entry[1][0] if spelled else word     # `lex` spelled it
                reads.append(word)
                sinks[number] = None           # an input file is not an output sink
                source = input_alias_fd(word)
                pipe_inputs[number] = source == "?" or pipe_inputs.get(source, False)
                pipe_outputs[number] = False
                reads_body(number, (word, not spelled, False) if op == "<<<" else
                           bodies.get(source) if source and source != "?" else None)
            else:
                writes.append(word)
                sinks[number] = sinks.get("1") if word in _STDOUT_ALIASES else word
                pipe_inputs[number] = False
                pipe_outputs[number] = (pipe_outputs.get("1", False)
                                        if word in _STDOUT_ALIASES else False)
                reads_body(number, None)
                if op.startswith("&"):
                    sinks["2"] = sinks[number]
                    pipe_inputs["2"] = False
                    pipe_outputs["2"] = pipe_outputs[number]
                    reads_body("2", None)
            continue
        if entry and entry[0] == "heredoc":
            heredoc, expands, fd = entry[1]
            number = fd.lstrip("0") or "0"
            pipe_inputs[number] = False
            pipe_outputs[number] = False
            reads_body(number, (heredoc, expands, True))
            if expands:
                substitutions.extend(_lift_substitutions(heredoc, _Parse(heredoc))[1])
            continue
        take(word)
        argv.append(word)
        words.append(word)
    if all(word in KEYWORDS or _ASSIGNMENT.match(word) for word in argv):
        for opener, elements in folds:  # the opener keeps the literal's `elements` too
            words[opener] = _Token(words[opener], _markers(words[opener]))
            setattr(words[opener], "elements", elements)
        argv = words        # it only assigns: an array of a command is read as run
    stdout, stdin = sinks.get("1"), bodies.get("0")
    return Stage(argv, writes, reads, stdin[0] if stdin and stdin[2] else heredoc,
                 substitutions, [stdout] if stdout is not None else [], group_open,
                 group_close, pipe_inputs["0"], pipe_outputs["1"],
                 tuple(fd for fd, connected in pipe_inputs.items() if connected),
                 stdin[:2] if stdin else None, pipe_outputs.get("2", False))


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages; in a
    lifted substitution's text, each heredoc where its marker stands (#2336)."""
    context = _Parse(script)
    text = lex(script, lambda *heredoc: context.new("heredoc", heredoc))
    for marker, (kind, value) in getattr(script, "heredocs", {}).items():
        text = text.replace(marker, context.new(kind, value))
    text, _inners = _lift_substitutions(text, context)
    out = []
    for raw, separator in _split(text, context):
        stages = [_stage(s, context) for s in raw]
        # A line-only boundary has no argv; keep its marker and the closer's separator.
        if any(s.argv or s.group_open or s.group_close for s in stages):
            out.append(Statement(stages, separator))
    return out
