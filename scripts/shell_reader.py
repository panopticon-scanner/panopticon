#!/usr/bin/env python3
"""As much of the POSIX shell as a guard over `run:` blocks has to read.

Split out of `scripts/workflow_guard.py` (#1647 fix round 1), which asks two questions of a
workflow step -- what does it download, and what checks the download -- and could answer neither
while its input was a regex match over shell TEXT. Both questions need the same thing first: the
commands, in order, with their arguments, their redirections, their heredocs and the commands
hidden inside their substitutions.

So this module reads shell, and nothing about supply chains lives here. The reading is
deliberately partial -- no expansion, no arithmetic, no control flow -- and the rule on top is
written to fail closed on what is missing (see that module's docstring). What IS handled,
because each one hid a download from the guard until it was:

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

The first three are settled on the TEXT, before any command is read, in the one quote-aware pass
`scripts/shell_lex.py` makes the way bash does (#1793), and the substitutions are lifted out of
it by `scripts/shell_text.py`. The wrappers' table, and the option grammar each one is read
with, are `scripts/shell_wrappers.py`'s (#2227). The words a parse hands back, and the markers
in them that say what was lifted out, are `scripts/shell_tokens.py`'s (#2628): split out at this
module's size and imported back here, so no caller moved. The statement splitter, `_split` and
what it reads, is `scripts/shell_split.py`'s (#3001), moved out the same way.

Stdlib only. `statements(script)` is the entry point; `command(argv)` strips
what stands in front of a command; `readable(text)` puts lifted substitutions
back for a human reading an error message."""
import collections
import fnmatch
import os
import re
import shlex

from shell_lex import lex
from shell_patterns import (DOUBLE_DOLLAR, MARK, QUOTED, QUOTED_DOLLAR, is_pattern, leads,
                            patterned, shell_words as shell_words)
from shell_text import (_lift_substitutions, join_continuations as join_continuations,
                        without_comments as without_comments)
from shell_tokens import (_Expanded as _Expanded, _Parse as _Parse, _Token as _Token, placed as placed,
                          _markers as _markers, at_place as at_place, bang as bang, derived as derived,
                          has_substitution as has_substitution, is_arm as is_arm,
                          is_marker as is_marker, kept as kept, readable as readable,
                          yields_words as yields_words)
from shell_wrappers import (WRAPPERS as WRAPPERS, Defaulted as Defaulted,
                            Rewritten as Rewritten, dynamic as dynamic, shadows, unwrap as unwrap)
from shell_command import (CONDITIONS as CONDITIONS, KEYWORDS as KEYWORDS,
                           OPTIONAL_NEXT as OPTIONAL_NEXT, _ASSIGNMENT as _ASSIGNMENT,
                           _DEFAULTS as _DEFAULTS, _ENVIRONMENT as _ENVIRONMENT,
                           _FETCHERS as _FETCHERS, _FUNCTION as _FUNCTION,
                           _INTERPRETERS as _INTERPRETERS, _NAME as _NAME, _OPTIONAL as _OPTIONAL,
                           _SHELLS as _SHELLS, _command_result as _command_result,
                           _optional as _optional, command as command, acted as acted, reads_held, body_read, carrier,
                           sources, track, credited_zero as credited_zero, sure_reader as sure_reader, unsure as unsure,
                           command_as_written as command_as_written, conditional as conditional,
                           negated as negated, unresolved_wrapper as unresolved_wrapper,
                           folds as folds, fronts, wrapper_words as wrapper_words)
from shell_split import (_BLANK as _BLANK, _BRACED_HEADER as _BRACED_HEADER, _ESCAPED as _ESCAPED,
                         _HEADER as _HEADER, _NESTED_CASE as _NESTED_CASE, _REDIRECT as _REDIRECT,
                         _bare_blanks as _bare_blanks, _negated as _negated, _split as _split)

# One shell command: its argv, the files it redirects into / reads from, the heredoc body
# attached to it, the command substitutions inside it -- the `$(...)`, `<(...)` and backtick
# texts, which are commands in their own right and where `eval "$(curl ...)"` hides its download
# -- and stdout_writes, the final file sink of descriptor 1 after ordered
# redirects/duplications. `writes` also carries an explicit OTHER fd (`2>err.log`) so the
# guard's file-tracking stays correct; `stdout_writes` is the one a caller may call THE
# destination (#1733). `&>word`/`&>>word` and the UNNUMBERED `>&word` land there too -- bash's
# `>word 2>&1` shorthand, a real file whatever `word` looks like. A target beginning with `&`
# whose remainder IS a duplication or close (`&1`, `&-`) -- `2>&1`, `>&2`, `>&-` -- lands in
# neither list. Parse-local subshell markers leave argv alone; counts retain their boundaries
# for the checksum handler without exposing marker tokens as commands. `heredoc` is the body a
# caller may quote back (a `sha256sum -c` sums list; of several, the one descriptor 0 reads if
# any -- `cat` and `-c` read stdin); `stdin_heredoc` is the body descriptor 0 FINALLY reads,
# with the flag that says whether it expanded -- `(body, expands)` or None. The two are
# different questions: `sh 3<<EOF` writes a body nothing reads on stdin, `sh <<EOF 0<&3` hands
# stdin somewhere else afterwards, and only the second question can say whether a heredoc is the
# SCRIPT of the interpreter in front of it (#1839). A here-string is a body the second question
# reads too (`sh <<< '...'`, #2293) -- expanding unless `lex` spelled its word -- and never the
# first's. `pipe_output_fds` are the descriptors that feed the next stage when the stage's
# redirections end, as `pipe_input_fds` are the ones the last stage feeds: `2>&1` adds 2, `>file`
# takes 1 away (#2744). `stdin_reads` are the file words descriptor 0 finally reads, copied in
# redirect order through a dup or a path of another descriptor (#2884).
Stage = collections.namedtuple(
    "Stage", "argv writes reads heredoc substitutions stdout_writes "
             "group_open group_close stdin_from_pipe stdout_to_pipe pipe_input_fds "
             "stdin_heredoc pipe_output_fds stdin_reads",
    defaults=(0, 0, True, True, ("0",), None, ("1",), ()))
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages in order,
# and the separator that FOLLOWS it -- which is where a shell says whether the
# command's exit status is allowed to matter (`... || true`, `... &`).
Statement = collections.namedtuple("Statement", "stages separator")


# The builtins whose words bash reads as assignments too: `declare -a a=(1 2)`.
_DECLARATIONS = ("declare", "typeset", "local", "export", "readonly")
# Put in front of a word that spells an assignment but for a quote or a backslash in its name or its operator,
# where a command word may stand (`_named`, #2480). `_WORD` is a word as written, quotes and all, to the blank
# shlex ends it at; `_SPELLED` one whose name and operator would read as an assignment's with every quote and
# backslash among them taken off -- which `_ASSIGNMENT` then says is one as written, or is not.
_NAMED = "\ue005"
_WORD = re.compile(r"""(?:[^ \t\r\n'"\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+""", re.S)
_SPELLED = re.compile(r"""["'\\]*[A-Za-z_](?:["'\\]*[A-Za-z0-9_])*["'\\]*(?:\[[^]]*\]["'\\]*)?(?:\+["'\\]*)?=""")
# A `$` word written whole in double quotes (`_stage`'s `double`): what stands between them.
_DOUBLE = re.compile(r'"(\$[^"\\\s]*)"')
# The paths of N a carry reads as N, past slashes or a climb: `//dev/fd/N`, `../proc/thread-self/fd/N` (#2881)
_FD_SPELLINGS = re.compile(r"^(?:/+|(?:\.\./+)+)(?:dev|proc/(?:thread-)?self)/+fd/")
# `/proc/self/root` and `/proc/thread-self/root` are the process's own root: in front of an absolute path they
# spell it once more, as often as they stand (#3051).
_OWN_ROOT = re.compile(r"^(?:/proc/(?:thread-)?self/root)+(?=/)")
# The listed names of a descriptor a pattern bash expands may match (`/dev/stdou[t]`, `/dev/fd/[1]`, #3051).
_DESCRIPTOR_NAMES = ("/dev/stdin", "/dev/stdout", "/dev/stderr", *("/dev/fd/%d" % n for n in range(10)),
                     *("/proc/self/fd/%d" % n for n in range(10)), *("/proc/thread-self/fd/%d" % n for n in range(10)))


# --- reading the shell -------------------------------------------------------

def _fd_or_close(word):
    """True for the historical ambiguity of the UNNUMBERED `>&word` form: real bash reads a word
    made only of digits, or exactly `-`, as a file descriptor to duplicate or close -- never a
    path -- and anything else as the file `>word 2>&1` would have named. Checked against bash 5
    (round 1 of #1733's fix): `>&2extra` writes a file called `2extra`; `>&2` does not. The
    `&>word` spelling carries no such ambiguity at all (`&>2` is always a file named `2`), so
    this is never consulted for it."""
    return word == "-" or (word.isascii() and word.isdigit())


def input_alias_fd(word):
    """Alias fd, ? for unresolved input, or None for a literal ordinary file."""
    if "$" in word or has_substitution(word):
        return "?"
    word = re.sub(r"^(?:/+|(?:\.\./)+)(?=dev/|proc/)", "/", os.path.normpath(word))     # `//dev/`, `../proc/`
    if word in (std := ("/dev/stdin", "/dev/stdout", "/dev/stderr")):
        return str(std.index(word))
    match = re.fullmatch(r"/dev/fd/([0-9]+)", word)
    if match:
        return match[1].lstrip("0") or "0"
    if word.startswith("/dev/fd/") or re.match(r"/proc/.*/fd/", word):
        return "?"
    return None


def output_alias_fd(word):
    """The descriptor of its own that a path a stage WRITES names, or None for a file of its own (#2744):
    `/dev/stdout`, `/dev/stderr`, `/dev/fd/N`, `/proc/self/fd/N` and `/proc/thread-self/fd/N`, in any spelling
    a kernel opens as that file -- repeated slashes, `.` and `..` among them, a climb to the root
    (`input_alias_fd` past `_FD_SPELLINGS`). Linux refuses `/dev/stdout/` and `/dev/fd/01`, which macOS opens,
    and macOS has no `/proc`: the reading is of either kernel (measured on both), and of `/dev/fd/1/` too,
    which neither opens. What a command writes there lands where THAT descriptor points -- the pipe, a file,
    nowhere. A word a value decides, and a path of another process's descriptor, are read as files, as before.
    A pattern bash expands is the one listed name it matches, where it matches one (`/dev/stdou[t]`; dash expands
    no redirection's pattern, a price under `sh`), and `/proc/self/root` in front of the path is dropped as often
    as it stands (#3051). What a `cd` or a link of the step's may make of the path is `sources`' to ask."""
    path = str(word)
    if isinstance(word, _Expanded):
        names = [name for name in _DESCRIPTOR_NAMES if fnmatch.fnmatchcase(name, path)]
        path = names[0] if len(names) == 1 else path
    path = _OWN_ROOT.sub("", os.path.normpath(path)) or "/"
    fd = input_alias_fd(_FD_SPELLINGS.sub("/dev/fd/", path))
    return None if fd == "?" else fd


def writes_pipe(word, stage):
    """Whether a path a command of `stage` writes is the stage's standard output, as the two listed spellings
    were to `main`, or another descriptor its redirections left feeding the next stage (`tee /dev/stderr
    2>&1`, `tee /dev/fd/3 3>&1`; #2744): what such a command writes there, the next stage reads."""
    fd = output_alias_fd(word)
    return fd == "1" or fd in stage.pipe_output_fds


def stdout_named(path, stage):
    """`/dev/stdout` for a path a command of `stage` writes that names the stage's descriptor 1 in any spelling
    (`output_alias_fd`), or another descriptor that feeds the next stage beside it (`-o /dev/stderr 2>&1`);
    else the path as it is: for a reader that asks a table of the listed names (`workflow_fetch`, #2744)."""
    fd = output_alias_fd(path) if path else None
    return "/dev/stdout" if fd == "1" or fd in stage.pipe_output_fds and stage.stdout_to_pipe else path


def _assigns(words):
    """Whether bash reads the word after `words` as an assignment: behind
    keywords and assignments only, or among a declaration's words. After any
    other command word an array literal is a syntax error, read as before."""
    words = [word for word in words if word not in KEYWORDS and not _ASSIGNMENT.match(word)]
    return not words or words[0] in _DECLARATIONS


def _whole(raw, context, span):
    """A word `_split` kept whole (`_bare_blanks`), as bash reads it before it splits it, and the
    `span` of `main`'s words it is: for the one reading that takes it whole, the command word
    (`shell_command._command_result`, #2731). Every other reading has `main`'s words (#2856
    round 8)."""
    plain = context.restore_arithmetic(raw.replace(MARK, "").replace(QUOTED, "")
                                       .replace(QUOTED_DOLLAR, "").replace(DOUBLE_DOLLAR, ""))
    word = context.token(plain.replace(_ESCAPED, "\\"))
    word = word if isinstance(word, _Token) else _Token(word, _markers(word))
    word.span = span
    word.at = context.whole()
    return word


def _named(text, context):
    """`text`, a stage's, with `_NAMED` in front of the word that stands where its command word may and spells
    an assignment but for a quote or a backslash in its name or its operator (`"X=1"`, `X\\=1`, `"A"+=x`,
    `X""=1`): bash reads an assignment off the word as written, so this one is a command of that name, which
    `shell_command._command_result` reads it as (#2480). A quote in the value or in a subscript leaves an
    assignment one (`X="1"`, `a["k"]=1`). The command word may stand behind a `(`, a `case` arm's token or a
    redirection as behind a keyword (`fronts`); behind a wrapper the word is the wrapper's, its quotes off."""
    front: bool | str = True
    target = False                      # the word a redirection's operator takes
    for word in _WORD.finditer(text):
        raw = word[0]
        entry = _markers(token := context.token(raw)).get(raw)
        if target or is_arm(token) or entry and entry[0] in ("group", "redirect", "heredoc"):
            target = not target and bool(entry) and entry[0] == "redirect"
            continue
        if _SPELLED.match(raw) and not _ASSIGNMENT.match(raw):
            return text[:word.start()] + _NAMED + text[word.start():]
        front = fronts(raw, front, text, word.end())
        if not front:
            break
    return text


def _stage(text, context):
    """Read lexical redirect operators in order, copying fd sinks by value, and an array literal
    as part of the word that assigns it (#2348). A word with a double-quoted `\\$` or `` \\` ``
    in it carries the text bash makes of it, `spelled`, which is the program a shell handed it
    runs (#2342): the backslash of each gone, a live `$` word beside them kept as the value word
    it is (#2466), a lifted substitution as its marker; it reads as before."""
    text = _named(text, context)
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
    # The ordinary files each descriptor may read, copied in the same order.
    # Unlike `reads`, this preserves which ones reach fd 0 after all redirects.
    input_files: dict[str, tuple[str, ...]] = {}
    # Which heredoc each descriptor reads, in that same order: a heredoc is an
    # input FILE opened on one descriptor, so a later open, copy or close of
    # that descriptor replaces it exactly as it replaces a pipe. A here-string
    # is one too; the third field says which, as only a heredoc is quoted back.
    bodies: dict[str, tuple[str, bool, bool]] = {}
    # fd 1 initially feeds the next pipeline stage. Opening its aliases copies
    # its CURRENT sink, so `>file >/dev/stdout` still writes to file.
    pipe_outputs = {"1": True}
    pending = None
    opened: dict[str, tuple[str, ...]] = {}  # the files `N<>` opened on N but 0, on each N they stand on
    # Where in `reads` each `0<>` put its file, and the one fd 0 still holds (`credited_zero`).
    zero: list[int] = []
    held: int | None = None
    literal: int | None = None          # where an array literal's words start
    words: list[str] = []               # argv with no literal folded
    folds: list[tuple[int, list[str]]] = []     # each literal folded: its opener in `words`, its elements

    def take(word):
        substitutions.extend(value for kind, value in _markers(word).values()
                             if kind == "subst")

    def reads_body(number, body):
        """Descriptor `number` now reads this heredoc body, or none at all."""
        if body is None:
            bodies.pop(number, None)
        else:
            bodies[number] = body

    # A word `_split` kept whole is read as `main` reads it, in the pieces its bare blanks split,
    # each read as any word is; the first carries the whole word and how many pieces it spans,
    # which only the command word reads (`shell_command._command_result`, #2731).
    pieces: list[tuple[str, str | None, int]] = []
    doubles: set[str] | None = None
    for raw in tokens:
        parts = ([part for part in raw.split(_BLANK) if part] or [raw]) if (
            _BLANK in raw and getattr(context, "blanks", True)) else [raw]
        whole = raw.replace(_BLANK, " ") if len(parts) > 1 else None
        pieces.extend((part, None if at else whole, len(parts)) for at, part in enumerate(parts))
    for raw, whole, span in pieces:
        named, raw = raw.startswith(_NAMED), raw.replace(_NAMED, "")
        plain = context.restore_arithmetic(raw.replace(MARK, "").replace(QUOTED, "")
                                           .replace(QUOTED_DOLLAR, "")
                                           .replace(DOUBLE_DOLLAR, ""))
        raw, word = raw.replace(_ESCAPED, "\\"), context.token(plain.replace(_ESCAPED, "\\"))
        if is_pattern(raw):             # bash expands it first (#2294)
            word = _Expanded(word, _markers(word))
            unquoted = raw.replace(QUOTED_DOLLAR, "").replace(DOUBLE_DOLLAR, "")
            setattr(word, "lead", leads(context.pattern.sub("${}", unquoted)))
        elif _ESCAPED in plain:
            word = word if _markers(word) else _Token(word, {})
            setattr(word, "spelled", context.token(plain.replace(_ESCAPED, "")))
        elif (raw.count(QUOTED_DOLLAR) + raw.count(DOUBLE_DOLLAR)
              == plain.count("$") > 0 and not _markers(word)):
            word = kept(word)               # every `$` of it quoted: bash keeps the word (#2472)
            # ...and where the whole value is double-quoted, `"$@"` may be no word at all (#3002).
            doubles = set(_DOUBLE.findall(text)) if doubles is None else doubles
            setattr(word, "double", plain in doubles)
            # A separate fact says whether every `$` is live. A single quote or backslash makes
            # eval or a child shell re-read it after applying a prefix assignment (#2433).
            setattr(word, "live_dollar", raw.count(DOUBLE_DOLLAR) == plain.count("$"))
        if named:                           # `"X=1"`, `X\=1`: a command of that name (#2480)
            word = word if isinstance(word, _Token) else _Token(word, {})
            setattr(word, "quoted", True)
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
                    # The folded word carries its `elements`, the words as bash splits them, each the
                    # token of this parse, beside the text it always read as; a word that only looks
                    # like a literal has none (the array-literal cluster, #2772).
                    folded = context.token("%s(%s)" % (argv[literal - 1], " ".join(argv[literal:])))
                    folded = folded if isinstance(folded, _Token) else _Token(folded, {})
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
            held = None if number == "0" else held      # a later redirection of fd 0 ends it
            # A dup, a move or a path of N (`_FD_SPELLINGS`, `input_alias_fd`, `carrier`) carries what N holds onto
            # its target, fd 0 too, until that is redirected again (`4<&3 <&4`, `</dev/fd/3 3<&-`, #2881);
            # a source a value decides (`<&$FD`, `<"$P"`) carries every file held, fail-closed (round 4)
            moved = re.fullmatch(r"(\d+)-", word) if op in (">&", "<&") else None
            source = (moved[1] if moved else word) if moved or op in (">&", "<&") and _fd_or_close(word) else (
                op != "<<<" and carrier(word, context, lambda path: input_alias_fd(derived(_FD_SPELLINGS.sub("/dev/fd/", path), word))))
            carried = tuple(dict.fromkeys(sum(opened.values(), ()))) if source == "?" else opened.get(
                (source or "-").lstrip("0") or "0", ())
            input_carried = tuple(dict.fromkeys(sum(input_files.values(), ()))) if source == "?" else input_files.get(
                (source or "-").lstrip("0") or "0", ())
            opened.pop(number, None)            # any redirection of N ends what `N<>` opened there
            input_files.pop(number, None)
            if moved:
                opened.pop(moved[1].lstrip("0") or "0", None)
                input_files.pop(moved[1].lstrip("0") or "0", None)
            if carried:
                opened[number] = carried
            if input_carried:
                input_files[number] = input_carried
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
            if op in ("<", "<<<") or op == "<>" and number == "0":   # `<>`: fd 0 reads (#2657)
                spelled = op == "<<<" and entry and entry[0] == "heredoc"
                word = entry[1][0] if spelled else word     # `lex` spelled it
                reads.append(word)
                if op == "<>":
                    zero.append(len(reads) - 1)
                    held = zero[-1]
                sinks[number] = None           # an input file is not an output sink
                reached = sources(word, op != "<<<" and context, input_alias_fd)   # as written, then by a link or a `cd`
                pipe_inputs[number] = "?" in reached or any(pipe_inputs.get(fd, False) for fd in reached)
                pipe_outputs[number] = False
                if op != "<<<":
                    input_files[number] = tuple(dict.fromkeys((*input_files.get(number, ()), word)))
                reads_body(number, (word, not spelled, False) if op == "<<<" else
                           body_read(bodies, reached))
            else:
                if op == "<>":                 # open for reading too: what reads N reads it (#2881)
                    opened[number] = (*carried, word)
                    input_files[number] = tuple(dict.fromkeys((*input_files.get(number, ()), word)))
                writes.append(word)
                # A path of N: where N points now (`2>&1 >/dev/stderr`, #2744) -- as written, or as a `cd` or a
                # link of the step's may make it (`sources`, #3051): what is written there may then reach the
                # next stage, the file kept beside, the reader knowing no `cd` or `ln` to have run.
                alias, *others = sources(word, context, output_alias_fd)
                sinks[number] = word if alias is None else sinks.get(alias)
                pipe_inputs[number] = False
                pipe_outputs[number] = any(fd == "?" or pipe_outputs.get(fd, False) for fd in (alias, *others) if fd)
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
            held = None if number == "0" else held
            input_files.pop(number, None)
            pipe_inputs[number] = False
            pipe_outputs[number] = False
            reads_body(number, (heredoc, expands, True))
            if expands:
                substitutions.extend(_lift_substitutions(heredoc, _Parse(heredoc))[1])
            continue
        if whole is not None:
            word = word if _markers(word) else _Token(word, {})
            setattr(word, "whole", _whole(whole, context, span))
            setattr(word, "span", span)
        take(word)
        argv.append(word)
        words.append(word)
    if all(word in KEYWORDS or _ASSIGNMENT.match(word) for word in argv):
        argv = words        # it only assigns: an array of a command is read as run
        for opener, elements in folds:          # and the opener keeps the literal's `elements`
            words[opener] = words[opener] if isinstance(words[opener], _Token) else _Token(words[opener], {})
            setattr(words[opener], "elements", elements)
    # An interpreter -- one any action of a `find` runs too (round 4; #2918) -- or a command word the step's
    # values decide (`$SH`, but not `$X/sha256sum`: a check is credited by its basename, round 5) reads what
    # `N<>` still holds open when its redirections end, on any descriptor, as `main` reads `N<` -- by a dup, a
    # path, a child program; no other command reads it, so no check is credited with a file it only holds
    # (`reads_held`, #2881).
    if opened and reads_held(argv):
        reads.extend(file for file in dict.fromkeys(sum(opened.values(), ())) if file not in reads)
    # A check reads what `0<>` opened only where fd 0 still holds it (#2856 round 12, B5).
    reads, writes = credited_zero(argv, reads, writes, zero, held)
    stdout, stdin = sinks.get("1"), bodies.get("0")
    return track(context, Stage(argv, writes, reads, stdin[0] if stdin and stdin[2] else heredoc,
                 substitutions, [stdout] if stdout is not None else [], group_open,
                 group_close, pipe_inputs["0"], pipe_outputs["1"],
                 tuple(fd for fd, connected in pipe_inputs.items() if connected),
                 stdin[:2] if stdin else None,
                 tuple(fd for fd, connected in pipe_outputs.items() if connected),
                 input_files.get("0", ())))


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages; in a
    lifted substitution's text, each heredoc where its marker stands (#2336)."""
    context = _Parse(script)
    shadows(script)                     # a wrapper's name the text defines is the step's own (#2670)
    # A step that spells a mark the reader puts in its text reads as `main` (#2856 round 8).
    context.blanks = not any(mark in script for mark in (
        MARK, QUOTED, _ESCAPED, QUOTED_DOLLAR, DOUBLE_DOLLAR, _BLANK))
    text = lex(script, lambda *heredoc: context.new("heredoc", heredoc))
    for marker, (kind, value) in getattr(script, "heredocs", {}).items():
        text = text.replace(marker, context.new(kind, value))
    text, _inners = _lift_substitutions(text, context)
    out = []
    for at, (raw, separator) in enumerate(_split(text, context)):
        stages = [_stage(s, context) for s in raw]
        if at in context.bangs:         # a negated group's `!`, marked on its first word
            stages[0].argv[0] = bang(stages[0].argv[0])
        for stage in stages[1:]:        # behind a `|` bash reads `time` as a program's name, no keyword (#2670)
            if stage.argv[:1] == ["time"] and not stage.group_open:
                stage.argv[0] = _Token("time", {})
                setattr(stage.argv[0], "piped", True)
        # A line-only boundary has no argv; keep its marker and the closer's separator.
        if any(s.argv or s.group_open or s.group_close for s in stages):
            out.append(Statement(stages, separator))
    return out
