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

Stdlib only. `statements(script)` is the entry point; `command(argv)` strips
what stands in front of a command; `readable(text)` puts lifted substitutions
back for a human reading an error message.
"""
import collections
import os
import re
import shlex

from shell_lex import lex
from shell_patterns import MARK, QUOTED, is_pattern, leads, patterned, shell_words
from shell_quote import ansi_c
from shell_text import (_lift_substitutions, join_continuations as join_continuations,
                        without_comments as without_comments)
from shell_tokens import (_Expanded as _Expanded, _Parse as _Parse, _Token as _Token,
                          _markers as _markers, derived as derived,
                          has_substitution as has_substitution, is_arm as is_arm,
                          is_marker as is_marker, readable as readable,
                          yields_words as yields_words)
from shell_wrappers import WRAPPERS, Defaulted, Rewritten, dynamic, unwrap

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
Stage = collections.namedtuple(
    "Stage", "argv writes reads heredoc substitutions stdout_writes "
             "group_open group_close stdin_from_pipe stdout_to_pipe pipe_input_fds "
             "stdin_heredoc",
    defaults=(0, 0, True, True, ("0",), None))
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages in order,
# and the separator that FOLLOWS it -- which is where a shell says whether the
# command's exit status is allowed to matter (`... || true`, `... &`).
Statement = collections.namedtuple("Statement", "stages separator")

# Shell keywords that stand in FRONT of the command: `if curl ...; then`,
# `while true; do /tmp/payload; done`. Statements are split on `;`, so each of
# these arrives as the first word of the statement it introduces -- and a guard
# that reads `if` as the command sees neither the fetch nor the use.
KEYWORDS = ("if", "then", "elif", "else", "fi", "do", "done", "while", "until",
            "for", "case", "esac", "in", "!", "{", "}", "(", ")", "function",
            "()")
# The words that make the following command CONDITIONAL rather than fatal: a
# command in an `if`/`while` test decides a branch, and `set -e` never applies
# to it. A guard reading exit statuses has to know the difference.
CONDITIONS = ("if", "elif", "while", "until")

# A word bash reads as an assignment in front of a command (#2348): `NAME=`,
# `NAME+=`, and to an array element, `a[1]=x` or `a[1]+=x`, which bash globs
# nothing in; an array literal (`a=(1 2)`) is folded into its word by `_stage`.
# Behind a wrapper the words are the wrapper's, and only `NAME=` is popped
# there, as `env X=1` and `sudo X=1` take it: `sudo a[1]=x` is a pattern.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
_ENVIRONMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# The builtins whose words bash reads as assignments too: `declare -a a=(1 2)`.
_DECLARATIONS = ("declare", "typeset", "local", "export", "readonly")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\(\)$")
# The shells whose options and program word a pattern may rewrite into a `-c`
# and its script (`sh {-c,'…'}`, review N-3): `workflow_programs._SHELL_STRING`.
_SHELLS = ("sh", "bash", "dash", "ash", "ksh", "zsh")
# A command word that is a parameter's default or alternate (#2337): `${X:-sh}`,
# `"${X-bash}"`, `${X:=sh}`, `${X:+sh}`. Where it spells a shell it is read as
# that shell, which bash runs wherever `X` leaves the word to it.
_DEFAULTS = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+]([^{}$`'\"\\\s]+)\}")
_REDIRECT = re.compile(r"<<<|&>>|&>|>>|>\||>&|<&|>|<")
_NESTED_CASE = re.compile(r"\s*case(?:\s|$)")
# Put in place of the backslash of a `\$` or `` \` `` inside "..." (`_split`),
# which bash drops and shlex keeps (#2342): a private-use character, as `MARK`.
_ESCAPED = "\ue002"
_STDOUT_ALIASES = ("/dev/stdout", "/dev/fd/1")


# --- reading the shell -------------------------------------------------------

def _split(text, context):
    """[[stage text, ...], ...]: statements, each a list of pipeline stages.

    Quote-aware by hand rather than by regex, because the whole defect being
    fixed is a regex that could not tell a `|` inside a URL from a pipeline.
    A `$'...'` whose escapes `shell_quote.ansi_c` decodes becomes the '...' of
    the text bash makes of it, so `sh $'-c'` reads as `sh -c` (#2344); a
    double-quoted `\\$` or `` \\` `` is marked for `_stage` (`_ESCAPED`), as
    shlex, reading what is left, no longer knows the quote it was in.
    """
    statements = []
    stages = []
    buf: list[str] = []
    quote, i, n, opened = None, 0, len(text), 0
    cases: list[str] = []
    groups = (context.new("group", "("), context.new("group", ")"))
    word_start, redirect_target = 0, False
    # A `case` header is exactly three words (`case`, the word, `in`), so the
    # shlex probe below only has to run while the buffer can still BE one --
    # `header_words` counts the words the buffer has closed, `header_live`
    # goes false as soon as the first word is not `case` or a third word has
    # gone by without a header, and both reset when the buffer does. Probing
    # unconditionally re-split the WHOLE buffer on every whitespace character,
    # which made `_split` quadratic: 42 KB of one statement took ~93 s against
    # 0.02 s before the probe existed, from a `run:` block this module reads
    # out of the TARGET repository (fix round on #1714, Critical 1).
    header_words, header_live = 0, True
    # `[[ ... ]]` is ONE compound command: the `&&`, `||`, `(`, `)`, `<` and
    # `>` in it are the conditional's operators, not list separators, subshells
    # or redirections (#2441) -- split at them, `CHECK && [[ -f a || -f b ]] ||
    # exit 1` lost the `|| exit 1` that ends the real list. `cond` is 0 outside
    # one and, inside, 1 plus the `(` it holds open, so a `)` it did not open
    # ends it where `shell_lex` does: a `case` arm's `[[)` is a pattern.
    # `at_head` says every word this stage closed is a keyword or an assignment
    # -- where bash reads `[[` as the conditional, not as `echo [[ a`'s word.
    # The test ends with the STATEMENT, not with a stage: bash makes one word
    # of `^(x|y)$`, and ending it at that `|` left the `)` closing a group
    # nothing had opened -- the unbalanced count #2334 reads as a lost list.
    cond, at_head = 0, True

    def end_stage():
        nonlocal header_words, header_live, word_start, redirect_target, at_head
        stages.append("".join(buf))
        del buf[:]
        header_words, header_live, word_start = 0, True, 0
        redirect_target, at_head = False, True

    def end_statement(separator):
        nonlocal cond
        end_stage()
        cond = 0
        if any(s.strip() for s in stages):
            statements.append((list(stages), separator))
            if cases and re.match(r"^\s*esac(?:\s|$)", stages[0]):
                cases.pop()
        del stages[:]

    while i < n:
        ch = text[i]
        if quote:
            buf.append(_ESCAPED if quote == '"' and text[i:i + 2] in ("\\$", "\\`") else ch)
            if ch == "\\" and quote != "'" and i + 1 < n:   # "..." and $'...'
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote[-1]:
                body = ansi_c("".join(buf[opened + 1:-1])) if quote == "$'" else None
                if body is not None:        # bash's text for a `$'...'`, quoted (#2344)
                    buf[opened:] = ["'%s'" % body.replace("'", "'\"'\"'")]
                quote = None
            i += 1
            continue
        if ch in "'\"" or text.startswith("$'", i):
            quote, opened = text[i:i + 2] if ch == "$" else ch, len(buf)
            buf.append(quote)
            i += len(quote)
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(text[i + 1])
            i += 2
            continue
        # A case header ends at its `in`, even when its first arm shares
        # the line. Quoted/escaped words remain intact until shlex reads them.
        # The count asks the BUFFER, not the source text, whether a word just
        # closed here: whitespace that only extends a run of whitespace ends
        # nothing, an escaped space ends nothing, and the character before a
        # statement's first space may be the `;` that ENDED the last one --
        # a source-text test miscounted that as a word and killed the probe
        # one word early, losing the second header of `case ... esac; case
        # ... in ...`. Whitespace inside a quote never reaches this branch.
        if ch.isspace() and buf and not buf[-1][-1].isspace():
            # The word that closed, quotes and all: `"[["` is the ordinary
            # word, never the conditional; empty just past a `case` arm token.
            closed = "".join(buf[word_start:])
            if closed == "[[" and at_head or closed == "]]" and cond:
                cond = int(closed == "[[")
            at_head = at_head and bool(not closed or closed in KEYWORDS
                                       or _ASSIGNMENT.match(closed))
            if header_live:
                header_words += 1
                try:
                    words = shlex.split("".join(buf))
                except ValueError:
                    words = []
                words = [w for w in words if w not in groups]
                if len(words) == 3 and words[0] == "case" and words[-1] == "in":
                    end_statement(";")
                    cases.append("pattern")
                elif header_words >= 3 or (words and words[0] != "case"):
                    header_live = False     # this buffer is not a header
        if ch == "(" and not (cases and cases[-1] == "pattern"):
            if cond:                        # `[[ ( -f a || -f b ) ]]`: no subshell
                cond, i = cond + 1, i + 1
                buf.append(ch)
                continue
            # Preserve function headers: `f()` and `f ()` are not subshells.
            if text[i:i + 2] == "()" and _NAME.fullmatch("".join(buf).strip()):
                buf.append("()")
                i += 2
                continue
            buf.append(" " + groups[0] + " ")
            word_start, redirect_target = len(buf), False
            i += 1
            continue
        if ch == ")":
            cond = max(cond - 1, 0)         # one it did not open ends it
            if cases and cases[-1] == "pattern":
                buf[:] = [context.new("arm") + "".join(buf).lstrip() + ")"]
                cases[-1] = "body"
                # Preserve the parent's arm region before its nested header.
                # Otherwise the arm marker hides `case` from the three-word
                # probe, and the inner pattern becomes the command (#2617).
                if _NESTED_CASE.match(text, i + 1):
                    end_statement(";")
            elif cond:
                buf.append(ch)              # the `(` the test opened, closed
            else:
                buf.append(" " + groups[1] + " ")
                word_start, redirect_target = len(buf), False
            i += 1
            continue
        redirect = _REDIRECT.match(text, i)
        # `[[ $a < $b ]]` compares two strings: no descriptor is redirected.
        if redirect and not cond and not (cases and cases[-1] == "pattern"):
            # Only unquoted, unescaped digits comprising the whole preceding
            # word are an IO number. An attached URL (or quoted "2") is argv.
            word = "".join(buf[word_start:])
            op, fd = redirect.group(), ""
            if (not redirect_target and not op.startswith("&")
                    and word.isascii() and word.isdigit()):
                fd = word
                del buf[word_start:]
            buf.append(" " + context.new("redirect", (fd, op)) + " ")
            word_start, redirect_target = len(buf), True
            i = redirect.end()
            continue
        if ch == "|" and text[i:i + 2] != "||":
            if cases and cases[-1] == "pattern":
                buf.append(ch)  # case alternatives are one pattern, not a pipeline
                i += 1
                continue
            combined = text[i:i + 2] == "|&"
            if combined:
                # Bash applies the implicit stderr copy AFTER explicit redirects.
                buf.append(" " + context.new("redirect", ("2", ">&")) + " 1 ")
            end_stage()
            i += 2 if combined else 1
            continue
        if ch in ";\n&|":
            pair = text[i:i + 2]
            separator = pair if pair in ("&&", "||") else ch
            # Inside the test they join its expressions, and a `]]` that the
            # operator itself closes (`[[ -f a ]]&& USE`) ends it first; a `;`,
            # `&` or newline there is a syntax error bash stops on, read as ever.
            if cond and pair in ("&&", "||") and "".join(buf[word_start:]) != "]]":
                buf.append(" %s " % pair)
                word_start, i = len(buf), i + 2
                continue
            end_statement(separator)
            # Every terminator that ENDS a case arm, not just `;;`: bash also
            # spells it `;&` (fall through into the next arm's body) and `;;&`
            # (resume matching at the next pattern). Reading only `;;` left
            # the state at "body", so the next arm's `b)` was read as a group
            # CLOSE and `b` became argv[0] -- shadowing the command behind it,
            # which is how a `curl` in the second arm went unseen entirely
            # (fix round on #1714, Critical 2). After any of the three the
            # next word is a pattern again.
            arm_end = next((t for t in (";;&", ";;", ";&")
                            if text.startswith(t, i)), None)
            if arm_end and cases:
                cases[-1] = "pattern"
            i += len(arm_end) if arm_end else len(separator)
            continue
        if ch.isspace() and len(buf) > word_start:
            redirect_target = False
        buf.append(ch)
        if ch.isspace():
            word_start = len(buf)
        i += 1
    end_statement("")
    return statements


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


def _assigns(words):
    """Whether bash reads the word after `words` as an assignment: behind
    keywords and assignments only, or among a declaration's words. After any
    other command word an array literal is a syntax error, read as before."""
    words = [word for word in words if word not in KEYWORDS and not _ASSIGNMENT.match(word)]
    return not words or words[0] in _DECLARATIONS


def _stage(text, context):
    """Read lexical redirect operators in order, copying fd sinks by value,
    and an array literal as part of the word that assigns it (#2348). A word
    with a double-quoted `\\$` or `` \\` `` and no other `$` or backtick in it
    carries the text bash makes of it, `spelled`, which is the program a
    shell handed it runs (#2342); it reads as before."""
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
        plain = context.restore_arithmetic(raw.replace(MARK, "").replace(QUOTED, ""))
        raw, word = raw.replace(_ESCAPED, "\\"), context.token(plain.replace(_ESCAPED, "\\"))
        if is_pattern(raw):             # bash expands it first (#2294)
            word = _Expanded(word, _markers(word))
            setattr(word, "lead", leads(context.pattern.sub("${}", raw)))
        elif plain.count(_ESCAPED) == plain.count("$") + plain.count("`") > 0 and not _markers(word):
            word = _Token(word, {})
            setattr(word, "spelled", plain.replace(_ESCAPED, ""))
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
                    argv[literal - 1:] = [context.token(
                        "%s(%s)" % (argv[literal - 1], " ".join(argv[literal:])))]
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
            if op in ("<", "<<<"):
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
        argv = words        # it only assigns: an array of a command is read as run
    stdout, stdin = sinks.get("1"), bodies.get("0")
    return Stage(argv, writes, reads, stdin[0] if stdin and stdin[2] else heredoc,
                 substitutions, [stdout] if stdout is not None else [], group_open,
                 group_close, pipe_inputs["0"], pipe_outputs["1"],
                 tuple(fd for fd, connected in pipe_inputs.items() if connected),
                 stdin[:2] if stdin else None)


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
        if any(s.argv for s in stages):
            out.append(Statement(stages, separator))
    return out


def _command_result(argv):
    """Shared parse result for execution extraction and unread decisions: the
    command, why it or a wrapper in front of it cannot be read (or None), and
    the words read as wrappers, as written. A command word that is a shell's
    default (`${X:-sh}`, `_DEFAULTS`) is read as that shell."""
    argv = list(argv)
    heads: list[str] = []
    # `xargs` appends words from its input to the argv behind it, so the
    # innermost wrapper read after one (`behind`, with its argv) was read from
    # an argv that is not the one that runs (#2227).
    appended, behind = False, None
    while argv:
        if (_ENVIRONMENT if heads else _ASSIGNMENT).match(argv[0]):
            argv.pop(0)
            continue
        if argv[0] in KEYWORDS:
            keyword = argv.pop(0)
            if keyword == "function" and argv and _NAME.match(argv[0]):
                argv.pop(0)                     # `function f { ... }`
            continue
        # A function header is not a command: `f() { curl ... ; }` and its
        # `f () {` spelling both put a name where the command was expected,
        # which is where a long step keeps its download. A `case` arm pattern
        # (`a) curl ... ;;`) is the same class, and hid the fetch outright.
        if _FUNCTION.match(argv[0]) or is_arm(argv[0]):
            argv.pop(0)
            continue
        if len(argv) > 1 and argv[1] == "()" and _NAME.match(argv[0]):
            del argv[0:2]
            continue
        default = None if heads else _DEFAULTS.fullmatch(argv[0])
        if default and os.path.basename(default[1]) in _SHELLS:
            argv[0] = Defaulted(default[1])     # the NAME, marked as unwritten
        head = os.path.basename(argv[0])
        if heads and dynamic(argv[0], has_substitution):
            return argv, "has a dynamic command operand behind a wrapper", heads
        if isinstance(argv[0], Rewritten):
            return argv, "`%s` is a pattern bash expands before anything runs" % readable(
                argv[0]), heads
        if head not in WRAPPERS:
            break
        heads.append(argv[0])
        if len(heads) > 16:
            return argv, "has too many nested wrappers", heads
        inner, reason = unwrap(argv, head, has_substitution)
        if reason:
            return argv, "`%s` %s" % (head, reason), heads
        behind = (head, argv) if appended else None
        appended = appended or head == "xargs"
        argv = inner
    reason = None
    if behind and not argv:
        # It runs nothing as written, but the appended words may be its
        # command (`xargs ionice`, `xargs flock FILE`, `xargs env FOO=1`) or
        # the last word it reads a pid from (`xargs taskset -p ...`).
        head, argv = behind
        reason = "`%s` has no command as written, and xargs appends words to it" % head
    if reason is None and argv and os.path.basename(argv[0]) in _SHELLS:
        word = next((w for w in shell_words(argv) if getattr(w, "lead", False)), None)
        if word is not None:
            reason = "`%s` is a pattern bash expands where `%s` looks for `-c` or a script" % (
                readable(word), os.path.basename(argv[0]))
    return argv, reason, heads


def command(argv):
    """`argv` with supported wrappers stripped; unresolved forms stay lists."""
    return _command_result(argv)[0]


def unresolved_wrapper(argv):
    """Why a wrapper at this command's head -- or, with none, a pattern bash
    expands where the command starts (#2294) -- cannot be resolved, if any."""
    return _command_result(argv)[1]


def wrapper_words(argv):
    """The words read as wrappers in front of the command, as written.

    A wrapper is known by its basename, so `./flock` is read as `flock` and
    read through, though what runs is the file at ./flock (#2227).
    """
    return _command_result(argv)[2]


def negated(argv):
    """True if this command runs under a `!`.

    `if ! sha256sum -c sums; then ...; fi` takes the THEN branch when the
    command FAILED, which inverts what its exit status means to everything
    reading it. Same family as `command()`: what stands in front of the
    command, rather than the command itself.
    """
    for token in argv:
        if token == "!":
            return True
        if token in KEYWORDS or _ASSIGNMENT.match(token):
            continue
        return False
    return False


def conditional(argv):
    """True if this command is an `if`/`while` TEST rather than a step.

    `if sha256sum -c sums; then ...; fi` runs the check for its answer, not
    for its effect: errexit does not apply to a condition, so the script sails
    on past a mismatch exactly as `... || true` does.
    """
    for token in argv:
        if token in CONDITIONS:
            return True
        if token in KEYWORDS or _ASSIGNMENT.match(token):
            continue
        return False
    return False
