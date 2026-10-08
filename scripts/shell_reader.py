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
from shell_patterns import (MARK, QUOTED, QUOTED_DOLLAR, is_pattern, leads, patterned,
                            shell_words as shell_words)
from shell_quote import ansi_c
from shell_text import (_lift_substitutions, join_continuations as join_continuations,
                        without_comments as without_comments)
from shell_tokens import (_Expanded as _Expanded, _Parse as _Parse, _Token as _Token,
                          _markers as _markers, bang as bang, derived as derived,
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
                           _optional as _optional, command as command, reads_held, resolved, track,
                           credited_zero as credited_zero,
                           command_as_written as command_as_written, conditional as conditional,
                           negated as negated, unresolved_wrapper as unresolved_wrapper,
                           folds as folds, wrapper_words as wrapper_words)

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
# first's.
Stage = collections.namedtuple(
    "Stage", "argv writes reads heredoc substitutions stdout_writes "
             "group_open group_close stdin_from_pipe stdout_to_pipe pipe_input_fds "
             "stdin_heredoc",
    defaults=(0, 0, True, True, ("0",), None))
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages in order,
# and the separator that FOLLOWS it -- which is where a shell says whether the
# command's exit status is allowed to matter (`... || true`, `... &`).
Statement = collections.namedtuple("Statement", "stages separator")


# The builtins whose words bash reads as assignments too: `declare -a a=(1 2)`.
_DECLARATIONS = ("declare", "typeset", "local", "export", "readonly")
_REDIRECT = re.compile(r"<<<|<>|&>>|&>|>>|>\||>&|<&|>|<")
# The parentheses of a function header, as bash and dash read them: `()` or `( )`, and a
# group's `{` with a header after it on the same line (#2664).
_HEADER = re.compile(r"\([ \t]*\)")
_BRACED_HEADER = re.compile(r"\{[ \t]+(?:function[ \t]+)?[A-Za-z_][A-Za-z0-9_-]*[ \t]*\([ \t]*\)")
_NESTED_CASE = re.compile(r"\s*case(?:\s|$)")
# Put in place of the backslash of a `\$` or `` \` `` inside "..." (`_split`),
# which bash drops and shlex keeps (#2342): a private-use character, as `MARK`.
_ESCAPED = "\ue002"
# Put in place of each blank inside an unquoted `${...}` (`_split`), which bash keeps as one
# expansion before it splits the result, where shlex would split the braces apart (#2731).
_BLANK = "\ue004"
_STDOUT_ALIASES = ("/dev/stdout", "/dev/fd/1")
# The paths of N a carry reads as N, past slashes or a climb: `//dev/fd/N`, `../proc/thread-self/fd/N` (#2881)
_FD_SPELLINGS = re.compile(r"^(?:/+|(?:\.\./+)+)(?:dev|proc/(?:thread-)?self)/+fd/")


# --- reading the shell -------------------------------------------------------

def _negated(text, context):
    """Where in `text`, a stage inside a `! { ... }` group, the `!` that bash's errexit-off reading
    of a negated compound gives every command in it stands, or None: a mark on its first word that
    `negated` reads (`bang`), and a `!` word only where #2849 reads it from no group (`_split`) --
    the command word past the keywords and the `case` arm that open the statement (`then CHECK`,
    `x) CHECK`), not a statement that is keywords alone (`}`, `fi`), a `for`/`case`/`select`/
    `function` header whose next words are names, an `if`/`elif`/`while`/`until` whose condition
    errexit never applied to, or one already negated (#2664, the second fix round; round 13)."""
    for match in re.finditer(r"\S+", text):
        word = match.group()
        mark = context.pattern.match(word)
        if word in KEYWORDS or mark and context.entries[mark.group()][0] == "arm":
            if word in CONDITIONS or word in ("for", "case", "select", "function", "!"):
                return None
            continue
        return match.start()
    return None


def _bare_blanks(text, i):
    """The `${…}` at `i`, as `(end, marked)`: where it ends, and its text with each blank no quote
    or backslash covers marked `_BLANK`. None where it has no such blank -- a quoted or escaped
    blank is the word's own, as shlex keeps it -- or holds a newline or an operator no quote
    covers (`${V:-a | sh}`, `${V:-a; b}`), or nothing ends it: `main` ends a statement or a stage
    there, and only the command word reads a word whole, so every statement and stage is `main`'s
    (#2856 round 8). The scan stops at that newline or operator, so it reads no `${` past its own
    stage, and ends at the first `}` no quote covers: a default holding a nested `${…}` names no
    shell (`shell_command._WHOLE_DEFAULTS` takes no `$`), so where that one ends decides nothing
    (round 9)."""
    out, quote, at = ["${"], "", i + 2
    while at < len(text):
        ch = text[at]
        if ch == "\\" and quote != "'" and at + 1 < len(text):
            out.append(text[at:at + 2])
            at += 2
            continue
        if quote:
            quote = "" if ch == quote[-1] else quote
        elif text.startswith("$'", at):
            # `$'…'` as `_split` reads it: bash's text for it, single-quoted (#2344).
            end = at + 2
            while end < len(text) and text[end] != "'":
                end += 2 if text[end] == "\\" else 1
            body = ansi_c(text[at + 2:end]) if end < len(text) else None
            if body is not None:
                out.append("'%s'" % body.replace("'", "'\"'\"'"))
                at = end + 1
                continue
            out.append("$'")
            quote, at = "$'", at + 2
            continue
        elif ch in "'\"":
            quote = ch
        elif ch in "\n;|&<>()":
            return None
        elif ch == "}":
            out.append(ch)
            return (at + 1, "".join(out)) if _BLANK in out else None
        out.append(_BLANK if ch in " \t" and not quote else ch)     # what the shells split on
        at += 1
    return None


def _split(text, context):
    """[[stage text, ...], ...]: statements, each a list of pipeline stages.

    Quote-aware by hand rather than by regex, because the whole defect being fixed is a regex
    that could not tell a `|` inside a URL from a pipeline. A `$'...'` whose escapes
    `shell_quote.ansi_c` decodes becomes the '...' of the text bash makes of it, so `sh $'-c'`
    reads as `sh -c` (#2344); a double-quoted `\\$` or `` \\` `` is marked for `_stage`
    (`_ESCAPED`), as shlex, reading what is left, no longer knows the quote it was in.
    """
    statements: list[tuple[list[str], str]] = []
    stages = []
    buf: list[str] = []
    quote, i, n, opened = None, 0, len(text), 0
    cases: list[str] = []
    groups = (context.new("group", "("), context.new("group", ")"))
    word_start, redirect_target = 0, False
    # A `case` header is exactly three words (`case`, the word, `in`), so the shlex probe below
    # only has to run while the buffer can still BE one -- `header_words` counts the words the
    # buffer has closed, `header_live` goes false as soon as the first word is not `case` or a
    # third word has gone by without a header, and both reset when the buffer does. Probing
    # unconditionally re-split the WHOLE buffer on every whitespace character, which made
    # `_split` quadratic: 42 KB of one statement took ~93 s against 0.02 s before the probe
    # existed, from a `run:` block this module reads out of the TARGET repository (fix round on
    # #1714, Critical 1).
    header_words, header_live = 0, True
    # `[[ ... ]]` is ONE compound command: the `&&`, `||`, `(`, `)`, `<` and `>` in it are the
    # conditional's operators, not list separators, subshells or redirections (#2441) -- split
    # at them, `CHECK && [[ -f a || -f b ]] || exit 1` lost the `|| exit 1` that ends the real
    # list. `cond` is 0 outside one and, inside, 1 plus the `(` it holds open, so a `)` it did
    # not open ends it where `shell_lex` does: a `case` arm's `[[)` is a pattern. `at_head` says
    # every word this stage closed is a keyword or an assignment -- where bash reads `[[` as the
    # conditional, not as `echo [[ a`'s word. The test ends with the STATEMENT, not with a
    # stage: bash makes one word of `^(x|y)$`, and ending it at that `|` left the `)` closing a
    # group nothing had opened -- the unbalanced count #2334 reads as a lost list.
    cond, at_head = 0, True
    # `! { ... }`: bash negates the GROUP's status, and errexit is off for every command inside
    # a negated compound, so each statement the group holds is read under the `!` (#2664, the
    # fix round: the `{`-ends-its-statement step above stranded the `!` on `{` alone). One
    # entry per open `{` group, True where a `!` stood before it; `_negated` places the `!`.
    negations: list[bool] = []

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
        if any(negations) and (at := _negated(stages[0], context)) is not None:
            context.bangs.add(len(statements))
            if not negations[-1]:   # a plain `{` in the negated one: #2849 reads a check's own group
                stages[0] = stages[0][:at] + "! " + stages[0][at:]
        if any(s.strip() for s in stages):
            statements.append((list(stages), separator))
        bang = False
        for word in (" ".join(stages).split() if any("{" in s or "}" in s for s in stages) else ()):
            if word == "{":
                negations.append(bang)
                bang = False
            elif word == "}" and negations:
                negations.pop()
            elif word == "!":
                bang = True
        del stages[:]

    def close_case():
        """Close a literal `esac` before an operator following it (#2610)."""
        if cases and re.fullmatch(r"\s*esac\s*", "".join(buf)):
            cases.pop()

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
        if text.startswith("$$", i):
            # Bash's PID, read as the pair before anything the second `$` could open: `$${`
            # is the PID and a brace, `$$'x'` the PID and a quote (#2756 fix round, B1).
            buf.append("$$")
            i += 2
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
        # Only a command word is read whole (#2856 round 8): a `${…}` that starts a word where
        # every word the stage closed is a keyword or an assignment (`at_head`), and no `case`
        # subject -- anywhere else shlex splits it `main`'s way, as it always did. The scan runs
        # only there, behind those tests (round 9).
        if text.startswith("${", i) and getattr(context, "blanks", True) and at_head and (
                len(buf) == word_start) and "".join(buf).split()[-1:] != ["case"] and (
                bare := _bare_blanks(text, i)):
            # An unquoted `${X:-bash -s}` is one word to the reader as to bash, which
            # expands it whole and only then splits the words (#2731): its bare blanks are
            # marked past shlex, and `_command_result` splits a shell default as bash does.
            i = bare[0]
            buf.extend(bare[1])
            continue
        # A case header ends at its `in`, even when its first arm shares the line.
        # Quoted/escaped words remain intact until shlex reads them. The count asks the BUFFER,
        # not the source text, whether a word just closed here: whitespace that only extends a
        # run of whitespace ends nothing, an escaped space ends nothing, and the character
        # before a statement's first space may be the `;` that ENDED the last one -- a
        # source-text test miscounted that as a word and killed the probe one word early, losing
        # the second header of `case ... esac; case ... in ...`. Whitespace inside a quote never
        # reaches this branch.
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
            # Preserve function headers: `f()`, `f ()` and `f ( )` are not subshells, nor
            # after a keyword or an opened `{` (`then f() {`, `{ f() {`), and a `{` glued to
            # one (`f(){`) is the body's own word, so the body's first command on the
            # header's line is read as a command and not as the header's argument (#2664).
            header = _HEADER.match(text, i)
            words = "".join(buf).split() if header else []
            if header and words and _NAME.fullmatch(words[-1]) and all(
                    w in KEYWORDS for w in words[:-1]):
                if words[-2:-1] != ["function"]:
                    buf.append("()")        # after `function NAME` bash takes them as nothing
                i = header.end()
                if i < n and not text[i].isspace():
                    text, n = text[:i] + " " + text[i:], n + 1
                continue
            buf.append(" " + groups[0] + " ")
            word_start, redirect_target = len(buf), False
            i += 1
            continue
        if ch == ")":
            cond = max(cond - 1, 0)         # one it did not open ends it
            # `esac )` ends the case and its enclosing subshell. A pattern
            # spelled `esac)` has no separating whitespace and remains an arm.
            case_end = re.fullmatch(r"\s*esac\s+", "".join(buf))
            if cases and cases[-1] == "pattern" and not case_end:
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
        if redirect or ch in ";\n&|":
            close_case()
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
            if ch == "\n" and stages and not "".join(buf).strip():
                # A line ending in `|` or `|&` continues on the next, as every shell reads
                # it (#2756): the stage it opened goes on past the newline (`&&` and `||`
                # end their statement at the operator, so the next line is read already).
                i += 1
                continue
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
            # Every terminator that ENDS a case arm, not just `;;`: bash also spells it `;&`
            # (fall through into the next arm's body) and `;;&` (resume matching at the next
            # pattern). Reading only `;;` left the state at "body", so the next arm's `b)` was
            # read as a group CLOSE and `b` became argv[0] -- shadowing the command behind it,
            # which is how a `curl` in the second arm went unseen entirely (fix round on #1714,
            # Critical 2). After any of the three the next word is a pattern again.
            arm_end = next((t for t in (";;&", ";;", ";&")
                            if text.startswith(t, i)), None)
            if arm_end and cases:
                cases[-1] = "pattern"
            i += len(arm_end) if arm_end else len(separator)
            continue
        if ch == "{" and at_head and _BRACED_HEADER.match(text, i):
            # `{ f() {`: the group's `{` is a statement of its own, as it is on a line of
            # its own, so the first brace after the name is the body's (#2664).
            buf.append(ch)
            end_statement(";")
            i += 1
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
    plain = context.restore_arithmetic(raw.replace(MARK, "").replace(QUOTED, "").replace(QUOTED_DOLLAR, ""))
    word = context.token(plain.replace(_ESCAPED, "\\"))
    word = word if isinstance(word, _Token) else _Token(word, _markers(word))
    word.span = span
    return word


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
    opened: dict[str, tuple[str, ...]] = {}  # the files `N<>` opened on N but 0, on each N they stand on
    # Where in `reads` each `0<>` put its file, and the one fd 0 still holds (`credited_zero`).
    zero: list[int] = []
    held: int | None = None
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

    # A word `_split` kept whole is read as `main` reads it, in the pieces its bare blanks split,
    # each read as any word is; the first carries the whole word and how many pieces it spans,
    # which only the command word reads (`shell_command._command_result`, #2731).
    pieces: list[tuple[str, str | None, int]] = []
    for raw in tokens:
        parts = ([part for part in raw.split(_BLANK) if part] or [raw]) if (
            _BLANK in raw and getattr(context, "blanks", True)) else [raw]
        whole = raw.replace(_BLANK, " ") if len(parts) > 1 else None
        pieces.extend((part, None if at else whole, len(parts)) for at, part in enumerate(parts))
    for raw, whole, span in pieces:
        plain = context.restore_arithmetic(
            raw.replace(MARK, "").replace(QUOTED, "").replace(QUOTED_DOLLAR, ""))
        raw, word = raw.replace(_ESCAPED, "\\"), context.token(plain.replace(_ESCAPED, "\\"))
        if is_pattern(raw):             # bash expands it first (#2294)
            word = _Expanded(word, _markers(word))
            setattr(word, "lead", leads(context.pattern.sub("${}", raw).replace(QUOTED_DOLLAR, "")))
        elif _ESCAPED in plain:
            word = word if _markers(word) else _Token(word, {})
            setattr(word, "spelled", context.token(plain.replace(_ESCAPED, "")))
        elif raw.count(QUOTED_DOLLAR) == plain.count("$") > 0 and not _markers(word):
            word = kept(word)               # every `$` of it quoted: bash keeps the word (#2472)
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
            held = None if number == "0" else held      # a later redirection of fd 0 ends it
            # A dup, a move or a path of N (`_FD_SPELLINGS`, `input_alias_fd`, `resolved`) carries what N holds onto
            # its target, fd 0 too, until that is redirected again (`4<&3 <&4`, `</dev/fd/3 3<&-`, #2881);
            # a source a value decides (`<&$FD`, `<"$P"`) carries every file held, fail-closed (round 4)
            moved = re.fullmatch(r"(\d+)-", word) if op in (">&", "<&") else None
            source = (moved[1] if moved else word) if moved or op in (">&", "<&") and _fd_or_close(word) else (
                op != "<<<" and input_alias_fd(derived(_FD_SPELLINGS.sub("/dev/fd/", resolved(word, context)), word)))
            carried = tuple(dict.fromkeys(sum(opened.values(), ()))) if source == "?" else opened.get(
                (source or "-").lstrip("0") or "0", ())
            opened.pop(number, None)            # any redirection of N ends what `N<>` opened there
            if moved:
                opened.pop(moved[1].lstrip("0") or "0", None)
            if carried:
                opened[number] = carried
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
                source = input_alias_fd(resolved(word, context))
                pipe_inputs[number] = source == "?" or pipe_inputs.get(source, False)
                pipe_outputs[number] = False
                reads_body(number, (word, not spelled, False) if op == "<<<" else
                           bodies.get(source) if source and source != "?" else None)
            else:
                if op == "<>":                 # open for reading too: what reads N reads it (#2881)
                    opened[number] = (*carried, word)
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
            held = None if number == "0" else held
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
                 stdin[:2] if stdin else None))


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages; in a
    lifted substitution's text, each heredoc where its marker stands (#2336)."""
    context = _Parse(script)
    # A step that spells a mark the reader puts in its text reads as `main` (#2856 round 8).
    context.blanks = not any(mark in script for mark in (MARK, QUOTED, _ESCAPED, QUOTED_DOLLAR, _BLANK))
    text = lex(script, lambda *heredoc: context.new("heredoc", heredoc))
    for marker, (kind, value) in getattr(script, "heredocs", {}).items():
        text = text.replace(marker, context.new(kind, value))
    text, _inners = _lift_substitutions(text, context)
    out = []
    for at, (raw, separator) in enumerate(_split(text, context)):
        stages = [_stage(s, context) for s in raw]
        if at in context.bangs:         # a negated group's `!`, marked on its first word
            stages[0].argv[0] = bang(stages[0].argv[0])
        # A line-only boundary has no argv; keep its marker and the closer's separator.
        if any(s.argv or s.group_open or s.group_close for s in stages):
            out.append(Statement(stages, separator))
    return out
