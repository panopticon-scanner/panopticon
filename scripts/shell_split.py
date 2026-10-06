#!/usr/bin/env python3
"""The one quote-aware pass that cuts lexed shell text into statements and pipeline stages.

Split out of `scripts/shell_reader.py` at that module's size (662 of its 700
lines, and the reader's own fixes still to come), byte for byte: `_split`,
which reads the text by hand -- quotes, `$'...'`, `${...}` with blanks,
subshells, function headers, `case` arms, `[[ ... ]]`, redirections, `|`,
`|&` and the list separators -- and the private-use marks it leaves in a
stage's text for `_stage` to read what stood quoted, escaped or inside one
`${...}` (`_ESCAPED`, `_BLANK`, `_QUOTED_AT`, `_QUOTE_END`, `_ESCAPE_AT`),
with the header and redirection spellings it matches. The reader imports
every name back under its own, so nothing that read `shell_reader._split` or
`shell_reader._MARKS` moved; this module imports nothing from the reader, so
the layers still run one way.

Stdlib only, like everything under it.
"""
import re
import shlex

from shell_command import KEYWORDS, _ASSIGNMENT, _NAME
from shell_patterns import _expansion_end
from shell_quote import ansi_c


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
# Put where a quote opens or a backslash escapes, outside quotes (`_split`): a word is an
# assignment only where nothing before its operator was quoted so (`_stage`'s `quoted`, #2480).
_QUOTED_AT = "\ue005"
# Put where that quote CLOSES, and where a backslash escapes one character outside quotes, so
# `_stage` can say which of a word's characters stood quoted (`quoted_spans`, the quoting half
# of #2593, #2747 and #2769): bash splits, globs or drops only what stood bare.
_QUOTE_END = "\ue006"
_ESCAPE_AT = "\ue007"
_MARKS = (_QUOTED_AT, _QUOTE_END, _ESCAPE_AT)


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
                buf.append(_QUOTE_END)
                quote = None
            i += 1
            continue
        if ch in "'\"" or text.startswith("$'", i):
            buf.append(_QUOTED_AT)
            quote, opened = text[i:i + 2] if ch == "$" else ch, len(buf)
            buf.append(quote)
            i += len(quote)
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(_ESCAPE_AT)
            buf.append(ch)
            buf.append(text[i + 1])
            i += 2
            continue
        if text.startswith("${", i):
            end = _expansion_end(text, i + 2)
            if end and any(c.isspace() for c in text[i:end]):
                # An unquoted `${X:-bash -s}` is one word to the reader as to bash, which
                # expands it whole and only then splits the words (#2731): its blanks are
                # marked past shlex, and `_command_result` splits a shell default as bash does.
                buf.extend(_BLANK if c.isspace() else c for c in text[i:end])
                i = end
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
            # Preserve function headers: `f()`, `f ()` and `f ( )` are not subshells, nor
            # after a keyword or an opened `{` (`then f() {`, `{ f() {`), and a `{` glued to
            # one (`f(){`) is the body's own word, so the body's first command on the
            # header's line is read as a command and not as the header's argument (#2664).
            header = _HEADER.match(text, i)
            words = "".join(buf).split()
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
