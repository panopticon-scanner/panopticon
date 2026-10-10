#!/usr/bin/env python3
"""The statement splitter: a lexed `run:` text cut into statements and pipeline stages.

Split out of `scripts/shell_reader.py` at that module's size (700 of its 700
lines; #3001), byte for byte: `_split`, which walks the text once, quote by
quote, and ends a stage at `|` and a statement at `;`, `&`, `&&`, `||` and a
newline; the readers it asks -- `_negated`, where a `!` in front of a group
belongs, and `_bare_blanks`, the unquoted `${...}` bash keeps as one word --
and the tables they read. `shell_reader` imports every name back under its
own, so nothing that read `shell_reader._split` or `shell_reader._BLANK`
moved; this module imports nothing from the reader, so the layers still run
one way.

Stdlib only, like everything under it.
"""
import re
import shlex

from shell_quote import ansi_c
from shell_command import CONDITIONS, KEYWORDS, fronts, _ASSIGNMENT, _NAME, _PARAMETER


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
    (`_ESCAPED`), as shlex, reading what is left, no longer knows the quote it was in."""
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
    cond, at_head, in_front = 0, True, True
    # `! { ... }`: bash negates the GROUP's status, and errexit is off for every command inside
    # a negated compound, so each statement the group holds is read under the `!` (#2664, the
    # fix round: the `{`-ends-its-statement step above stranded the `!` on `{` alone). One
    # entry per open `{` group, True where a `!` stood before it; `_negated` places the `!`.
    negations: list[bool] = []

    def end_stage():
        nonlocal header_words, header_live, word_start, redirect_target, at_head, in_front
        stages.append("".join(buf))
        del buf[:]
        header_words, header_live, word_start = 0, True, 0
        redirect_target, at_head, in_front = False, True, True

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
        # only there, behind those tests (round 9). Behind a function's header too (`in_front`,
        # #2954), a default or an alternate alone: a body's first word on its header's line.
        if text.startswith("${", i) and getattr(context, "blanks", True) and in_front and (
                len(buf) == word_start) and "".join(buf).split()[-1:] != ["case"] and (
                bare := (at_head or _PARAMETER.match(text, i)) and _bare_blanks(text, i)):
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
            in_front = in_front and fronts(closed, in_front, text, i)
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
