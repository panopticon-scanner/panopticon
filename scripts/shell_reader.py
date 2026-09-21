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

Stdlib only. `statements(script)` is the entry point; `command(argv)` strips
what stands in front of a command; `readable(text)` puts lifted substitutions
back for a human reading an error message.
"""
import collections
import os
import re
import shlex

# One shell command: its argv, the files it redirects into / reads from, the
# heredoc body attached to it, the command substitutions inside it -- the
# `$(...)`, `<(...)` and backtick texts, which are commands in their own right
# and where `eval "$(curl ...)"` hides its download -- and stdout_writes, the
# subset of `writes` a shell actually delivers to file descriptor 1. `writes`
# also carries an explicit OTHER fd (`2>err.log`) so the guard's file-tracking
# stays correct; `stdout_writes` is the one a caller may call THE destination
# (#1733). `&>word`/`&>>word` and the UNNUMBERED `>&word` land there too --
# bash's `>word 2>&1` shorthand, a real file whatever `word` looks like. A
# target beginning with `&` whose remainder IS a duplication or close (`&1`,
# `&-`) -- `2>&1`, `>&2`, `>&-` -- lands in neither list.
Stage = collections.namedtuple("Stage", "argv writes reads heredoc substitutions stdout_writes")
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages in order,
# and the separator that FOLLOWS it -- which is where a shell says whether the
# command's exit status is allowed to matter (`... || true`, `... &`).
Statement = collections.namedtuple("Statement", "stages separator")

# Leading words that are not the command: `sudo`, `env FOO=1`, `timeout 300`.
WRAPPERS = ("sudo", "command", "exec", "nohup", "nice", "stdbuf", "env",
            "time", "timeout", "xargs", "doas")
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

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\(\)$")
# A token ending in an unquoted `)` where a command was expected: a `case`
# arm pattern -- `a)`, `*)`, `(a)`, `"a b")` (quoted, so the word carries a
# space), and the tail of an `a|b)` alternation (the statement split cuts that
# on the `|`) -- or the one-word tail of a tight subshell, `( ... || true)`.
# Neither is a command name; the reader strips it and reads what follows. The
# subshell's HEAD, `(curl ...`, is the other side of that coin: one token, so
# the fetch it starts is unseen (a documented gap, see `workflow_guard`).
ARM = re.compile(r"^(?!\(\)$)\S(?:.*[^(])?\)$")
_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_REDIRECT = re.compile(r"^(\d*)(>>|>|<)(.*)$")
# `&>word`/`&>>word`: bash's combined-stream shorthand for `>word 2>&1` --
# always fd 1, and `_split` already keeps it glued to `word` (the `&`/`>`
# handling it shares with `2>&1`). It never takes a leading fd digit.
_AMP_REDIRECT = re.compile(r"^&(>>|>)(.*)$")
_HEREDOC_OP = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<word>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")
_HEREDOC_REF = re.compile(r"^@@heredoc(\d+)@@$")
SUBST_REF = re.compile(r"@@subst(\d+)@@")
_SUBST_OPEN = re.compile(r"\$\(|<\(|>\(")

# --- reading the shell -------------------------------------------------------

def without_comments(script):
    """The script with whole-line comments dropped.

    Half this repo's workflow prose QUOTES the command it is explaining, and a
    guard that reads its own documentation as an act flags the explanation.
    Shared with `tests/test_workflow_pins.py`'s install rule, which learned the
    same lesson (#1641).
    """
    return "\n".join(line for line in script.splitlines()
                     if not line.lstrip().startswith("#"))


def join_continuations(script):
    """`\\`-continuations folded in, so a fetch written across four lines reads
    as the one command it is."""
    return re.sub(r"\\\n\s*", " ", script)


def _lift_heredocs(text):
    """(text with each heredoc body replaced by a `@@heredocN@@` token, bodies).

    `sha256sum -c <<EOF ... EOF` is one of the two ways a step writes down what
    it expects, so the body has to reach the checker rather than being parsed
    as a dozen stray statements.
    """
    lines, bodies, out, i = text.splitlines(), [], [], 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_OP.search(line)
        if not m:
            out.append(line)
            i += 1
            continue
        word, body, j = m.group("word"), [], i + 1
        while j < len(lines) and lines[j].strip() != word:
            body.append(lines[j])
            j += 1
        if j >= len(lines):
            # No terminator: this `<<` is text inside a string, not a heredoc
            # (`echo "shift << 2"`). Swallowing the rest of the script as a
            # body would hide every statement after it.
            out.append(line)
            i += 1
            continue
        bodies.append(("\n".join(body), not m.group("q")))
        out.append("%s @@heredoc%d@@ %s"
                   % (line[:m.start()], len(bodies) - 1, line[m.end():]))
        i = j + 1
    return "\n".join(out), bodies


def _closing(text, opening):
    """Index just past the `)` that closes the group opening at `opening`."""
    depth, i, quote = 0, opening, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return None


def _lift_substitutions(text):
    """(text with each substitution replaced by a `@@substN@@` token, inners).

    `$(...)`, `<(...)` and backticks are commands, and a `|` or `;` inside one
    belongs to THAT command, not to the statement around it -- so they come out
    before the statement split, and go back in as commands of their own. This is
    where `eval "$(curl -fsSL ... )"` and `bash <(curl ...)` keep their fetch.
    """
    inners, out, i, quote = [], [], 0, None
    while i < len(text):
        ch = text[i]
        if quote == "'":                        # single quotes suppress all of it
            out.append(ch)
            quote = None if ch == "'" else quote
            i += 1
            continue
        if ch == "\\" and i + 1 < len(text):
            out.append(text[i:i + 2])
            i += 2
            continue
        if ch in "'\"":
            quote = None if quote == ch else ch
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            end = text.find("`", i + 1)
            if end != -1:
                inners.append(text[i + 1:end])
                out.append("@@subst%d@@" % (len(inners) - 1))
                i = end + 1
                continue
        opening = _SUBST_OPEN.match(text, i)
        if opening:
            end = _closing(text, opening.end() - 1)
            inner = text[opening.end():end - 1] if end else ""
            if end and not inner.startswith("("):   # `$((...))` is arithmetic
                inners.append(inner)
                out.append("@@subst%d@@" % (len(inners) - 1))
                i = end
                continue
        out.append(ch)
        i += 1
    return "".join(out), inners


def _split(text):
    """[[stage text, ...], ...]: statements, each a list of pipeline stages.

    Quote-aware by hand rather than by regex, because the whole defect being
    fixed is a regex that could not tell a `|` inside a URL from a pipeline.
    """
    statements, stages, buf = [], [], []
    quote, at_token_start, i, n = None, True, 0, len(text)

    def end_stage():
        stages.append("".join(buf))
        del buf[:]

    def end_statement(separator):
        end_stage()
        if any(s.strip() for s in stages):
            statements.append((list(stages), separator))
        del stages[:]

    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote, at_token_start = ch, False
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(text[i + 1])
            at_token_start, i = False, i + 2
            continue
        if ch == "#" and at_token_start:
            while i < n and text[i] != "\n":
                i += 1
            continue
        prev = "".join(buf[-1:]).strip()
        if ch in "&|" and (prev in (">", "&") or text[i:i + 2] == "&>"):
            buf.append(ch)                      # `2>&1`, `&>log`: a redirection
            at_token_start, i = False, i + 1
            continue
        if ch == "|" and text[i:i + 2] != "||":
            end_stage()
            at_token_start, i = True, i + 1
            continue
        if ch in ";\n&|":
            pair = text[i:i + 2]
            separator = pair if pair in ("&&", "||") else ch
            end_statement(separator)
            at_token_start = True
            i += len(separator)
            continue
        buf.append(ch)
        at_token_start = ch.isspace()
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
    return word == "-" or word.isdigit()


def _stage(text, bodies, inners):
    """One pipeline stage, with its redirections, heredoc and substitutions
    lifted out."""
    try:
        tokens = shlex.split(text)
    except ValueError:                          # an unbalanced quote
        tokens = text.split()
    argv, writes, reads, heredoc = [], [], [], None
    stdout_writes, substitutions, pending = [], [], None

    def take(token):
        # A redirection TARGET can be a command too (`bash < <(curl ...)`), so
        # the substitutions come off the token before it is filed away as a
        # path -- otherwise the whole command inside it is discarded unread.
        # An index past the end belongs to ANOTHER parse: a caller re-reading
        # a substitution's text hands over markers this parse never made, and
        # a guard that raises on them reports nothing at all.
        substitutions.extend(inners[int(n)] for n in SUBST_REF.findall(token)
                             if int(n) < len(inners))

    def write(fd, target):
        # `1>x` and a bare `>x` both mean fd 1 -- the shell's default target
        # for `>`/`>>` with no leading digit -- and only that one is where
        # `curl`/`wget`'s stream actually goes; `2>x` is a real write this
        # stage makes (kept in `writes` for the file-tracking that reads it),
        # but never the destination a fetch is reported against (#1733).
        writes.append(target)
        if fd in ("", "1"):
            stdout_writes.append(target)

    def combined_write(target):
        # `&>word`, `&>>word`, and the UNNUMBERED `>&word`: bash's shorthand
        # for `>word 2>&1` -- always fd 1, and always a real file, whatever
        # `word` looks like (round 1 of #1733's fix; see `_fd_or_close`).
        take(target)
        write("1", target)

    for token in tokens:
        if pending is not None:
            kind, fd, is_write = pending
            pending = None
            if kind == "amp":
                # `>& word` / `&> word`: the target landed in its own token
                # because whitespace separates it from the operator. Only the
                # unnumbered `>&`/`&>` (write side) carries a real file here:
                # a numbered `N>&` (`is_write` but `fd` set) is a bash
                # "ambiguous redirect" runtime error for a non-digit word,
                # and the read side (`<&`) has no file-fallback AT ALL, so
                # neither is modelled as a write.
                if not fd and _fd_or_close(token):
                    continue                     # `>& 2`, `>& -`
                if is_write and not fd:
                    combined_write(token)         # `>& word`, `&> word`
                continue
            take(token)
            if is_write:
                write(fd, token)
            else:
                reads.append(token)
            continue
        ref = _HEREDOC_REF.match(token)
        if ref and int(ref.group(1)) < len(bodies):
            heredoc, expands = bodies[int(ref.group(1))]
            if expands:
                # `<<EOF` expands, `<<'EOF'` does not: the body of an expanding
                # heredoc is shell, and the interpreter reading it runs what a
                # `$(...)` in there produced.
                substitutions.extend(_lift_substitutions(heredoc)[1])
            continue
        amp = _AMP_REDIRECT.match(token)
        if amp:
            target = amp.group(2)
            if target:
                combined_write(target)
            else:
                pending = ("amp", "", True)      # `&> word`: always unnumbered
            continue
        redirect = _REDIRECT.match(token)
        if redirect:
            fd, op, target = redirect.groups()
            is_write = op != "<"
            if target:
                if target.startswith("&"):
                    remainder = target[1:]
                    if is_write and not fd and remainder and (
                            not _fd_or_close(remainder)):
                        combined_write(remainder)  # unnumbered `>&word`
                    elif not remainder:
                        pending = ("amp", fd, is_write)  # bare `>&`/`<&`
                    # else `2>&1`, `>&2`, `>&-`: duplication/close -- nothing
                    continue
                take(target)
                if is_write:
                    write(fd, target)
                else:
                    reads.append(target)
            else:
                pending = ("write" if is_write else "read", fd, is_write)
            continue
        take(token)
        argv.append(token)
    return Stage(argv, writes, reads, heredoc, substitutions, stdout_writes)


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages."""
    text, bodies = _lift_heredocs(join_continuations(without_comments(script)))
    text, inners = _lift_substitutions(text)
    out = []
    for raw, separator in _split(text):
        stages = [_stage(s, bodies, inners) for s in raw]
        if any(s.argv for s in stages):
            out.append(Statement(stages, separator))
    return out


def command(argv):
    """`argv` with the wrappers stripped: `sudo mv x y` -> `mv x y`."""
    argv = list(argv)
    while argv:
        if _ASSIGNMENT.match(argv[0]) and not argv[0].startswith("-"):
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
        if _FUNCTION.match(argv[0]) or ARM.match(argv[0]):
            argv.pop(0)
            continue
        if len(argv) > 1 and argv[1] == "()" and _NAME.match(argv[0]):
            del argv[0:2]
            continue
        head = os.path.basename(argv[0])
        if head not in WRAPPERS:
            break
        argv.pop(0)
        while argv and argv[0].startswith("-"):
            argv.pop(0)
        if head == "timeout" and argv and _DURATION.match(argv[0]):
            argv.pop(0)
    return argv




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


def readable(text):
    """A lifted substitution back in a shape a human recognises, for an error
    message: `-o $(mktemp)` should not be reported as `-o @@subst0@@`."""
    return SUBST_REF.sub("$(...)", text) if text else text


def is_marker(token):
    """True for a token that is (or contains) something this parse lifted out.

    A `@@substN@@` or `@@heredocN@@` stands for text held in THIS parse's
    tables, so it means nothing to any other parse: a reader that re-reads a
    token as a script of its own has to ask this first.
    """
    return bool(SUBST_REF.search(token) or _HEREDOC_REF.match(token))
