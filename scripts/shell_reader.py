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
import secrets
import shlex
import signal

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
Stage = collections.namedtuple(
    "Stage", "argv writes reads heredoc substitutions stdout_writes "
             "group_open group_close stdin_from_pipe stdout_to_pipe pipe_input_fds",
    defaults=(0, 0, True, True, ("0",)))
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
_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_REDIRECT = re.compile(r"&>>|&>|>>|>\||>&|<&|>|<")
_STDOUT_ALIASES = ("/dev/stdout", "/dev/fd/1")
_HEREDOC_OP = re.compile(
    r"(?P<fd>(?<!\w)[0-9]+)?<<-?\s*(?P<q>['\"]?)(?P<word>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")


class _Token(str):
    """String-compatible shell word with capabilities from its own parse.

    String operations deliberately discard provenance. Consumers deriving a
    path must use `derived` to retain only the markers actually in that path.
    Re-parsing a word starts a fresh context, never reuses these capabilities.
    """
    def __new__(cls, text, markers):
        token = super().__new__(cls, text)
        token.markers = markers
        return token

    markers: dict[str, tuple[str, object]]


def _markers(text):
    return text.markers if isinstance(text, _Token) else {}


def derived(text, *sources):
    """Carry provenance through an explicit substring/path transformation."""
    markers = {key: value for source in sources
               for key, value in _markers(source).items() if key in text}
    return _Token(text, markers) if markers else text


class _Parse:
    def __init__(self, source):
        # No source spelling can collide, even if a nonce source is replaced
        # in a test. No global registry: tokens retain only their own entries.
        self.prefix = "@@shell-" + secrets.token_hex(16) + "-"
        while self.prefix in source:
            self.prefix += "x"
        self.entries: dict[str, tuple[str, object]] = {}
        self.pattern = re.compile(re.escape(self.prefix) + r"\d+@@")

    def new(self, kind, value=None):
        marker = self.prefix + str(len(self.entries)) + "@@"
        self.entries[marker] = (kind, value)
        return marker

    def token(self, text):
        markers = {m: self.entries[m] for m in self.pattern.findall(text)
                   if m in self.entries}
        return _Token(text, markers) if markers else text


def is_arm(token):
    return any(kind == "arm" and token.startswith(key)
               for key, (kind, _value) in _markers(token).items())


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


def _lift_heredocs(text, context):
    """Replace each heredoc with a token belonging to this parse context.

    `sha256sum -c <<EOF ... EOF` is one of the two ways a step writes down what
    it expects, so the body has to reach the checker rather than being parsed
    as a dozen stray statements.
    """
    lines, out, i = text.splitlines(), [], 0
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
        marker = context.new("heredoc", ("\n".join(body), not m.group("q"),
                                         m.group("fd") or "0"))
        out.append("%s %s %s" % (line[:m.start()], marker, line[m.end():]))
        i = j + 1
    return "\n".join(out)


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


def _lift_substitutions(text, context):
    """(text with parse-local substitution tokens, inner shell texts).

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
                out.append(context.new("subst", inners[-1]))
                i = end + 1
                continue
        opening = _SUBST_OPEN.match(text, i)
        if opening:
            end = _closing(text, opening.end() - 1)
            inner = text[opening.end():end - 1] if end else ""
            if end and not inner.startswith("("):   # `$((...))` is arithmetic
                inners.append(inner)
                out.append(context.new("subst", inners[-1]))
                i = end
                continue
        out.append(ch)
        i += 1
    return "".join(out), inners


def _split(text, context):
    """[[stage text, ...], ...]: statements, each a list of pipeline stages.

    Quote-aware by hand rather than by regex, because the whole defect being
    fixed is a regex that could not tell a `|` inside a URL from a pipeline.
    """
    statements = []
    stages = []
    buf: list[str] = []
    quote, at_token_start, i, n = None, True, 0, len(text)
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

    def end_stage():
        nonlocal header_words, header_live, word_start, redirect_target
        stages.append("".join(buf))
        del buf[:]
        header_words, header_live, word_start = 0, True, 0
        redirect_target = False

    def end_statement(separator):
        end_stage()
        if any(s.strip() for s in stages):
            statements.append((list(stages), separator))
            if cases and re.match(r"^\s*esac(?:\s|$)", stages[0]):
                cases.pop()
        del stages[:]

    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
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
        # A case header ends at its `in`, even when its first arm shares
        # the line. Quoted/escaped words remain intact until shlex reads them.
        # The count asks the BUFFER, not the source text, whether a word just
        # closed here: whitespace that only extends a run of whitespace ends
        # nothing, an escaped space ends nothing, and the character before a
        # statement's first space may be the `;` that ENDED the last one --
        # a source-text test miscounted that as a word and killed the probe
        # one word early, losing the second header of `case ... esac; case
        # ... in ...`. Whitespace inside a quote never reaches this branch.
        if ch.isspace() and header_live and buf and not buf[-1][-1].isspace():
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
                header_live = False         # this buffer is not a header
        if ch == "(" and not (cases and cases[-1] == "pattern"):
            # Preserve function headers: `f()` and `f ()` are not subshells.
            if text[i:i + 2] == "()" and _NAME.fullmatch("".join(buf).strip()):
                buf.append("()")
                at_token_start, i = False, i + 2
                continue
            buf.append(" " + groups[0] + " ")
            word_start, redirect_target = len(buf), False
            at_token_start, i = True, i + 1
            continue
        if ch == ")":
            if cases and cases[-1] == "pattern":
                buf[:] = [context.new("arm") + "".join(buf).lstrip() + ")"]
                cases[-1] = "body"
            else:
                buf.append(" " + groups[1] + " ")
                word_start, redirect_target = len(buf), False
            at_token_start, i = True, i + 1
            continue
        redirect = _REDIRECT.match(text, i)
        if redirect and not (cases and cases[-1] == "pattern"):
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
            at_token_start, i = True, redirect.end()
            continue
        if ch == "|" and text[i:i + 2] != "||":
            if cases and cases[-1] == "pattern":
                buf.append(ch)  # case alternatives are one pattern, not a pipeline
                at_token_start, i = False, i + 1
                continue
            combined = text[i:i + 2] == "|&"
            if combined:
                # Bash applies the implicit stderr copy AFTER explicit redirects.
                buf.append(" " + context.new("redirect", ("2", ">&")) + " 1 ")
            end_stage()
            at_token_start, i = True, i + (2 if combined else 1)
            continue
        if ch in ";\n&|":
            pair = text[i:i + 2]
            separator = pair if pair in ("&&", "||") else ch
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
            at_token_start = True
            i += len(arm_end) if arm_end else len(separator)
            continue
        if ch.isspace() and len(buf) > word_start:
            redirect_target = False
        buf.append(ch)
        at_token_start = ch.isspace()
        if at_token_start:
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


def _stage(text, context):
    """Read lexical redirect operators in order, copying fd sinks by value."""
    try:
        tokens = shlex.split(text)
    except ValueError:                          # an unbalanced quote
        tokens = text.split()
    argv, writes, reads = [], [], []
    group_open = group_close = 0
    substitutions: list[str] = []
    heredoc = None
    # Missing and closed fds have no known file sink. A dup copies the current
    # sink; later opens/closes of the original fd cannot change that snapshot.
    sinks: dict[str, str | None] = {}
    # fd 0 initially receives the preceding pipeline stage. Like output
    # sinks, input origins are copied in lexical redirect order.
    pipe_inputs = {"0": True}
    # fd 1 initially feeds the next pipeline stage. Opening its aliases copies
    # its CURRENT sink, so `>file >/dev/stdout` still writes to file.
    pipe_outputs = {"1": True}
    pending = None

    def take(word):
        substitutions.extend(value for kind, value in _markers(word).values()
                             if kind == "subst")

    for raw in tokens:
        word = context.token(raw)
        entry = _markers(word).get(word)
        if entry and entry[0] == "group":
            if entry[1] == "(":
                group_open += 1
            else:
                group_close += 1
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
                    continue
                if fd or op == "<&":
                    sinks[number] = None       # invalid/unresolved fd operand
                    pipe_inputs[number] = False
                    pipe_outputs[number] = False
                    continue
                op = "&>"                     # unnumbered >&file
            if op == "<":
                reads.append(word)
                sinks[number] = None           # an input file is not an output sink
                source = input_alias_fd(word)
                pipe_inputs[number] = source == "?" or pipe_inputs.get(source, False)
                pipe_outputs[number] = False
            else:
                writes.append(word)
                sinks[number] = sinks.get("1") if word in _STDOUT_ALIASES else word
                pipe_inputs[number] = False
                pipe_outputs[number] = (pipe_outputs.get("1", False)
                                        if word in _STDOUT_ALIASES else False)
                if op.startswith("&"):
                    sinks["2"] = sinks[number]
                    pipe_inputs["2"] = False
                    pipe_outputs["2"] = pipe_outputs[number]
            continue
        if entry and entry[0] == "heredoc":
            heredoc, expands, fd = entry[1]
            number = fd.lstrip("0") or "0"
            pipe_inputs[number] = False
            pipe_outputs[number] = False
            if expands:
                substitutions.extend(_lift_substitutions(heredoc, _Parse(heredoc))[1])
            continue
        take(word)
        argv.append(word)
    stdout = sinks.get("1")
    return Stage(argv, writes, reads, heredoc, substitutions,
                 [stdout] if stdout is not None else [], group_open, group_close,
                 pipe_inputs["0"], pipe_outputs["1"],
                 tuple(fd for fd, connected in pipe_inputs.items() if connected))


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages."""
    context = _Parse(script)
    text = _lift_heredocs(join_continuations(without_comments(script)), context)
    text, _inners = _lift_substitutions(text, context)
    out = []
    for raw, separator in _split(text, context):
        stages = [_stage(s, context) for s in raw]
        if any(s.argv for s in stages):
            out.append(Statement(stages, separator))
    return out


# Supported wrapper options: short flags, short operands, long flags, long operands.
# Unknown options retain the wrapper: never search arbitrary words for a command.
_WRAPPER_OPTIONS = {
    "sudo": ("AbEHiknPSs", "CDghpRTurt", "askpass background reset-timestamp preserve-env preserve-groups set-home non-interactive stdin shell login",
             "close-from chdir group host prompt chroot command-timeout user role type"),
    "timeout": ("v", "ks", "foreground preserve-status verbose", "kill-after signal"),
    "nice": ("", "n", "", "adjustment"),
    "env": ("iv", "uCPS", "ignore-environment debug default-signal ignore-signal block-signal",
            "unset chdir split-string"),
    "stdbuf": ("", "ioe", "", "input output error"),
    "xargs": ("0prtx", "EILPnds", "null no-run-if-empty interactive verbose exit",
              "eof replace max-lines max-procs max-args delimiter max-chars"),
    "exec": ("cl", "a", "", ""),
    "command": ("p", "", "", ""),
    "nohup": ("", "", "", ""),
    "time": ("pav", "fo", "portability append verbose", "format output"),
    "doas": ("ns", "u", "", ""),
}


def _env_split(value):
    """A bounded, static subset of GNU env's -S grammar (not shell syntax)."""
    if len(value) > 4096:
        return None
    words: list[str] = []
    word: list[str] = []
    quote, started, i = None, False, 0
    while i < len(value):
        ch = value[i]
        if ch in "'\"" and quote in (None, ch):
            quote = None if quote == ch else ch
            started = True
        elif ch.isspace() and quote is None:
            if started:
                words.append("".join(word))
                if len(words) > 128:
                    return None
                word, started = [], False
        elif ch == "#" and not started:
            break
        elif (ch == "\\" and (quote != "'" or
              (i + 1 < len(value) and value[i + 1] in "\\'"))):
            i += 1
            if i == len(value):
                return None
            escaped = value[i]
            if escaped == "c":
                if quote == '"':
                    return None
                break
            if escaped == "_":
                if quote != '"':
                    if started:
                        words.append("".join(word))
                        word, started = [], False
                    i += 1
                    continue
                escaped = " "
            elif escaped in "fnrtv":
                escaped = {"f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}[escaped]
            elif escaped not in "\"#$'\\":
                return None
            word.append(escaped)
            started = True
        elif ch == "$" and quote != "'":
            return None  # GNU expands ${NAME}; its value is not static here.
        else:
            word.append(ch)
            started = True
        i += 1
    if quote:
        return None
    if started:
        words.append("".join(word))
    return words if len(words) <= 128 else None


def _signal_list(value):
    """Accept only signal names/numbers the host's stdlib can identify."""
    known = {name.removeprefix("SIG") for name in signal.Signals.__members__}
    numbers = {member.value for member in signal.Signals}
    return bool(value) and all(
        part in known or (part.isascii() and part.isdecimal()
                          and len(part) <= 3 and int(part) in numbers)
        for part in value.split(","))


def _wrapped(argv, head):
    """(command suffix, unresolved reason), with no arbitrary operand search."""
    flags, values, long_flags, long_values = _WRAPPER_OPTIONS[head]
    i = 1
    splits = 0
    noexec = False
    while i < len(argv) and argv[i].startswith("-"):
        argument, i = argv[i], i + 1
        if has_substitution(argument) or "$" in argument:
            return None, "has a dynamic option"
        if argument == "--":
            break
        if head == "sudo" and argument in ("-K", "--remove-timestamp"):
            if len(argv) == 2:
                return [], None  # Timestamp removal has no command mode.
            return None, "combines timestamp removal with a command or option"
        if head == "sudo" and argument == "-h" and len(argv) == 2:
            return [], None  # Standalone -h requests help; -h HOST runs a command.
        if head == "sudo" and argument in ("-l", "--list", "-v", "--validate",
                                           "--help", "-V", "--version"):
            noexec = True  # Explicit sudo query/maintenance modes.
            continue
        if head == "command" and argument in ("-v", "-V"):
            noexec = True  # Shell command lookup, not execution.
            continue
        if head == "nice" and re.fullmatch(r"-\d+", argument):
            continue
        if argument.startswith("--"):
            name, sep, value = argument[2:].partition("=")
            if head == "env" and name in ("default-signal", "ignore-signal",
                                           "block-signal"):
                if sep and not _signal_list(value):
                    return None, "has an unsupported signal list"
                continue  # Optional argument only in the = form.
            if ((head == "sudo" and name == "preserve-env") or
                    (head == "xargs" and name in ("replace", "eof", "max-lines"))):
                continue  # Optional operands are accepted only after '='.
            if name in long_values.split():
                if head == "env" and name == "split-string":
                    if not sep:
                        return None, "needs --split-string=STRING"
                    split = _env_split(value)
                    if split is None or splits >= 4:
                        return None, "has an unsupported split-string"
                    argv = argv[:i] + split + argv[i:]
                    splits += 1
                    continue
                if i >= len(argv) and not sep:
                    return None, "is missing an option operand"
                if not sep and (has_substitution(argv[i]) or "$" in argv[i]):
                    return None, "has a dynamic option operand"
                i += not sep
            elif name not in long_flags.split() or sep:
                return None, "has an unknown option"
            continue
        if argument == "-":
            if head == "env":
                break  # env's legacy ignore-environment flag ends option parsing
            return None, "has an unknown option"
        for j, ch in enumerate(argument[1:], 2):
            if ch in values:
                if head == "env" and ch == "S":
                    value = argument[j:] if j < len(argument) else (argv[i] if i < len(argv) else None)
                    if value is None:
                        return None, "is missing a split-string operand"
                    if has_substitution(value):
                        return None, "has a dynamic split-string"
                    split = _env_split(value)
                    if split is None or splits >= 4:
                        return None, "has an unsupported split-string"
                    if j == len(argument):
                        i += 1
                    argv = argv[:i] + split + argv[i:]
                    splits += 1
                    break
                if j == len(argument) and i >= len(argv):
                    return None, "is missing an option operand"
                if j == len(argument) and (has_substitution(argv[i]) or "$" in argv[i]):
                    return None, "has a dynamic option operand"
                i += j == len(argument)
                break
            if ch not in flags:
                return None, "has an unknown option"
    if head == "timeout":
        if i >= len(argv) or not _DURATION.fullmatch(argv[i]):
            return None, "has no supported duration"
        i += 1
    if noexec:
        return [], None
    if not argv[i:]:
        if head == "env":
            return [], None  # env without a command prints its environment.
        return None, "is missing a command"
    return argv[i:], None


def _command_result(argv):
    """Shared parse result for execution extraction and unread decisions."""
    argv = list(argv)
    wrappers = 0
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
        if _FUNCTION.match(argv[0]) or is_arm(argv[0]):
            argv.pop(0)
            continue
        if len(argv) > 1 and argv[1] == "()" and _NAME.match(argv[0]):
            del argv[0:2]
            continue
        head = os.path.basename(argv[0])
        if head not in WRAPPERS:
            if wrappers and (has_substitution(argv[0]) or "$" in argv[0]):
                return argv, "has a dynamic command operand behind a wrapper"
            break
        wrappers += 1
        if wrappers > 16:
            return argv, "has too many nested wrappers"
        inner, reason = _wrapped(argv, head)
        if reason:
            return argv, "`%s` %s" % (head, reason)
        argv = inner
    return argv, None


def command(argv):
    """`argv` with supported wrappers stripped; unresolved forms stay lists."""
    return _command_result(argv)[0]


def unresolved_wrapper(argv):
    """Why a wrapper at this command's head cannot be resolved, if any."""
    return _command_result(argv)[1]




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
    """Render only this token's genuine lifted substitutions for diagnostics."""
    for key, (kind, _value) in _markers(text).items():
        if kind == "subst":
            text = text.replace(key, "$(...)")
    return text


def is_marker(token):
    """True only for actual lifted text, never a target-authored lookalike."""
    return bool(_markers(token))


def has_substitution(token):
    """Whether a word/path depends on a substitution generated by its parse."""
    return any(kind == "subst" for kind, _value in _markers(token).values())
