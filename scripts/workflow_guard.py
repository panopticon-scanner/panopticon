#!/usr/bin/env python3
"""#1647 (ARC-F2C): what a workflow `run:` step FETCHES, and whether what it
then runs was checked against a digest bound to the file it downloaded.

The rule is #1529's: a workflow can step outside the supply chain that
SHA-pinned `uses:` references govern simply by curling a binary and running
it, so nothing unverified may become executable. The Dockerfile was hardened
for exactly this act (ten artifact fetches, every one `sha256sum -c`'d) and
`tests/test_dockerfile.py` guards it; the same act spelled in shell inside a
`run:` block was guarded by two regexes, and run-13 found both failing OPEN:

* the fetch pattern required a whitespace-separated short `-o`/`-O` and
  excluded pipe characters, so `curl -fsSL https://... | sh`,
  `wget -qO- ... | bash` and every `--output` form yielded an EMPTY fetch set
  -- not "unverified", not seen as a download at all; and
* "verified" was the first `sha256sum`/`shasum` carrying `-c` anywhere earlier
  in the step, bound to no path and no digest, so an unrelated checksum of one
  artifact cleared a later `curl -o payload; chmod +x payload`.

A regex over shell text reports a clean pass on every form it cannot parse,
which is the worst answer a control can give -- so this module parses the
shell instead, as much of it as the question needs: comments dropped,
`\\`-continuations, heredocs and `$(...)`/`<(...)`/backtick substitutions
lifted out, statements split quote-aware on `;`, `&&`, `||`, `|` and newlines,
argv from `shlex`. Then two questions of the result: which statements FETCH,
and which statements CHECK what a fetch wrote -- naming that path, carrying a
digest, before the statement that first uses it.

Stdlib only, so the test suite imports it with no dependency (`import
workflow_guard` -- repo-root `scripts/` is on the path via tests/conftest.py).
`main()` reads YAML and is the same rule for a human at a shell:

    python3 scripts/workflow_guard.py .github/workflows/*.yml

CI gets NO separate lint step for it: `tests/test_workflow_pins.py` applies
this module to every `run:` step in the fleet and `ci.yml` runs the suite on
every PR, so a second invocation would be the same assertion wearing a
different hat -- and one that can rot out of step with the first.

What it does not model, and how each gap falls: variable expansion
(`${VERSION}`, `$TMP` stay literal -- the guard tracks the NAME a step writes,
so a checksum naming the same variable binds, and a path that is spelled
differently each time never matches anything, including its own use), globs in
a `chmod`, and fetchers other than curl/wget (`gh release download`,
`aws s3 cp`). The standing requirement on every one of them is to fail CLOSED:
an unparsed form must be REPORTED, never silently accepted, which is precisely
what the two regexes did not do. `tests/test_workflow_guard.py` states each
form that was probed and found open before it was parsed.
"""
import collections
import os
import re
import shlex
import sys

# A download: the tool that ran, the URL it was given, the file it lands in
# (None = standard output, which is the pipe-to-shell shape), and the argv of
# the next pipeline stage (None when the fetch ends the pipeline).
Fetch = collections.namedtuple("Fetch", "tool url dest piped_to")

# One shell command: its argv, the files it redirects into / reads from, the
# heredoc body attached to it, and the command substitutions inside it -- the
# `$(...)`, `<(...)` and backtick texts, which are commands in their own right
# and where `eval "$(curl ...)"` hides its download.
Stage = collections.namedtuple("Stage", "argv writes reads heredoc substitutions")
# One `;`/`&&`/`||`/newline-separated statement: its pipeline stages, in order.
Statement = collections.namedtuple("Statement", "stages")

FETCHERS = ("curl", "wget")
CHECKSUM_TOOLS = ("sha256sum", "sha512sum", "sha384sum", "shasum")
INTERPRETERS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3",
                "perl", "ruby", "node", "php", "pwsh", "eval", "source", ".")
# Unpacking a downloaded archive is executing it too: the bytes decide what
# lands on disk and under what name. `install` places a file into a directory
# with a mode; `tar`/`unzip` write whatever the archive says.
UNPACKERS = ("tar", "unzip", "install", "gunzip", "bsdtar")
EXECUTORS = INTERPRETERS + UNPACKERS
# `mv`/`cp` of a fetched file into one of these is what makes it runnable by
# name for the rest of the job.
BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin",
            "/opt/bin", "/bin", "/sbin")
# Leading words that are not the command: `sudo`, `env FOO=1`, `timeout 300`.
WRAPPERS = ("sudo", "command", "exec", "nohup", "nice", "stdbuf", "env",
            "time", "timeout", "xargs", "doas")
# Shell keywords that stand in FRONT of the command: `if curl ...; then`,
# `while true; do /tmp/payload; done`. Statements are split on `;`, so each of
# these arrives as the first word of the statement it introduces -- and a guard
# that reads `if` as the command sees neither the fetch nor the use.
KEYWORDS = ("if", "then", "elif", "else", "fi", "do", "done", "while", "until",
            "for", "case", "esac", "in", "!", "{", "}")

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_REDIRECT = re.compile(r"^(\d*)(>>|>|<)(.*)$")
_HEREDOC_OP = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<word>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")
_HEREDOC_REF = re.compile(r"^@@heredoc(\d+)@@$")
_SUBST_REF = re.compile(r"@@subst(\d+)@@")
_SUBST_OPEN = re.compile(r"\$\(|<\(|>\(")
# An expected digest: a literal, or the variable a workflow pins one in
# (`${HADOLINT_SHA256}`, `$SHA`). Naming a file is not checking it -- something
# in the checked line has to BE the expectation.
_DIGEST = re.compile(r"\b[0-9a-f]{40,128}\b|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

# curl and wget spell the same options differently, and the difference is
# load-bearing: curl's `-o` is the output file, wget's `-o` is the LOG file and
# its `-O` is the output document. One shared table writes a log path into the
# guard's dest field and then verifies the wrong thing.
# Short options that consume the next word, so it is not mistaken for the URL:
# curl's -A/-b/-c/-C/-d/-D/-e/-E/-F/-H/-K/-m/-o/-P/-Q/-r/-t/-T/-u/-U/-w/-x/-X/
# -y/-Y/-z, wget's -a/-o/-O/-i/-B/-t/-T/-w/-Q/-P/-D/-A/-R/-I/-X/-U/-e/-l.
_VALUE_SHORT = {"curl": set("AbcCdDeEFHKmoPQrtTuUwxXyYz"),
                "wget": set("aoOiBtTwQPDARIXUel")}
_VALUE_LONG = {
    "curl": {"output", "url", "connect-timeout", "max-time", "retry",
             "retry-delay", "retry-max-time", "header", "data", "data-raw",
             "data-binary", "data-urlencode", "user", "user-agent", "proxy",
             "proxy-user", "cacert", "capath", "cert", "key", "cookie",
             "cookie-jar", "referer", "request", "range", "write-out",
             "max-filesize", "limit-rate", "resolve", "form", "form-string",
             "oauth2-bearer", "unix-socket", "interface", "dump-header",
             "upload-file", "continue-at", "config", "location-trusted"},
    "wget": {"output-document", "output-file", "append-output",
             "directory-prefix", "timeout", "connect-timeout", "read-timeout",
             "dns-timeout", "tries", "waitretry", "wait", "user", "password",
             "user-agent", "header", "quota", "input-file", "base", "referer",
             "post-data", "post-file", "ca-certificate", "certificate",
             "private-key", "limit-rate", "bind-address"},
}
_DEST_SHORT = {"curl": "o", "wget": "O"}
_DEST_LONG = {"curl": ("output",), "wget": ("output-document",)}
# The directory the file lands in when it is not part of the destination:
# curl's `--output-dir` applies to `-o` and `-O` alike; wget's `-P` applies to
# the default name only (`-O` wins outright).
_DIR_LONG = {"curl": ("output-dir",), "wget": ("directory-prefix",)}
_DIR_SHORT = {"curl": "", "wget": "P"}
_STDOUT = ("-", "/dev/stdout", "/dev/fd/1", "/dev/null")
_UNSET = object()


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
        bodies.append("\n".join(body))
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

    def end_statement():
        end_stage()
        if any(s.strip() for s in stages):
            statements.append(list(stages))
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
            end_statement()
            at_token_start = True
            i += 2 if text[i:i + 2] in ("&&", "||") else 1
            continue
        buf.append(ch)
        at_token_start = ch.isspace()
        i += 1
    end_statement()
    return statements


def _stage(text, bodies, inners):
    """One pipeline stage, with its redirections, heredoc and substitutions
    lifted out."""
    try:
        tokens = shlex.split(text)
    except ValueError:                          # an unbalanced quote
        tokens = text.split()
    argv, writes, reads, heredoc, pending = [], [], [], None, None
    substitutions = []
    for token in tokens:
        if pending is not None:
            (writes if pending else reads).append(token)
            pending = None
            continue
        ref = _HEREDOC_REF.match(token)
        if ref:
            heredoc = bodies[int(ref.group(1))]
            continue
        redirect = _REDIRECT.match(token)
        if redirect:
            target, is_write = redirect.group(3), redirect.group(2) != "<"
            if target:
                (writes if is_write else reads).append(target)
            else:
                pending = is_write
            continue
        substitutions.extend(inners[int(n)] for n in _SUBST_REF.findall(token))
        argv.append(token)
    return Stage(argv, writes, reads, heredoc, substitutions)


def statements(script):
    """Every statement in a `run:` script, in order, as parsed stages."""
    text, bodies = _lift_heredocs(join_continuations(without_comments(script)))
    text, inners = _lift_substitutions(text)
    out = []
    for raw in _split(text):
        stages = [_stage(s, bodies, inners) for s in raw]
        if any(s.argv for s in stages):
            out.append(Statement(stages))
    return out


def command(argv):
    """`argv` with the wrappers stripped: `sudo mv x y` -> `mv x y`."""
    argv = list(argv)
    while argv:
        if _ASSIGNMENT.match(argv[0]) and not argv[0].startswith("-"):
            argv.pop(0)
            continue
        if argv[0] in KEYWORDS:
            argv.pop(0)
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


# --- which statements fetch --------------------------------------------------

def _basename(url):
    if not url:
        return None
    name = os.path.basename(url.split("?", 1)[0].split("#", 1)[0].rstrip("/"))
    return name or None


def _pick_url(operands):
    """The operand that is the URL. A scheme wins outright; a variable is the
    next best answer (`curl -o x "$URL"`); otherwise the first operand, which
    is where both tools take it."""
    for operand in operands:
        if "://" in operand:
            return operand
    for operand in operands:
        if operand.startswith("$"):
            return operand
    return operands[0] if operands else None


def _parse_fetch(tool, args, stage, piped_to):
    """One `curl`/`wget` argv -> the Fetch it performs."""
    value_short, value_long = _VALUE_SHORT[tool], _VALUE_LONG[tool]
    dest_short, dest_long = _DEST_SHORT[tool], _DEST_LONG[tool]
    dir_short, dir_long = _DIR_SHORT[tool], _DIR_LONG[tool]
    dest, remote_name, operands, i = _UNSET, False, [], 0
    directory = None
    while i < len(args):
        token, i = args[i], i + 1
        if token == "--":
            operands.extend(args[i:])
            break
        if token.startswith("--"):
            name, sep, inline = token[2:].partition("=")
            if name in dest_long:
                dest = inline if sep else (args[i] if i < len(args) else None)
                i += 0 if sep else 1
            elif name in dir_long:
                directory = inline if sep else (args[i] if i < len(args) else None)
                i += 0 if sep else 1
            elif name in value_long and not sep:
                i += 1
            continue
        if token.startswith("-") and len(token) > 1:
            j = 1
            while j < len(token):
                ch, j = token[j], j + 1
                if ch == dest_short:
                    dest = token[j:] if token[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if token[j:] else 1
                    break
                if tool == "curl" and ch == "O":
                    remote_name = True
                    continue
                if dir_short and ch == dir_short:
                    directory = token[j:] if token[j:] else (
                        args[i] if i < len(args) else None)
                    i += 0 if token[j:] else 1
                    break
                if ch in value_short:
                    if not token[j:]:
                        i += 1
                    break
            continue
        operands.append(token)
    url = _pick_url(operands)
    named = dest is not _UNSET
    if not named:
        # wget writes the URL's basename by default; curl streams to stdout
        # unless asked for the remote name.
        dest = _basename(url) if (tool == "wget" or remote_name) else None
    if directory and dest and not os.path.isabs(dest) and (
            tool == "curl" or not named):
        dest = os.path.join(directory, dest)
    if stage.writes:
        dest = stage.writes[-1]                 # `curl ... > /tmp/x`
    if dest is None and piped_to and os.path.basename(piped_to[0]) == "tee":
        # `curl ... | sudo tee /usr/local/bin/tool`: the pipeline IS the
        # download's destination, and what tee wrote is what runs next.
        written = [t for t in piped_to[1:] if not t.startswith("-")]
        dest = written[0] if written else None
    if dest in _STDOUT:
        dest = None
    return Fetch(tool, url, dest, piped_to)


def _fetch_records(stmts):
    """[(statement index, Fetch)] for every download in the script."""
    found = []
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if argv and os.path.basename(argv[0]) in FETCHERS:
                following = statement.stages[position + 1:]
                piped_to = tuple(command(following[0].argv)) if following else None
                found.append((index, _parse_fetch(os.path.basename(argv[0]),
                                                  argv[1:], stage, piped_to)))
            found.extend((index, f) for f in _substituted(argv, stage))
    return found


def _substituted(argv, stage):
    """Every fetch inside this stage's command substitutions, credited to the
    command that CONSUMES it -- `eval`, `sh -c`, `bash <(...)` -- because that
    is what decides whether the downloaded bytes become behaviour."""
    consumer = tuple(t for t in argv if not _SUBST_REF.search(t)) or None
    executes = consumer and os.path.basename(consumer[0]) in EXECUTORS
    found = []
    for inner in stage.substitutions:
        for _index, fetch in _fetch_records(statements(inner)):
            if executes or fetch.piped_to is None:
                fetch = fetch._replace(piped_to=consumer)
            found.append(fetch)
    return found


def fetches(script):
    """Every download a `run:` script performs, in order."""
    return [fetch for _index, fetch in _fetch_records(statements(script))]


# --- which statements check, and what they check -----------------------------

def _same_file(token, path):
    return os.path.normpath(token) == os.path.normpath(path)


def _names(content, dest):
    """Does this checked text name `dest`?

    Word-exact against the path or its basename -- a checksum list legitimately
    carries bare names -- and NEVER a substring match: `/tmp/payload-old` must
    not clear `/tmp/payload`.
    """
    base = os.path.basename(dest)
    return any(_same_file(word, dest) or (base and _same_file(word, base))
               for word in content.split())


def _has_check_flag(argv):
    for token in argv[1:]:
        if token in ("-c", "--check"):
            return True
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return True
    return False


def _operands(argv):
    return [t for t in argv[1:] if not t.startswith("-")]


def _checked_text(statement, position, stage, argv, written):
    """The text a checksum stage reads, or None if nothing ties it to one.

    Three ways a step says what it expects, and each is BOUND to a source: a
    heredoc body, a sums file this same step wrote, or the previous pipeline
    stage (`echo "<sha>  <file>" | sha256sum -c -`). A `sha256sum -c` over a
    file nothing in the step produced ties this check to no download.
    """
    if stage.heredoc:
        return stage.heredoc
    files = [f for f in _operands(argv) + stage.reads if f not in _STDOUT]
    # `shasum -a 256 -c -`: the `256` is `-a`'s value, not a sums file.
    files = [f for f in files if not re.fullmatch(r"\d+", f)]
    if files:
        known = [written[f] for f in files if f in written]
        return "\n".join(known) if known else None
    if position:
        return " ".join(command(statement.stages[position - 1].argv))
    return None


def _record_writes(statement, written):
    """What this statement leaves in each file it writes, so a later
    `sha256sum -c <file>` can be bound to it."""
    for position, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        text = " ".join(argv) + ("\n" + stage.heredoc if stage.heredoc else "")
        targets = list(stage.writes)
        if argv and os.path.basename(argv[0]) == "tee":
            targets += _operands(argv)
            if position:
                text = " ".join(command(statement.stages[position - 1].argv))
        for target in targets:
            written[target] = text


def _checks(stmts):
    """[(statement index, checked text)] for every bound checksum check."""
    found, written = [], {}
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if not argv or os.path.basename(argv[0]) not in CHECKSUM_TOOLS:
                continue
            if not _has_check_flag(argv):
                continue
            text = _checked_text(statement, position, stage, argv, written)
            if text and _DIGEST.search(text):
                found.append((index, text))
        _record_writes(statement, written)
    return found


# --- which statements execute what was fetched -------------------------------

def _uses(stmts, dest, after):
    """[(statement index, what it does)] for every statement at or after
    `after` that turns `dest` into behaviour."""
    out = []
    for index, statement in enumerate(stmts):
        if index < after:
            continue
        for position, stage in enumerate(statement.stages):
            how = _use(statement, position, command(stage.argv), dest)
            if how:
                out.append((index, how))
                break
    return out


def _use(statement, position, argv, dest):
    if not argv:
        return None
    name, rest = os.path.basename(argv[0]), argv[1:]
    mentions = [t for t in rest if _same_file(t, dest)]
    if name == "chmod" and mentions:
        modes = [t for t in rest if re.fullmatch(r"[0-7]{3,4}", t)]
        if any(t.startswith("+") and "x" in t for t in rest) or any(
                int(digit) % 2 for mode in modes for digit in mode[-3:]):
            return "making it executable"
    if _same_file(argv[0], dest):
        return "running it"
    if not mentions:
        return None
    if name in INTERPRETERS:
        return "running it under `%s`" % name
    if name == "install":
        return "installing it"
    if name in UNPACKERS:
        return "unpacking it with `%s`" % name
    if name in ("mv", "cp") and any(
            t.startswith(BIN_DIRS) or "/bin/" in t for t in rest):
        return "putting it on PATH with `%s`" % name
    if name == "cat" and position + 1 < len(statement.stages):
        following = command(statement.stages[position + 1].argv)
        if following and os.path.basename(following[0]) in INTERPRETERS:
            return "piping it into `%s`" % os.path.basename(following[0])
    return None


# --- the rule ----------------------------------------------------------------

def _readable(text):
    """A lifted substitution back in a shape a human recognises, for the
    message: `-o $(mktemp)` should not be reported as `-o @@subst0@@`."""
    return _SUBST_REF.sub("$(...)", text) if text else text


def _describe(fetch):
    return "%s -> %s" % (_readable(fetch.url) or "an unparsed URL",
                         _readable(fetch.dest))


def _remedy(dest):
    return ('verify it first: `echo "<sha256>  %s" | sha256sum -c -` between '
            "the download and that use" % _readable(dest))


def _defect(fetch, index, stmts, checks):
    """Why this one fetch is unverified, or None."""
    if fetch.dest is None:
        if not fetch.piped_to:
            return None
        target = os.path.basename(fetch.piped_to[0])
        if target not in EXECUTORS:
            return None
        # Nothing landed on disk, so no checksum anywhere in the step can be
        # about these bytes: the only fix is to stop streaming them into a
        # shell (`curl ... | sh`, `eval "$(curl ...)"`, `bash <(curl ...)`).
        return ("hands %s straight to `%s`, so there is no file to check -- "
                "download it to a file, `sha256sum -c` that file, then run it"
                % (_readable(fetch.url) or "a download",
                   _readable(" ".join(fetch.piped_to))))
    uses = _uses(stmts, fetch.dest, after=index)
    if not uses:
        return None                             # fetched and only read: not this rule
    first_use, how = uses[0]
    naming = [i for i, text in checks if i > index and _names(text, fetch.dest)]
    if any(i < first_use for i in naming):
        return None
    if naming:
        # Ordering is the substance: a checksum that runs after the bytes are
        # made runnable is theatre.
        return ("verifies %s only AFTER %s" % (_readable(fetch.dest), how))
    if [i for i, _text in checks if i > index]:
        return ("fetches %s and %s; the step's checksum does not name %s, and a "
                "checksum of a different file verifies nothing -- %s"
                % (_describe(fetch), how, _readable(fetch.dest),
                   _remedy(fetch.dest)))
    return ("fetches %s and %s with nothing verifying what arrived -- %s"
            % (_describe(fetch), how, _remedy(fetch.dest)))


def fetch_exec_defects(script):
    """Every unverified fetch-and-execute in one `run:` script."""
    stmts = statements(script)
    checks = _checks(stmts)
    found = []
    for index, fetch in _fetch_records(stmts):
        why = _defect(fetch, index, stmts, checks)
        if why:
            found.append(why)
    return found


def fetch_exec_defect(script):
    """Why this `run:` script fetches and executes without verifying, or None."""
    return "; ".join(fetch_exec_defects(script)) or None


def run_steps(doc):
    """[(step name, run text)] for every `run:` step in a parsed workflow."""
    steps = []
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict) and step.get("run"):
                steps.append((step.get("name") or "<unnamed step>", step["run"]))
    return steps


def main(argv=None, out=print):
    """`python3 scripts/workflow_guard.py [workflow.yml ...]` -> 0 or 1."""
    import yaml                                 # not needed to IMPORT the rule
    paths = list(argv if argv is not None else sys.argv[1:])
    if not paths:
        directory = os.path.join(".github", "workflows")
        paths = sorted(os.path.join(directory, n) for n in os.listdir(directory)
                       if n.endswith((".yml", ".yaml")))
    defects = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle.read()) or {}
        for name, script in run_steps(doc):
            for why in fetch_exec_defects(script):
                defects.append("%s / %s -- %s" % (os.path.basename(path), name, why))
    for line in defects:
        out(line)
    if defects:
        out("%d unverified fetch-and-exec step(s); see scripts/workflow_guard.py"
            % len(defects))
    return 1 if defects else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
