"""The walk back through a group piped to a shell (#3026, #3117), and the pipe's plumbing it rests on.

Split out of `scripts/workflow_printers.py` at that module's size (#3117), and imported back there under
each name's own, so nothing that read `workflow_printers._grouped`, `_piped`, `_passes_through` or
`piped_group_member` moved. `workflow_printers.group_reading` asks `_grouped` for the pipelines of the
group closing in front of a shell -- back from the closer (`}`, `fi`, `done`, `esac`, a subshell's `)`,
or a step-defined function's piped call) over the statements in front of it to the opener, through
nested groups and compound bodies (`_walk`, `_structure`, `_stripped`) -- a group `main` reads, a `{ }` or
`( )` group among the step's own statements or a substitution script's, read as `main` reads it, braces and
subshells its only structure and every statement a pipeline (`strict`: a keyword a step types as a word of
its own, which the reader hands back as the keyword's text, is then no structure; a compound nested there
reads LOUD, as it does for `main`) -- or back from a call to the body
of the definition it names (`_function_body`); `workflow_annotate` asks `piped_group_member` whether a
printer stands in such a group; `workflow_written` reads a group written to a file through `_grouped`.
Bounded: `_GROUP_LINES` statements a walk follows, `_CALL_REACH` statements back to a definition; past the
first the walk ends in a stand-in word told by its type (`_PastGroup`), never by its text, which a step may
type.

Stdlib only, like everything under it.
"""
import collections
import os

import shell_reader
from workflow_function_calls import _function_syntax


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


def _cat_reads_stdin(argv):
    """Whether `argv` is a `cat` reading its own stdin (R-P5, R-F5, R-F14): no operand, or a `-`
    among its operands -- every word after the FIRST `--` (R-F10: it ends the options, itself none),
    and before it each `-` or word not beginning with `-`. So `cat - f` and `cat f -` read stdin
    among `f`'s own text (fail-closed for the body; `f` stays unread unless it is itself a download,
    as `cat f | sh` already is), and an option word changes nothing: the body is read whole, as
    `-u`, `-s` and `-v` (ASCII) print it. The price, over-reported: `-n`/`-b` number each line, so
    its first command never runs, `-e` (GNU's `-E`/`-A`) ends it with `$`, spoiling its last word,
    BSD's `cat` prints nothing given `-E`, `-T`, `-A` or a piped `-l`, and GNU refuses `-l` too;
    `--help`/`--version` print their own text and read nothing (GNU; BSD refuses them)."""
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    at = words.index("--") if "--" in words else len(words)
    operands = [w for w in words[:at] if w == "-" or not w.startswith("-")] + words[at + 1:]
    return bool(argv) and os.path.basename(argv[0]) == "cat" and (not operands or "-" in operands)


# The options a `tee` takes that leave the text it hands on as it read it (#2478): append to the
# files rather than truncate them, and what to do on a write error or an interrupt.
_TEE_OPTIONS = ("-a", "-p", "-i", "--append")


def _passes_through(argv, stage):
    """Whether this stage hands what its stdin reads on to its stdout UNCHANGED (#2478): a `tee`
    whose words are all plain -- no marker, no `$` value, no pattern (`shell_reader.dynamic`: a
    `>(...)` operand may write into the stream too) -- each a FILE operand or one of
    `_TEE_OPTIONS`, `--output-error` or `--output-error=…`, and no operand the pipe itself
    (`shell_reader.writes_pipe`: `tee /dev/stdout` hands the text on twice, review I-3a); or
    a `cat` reading its own stdin (`_cat_reads_stdin`) with no heredoc or here-string there and no
    OPTION word -- only `-` and the `--` that ends the options (R-P5): `cat -n` numbers the lines
    it hands on. Neither behind `xargs` (`shell_reader.wrapper_words`, review I-2), which hands
    `cat` the piped words as FILE operands: of the wrappers the reader strips it alone changes WHAT
    the command reads, where `sudo tee f`, `nice cat` or `stdbuf -oL tee f` changes only how it
    runs, and passes (fix round 1b). Any other stage that reads the pipe -- `tr`, `sed`,
    `base64 -d`, `tee -x`, `tee >(...)`, `cat file` -- rewrites or adds to the text, and a shell
    after it reads a program no printer's words spell out."""
    name = os.path.basename(argv[0]) if argv else ""
    # A `tee` or `cat` is no wrapper, so where `shell_reader.command` hands back the stage's own
    # first word, nothing stood in front of it and there is no wrapper to ask `wrapper_words`
    # about (asking at every stage made a long `cat` chain 1.5x slower). Not a length test:
    # `command` can SPLICE as well as strip -- `env -S 'xargs cat - -'` (`--split-string=`) gives
    # back as many words as the stage has, `xargs` among the wrappers (review N-2).
    if name not in ("tee", "cat") or (argv[:1] != stage.argv[:1] and any(
            os.path.basename(w) == "xargs" for w in shell_reader.wrapper_words(stage.argv))):
        return False
    if any(shell_reader.dynamic(w, shell_reader.has_substitution) or shell_reader.is_marker(w)
           for w in argv[1:]):
        return False
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if name == "tee":
        return all((not w.startswith("-") and not shell_reader.writes_pipe(w, stage))
                   or w in _TEE_OPTIONS or w == "--output-error"
                   or w.startswith("--output-error=") for w in words)
    if stage.stdin_heredoc is not None or not _cat_reads_stdin(argv):
        return False
    at = words.index("--") if "--" in words else len(words)
    return all(w == "-" for w in words[:at] + words[at + 1:])


_GROUP_LINES = 64
_CALL_REACH = 4 * _GROUP_LINES      # how far back a piped call's definition is looked for, in statements
_PAST_GROUP = ("a group of more statements than this guard follows, %d" % _GROUP_LINES,
               'exec "$PROGRAM"')
_HEADERS = ("if", "while", "until", "for", "case", "select")     # a compound's header: it opens the compound
_ENDS = ("fi", "done", "esac")                                   # ... and its closer
_CLOSERS = ("}",) + _ENDS
_DROPPED = ("{", "then", "do", "else", "time")                   # a body statement's opening words


def _structure(stage, strict=False):
    """`(opens, closes)`: the groups and compounds a stage opens and closes -- its structural `{` and `}`
    (`_function_syntax`: never an operand's), the subshells the parser counted, and a keyword compound's header
    (`if`, `while`, `until`, `for`, `case`, `select`) or closer (`fi`, `done`, `esac`) among its leading
    keywords (`{ if x`: two); a closer counts only as a statement's sole word, which is the only place a shell
    reads one (`} | cat`, `fi`, `done < f`: a `}` typed among a statement's words is that statement's, a word),
    and a header never as one (`if` alone: a word a step typed, or the rare header whose test starts on the
    next line -- read as a word, no printer's, so a typed header cannot end a walk early).
    `strict` (a `{ }` or `( )` group, which `main` reads one level): the braces and subshells alone."""
    words = list(stage.argv)
    name, braces = _function_syntax(words)
    opens, closes = stage.group_open, stage.group_close
    if name is not None:                    # a function header: its structural braces, `f() {`
        return opens + braces.count("{"), closes + braces.count("}")
    for word in words:                      # the leading keywords, `time` among them (`time { P; } | sh`)
        if not isinstance(word, str) or word == "function" or not (
                word in shell_reader.KEYWORDS or word in _HEADERS or word == "time"):
            break
        opens += word == "{" or not strict and word in _HEADERS and len(words) > 1
        closes += len(words) == 1 and (word == "}" or not strict and word in _ENDS)
    return opens, closes


def _own(front, statements):
    """The closer's own statement where the caller handed it last (its last stage is `front`), else None."""
    last = next(reversed(statements), None)
    return last if last is not None and any(stage is front for stage in last.stages) else None


def _behind(statements, own):
    """The statements in front of the closer's own, nearest first: `statements` read backwards, `own` skipped.
    `statements` is any object read backwards (`reversed`): a list, or `workflow_written._Front`."""
    for statement in reversed(statements):
        if statement is not own:
            yield statement


def _kin(statement, own):
    """Whether `statement` is one the step wrote beside the closer's: of the same kind, and of the same string
    where both were read into place by `workflow_forms.flattened` (an `Inlined` statement with the same `key`:
    a program the string's own shell was handed is read into place before the statement handing it, under a
    key of its own); with no `own`, a plain `Statement` -- never a program a shell in front was handed."""
    if own is None:
        return type(statement) is shell_reader.Statement
    return type(statement) is type(own) and getattr(statement, "key", None) == getattr(own, "key", None)


def _stripped(stages, strict=False):
    """The pipeline a body statement runs once its opening words are dropped -- a function header's `f() {`,
    `{`, `then`, `do`, `else`, `time`, a case arm's marker (the parser's own, `shell_reader.is_arm`: never a word
    a step types in that shape) -- or None where the statement is a compound's header (`if`, `while`, `until`,
    `for`, `case`, `select`: its own output is not read, a named limit), an `elif` or `in` line, or holds no
    command; a header word alone (`if` with nothing behind it on its line) is a word, kept, no printer's --
    LOUD, so a header a step types cannot end the walk early. `strict` (a `{ }` or `( )` group, which `main`
    reads one level): the opener's `{` dropped as `main` drops it, a nested opener's too while a word follows
    (`{ { echo P`; `{ '{'` keeps the typed one), and every other word kept -- `shell_reader.command` reads the
    pipeline's keywords as `main` reads them, and a keyword a step types as a word of its own is no printer's,
    LOUD. A function header is dropped only where it opens its body on its line (`f() {`, `h() (`,
    `function f {`): a bare `f()` is a word (the two-line form's `{` is met first, going back)."""
    words = list(stages[0].argv)
    name = _function_syntax(words)[0]
    if name is not None:
        at = next(i for i, w in enumerate(words) if w in (name, name + "()"))
        after = words[at + 1 + (words[at + 1:at + 2] == ["()"]):]
        if after[:1] == ["{"] or stages[0].group_open:          # a header opening its body on its line
            words = after
    if strict:
        words = words[1:] if words[:1] == ["{"] else words
        while words[:1] == ["{"] and any(w != "{" for w in words):    # a nested opener's, with a word behind
            words = words[1:]
    else:
        while words and (words[0] in _DROPPED or shell_reader.is_arm(words[0])):
            words = words[1:]
    if not words:
        return list(stages[1:]) or None
    if not strict and len(words) > 1 and (words[0] in _HEADERS or words[0] in ("elif", "in")):
        return None
    return [stages[0]._replace(argv=words)] + list(stages[1:])


class _PastGroup(str):
    """The one word of `_past`'s stand-in pipeline, `_PAST_GROUP`'s reason as its text: told from a step's words
    by its TYPE (`_stopped`, `isinstance`), never by that text, which a step may type as a word of its own --
    out of band, as `workflow_forms._Quiet` is (#3142 round 1; the in-band marks of #3138)."""


_PAST_WORD = _PastGroup(_PAST_GROUP[0])


def _past(stage):
    """The stand-in pipeline of a group the walk stopped in (`_GROUP_LINES`): one stage, no printer's, whose
    word is `_PAST_WORD` -- `group_reading` answers `_PAST_GROUP` for it, and a caller reading the pipelines as
    `_printer_of` does meets a pipeline no printer spells (LOUD, fail-closed)."""
    return [stage._replace(argv=[_PAST_WORD], stdout_to_pipe=True)]


def _stopped(pipelines):
    """Whether `pipelines` ends in `_past`'s stand-in: one word, of `_PastGroup`'s type. A step's word spelling
    the same text is none, and reads as any other word reads."""
    if not pipelines or not pipelines[-1]:
        return False
    argv = pipelines[-1][-1].argv
    return len(argv) == 1 and isinstance(argv[0], _PastGroup)


def _grouped(front, before, statements):
    """The pipelines of the group that closes at `front` which `producer`'s walk never reaches (#3026, #3117), in
    order, or None. `front` closes the group: a bare `}`, `fi`, `done` or `esac`; a stage closing a subshell; or
    the call of a function the step defines, with no words (`f | sh`: its body is the group, `_function_body`).
    The closer's own pipeline -- `echo P` in `( X; echo P ) | sh` -- stands in the pipe, so `producer` reads it
    as `main` does and it is not among these. `statements` are those in front of the closer's own, in order, or
    those with the closer's own last; read backwards only (`_behind`). None without `statements`, where no
    opener is met, and for a subshell closer that opens its own group (`( P ) | sh`: nothing beyond
    `producer`'s). Bounded: past `_GROUP_LINES` statements the walk stops and the pipelines end in `_past`'s
    stand-in, a pipeline no printer spells. A `{ }` or `( )` group is read `strict`, as `main` reads one at the
    top of a step: braces and subshells its only structure, every statement a pipeline -- wherever it stands,
    since the reader hands a keyword a step types as a quoted word back as the keyword's text (#3142 round 2),
    and a function's body is one; a keyword compound piped at its own closer (`fi`, `done`, `esac`) is read in
    full, its header, arms and loop control known from that closer."""
    if statements is None:
        return None
    own = _own(front, statements)
    argv = list(front.argv)
    closer = argv[0] if len(argv) == 1 and argv[0] in _CLOSERS else None
    if closer is None and not front.group_close and len(argv) == 1 and isinstance(argv[0], str):
        return _function_body(argv[0], statements, own)
    if not (closer or front.group_close) or not closer and front.group_open:
        return None
    return _walk(_behind(statements, own), own, closer, bool(front.group_close) or closer not in _ENDS)


def _walk(statements, own, closer=None, strict=False):
    """Back from a group's closer over `statements`, the ones in front of it NEAREST FIRST, to its opener: the
    pipelines of the group, in order, or None where no opener is met. Each statement's closers (`_structure`)
    are met first, going back, then its own pipeline (`_stripped`), then its openers; a nested group is read
    through, its body dropped whole where its closer sends the stdout elsewhere (`{ ...; } > f`), so `nested`
    holds, for each group entered on the way back, whether its output reaches the pipe; a compound's header is
    passed over and every branch of an `if` or `case` is read, fail-closed. Passed over too: a statement not
    written beside the closer's (`_kin`), a pipeline whose last stage sends its stdout elsewhere (`_fed`), and a
    loop body's `break` or `continue` (`_silent`) -- inside a `done` the walk is in (`closer`, or a nested one,
    `loops`); elsewhere it is no printer's and the group reads LOUD, as `main` reads it. `strict` (a `{ }` or
    `( )` group): braces and subshells are the only structure met and no word is dropped (`_structure`,
    `_stripped`), so every statement `main` counts is a pipeline here too. A walk that entered a nested group
    on the way back and runs out of statements without the opener met reads LOUD, fail-closed: a closer's word
    a step typed, which the nested group's reading took for a closer, popped the opener's level."""
    body: list[list] = []
    nested: list[bool] = []
    blocked = walked = popped = 0           # the nested groups entered whose output leaves the pipe; the cost
    loops, kinds = int(closer == "done"), []    # the loops the walk is in; per nested group, whether a loop
    stage = None
    for statement in statements:
        if not _kin(statement, own):
            continue
        stages = list(statement.stages)
        if not stages:
            continue
        stage = stages[0]
        walked += 1
        if walked > _GROUP_LINES:
            return (_fed(body) or []) + [_past(stages[0])]
        opens = closes = 0
        for stage in stages:
            opened, closed = _structure(stage, strict)
            opens, closes = opens + opened, closes + closed
        for _each in range(closes):
            nested.append(stages[-1].stdout_to_pipe)
            blocked += not nested[-1]
            kinds.append(list(stages[0].argv) == ["done"])
            loops += kinds[-1]
        if closes and (not stages[0].argv or len(stages[0].argv) == 1 and stages[0].argv[0] in _CLOSERS):
            # A nested closer's statement: no pipeline of its own; the stages behind the closer (`} | cat`) hand
            # the nested group's text on unchanged where each passes through (`_passes_through`), else they
            # rewrite it, and stand in the body as a pipeline no printer spells (LOUD, fail-closed).
            tail = stages[1:]
            if tail and not blocked and not all(_passes_through(shell_reader.command(s.argv), s) for s in tail):
                body.insert(0, tail)
        else:
            pipeline = _stripped(stages, strict)    # a body pipeline of its own
            if pipeline and not blocked and not (loops and _silent(pipeline)):
                body.insert(0, pipeline)
        for _each in range(opens):
            if not nested:
                return _fed(body)
            blocked -= not nested.pop()
            loops -= kinds.pop()
            popped += 1
    return (_fed(body) or []) + [_past(stage)] if popped and stage is not None else None


def _closing(statements, index, own):
    """The index of the statement closing the group a function header at `index` opens -- `f() {` to its `}`,
    `h() (` to its `)`, `f()` with its `{` on the next line -- or None where none does."""
    depth = 0
    for at in range(index, len(statements)):
        if not _kin(statements[at], own):
            continue
        for stage in statements[at].stages:
            opens, closes = _structure(stage)
            depth += opens
            for _each in range(closes):
                depth -= 1
                if depth <= 0:
                    return at
    return None


def _function_body(name, statements, own):
    """The pipelines of the body of the function `name` defined last before the call (#3117), read back from its
    closer as a group (`_walk`): the definition's own pipeline with `f() {` dropped, then the body's; a body on
    the definition's line (`h() ( echo ok )`) is that one pipeline. Back from the call to the definition, the
    last `_GROUP_LINES` statements passed are kept (the body closes among them, or the group is `_past`);
    None where no definition is met within `_CALL_REACH` statements (bounded: a call is read in time linear in
    the step, and a word that names no function the step defines -- a program -- costs the same)."""
    trail: collections.deque = collections.deque(maxlen=_GROUP_LINES + 1)
    reached = 0
    for statement in _behind(statements, own):
        if not _kin(statement, own) or not statement.stages:
            continue
        reached += 1
        if reached > _CALL_REACH:
            return None
        if _function_syntax(list(statement.stages[0].argv))[0] != name:
            trail.append(statement)
            continue
        body = [statement] + list(reversed(trail))
        close = _closing(body, 0, own)
        if close is None:
            return [_past(statement.stages[0])] if len(trail) == trail.maxlen else None
        if close == 0:
            stages = list(statement.stages)
            pipeline = _stripped(stages, True)
            return _fed([pipeline]) if pipeline and stages[-1].stdout_to_pipe else None
        return _walk(reversed(body[:close]), own, None, True)
    return None


def piped_group_member(stmts, index):
    """Whether statement `index` lies in a `{ ...; }` or `( ...; )` group, or a keyword compound, whose closer
    pipes on (#3117): `workflow_annotate` then gives a printer there its values' texts as it gives one piped
    within its own statement. Forward from `index` to the first closer of a group it sits inside -- groups
    opened after it are stepped over (`nested`) -- that closer's statement answers: a stage behind the closer
    (`} | sh`, `) | sh`) is the pipe; a closer sending the group's stdout elsewhere (`} > f`) is none; a bare
    closer hands it to the group outside, asked next. Bounded: past `_GROUP_LINES` statements the walk stops
    and answers False, the printer read as written (its values' texts unspelled, which the group's reading
    never takes as CLEAN)."""
    own, nested = stmts[index], 0
    for following in range(index, min(len(stmts), index + _GROUP_LINES + 1)):
        statement = stmts[following]
        if not _kin(statement, own):
            continue
        stages = list(statement.stages)
        for position, stage in enumerate(stages):
            opens, closes = _structure(stage)
            if following > index:
                nested += opens
            for _each in range(closes):
                if nested:
                    nested -= 1
                    continue
                if position + 1 < len(stages):
                    return True
                if not stage.stdout_to_pipe:
                    return False
    return False


_SILENT = ("break", "continue")


def _silent(pipeline):
    """Whether a pipeline is a `break` or `continue` alone (#3117), which writes nothing: a loop's body read through
    them is read by its printers (`_walk`, inside a `done`). No other statement is: a group holding one that is no
    printer's reads LOUD, `_GROUPED`, as #3026 read an assignment beside a printer -- a reading `main` gives that
    this one keeps, a `break` outside a loop among them."""
    return len(pipeline) == 1 and list(map(str, shell_reader.command(pipeline[0].argv))) in (["break"], ["continue"])


def _fed(pipelines):
    """The pipelines of a group that write the group's stdout, or None where none does: a pipeline whose last
    stage sends its stdout elsewhere (`> f`, `>> f`: `stdout_to_pipe` off) hands the pipe nothing."""
    fed = [p for p in pipelines if p and p[-1].stdout_to_pipe]
    return fed or None
