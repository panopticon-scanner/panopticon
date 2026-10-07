#!/usr/bin/env python3
"""Failure contexts around checks in workflow shell statements.

Split verbatim from ``workflow_gating`` so the gating layer stays below the
flat-module ceiling.  ``workflow_gating`` keeps compatibility imports for the
callers that already name these helpers there.
"""
import shell_reader
from shell_reader import command
from workflow_function_calls import _function_syntax, _known_status


def _structural_groups(stage):
    """Leading brace and subshell opens/closes carried by this stage."""
    braces = []
    words, at = stage.argv, 0
    while at < len(words):
        token = words[at]
        if token == "coproc":
            at += 1
            if (at + 1 < len(words) and words[at + 1] in ("{", "(")
                    and _function_syntax([words[at], "()"])[0] == words[at]):
                at += 1
            continue
        if token not in shell_reader.KEYWORDS:
            break
        if token in ("{", "}"):
            braces.append(token)
        at += 1
    return stage.group_open + braces.count("{"), stage.group_close + braces.count("}")


def conditional_contexts(stmts):
    """{statement: ((list head, carrier end), ...)} for conditional groups."""
    stack, active = [], []
    for index, statement in enumerate(stmts):
        opens = closes = 0
        for stage in statement.stages:
            opened, closed = _structural_groups(stage)
            opens, closes = opens + opened, closes + closed
        for _opening in range(opens):
            group = [index, None]
            stack.append(group)
        active.append(tuple(stack))
        for _closing in range(closes):
            if stack:
                stack.pop()[1] = index
    contexts = {}
    for position, groups in enumerate(active):
        ends: dict[int, list[int | None]] = {}
        for start, end in groups:
            if start and stmts[start - 1].separator in ("&&", "||"):
                ends.setdefault(start, []).append(end)
        found = [(start - 1, None if None in bounds
                  else max(end for end in bounds if end is not None))
                 for start, bounds in ends.items()]
        if (position and position not in ends
                and stmts[position - 1].separator in ("&&", "||")):
            found.append((position - 1, position))
        if found:
            contexts[position] = tuple(found)
    return contexts


def _negation_count(words):
    """Leading status inversions; assignments end the reserved-word prefix."""
    count = 0
    for word in words:
        if word == "!":
            count += 1
        elif word not in shell_reader.KEYWORDS:
            break
    return count


def _is_negated_context(words, structure=None):
    """Whether any pipeline around this command has an odd `!` parity.

    Compound keywords separate pipelines: an outer `! { ...; }` never
    cancels an inner `! command`.  Parenthesis positions do not survive the
    reader, so a stage with a hidden group boundary and leading inversions is
    conservatively negated when those inversions could sit on either side.
    """
    if structure is None:
        structure = getattr(words, "structure", None)
    parities, count = [], 0
    for word in words:
        if word == "!":
            count += 1
        elif word not in shell_reader.KEYWORDS:
            break
        else:
            parities.append(count % 2)
            count = 0
    parities.append(count % 2)
    if any(parities):
        return True
    return bool(structure and structure.group_open > structure.group_close
                and _negation_count(words))


def _known_failure(statement):
    """Whether this one command certainly leaves a failing list status."""
    if len(statement.stages) != 1:
        return False
    stage = statement.stages[0]
    # Defining a function succeeds without running its body.  In particular,
    # `false || f() ( false ) || CHECK` skips CHECK; the body's known status
    # says nothing about the definition command that the `||` list sees.
    if _function_syntax(stage.argv)[0] is not None:
        return False
    status = _known_status(command(stage.argv), None)
    if status is None:
        return False
    return (status != 0) != bool(_negation_count(_failure_context(stage.argv)) % 2)


def _skippable_or(stmts, index):
    """Whether an earlier successful `||` path may skip this statement."""
    contexts = conditional_contexts(stmts)
    pending, seen = [index], set()
    while pending:
        position = pending.pop()
        if position in seen:
            continue
        seen.add(position)
        for source, _carrier in contexts.get(position, ()):
            if stmts[source].separator != "||":
                continue
            if not _known_failure(stmts[source]):
                return True
            pending.append(source)
    return False


def _function_body(words, bare=0):
    """Words after a function header, whatever compound opens its body."""
    name = _function_syntax(words)[0]
    start = 0
    while (start < len(words) and words[start] in shell_reader.KEYWORDS
           and words[start] != "function"):
        start += 1
    # Inside another function, or after `then` / a group opener, shell_reader
    # can retain only the bare name from `name() compound-command`.
    explicit = (start + 1 < len(words)
                and words[start + 1] in ("{", "(", "if", "while", "until", "for", "case"))
    if (name is None and start + 1 < len(words) and (explicit or bare)
            and (_function_syntax([words[start], "()"])[0] == words[start])):
        # The reader removes the `()` from a bare function header.  When its
        # aggregate parenthesis counts are the evidence for that header, spend
        # that evidence once even if the following compound opener is visible;
        # otherwise a later ordinary command can be mistaken for a second
        # header in the same stage.
        return words[:start] + words[start + 1:], bool(bare)
    if name is None:
        return None
    if words[start] == "function":
        end = start + 2
    elif words[start] == name + "()":
        end = start + 1
    else:                                           # `name () compound-command`
        end = start + 2
    if end < len(words) and words[end] == "()":
        end += 1
    return words[end:], False


def _failure_context(argv, plain_arm=False, structure=None, leading_arm=None):
    """Words around a status after its structural headers, to a fixed point."""
    # Parentheses lost from `name()` and a subshell body remain in stage counts.
    bare = (min(structure.group_close, max(structure.group_open - structure.group_close, 0))
            if structure is not None else 0)
    compound = bool(structure and structure.group_open > structure.group_close)
    words = argv
    while words:
        if shell_reader.is_arm(words[0]):
            words = words[1:]
            continue
        # A reader-lifted case-arm `)` is the structural evidence that argv[0]
        # is the pattern, even when the pattern itself is a reserved word such
        # as `!`.  A case opened later in this same stage owns that close; its
        # leading `!` still belongs to the command around the case.
        if leading_arm is None:
            leading_arm = False
        lifted_arm = plain_arm and leading_arm
        if (plain_arm and len(words) > 1 and
                (lifted_arm or
                 words[0] not in shell_reader.KEYWORDS and
                 (words[1] in shell_reader.KEYWORDS
                  or _function_syntax(words[1:])[0] is not None))):
            words, plain_arm = words[1:], False
            continue
        body = _function_body(words, bare)
        if body is not None:
            words, consumed = body
            bare -= consumed
            continue
        lead = next((at for at, word in enumerate(words)
                     if word not in shell_reader.KEYWORDS), len(words))
        if lead < len(words) and words[lead] in ("time", "coproc"):
            end = lead + 1
            if words[lead] == "time":
                while end < len(words) and words[end].startswith("-"):
                    end += 1
            elif (end < len(words) and (compound or
                  end + 1 < len(words) and words[end + 1] in ("{", "("))
                  and (_function_syntax([words[end], "()"])[0] == words[end])):
                end += 1
            # Bash 3.2 runs external `time` here, whose rejected `!` a leading
            # negation turns successful; Bash 5 instead reads both as reserved words.
            bash3_time = (words[lead] == "time" and _negation_count(words[:lead]) % 2
                          and _negation_count(words[end:]) % 2)
            words = words[:lead] + ["!"] * bool(bash3_time) + words[end:]
            continue
        opening = next((at for at, word in enumerate(words)
                        if word not in ("{", "(")), len(words))
        if opening:
            words = words[opening:]
            continue
        # A function header before `case` makes shell_reader retain the arm as
        # plain words rather than an arm token: `case WORD in PATTERN command`.
        if len(words) >= 4 and words[0] == "case" and words[2] == "in":
            words = words[4:]
            continue
        return words
    return words


class _EnclosingContext(list):
    """A list-compatible prefix retaining the stage that opened its group."""

    def __init__(self, words=(), structure=None, asynchronous=False):
        super().__init__(words)
        self.closed_at = None
        self.structure = structure
        self.asynchronous = asynchronous
        self.through = None


class _GroupFrame:
    """Persistent structural stack node; snapshots stay O(1) while scanning."""

    __slots__ = ("carrier", "carrier_start", "closed", "context",
                 "last_statement", "opened_at", "previous")

    def __init__(self, context, previous, opened_at):
        self.carrier = None
        self.carrier_start = None
        self.closed = False
        self.context = context
        self.last_statement = None
        self.opened_at = opened_at
        self.previous = previous


class _StageShape:
    """Case-aware group events and arm state for one parser stage."""

    __slots__ = ("continuation", "events", "has_command", "leading_arm", "plain_arm")

    def __init__(self, events, plain_arm, leading_arm, has_command, continuation=False):
        self.continuation = continuation
        self.events = events
        self.plain_arm = plain_arm
        self.leading_arm = leading_arm
        self.has_command = has_command


class _CaseState:
    """Whether an unmarked arm is active and its structural group depth."""

    __slots__ = ("depth", "plain")

    def __init__(self, plain=False):
        self.depth = 0
        self.plain = plain


def _move_case_depth(cases, change, count=1):
    """Apply structural events to every case arm they occur inside."""
    for _event in range(count):
        for case in cases:
            case.depth = max(0, case.depth + change)


def _coproc_prefix(words):
    """Whether the command-position prefix starts an asynchronous coprocess."""
    return next((word for word in words if word not in shell_reader.KEYWORDS), None) == "coproc"


def _body_words(stage):
    """Expose structural words hidden behind any retained function headers."""
    words = stage.argv
    bare = min(stage.group_close, max(stage.group_open - stage.group_close, 0))
    while True:
        # Without explicit function syntax, lifted parentheses are the only
        # evidence that a bare leading name was a function header.
        if (_function_syntax(words)[0] is None
                and not (stage.group_open or stage.group_close)):
            break
        body = _function_body(words, bare)
        if body is None:
            break
        following, consumed = body
        if following == words:
            break
        words, bare = following, bare - consumed
    return words


_COMMAND_RESTARTS = ("then", "elif", "else", "do")


def _self_contained_hidden_pairs(words, opens, closes):
    """Hidden parenthesis pairs proved to open and close within one clause.

    The reader keeps only aggregate parenthesis counts.  Compound-clause
    boundaries still prove the open-before-close order in the common forms
    below.  Consuming only those pairs prevents an inner `( command )` from
    popping an already-open outer group.  Any surplus remains structural and
    is handled conservatively by the ordinary close/open events.
    """
    available = min(opens, closes)
    if not available:
        return 0
    pairs = 0
    for start, ends in (("if", ("then",)), ("elif", ("then",)),
                        ("while", ("do",)), ("until", ("do",)),
                        ("then", ("elif", "else", "fi")),
                        ("else", ("fi",)), ("do", ("done",))):
        positions = [at for at, word in enumerate(words) if word == start]
        for at in positions:
            if any(end in words[at + 1:] for end in ends):
                pairs += 1
                break
    return min(available, pairs)


def _stage_shape(stage, cases):
    """Read case arms and explicit braces in their surviving source order.

    Parentheses have no positions after ``shell_reader``.  Same-stage pairs
    therefore cancel each other, while a surplus close precedes and a surplus
    open precedes the surviving argv.  Case-arm closes are claimed first and
    never allowed to consume a structural group.
    """
    words = _body_words(stage)
    remaining_closes = stage.group_close
    braces = []
    has_command = False
    leading_arm = False
    plain_arm = False
    head = True
    at = 0
    prefix = 0
    segment = 0
    arm_closes = 0

    # A close for a group opened in the active arm precedes this stage's words;
    # it cannot also be the lifted `)` of a following unmarked pattern.
    structural_leading = (min(cases[-1].depth, remaining_closes) if cases else 0)
    _move_case_depth(cases, -1, structural_leading)

    # A later unmarked arm starts with PATTERN and carries its lifted `)` as a
    # close.  That marker, rather than the spelling of PATTERN, identifies it.
    marked_arm = False
    while at < len(words) and shell_reader.is_arm(words[at]):
        marked_arm = True
        if cases:
            cases[-1].plain = False
            cases[-1].depth = 0
        at += 1
    if (cases and not marked_arm and remaining_closes > structural_leading and at < len(words)
            and words[at] != "esac"
            and not (at + 2 < len(words) and words[at] == "case"
                     and words[at + 2] == "in")):
        at += 1
        arm_closes += 1
        cases[-1].plain = True
        cases[-1].depth = 0
        leading_arm = True
        plain_arm = True

    while at < len(words):
        word = words[at]
        if not head:
            if word in _COMMAND_RESTARTS:
                prefix = at
                segment = at
                head = True
            at += 1
            continue
        if word == "{":
            braces.append((at, "open", words[segment:at + 1]))
            _move_case_depth(cases, 1)
            segment = at + 1
            at += 1
            continue
        if word == "}":
            braces.append((at, "close", None))
            _move_case_depth(cases, -1)
            prefix = at + 1
            segment = at + 1
            at += 1
            continue
        if word == "case" and at + 2 < len(words) and words[at + 2] == "in":
            cases.append(_CaseState())
            at += 3
            if at < len(words) and shell_reader.is_arm(words[at]):
                at += 1
            elif at < len(words) and remaining_closes > structural_leading + arm_closes:
                # The first pattern belongs to this case, including `!`.
                at += 1
                arm_closes += 1
                cases[-1].plain = True
                plain_arm = True
            head = True
            continue
        if word == "esac":
            if cases:
                cases.pop()
            at += 1
            continue
        if word in shell_reader.KEYWORDS:
            at += 1
            continue
        if word == "time":
            at += 1
            while at < len(words) and words[at].startswith("-"):
                at += 1
            continue
        if word == "coproc":
            at += 1
            if (at + 1 < len(words) and words[at + 1] in ("{", "(")
                    and _function_syntax([words[at], "()"])[0] == words[at]):
                at += 1
            continue
        has_command = True
        head = False
        at += 1

    remaining_closes -= arm_closes
    _move_case_depth(cases, -1, remaining_closes - structural_leading)
    hidden_opens = stage.group_open
    paired = _self_contained_hidden_pairs(words, hidden_opens, remaining_closes)
    transition = (hidden_opens > paired and remaining_closes > paired
                  and any(word in _COMMAND_RESTARTS for word in words))
    if not transition:
        paired = min(hidden_opens, remaining_closes)
    hidden_opens -= paired
    remaining_closes -= paired
    _move_case_depth(cases, 1, hidden_opens)
    before = [(event, context) for position, event, context in braces if position < prefix]
    after = [(event, context) for position, event, context in braces if position >= prefix]
    post_restart = (transition or bool(before)
                    or paired and words[:1] in (["then"], ["else"], ["do"]))
    hidden_prefix = words[prefix:] if prefix and post_restart else stage.argv
    events = ([("close", None)] * remaining_closes + before
              + [("open", hidden_prefix)] * hidden_opens + after)
    return _StageShape(events, plain_arm or any(case.plain for case in cases),
                       leading_arm, has_command, words[:1] in (["then"], ["elif"],
                                                               ["else"], ["do"]))


class _StatementAnalysis:
    """One source-ordered case/group pass shared by every check in a list."""

    def __init__(self, stmts):
        self.leading_arms = {}
        self.opened: dict[int, list[tuple[object, _EnclosingContext]]] = {}
        self.plain_arms = []
        self.enclosing: list[_GroupFrame | None] = []
        cases: list[_CaseState] = []
        top = None
        for index, statement in enumerate(stmts):
            self.enclosing.append(top)
            plain_arm = False
            for stage in statement.stages:
                shape = _stage_shape(stage, cases)
                self.leading_arms[id(stage)] = (stage, shape.leading_arm)
                plain_arm = plain_arm or shape.plain_arm
                if shape.has_command and top is not None:
                    self._carry(top, index, index, stmts,
                                continuation=shape.continuation)
                for event, prefix in shape.events:
                    if event == "close":
                        if top is not None:
                            closed, top = top, top.previous
                            closed.closed = True
                            closed.context.closed_at = index
                            closed.context.through = closed.carrier
                            if top is not None and closed.carrier is not None:
                                self._carry(top, closed.carrier_start,
                                            index, stmts, closed.carrier,
                                            closed.opened_at)
                        continue
                    context = _EnclosingContext(
                        _failure_context(prefix, shape.plain_arm, stage,
                                         shape.leading_arm), stage,
                        _coproc_prefix(prefix)
                    )
                    self.opened.setdefault(id(stage), []).append((stage, context))
                    top = _GroupFrame(context, top, index)
                if shape.has_command and top is not None:
                    self._carry(top, index, index, stmts,
                                continuation=shape.continuation)
            self.plain_arms.append(plain_arm)

    def leading_arm(self, stage):
        """Whether this list's source walk placed an arm at ``stage``."""
        found = self.leading_arms.get(id(stage))
        return found[1] if found is not None and found[0] is stage else None

    def opened_contexts(self, stage):
        """Contexts for groups this stage opens in this statement list."""
        return tuple(context for found, context in self.opened.get(id(stage), ())
                     if found is stage)

    @staticmethod
    def _carry(frame, start, statement, stmts, carrier=None, group_start=None,
               continuation=False):
        """Make one command the frame's tail, preserving its `&&`/`||` chain."""
        if frame.last_statement == statement:
            return
        nested_join = (group_start is not None and group_start > 0
                       and stmts[group_start - 1].separator in ("&&", "||"))
        if (not nested_join and not continuation and (frame.last_statement is None
                or stmts[frame.last_statement].separator not in ("&&", "||"))):
            frame.carrier_start = start
        frame.carrier = statement if carrier is None else carrier
        frame.last_statement = statement


def statement_analysis(stmts):
    """Build one structural analysis for callers to share over this list."""
    return _StatementAnalysis(stmts)


def _inside_unmarked_case(stmts, index, analysis=None):
    """Whether this statement is in an arm whose marker the reader lost."""
    analysis = statement_analysis(stmts) if analysis is None else analysis
    return index < len(analysis.plain_arms) and analysis.plain_arms[index]


def _enclosing_failure_contexts(stmts, index, analysis=None):
    """Failure prefixes on structural groups enclosing this statement."""
    # A proved failure immediately after this command stops the same `&&`
    # chain before any following payload.  Keep only an enclosing group that
    # also carries that failure: its inversion can still make an outer use run.
    known_after = (index + 1 < len(stmts) and stmts[index].separator == "&&"
                   and _known_failure(stmts[index + 1]))
    analysis = statement_analysis(stmts) if analysis is None else analysis
    top = analysis.enclosing[index] if index < len(analysis.enclosing) else None
    contexts = []
    while top is not None:
        carries = (top.carrier_start is not None
                   and top.carrier_start <= index <= top.carrier)
        closed_at = top.context.closed_at
        unconditionally_followed = (closed_at is not None
                                    and stmts[closed_at].separator not in ("&&", "||"))
        if ((not top.closed or carries or unconditionally_followed)
                and (not known_after or top.carrier is not None
                     and top.carrier >= index + 1)):
            contexts.append(top.context)
        top = top.previous
    contexts.reverse()
    return contexts


def _bounded_enclosing_failure_contexts(stmts, index, analysis=None):
    """Closed prefixes that suppress failure only through their own group.

    A later successful tail can decide a group's `&&`/`||` status, so its
    prefix cannot refuse every later use.  It still suppresses errexit for a
    check and any use inside that group; callers bind the refusal at the close.
    """
    analysis = statement_analysis(stmts) if analysis is None else analysis
    top = analysis.enclosing[index] if index < len(analysis.enclosing) else None
    contexts = []
    while top is not None:
        carries = (top.carrier_start is not None
                   and top.carrier_start <= index <= top.carrier)
        closed_at = top.context.closed_at
        if (top.closed and not carries and closed_at is not None
                and stmts[closed_at].separator in ("&&", "||")):
            contexts.append((top.context, closed_at))
        top = top.previous
    contexts.reverse()
    return contexts
