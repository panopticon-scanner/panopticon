#!/usr/bin/env python3
"""Whether a `run:` step's failure is allowed to matter, with no rule on top.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups, fix round one of
#2334) the way `scripts/workflow_operands.py` was: it had reached its size,
and this part is a layer of its own. `workflow_forms` re-exports it for the
guard.

A checksum is a gate only when its failure stops the step, and the shell
around it decides that, not the command:

    `swallowed`                the separator, the `!` and the `if`/`while`
                               around a check, and whether an `||` branch
                               after it fails the step (`_stops_the_job`)
    `_stops_step`              the imported function-call/status proof: how
                               far a failure reaches in the step's own shell
                               (`workflow_function_calls`)
    `conditional_reach`        how far a use shares the path that reaches a
                               check written behind `&&` or `||`

The layers run one way: this module imports nothing from `workflow_forms`,
which sits above it and hosts `step_credit`, the step's own answer -- the one
gating question that needs that layer's readers, the branch bodies
(`regions`) and the `set`s (`_errexit_states`) -- and `workflow_guard` sits
on top of both. It reads `workflow_function_calls` BELOW it for the mutually
recursive function/status proof, then `workflow_posture` for `seed` and `_errexit`,
the option words `flattened` shares, split out there at this module's size
(#2620) and re-exported here so no caller moved -- which reads the option
tables in `workflow_programs` under it (#2443). `Inlined` -- a statement
of a script `workflow_forms.flattened` reads in place -- lives here because
both layers read it.

Stdlib only, like everything under it.
"""
import collections

import shell_reader
from shell_reader import command, conditional, negated
from workflow_failure_contexts import (_enclosing_failure_contexts as _enclosing_failure_contexts,
                                       _failure_context as _failure_context,
                                       _function_body as _function_body,
                                       _inside_unmarked_case as _inside_unmarked_case,
                                       _is_negated_context as _is_negated_context,
                                       _known_failure as _known_failure,
                                       _negation_count as _negation_count,
                                       _skippable_or as _skippable_or,
                                       _structural_groups as _structural_groups,
                                       conditional_contexts as conditional_contexts,
                                       statement_analysis as statement_analysis)
from workflow_function_calls import (FunctionGate, PipelineGate, Reach as Reach, _CLOSES,
                                     _DETACHED, _LOST as _LOST, _NO_E as _NO_E,
                                     _NO_PIPEFAIL as _NO_PIPEFAIL, _OPENS, _RESCUED,
                                     _READ_RESCUED, _SET_E as _SET_E, _UNPROVED_RESCUE,
                                     _closes, _control_depths, _function_scope, _function_syntax,
                                     _gating_function_call, _posture_barrier,
                                     _stops_the_job, _stops_step as _stops_step, clears as _clears)
from workflow_posture import (_errexit as _errexit, _rejected as _rejected,
                              _takes_value as _takes_value, seed as seed)


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")


def _pipeline_groups(stage):
    """Compound opens/closes that keep one pipeline stage alive."""
    opens, closes = _structural_groups(stage)
    for token in stage.argv:
        if token not in shell_reader.KEYWORDS:
            break
        opens += token in _OPENS and token != "{"
        closes += token in _CLOSES and token != "}"
    return opens, closes


def _pipeline_end(stmts, index, position):
    """The last readable statement of a pipeline stage starting here."""
    depth, started = 0, False
    for following in range(index, len(stmts)):
        first = position if following == index else 0
        for stage in stmts[following].stages[first:]:
            opens, closes = _pipeline_groups(stage)
            if not started and not stage.argv and not opens:
                continue
            started = True
            depth += opens - closes
        if started and depth <= 0:
            return following
    # An unbalanced group leaves the boundary unknown. Refuse the remainder
    # of the step rather than crediting a potentially concurrent use.
    return len(stmts) - 1


def _piped_group_end(stmts, index):
    """The piped close of a structural group open at `index`, or None.

    A group opened later is a sequential sibling or child, so its pipeline
    is not concurrent with the check.
    """
    depth = 0
    for statement in stmts[:index + 1]:
        for stage in statement.stages:
            opens, closes = _structural_groups(stage)
            depth += opens - closes
    remaining, opened_after = depth, 0
    if remaining <= 0:
        return None
    for following, statement in enumerate(stmts[index + 1:], index + 1):
        for position, stage in enumerate(statement.stages):
            opens, closes = _structural_groups(stage)
            opened_after += opens
            for _close in range(closes):
                if opened_after:
                    opened_after -= 1
                    continue
                remaining -= 1
                if position + 1 < len(statement.stages):
                    return _pipeline_end(stmts, following, position + 1)
                if remaining <= 0:
                    return None
    return None


def _group_counts(stage):
    """A stage's structural brace/subshell opens and closes -- the braces of a
    `f() { ... }` header included, which `_structural_groups` leaves out, and
    never a `{`/`}` that is an operand (`echo "{"`). `_function_syntax` reports
    exactly the structural braces a stage carries."""
    _name, braces = _function_syntax(stage.argv)
    return stage.group_open + braces.count("{"), stage.group_close + braces.count("}")


def _piped_group_stage(stmts, index):
    """The end of the pipeline a `{ }`/`( )` enclosing `stmts[index]` feeds, or
    None when no group it sits inside is a pipeline stage.

    A group that is a pipeline stage runs in a subshell, so an `exit`/`return`
    written in it -- or a function called in it -- sets only that stage's
    status, which `pipefail` alone carries to the step (`{ CHECK || exit 1; } |
    cat`, `{ f; } | cat`). Groups opened AFTER `index` are its children or
    siblings and are stepped over (`nested`); only a closer of a group `index`
    sits inside is read, and a closer with no visible open -- a `(` the reader
    dropped at a line end -- counts too, its depth going negative, so a dropped
    paren fails closed rather than reading as unpiped."""
    inside = 0
    for statement in stmts[:index + 1]:
        for stage in statement.stages:
            opens, closes = _group_counts(stage)
            inside += opens - closes
    nested = 0
    for following in range(index + 1, len(stmts)):
        statement = stmts[following]
        for position, stage in enumerate(statement.stages):
            opens, closes = _group_counts(stage)
            nested += opens
            for _close in range(closes):
                if nested:
                    nested -= 1
                    continue
                if position + 1 < len(statement.stages):
                    return _pipeline_end(stmts, following, position + 1)
                inside -= 1
                if inside <= 0:
                    return None
    return None


# A rescue (`|| exit 1`, `|| return 1`) written inside a group that is a
# pipeline stage stops only that stage's subshell, so where this guard reads
# `pipefail` as off the pipeline takes the last stage's status and the step
# carries on past the checksum failure the rescue was meant to be fatal to.
_PIPED_RESCUE = ("hands its failure to a rescue inside a group piped into another command, so the "
                 "rescue stops only that stage and, where this guard reads `pipefail` as off, the "
                 "pipeline takes the last stage's status and the step carries on past its failure")


def _piped_function_end(stmts, index):
    """The first pipeline entered by a call of this function, directly
    (`f | cat`) or inside a group that is a pipeline stage (`{ f; } | cat`).

    A top-level call has the pipeline's readable end. Where a prior statement
    makes posture uncertain, or the call is conditional, nested, or in a list,
    use the step's end: no later use is cleared by an unproved boundary.
    """
    function = _function_scope(stmts, index)
    if function is None:
        return None
    name, close = function
    controls = _control_depths(stmts)
    functions = {function for statement in stmts for stage in statement.stages
                 if (function := _function_syntax(stage.argv)[0]) is not None}
    uncertain = False
    for call in range(close + 1, len(stmts)):
        statement = stmts[call]
        if any(_function_syntax(stage.argv)[0] == name for stage in statement.stages):
            uncertain = True
            continue
        for position, stage in enumerate(statement.stages[:-1]):
            if command(stage.argv)[:1] == [name]:
                if (uncertain or controls[call] or negated(stage.argv)
                        or conditional(stage.argv)):
                    return len(stmts) - 1
                scope = _function_scope(stmts, call)
                if scope is not None or statement.separator in ("&", "&&", "||"):
                    return len(stmts) - 1
                return _pipeline_end(stmts, call, position + 1)
        # A call written as the last stage of its statement is not piped on its
        # own, but one inside a group that is a pipeline stage (`{ f; } | cat`)
        # loses the function's status to that pipeline, the call twin of a piped
        # group ending a check.
        tail = statement.stages[-1] if statement.stages else None
        if tail is not None and command(tail.argv)[:1] == [name]:
            group_end = _piped_group_stage(stmts, call)
            if group_end is not None:
                if (uncertain or controls[call] or negated(tail.argv)
                        or conditional(tail.argv) or _function_scope(stmts, call) is not None):
                    return len(stmts) - 1
                return group_end
        if _posture_barrier(statement, functions):
            uncertain = True
    return None


_OWN_RESCUE = ("is followed by that use in its own `||` rescue branch, which runs only after "
               "the checksum fails")
_BOUNDED_RESCUE = ("; a use in its own `||` rescue branch runs only after the checksum fails, "
                   "and a use after that reach still runs")
_CONDITIONAL = ("is reached only through the `&&`/`||` list before it, so it may be skipped "
                "while that use still runs")


class RescueGate(Reach):
    """A check that gates only uses after its stopping rescue finishes."""

    def __new__(cls, start, through, outside=None):
        gate = str.__new__(cls, _OWN_RESCUE if outside is None
                           else str(outside) + _BOUNDED_RESCUE)
        gate.span = outside.span if isinstance(outside, Reach) else None
        gate.start, gate.through, gate.outside = start, through, outside
        return gate

    def at_use(self, _check, use):
        """This refusal inside the rescue; the original answer outside it."""
        return self if self.start <= use <= self.through else self.outside


class FunctionStatusGate(FunctionGate):
    """A called function gate that also keeps the check's reach in its body."""

    body_span: int | None

    def __new__(cls, through, body=None, outer=None):
        gate = FunctionGate.__new__(cls, through, outer)
        gate.body_span = body.span if isinstance(body, Reach) else body
        return gate


def clears(why, check, use):
    """Whether a check clears this use, excluding its own rescue body."""
    if isinstance(why, RescueGate):
        contextual = why.at_use(check, use)
        if contextual is why:
            return False
        why = contextual
    if (isinstance(why, FunctionStatusGate) and why.body_span is not None
            and check < use and use - check <= why.body_span):
        return True
    return _clears(why, check, use)


def conditional_reach(why, stmts, contexts, indexes, index, inner, on, fails):
    """Bound a conditional check to uses that require its carrier to run.

    A failure before `&&` skips the check and the same suffix its failure
    skips; `_stops_step` gives that suffix, including a stopping rescue or
    step end. Success before `||` may skip the check but reach anything after
    its carrier, so only statements inside its structural or inlined carrier
    share that path.
    """
    if not contexts:
        return why
    spans = []
    for source, carrier in contexts:
        if stmts[source].separator == "&&":
            end = _stops_step(stmts, source, on, fails)
            if end is None:
                continue
        else:
            end = carrier
        through = indexes[end] if isinstance(end, int) and end > source else index
        spans.append(through - inner)
    if not spans:
        return why
    span = min(spans)
    if why is None or isinstance(why, Reach) and why.span is not None and span < why.span:
        return Reach(span, _CONDITIONAL)
    return why


def inlined_stops(stmts, start, carrier, index, on=None, fails=None, analysis=None):
    """Whether this handed-script statement's failure reaches its carrier.

    Without recorded option states, the child proof being tested already
    requires its own `-e`; read that as on, but pipefail as off so an uncertain
    pipeline stays fail-closed. Reuse `_stops_step` for `&&`/compound-list
    bounds and `swallowed` for `||` rescues and conditional tests before
    narrowing a parent refusal to the carrier. Ignore this statement's
    precomputed credit: it was derived while flattening the parent, whose
    posture is exactly what is being bounded.
    """
    body = stmts if start == 0 and carrier == len(stmts) else stmts[start:carrier]
    analysis = statement_analysis(body) if analysis is None else analysis
    position = index - start
    if not 0 <= position < len(body) or not body[position].stages:
        return False
    statement = body[position]
    if isinstance(statement, Inlined):
        statement = statement._replace(credit=(None, None))
    enabled = [True] * len(body) if on is None else on[start:carrier]
    piped = [False] * len(body) if fails is None else fails[start:carrier]
    return (_stops_step(body, position, enabled, piped) is None
            and swallowed(body, position, statement, statement.stages[-1],
                          analysis=analysis) is None)


def inlined_reaches(flat, stmts, indexes, on, fails):
    """Give a handed script's bounded failures their reach in flat indices.

    `_stops_step` measures an `&&` list in the child statement list, while
    `clears` compares positions after nested scripts have been flattened.
    `indexes` maps between them. Keep an existing refusal in either credit
    slot: parent posture and a pipeline without pipefail remain stronger.
    """
    for position, index in enumerate(indexes):
        stops = _stops_step(stmts, position, on, fails)
        why = (Reach(0, _LOST) if stops is _LOST
               else Reach(indexes[stops] - index)
               if isinstance(stops, int) and stops >= position else None)
        statement = flat[index]
        if why is not None and statement.credit[0] is None:
            flat[index] = statement._replace(credit=(why, statement.credit[1] or why))
    return flat


def _rescue_bounds(stmts, branch):
    """Inclusive statement bounds for the rescue after an `||` separator."""
    start = branch + 1
    if start >= len(stmts):
        return None
    depth = 0
    for end, statement in enumerate(stmts[start:], start):
        for stage in statement.stages:
            opens, closes = _structural_groups(stage)
            depth += opens - closes
        if end == start and depth <= 0:
            return start, start
        if depth <= 0:
            return start, end
    return None


def _stopping_rescue(stmts, index, errexit=True, pipefail=False):
    """Bounds and status proof for this check's later stopping rescue."""
    branch = index
    while branch < len(stmts) and stmts[branch].separator == "&&":
        branch += 1
    if branch >= len(stmts) or stmts[branch].separator != "||":
        return None
    stops = _stops_the_job(stmts, branch, errexit, pipefail)
    bounds = _rescue_bounds(stmts, branch) if stops else None
    return (*bounds, stops) if bounds is not None else None


_UNMEASURED = object()
_FUNCTION_BODY = ("is inside a function that has not run through a failure gate before that "
                  "use")


def _function_status(stmts, index, answer, errexit):
    """Bind definition-time credit to a proved call, preserving body reach."""
    function, carrier = _function_scope(stmts, index), index
    if function is None and isinstance(stmts[index], Inlined):
        carrier = next((at for at in range(index + 1, len(stmts))
                        if not isinstance(stmts[at], Inlined)), index)
        function = _function_scope(stmts, carrier)
    if function is None or answer is not None and type(answer) is not Reach:
        return answer
    name, close = function
    soft = isinstance(answer, Reach) and "continue-on-error" in answer
    reaches_close = (isinstance(answer, Reach) and answer.span is not None
                     and index + answer.span >= close)
    if answer is not None and not reaches_close:
        return answer
    returned = reaches_close or (carrier != index and all(
        _closes(item) for item in stmts[carrier + 1:close + 1]
    )) or carrier == index
    call = _gating_function_call(stmts, name, close, errexit, returned)
    if call is None:
        return _FUNCTION_BODY
    body = answer if isinstance(answer, Reach) and not soft else close - index
    return FunctionStatusGate(
        call, body, answer if soft else None
    )


def swallowed(stmts, index, statement, stage, credit=_UNMEASURED, analysis=None):
    """Why this check's failure would go nowhere, or None.

    Phrased to follow "the checksum that names <file>", because that is the
    sentence a reader gets when the check they wrote did not clear the fetch
    they wrote it for. What is read here is the shell right around the check
    -- an `Inlined` statement's strong `credit` first, while a local `Reach`
    still passes through its separator, `!`, `if` and function call -- and
    `credit` is the step's own answer for the statement, read
    last: `step_credit`'s, the guard's `_SOFT_STEP` pair where the step
    carries `continue-on-error: true` (`job_defects`), or None where it has
    none. A `Reach` answer is a check ahead of `&&`, which still stops what
    its list runs, its own command where the list's end is lost, or a group
    gate that takes effect only after its concurrent pipeline (`clears`).
    """
    measuring_uses = credit is not _UNMEASURED
    if credit is _UNMEASURED:
        credit = None
    inherited_child_reach, local = False, None
    analysis = statement_analysis(stmts) if analysis is None else analysis
    plain_arm = _inside_unmarked_case(stmts, index, analysis)
    contexts = [(_failure_context(item.argv, plain_arm, item,
                                  analysis.leading_arm(item)), item)
                for item in statement.stages]
    if not contexts:
        contexts = [(_failure_context(stage.argv, plain_arm, stage,
                                      analysis.leading_arm(stage)), stage)]
    enclosing = _enclosing_failure_contexts(stmts, index, analysis)
    is_negated = (any(_is_negated_context(context, item)
                      for context, item in contexts)
                  or any(_is_negated_context(context) for context in enclosing))
    is_conditional = (any(conditional(context) for context, _item in contexts)
                      or any(conditional(context) for context in enclosing))
    opened = (context for _local, item in contexts for context in analysis.opened_contexts(item))
    async_spans = [max(0, (context.through if context.through is not None else index) - index)
                   for context in (*enclosing, *opened)
                   if getattr(context, "asynchronous", False)]
    if async_spans:
        local = Reach(min(async_spans), "runs asynchronously under `coproc`")
    if isinstance(statement, Inlined):
        own = statement.credit[stage is not statement.stages[-1]]
        outer = credit[stage is not statement.stages[-1]] if credit else None
        # `flattened` uses an unbounded base Reach when the child gates its own
        # remainder but its parent does not stop on the child's status. A later
        # step-level Reach supplies the carrier boundary; every other local
        # refusal remains stronger and is returned unchanged. A bounded local
        # Reach still needs its negation/condition and function call read below.
        inherited_child_reach = (type(own) is Reach and own.span is None
                                 and isinstance(outer, Reach))
        if own and not inherited_child_reach:
            if type(own) is Reach and own.span is not None:
                local = None if _skippable_or(stmts, index) else own
            elif not (is_negated or is_conditional or local):
                return own
    if statement.separator == "&":
        return _DETACHED
    if statement.separator == "||":
        # Only the two posture answers in a credit pair mean `-e` is off;
        # job-level policy such as `continue-on-error` does not alter the shell.
        why = credit[0] if isinstance(credit, tuple) else None
        errexit = not (why == _SET_E or
                       isinstance(why, str) and why.startswith("runs under `shell:"))
        pipefail = isinstance(credit, tuple) and credit[1] is None
        stops = _stops_the_job(stmts, index, errexit, pipefail)
        # The walk reads an `exit`/`return` rescue as stopping the step, but one
        # written inside a group that is a pipeline stage stops only that stage;
        # where pipefail is off its failure goes to the pipeline, not the step.
        piped_group = not pipefail and _piped_group_stage(stmts, index) is not None
        # The full walk includes an enclosing pipeline or rescue. Ask the local
        # slice too so an exiting rescue still gets the established piped-group
        # diagnosis when that carrier, rather than the rescue itself, swallows it.
        carrier_stops = stops or (piped_group and _stops_the_job(
            stmts[index:], 0, errexit, pipefail
        ))
        if piped_group and carrier_stops:
            return _PIPED_RESCUE
        if isinstance(stops, FunctionGate) and why and errexit:
            # Keep the proved call as a lower bound and a Reach as its upper
            # bound; an ordinary refusal still applies to the whole check.
            answer = FunctionGate(stops.through, why) if isinstance(why, Reach) else why
            rescue = _rescue_bounds(stmts, index) if measuring_uses else None
            return RescueGate(rescue[0], rescue[1], answer) if rescue is not None else answer
        if isinstance(stops, Reach):
            rescue = _rescue_bounds(stmts, index) if measuring_uses else None
            return RescueGate(rescue[0], rescue[1], stops) if rescue is not None else stops
        if not stops:
            return (why if not errexit and why else
                    _READ_RESCUED if stops is _UNPROVED_RESCUE else _RESCUED)
    # `if`, `while` and `!` govern the PIPELINE, and they sit on its head:
    # in `if echo "<sha>  x" | sha256sum -c -; then` -- the spelling this
    # module's own remedy text recommends -- the checksum is the second stage
    # and its own argv says nothing about the test wrapped around it. Ask the
    # head as well as the stage, because a one-stage statement is both.
    if is_negated:
        return "is negated, so the failing path is the THEN branch"
    if is_conditional:
        return "is an `if`/`while` test, which errexit does not apply to"
    why = local or (credit[stage is not statement.stages[-1]] if credit else None)
    piped_end = (_piped_group_end(stmts, index)
                 if not inherited_child_reach
                 and (why is None or isinstance(why, Reach)) else None)
    function_end = _piped_function_end(stmts, index) if piped_end is None else None
    if function_end is not None:
        # The definition is not itself piped. `step_credit`'s pipeline slot
        # nevertheless carries the call site's pipefail posture across these
        # reader statements, so use it before applying the function's bound.
        why = credit[1] if credit else None
        piped_end = function_end
    answer = (PipelineGate(piped_end, why)
              if piped_end is not None and (why is None or isinstance(why, Reach)) else why)
    pair = credit if isinstance(credit, tuple) else (None, None)
    errexit = not (pair[0] == _SET_E or
                   isinstance(pair[0], str) and pair[0].startswith("runs under `shell:"))
    if measuring_uses and (answer is None or isinstance(answer, Reach)):
        rescue = _stopping_rescue(
            stmts, index, errexit, isinstance(credit, tuple) and pair[1] is None
        )
        if rescue is not None:
            start, through, stops = rescue
            outside = stops if isinstance(stops, Reach) else answer
            return RescueGate(start, through, outside)
    return _function_status(stmts, index, answer, errexit) if measuring_uses else answer
