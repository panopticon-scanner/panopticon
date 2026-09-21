"""One launch that proves an advertised output-schema flag's SHAPE (#1732).

`probes/common.probe_cli_flags` reads `<cli> --help` and answers whether the
flag is ADVERTISED. That is a read of the flag's NAME, and run 14 proved a
name is not a contract: `claude --help` advertises `--json-schema`, the driver
handed it the schema's PATH, the CLI wants its TEXT, and every `return_json`
entry of every checkpoint exited 1 in ~120 ms with no envelope. The
tool-verify round's 103 entries were launched three times over -- 309
launches, ~35 minutes -- while the host-capabilities line said "5 of 5
capabilities proven", because the one thing nobody had measured was whether
the argv the driver builds is an argv the CLI accepts.

So: one real launch per run, through the family's own `run_entry`, with the
family's real argv, BEFORE the phase engine writes the first dispatch request.
Cheap (one bounded turn, a trivial prompt, a three-key schema) and decisive.

NOT a capability probe, and deliberately not in `host_probes.PROBE_IDS`: it
returns no `(state, by, detail)` triple, maps to no capability and gates
nothing. Its verdict is written BESIDE `capabilities`, inside the
`cli_flags.output_schema` row the `--help` read already owns -- the same
reason that row lives there, namely that a CLI upgraded mid-run must not read
as posture drift.

`unmeasured` is the answer to every question this probe could not ask, and it
changes nothing: entries are stamped exactly as they were. Only `refuted`
moves anything, and what it moves is a fall-back to the state that existed
before the flag did -- a reply in fenced JSON, which the persist layer has
always validated against the same schema on receipt.
"""
import os
import time

import scripts.hosts as hosts
import scripts.redact as redact
import scripts.runners.base as runners_base
import scripts.runners.outage as outage
import scripts.runners.schema as runners_schema
import scripts._version as version


# The entry id this probe launches under. RESERVED
# (docs/FAMILY-PR-GUARDRAILS.md): it is not a dispatch entry, it is never in
# a request, it is never ledgered, and a family that saw it would be seeing
# this probe.
PROBE_ENTRY_ID = "probe-output-schema"
# The schema it names, published under `skill/reference/` so
# `runners.schema.published_schema` admits it -- the containment rule for the
# one argv value a target could otherwise choose applies to this launch
# exactly as it applies to a real one.
PROBE_SCHEMA = "probe-output-schema.json"
PROBE_PROMPT = 'Reply with the JSON object {"ok": true} and nothing else.'
# One turn and thirty seconds. The measurement is about the ARGV: a CLI that
# accepted it has said so by the time it starts its first turn, and a model
# that wants longer than this has already answered the question.
PROBE_MAX_TURNS = 1
PROBE_ENTRY_TIMEOUT = 30
# Under this, a non-zero exit with nothing to show for it is the CLI refusing
# its own argv rather than an entry failing. Run 14's refusals took ~120 ms;
# two seconds is an order of magnitude above that and an order of magnitude
# below the cheapest real launch.
SHAPE_PROOF_REFUTE_MS = 2000
# The one substring every family puts in a timeout message (`claude -p timed
# out after 30s`, `codex timed out after 30s`, `kimi -p timed out after 30s`).
# A timeout says nothing about the argv, and `RunResult` carries no structured
# reason, so this is where the three spellings are recognised; a family that
# words it differently degrades to a `proven` reading of a 30-second failure,
# which is the harmless direction (it stamps entries exactly as today).
_TIMED_OUT = "timed out"
# Likewise for the suite's structural refusal. `runners/kimi.py` re-raises it,
# while `claude` and `codex` fold every exception into a failed result's
# message (spec 4.4: `run_entry` never raises) -- so it arrives both as a type
# and as a name inside a string, and both mean "no measurement was made".
_REFUSED = runners_base.LaunchRefused.__name__


def _verdict(state, detail):
    return {hosts.SHAPE: state, hosts.SHAPE_DETAIL: detail}


def _spend(result):
    """What the probe cost, for `shape_detail` (ruling 5).

    Recorded HERE and in no ledger row: `Ledger.usage_document` counts every
    row as a launch of a cell, so a row for this would put a phantom entry in
    `usage.json` and in the report's cost table. The spend still has to be
    visible, so it goes in the sentence.
    """
    usage = getattr(result, "usage", None) or {}
    cost = getattr(result, "cost_usd", None)
    parts = ["%s %s" % (value, name) for name, value in sorted(usage.items()) if value]
    if cost is not None:
        parts.append("$%s" % cost)
    return "; cost: %s" % ", ".join(parts) if parts else ""


def prove(host, run_dir, review_root, runner=None):
    """Launch once and answer `{shape, shape_detail}` -- never raise.

    THE RULE, in one place (ruling 3). "The CLI accepted the argv" is any of:

      * the launch came back ok; or
      * it failed but took at least `SHAPE_PROOF_REFUTE_MS` -- it got far
        enough to do work, so whatever went wrong is not the argv; or
      * it failed carrying an envelope (`text`, or the host's own error
        surface) -- it parsed its argv, started, and then failed for a reason
        of its own.

    Anything else that is an ENTRY-class failure refutes the shape. Everything
    the probe could not ask -- no runner, no flag, no published schema, a
    host-class failure (that is the host, not the argv), a timeout, a
    `LaunchRefused`, a failure that never reached the CLI at all -- is
    `unmeasured`, which blocks nothing and changes no stamping.

    `runner` is a test seam; production resolves the family's own through
    `runners_base.runner_for`, exactly as `probe_cli_flags` does.
    """
    try:
        runner = runners_base.runner_for(host, "headless") if runner is None else runner
        flag = tuple(getattr(runner, "OUTPUT_SCHEMA_FLAG", ()) or ())
    except Exception as exc:          # noqa: BLE001 -- a probe reports, never raises
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "host %r has no usable headless runner to launch: %s: %s"
                        % (host, type(exc).__name__, exc))
    if not flag:
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "host %r declares no output-schema flag, so there is no shape "
                        "to prove" % host)
    schema = runners_schema.published_schema(
        os.path.abspath(version.reference_path(PROBE_SCHEMA)))
    if schema is None:
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "the probe schema %s is not published under skill/reference/, so "
                        "no launch would carry the flag at all" % PROBE_SCHEMA)
    entry = {"id": PROBE_ENTRY_ID, "prompt": PROBE_PROMPT, "enforced": False,
             "model": None, "delivery": "return_json", "output_schema": schema,
             # Named because a family's argv builder may read it; nothing ever
             # writes it, and the probe asserts nothing about it.
             "out_file": os.path.join(run_dir, PROBE_ENTRY_ID + ".json")}
    try:
        runner.prepare(run_dir, review_root)
    except Exception as exc:          # noqa: BLE001
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "host %r could not be prepared for a probe launch: %s: %s"
                        % (host, type(exc).__name__, exc))
    runner.max_turns, runner.entry_timeout = PROBE_MAX_TURNS, PROBE_ENTRY_TIMEOUT
    # Did the CLI really START? A family refuses an entry it cannot build an
    # argv for BEFORE it calls its launcher (codex requires an explicit model;
    # kimi requires a resolvable shell), and those refusals are instant and
    # entry-class -- indistinguishable, from the result alone, from the CLI
    # rejecting its own argv. They are measurements of THIS driver, not of the
    # CLI, so they must not refute anything. The launcher is the family's own
    # injected seam (`runner.runner`, what the suite swaps for a refusal), so
    # wrapping it here observes the one fact that separates them. A family
    # that exposes no such attribute is unobservable and is given the benefit
    # of the plain rule.
    started, launcher = [], getattr(runner, "runner", None)
    if launcher is not None:
        def watched(*args, **kwargs):
            started.append(True)
            return launcher(*args, **kwargs)
        runner.runner = watched
    clock = time.monotonic()
    try:
        result = runner.run_entry(entry, {runners_base.ENV_ENTRY_ID: PROBE_ENTRY_ID})
    except runners_base.LaunchRefused as exc:
        return _verdict(hosts.SHAPE_UNMEASURED, "no launch was made: %s" % exc)
    except Exception as exc:          # noqa: BLE001 -- spec 4.4 says this cannot happen
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "the probe launch raised %s: %s" % (type(exc).__name__, exc))
    finally:
        if launcher is not None:
            runner.runner = launcher
    duration_ms = int((time.monotonic() - clock) * 1000)
    error = redact.redact(getattr(result, "error", None) or "")
    if getattr(result, "ok", False):
        return _verdict(hosts.SHAPE_PROVEN,
                        "one `%s` launch was accepted by the CLI and answered in %d ms%s"
                        % (PROBE_ENTRY_ID, duration_ms, _spend(result)))
    if getattr(result, "failure_class", None) == outage.HOST_FAILURE:
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "the probe launch failed host-class (the host, not the argv): %s"
                        % error)
    if _TIMED_OUT in error:
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "the probe launch timed out after %ss, which says nothing about "
                        "the argv" % PROBE_ENTRY_TIMEOUT)
    if _REFUSED in error:
        return _verdict(hosts.SHAPE_UNMEASURED, "no launch was made: %s" % error)
    if launcher is not None and not started:
        return _verdict(hosts.SHAPE_UNMEASURED,
                        "the CLI was never started -- host %r refused the probe entry "
                        "before building an argv: %s" % (host, error))
    if duration_ms >= SHAPE_PROOF_REFUTE_MS or getattr(result, "text", None) \
            or getattr(result, "host_error", None):
        return _verdict(hosts.SHAPE_PROVEN,
                        "one `%s` launch was accepted by the CLI, which then failed on "
                        "its own account after %d ms: %s%s"
                        % (PROBE_ENTRY_ID, duration_ms, error, _spend(result)))
    return _verdict(
        hosts.SHAPE_REFUTED,
        "one `%s` launch failed in %d ms with no envelope: %s; stderr: %s"
        % (PROBE_ENTRY_ID, duration_ms, error,
           redact.redact(getattr(result, "stderr", None) or "")[:runners_base.STDERR_HEAD]
           or "(nothing)"))
