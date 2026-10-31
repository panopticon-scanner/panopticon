"""The run's dispatch/usage ledger (meta.cost)."""
from dataclasses import dataclass
import glob
import json
import os
import re
import sys

import scripts.runners.base as runners_base
import scripts.safe_write as safe_write
import scripts.tolerant_json as tolerant_json
import scripts.tools.base as tool_base
from . import artifacts as artifacts_mod
from . import plan as plan_mod


@dataclass(frozen=True)
class CostInputs:
    """What meta.cost is derived from (WS-0 S2): the driver's per-class
    dispatch counts (None off the driver path) and the host's usage.json
    (None when the host wrote none -- never an estimate), and the models its
    ledger measured (empty on a run with no ledger -- never what was requested)."""
    driver_cost: dict | None = None
    run_usage: dict | None = None
    ledger_models: tuple = ()

    @classmethod
    def load(cls, run_dir, verdicts_dir, tools_produced):
        """meta.cost's inputs from the run folder (WS-0 S3). #21: the driver
        plan and the verdicts resolve under `run_dir` like every other run
        artifact -- reading them flat left driver_cost None on every 5.1 run."""
        return cls(driver_cost=driver_cost_counts(run_dir, verdicts_dir, tools_produced),
                   run_usage=load_run_usage(run_dir),
                   ledger_models=load_ledger_models(run_dir))


def load_run_usage(run_dir):
    """Host-reported dispatch usage for `meta.cost.tokens` (#run10 D4), or None.

    The driver is a subprocess; per-dispatch token usage lives in the HOST's
    fan-out journal, so the driver structurally cannot observe it and
    `meta.cost.tokens` sat permanently null -- a release themed *honest
    instrumentation* under-reporting its own run (run-10 surfaced ~21.05 M
    subagent tokens the ledger never recorded).

    The fix is a channel, not a guess: a host that knows its usage writes
    `<run_dir>/usage.json`, and it is surfaced verbatim. Absent or malformed ->
    None, and the slot stays null exactly as before. We never estimate tokens
    from counts: a fabricated ledger is worse than an honest gap.

    Shape (all keys optional, host-defined beyond `total`):
        {"total": 21053000, "by_phase": {"review": 10290000, ...}}
    """
    if not run_dir:
        return None
    try:
        data = artifacts_mod.read_json(os.path.join(run_dir, 'usage.json'), announce=True)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data else None

# What `models_used[].role` says when nothing ties a model to a dispatch.
UNKNOWN_ROLE = "unknown"
_MODEL_NAME_MAX = 200
_VERIFY_STAGE = re.compile(r"-(primary|backup)(?:-part[0-9]+)?$")
_ROLE_OF_STAGE = {"primary": "domain_advisor", "backup": "domain_advisor_backup"}


def _role_of_entry(entry_id):
    """The `dispatches[*].role` a ledger row's entry id names, from the id builders in
    `phases/coverage`, `review`, `verify` and `verify_tools`. A group name may hold a hyphen, so a
    verify stage is read from the end of the id."""
    text = entry_id if isinstance(entry_id, str) else ""
    if text.startswith("scout-"):
        return "scout"
    if text.startswith("review-"):
        return "domain_panel"
    if text.startswith("verify-tool-"):
        return "tool_advisor"
    stage = _VERIFY_STAGE.search(text) if text.startswith("verify-") else None
    return _ROLE_OF_STAGE[stage.group(1)] if stage else UNKNOWN_ROLE


def _model_name(value):
    """A host-reported model name safe to publish, or None: the file holding it sits in the
    reviewed tree, as usage.json does."""
    if not isinstance(value, str):
        return None
    return tool_base.inert_text(value, limit=_MODEL_NAME_MAX) or None


def load_ledger_models(run_dir):
    """The distinct (role, model) pairs the run's ledger measured, first seen first (#3368).

    Only what a host REPORTED for a launch. Never a plan entry's `model`: that is what the run
    requested, and it is None on a host with no model policy. A session-mode run has no ledger
    rows, so this is empty there. A line that cannot be read is skipped, as `Ledger.lines` does.
    """
    if not run_dir:
        return ()
    path = os.path.join(run_dir, runners_base.LEDGER_FILE)
    try:
        raw = safe_write.read_regular_bytes(path, artifacts_mod.MAX_JSON_BYTES)
    except FileNotFoundError:
        return ()
    except (OSError, ValueError) as exc:
        print("synthesize: artifact %r could not be read (%s); ignoring" % (path, exc),
              file=sys.stderr)
        return ()
    pairs = {}
    for line in raw.decode("utf-8", "replace").split("\n"):
        try:
            row = json.loads(tolerant_json.depth_checked(line))
        except (ValueError, RecursionError):
            continue
        model = _model_name(row.get("model")) if isinstance(row, dict) else None
        if model:
            pairs[(_role_of_entry(row.get("entry_id")), model)] = True
    return tuple(pairs)


def models_used(cost):
    """`meta.models_used` (#3368): the ledger's pairs. With no ledger pairs, the names a host's
    usage.json measured, which no dispatch is tied to, so their role is UNKNOWN_ROLE (session mode,
    `collect_usage`). With neither, empty: a run that recorded no model reports none."""
    if cost.ledger_models:
        return [{"model": model, "role": role} for role, model in cost.ledger_models]
    by_model = (cost.run_usage or {}).get("by_model")
    names = {_model_name(name) for name in by_model} if isinstance(by_model, dict) else ()
    return [{"model": name, "role": UNKNOWN_ROLE} for name in sorted(filter(None, names))]


def _with_ledger_models(rows, ledger_models):
    """Put the model on each row whose role ran exactly one. A role that ran two stays null, and
    `models_used` names both: picking one would claim what the other's dispatches did not run."""
    by_role: dict[str, list[str]] = {}
    for role, model in ledger_models:
        by_role.setdefault(role, []).append(model)
    for row in rows:
        models = by_role.get(row["role"], ())
        if len(models) == 1:
            row["model"] = models[0]
    return rows


def cost_dispatches(scout_profiles_seen, verify_queued, driver_cost=None):
    """Assemble the meta.cost dispatch ledger rows. Pure.

    Plan-less path (`driver_cost` is None -- synthesize pointed at an artifacts
    directory with no `dispatch-plan-driver.json`): a scout row and a single
    queued-count advisor row.

    5.0 driver path (`driver_cost` is a dict of per-class counts): one row per
    real dispatch class -- the review domain-panel cells, the verify
    primary/backup domain-advisor rounds, the per-finding tool-advisor round,
    and the deterministic tool scan.

    #run10: the plan-less path also emitted `fan_out` rows counted by filtering
    plan entries on `role in (panel_review, lens_sweep)`. Driver plan entries
    carry no `role` at all (phases.requests._driver_plan_entries says so outright), and
    the 4.x roles that did are retired (#1441), so that filter matched nothing
    on any run it could still be reached on -- it contributed an always-empty
    list. Removed rather than left as a permanently-zero ledger section.
    """
    scout = [{"phase": "scout", "role": "scout", "model": None,
              "count": scout_profiles_seen}]
    if driver_cost is None:
        return scout + [{"phase": "verify", "role": "advisor", "model": None,
                         "count": verify_queued}]
    # Driver rows carry model=None like the scout/advisor rows above, until
    # `cost_section` fills in what the ledger measured: the count is the
    # load-bearing figure, and token attribution rides the `tokens` slot (null
    # until a host exposes per-dispatch usage). The verify
    # rounds are pipeline phases, always disclosed even at count 0; the tool
    # scan row appears only when the scan actually ran.
    rows = scout + [
        {"phase": "review", "role": "domain_panel", "model": None,
         "count": driver_cost.get("review_cells", 0)},
        {"phase": "verify", "role": "domain_advisor", "model": None,
         "count": driver_cost.get("verify_primary", 0)},
        {"phase": "verify", "role": "domain_advisor_backup", "model": None,
         "count": driver_cost.get("verify_backup", 0)},
        {"phase": "verify", "role": "tool_advisor", "model": None,
         "count": driver_cost.get("verify_tools", 0)},
    ]
    if driver_cost.get("tool_scan", 0):
        rows.append({"phase": "tools", "role": "scan", "model": None,
                     "count": driver_cost["tool_scan"]})
    return rows

def driver_cost_counts(pano_dir, verdicts_dir, tools_produced):
    """Count each 5.0 driver dispatch class from its own on-disk artifact, for
    meta.cost (#1030). Returns None on the legacy path (no
    dispatch-plan-driver.json) so `cost_dispatches` keeps the 4.x shape.

    Every count is artifact-derived -- the driver's gating logic is never
    re-run here:
      review cells   = the (group, domain) cell declarations in
                       dispatch-plan-driver.json (each is one domain-panel
                       dispatch; read straight from the plan, not the validated
                       union, so the count stays faithful to what was declared)
      verify primary = the self-written cell bundles verdicts-<g>-<d>.json
      verify backup  = the ...-backup.json bundles
      tool-advisor   = the return-persisted verdicts/<queue_id>.json files
      tool scan      = the adapters that produced output
                       (`tools_produced`) -- #1335: this counts SPEND, so a
                       no-op scanner still counts; it is deliberately not
                       `tools_ran`, which answers the coverage question
    """
    plan_path = os.path.join(pano_dir, plan_mod.DRIVER_DISPATCH_PLAN)
    if not os.path.lexists(plan_path):
        return None
    try:
        entries = artifacts_mod.read_json(plan_path)
    # tolerant: a corrupt plan counts 0 cells. RecursionError (a RuntimeError,
    # from a deeply nested document) and MemoryError (from a huge one) are part
    # of "corrupt" -- `except (OSError, ValueError)` left both escaping into
    # CostInputs.load, the same way DAT-2808086775 escaped coverage_io.
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        # `str(exc) or type(exc).__name__`, not `exc or ...`: str(MemoryError())
        # is "" while the instance itself is TRUTHY, so the short form renders
        # "could not be read ()" -- a line an operator cannot act on.
        print("synthesize: %s could not be read (%s); counting 0 review cells"
              % (os.path.basename(plan_path), str(exc) or type(exc).__name__),
              file=sys.stderr)
        entries = []
    # DAT-3713947858: the plan is target-writable (the agentic path globs the
    # run folder out of the SCANNED repository), and "tolerant" above covered
    # only the PARSE -- every scalar document then raised TypeError on the
    # iteration below. Pin the type at the read, announced, the way
    # plan_contract.driver_plan_issues and plan.load_dispatch_plans already do.
    if not isinstance(entries, list):
        print("synthesize: %s is not a JSON array; counting 0 review cells"
              % os.path.basename(plan_path), file=sys.stderr)
        entries = []
    review_cells = sum(1 for e in entries
                       if isinstance(e, dict) and e.get("domain"))
    # #1052: the driver writes BOTH classes of verdict into the SAME verdicts/
    # subdir -- the domain-advisor cell bundles verdicts-<g>-<d>[-backup].json
    # (_verify_out_file) and the per-finding tool-advisor verdicts
    # <queue_id>.json (_tool_verdict_out_file, queue_id = a 16-char sha prefix,
    # never "verdicts-*"). The old code globbed cell bundles from the pano_dir
    # ROOT -- where the driver never writes them -- so primary/backup counted 0
    # and every verdicts/*.json (cell bundles included) was swept into
    # tool_advisor (run-5: 0/0/235). Split on the bundle prefix, both in the
    # subdir where the artifacts actually land.
    vdir = verdicts_dir or os.path.join(pano_dir, "verdicts")
    have_vdir = os.path.isdir(vdir)
    bundles = (glob.glob(os.path.join(vdir, "verdicts-*.json"))
               if have_vdir else [])
    backup = sum(1 for p in bundles if p.endswith("-backup.json"))
    tool_adv = (sum(1 for p in glob.glob(os.path.join(vdir, "*.json"))
                    if not os.path.basename(p).startswith("verdicts-"))
                if have_vdir else 0)
    return {"review_cells": review_cells,
            "verify_primary": len(bundles) - backup,
            "verify_backup": backup,
            "verify_tools": tool_adv,
            "tool_scan": len(tools_produced) if tools_produced else 0}


def cost_section(cost, scout_profiles_seen, queued):
    """`meta.cost`: the run's dispatch ledger, derived from the artifacts already
    ingested (scout profiles, dispatch plans, verify queue / driver verdict
    bundles) -- never hand-assembled. On the 5.0 driver path `driver_cost`
    carries the per-class counts so review cells + verify rounds + the tool
    scan are all represented (#1030); it is None only when there is no driver
    plan to read. `tokens` is the host-reported usage when the host wrote
    usage.json (see load_run_usage); still null when it did not."""
    return {
        "dispatches": _with_ledger_models(
            cost_dispatches(scout_profiles_seen, queued, cost.driver_cost), cost.ledger_models),
        "tokens": cost.run_usage,
    }
