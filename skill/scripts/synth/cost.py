"""The run's dispatch/usage ledger (meta.cost)."""
from dataclasses import dataclass
import glob
import json
import os

from . import plan as plan_mod


@dataclass(frozen=True)
class CostInputs:
    """What meta.cost is derived from (WS-0 S2): the driver's per-class
    dispatch counts (None off the driver path) and the host's usage.json
    (None when the host wrote none -- never an estimate)."""
    driver_cost: dict | None = None
    run_usage: dict | None = None


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
        with open(os.path.join(run_dir, "usage.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data else None

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
    carry no `role` at all (driver._driver_plan_entries says so outright), and
    the 4.x roles that did are retired (#1441), so that filter matched nothing
    on any run it could still be reached on -- it contributed an always-empty
    list. Removed rather than left as a permanently-zero ledger section.
    """
    scout = [{"phase": "scout", "role": "scout", "model": None,
              "count": scout_profiles_seen}]
    if driver_cost is None:
        return scout + [{"phase": "verify", "role": "advisor", "model": None,
                         "count": verify_queued}]
    # Driver rows carry model=None like the scout/advisor rows above: the count
    # is the load-bearing figure, and per-model/token attribution rides the
    # `tokens` slot (null until a host exposes per-dispatch usage). The verify
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

def driver_cost_counts(pano_dir, verdicts_dir, tools_ran):
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
      tool scan      = the adapters that produced output (`tools_ran`)
    """
    plan_path = os.path.join(pano_dir, plan_mod.DRIVER_DISPATCH_PLAN)
    if not os.path.isfile(plan_path):
        return None
    try:
        with open(plan_path, encoding="utf-8") as fh:
            entries = json.load(fh)
    except (OSError, ValueError):   # tolerant: a corrupt plan counts 0 cells
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
            "tool_scan": len(tools_ran) if tools_ran else 0}


def cost_section(cost, scout_profiles_seen, queued):
    """`meta.cost`: the run's dispatch ledger, derived from the artifacts already
    ingested (scout profiles, dispatch plans, verify queue / driver verdict
    bundles) -- never hand-assembled. On the 5.0 driver path `driver_cost`
    carries the per-class counts so review cells + verify rounds + the tool
    scan are all represented (#1030); it is None only when there is no driver
    plan to read. `tokens` is the host-reported usage when the host wrote
    usage.json (see load_run_usage); still null when it did not."""
    return {
        "dispatches": cost_dispatches(scout_profiles_seen, queued, cost.driver_cost),
        "tokens": cost.run_usage,
    }
