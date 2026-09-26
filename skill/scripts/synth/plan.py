"""Dispatch plans, coverage cells, out-of-scope and the run-folder loaders.

The TOOL axis -- the runner's manifest, the per-adapter dispositions and
`reconcile` -- is `synth/tool_axis.py`, split out of here when this module
reached the 700-line ceiling (#1701).
"""
from typing import Any
from dataclasses import dataclass, field
import glob
import json
import os
import sys

import scripts.evidence as evidence_mod
import scripts.group_runner as group_runner
import scripts.ingest_tools as ingest_tools
import scripts.plan_contract as plan_contract
import scripts.score_gate as score_gate
from . import coverage_io as coverage_io
from . import findings as findings_mod
from . import integrity as integrity_mod
from . import repair as repair_mod
from . import tool_axis as tool_axis_mod


@dataclass(frozen=True)
class PlanInputs:
    """What the run folder says was planned and what happened to it (WS-0 S2):
    group definitions, fan-out accounting, scout requests, lane discipline,
    per-group coverage cells, the integrity dict main() assembled, and resume
    stats. Every default is the "not measured" value the omitted build_report
    keyword carried."""
    groups_meta: list = field(default_factory=list)
    fan_out: dict | None = None
    scout_requested: list | None = None
    scout_profiles_seen: int = 0
    out_of_scope: dict | None = None
    coverages: list | None = None
    integrity: dict | None = None
    resume: dict | None = None
    # #1638 P13: {unit: "complete"|"empty"|"split"} -- whether each cell's
    # reviewers could believe their own test inventory. {} / None when this
    # run did not measure it (a direct synthesize.py call over hand-collected
    # findings had no driver to write the tally).
    test_inventory: dict | None = None
    # #2013: the target's own Git driver commands this scan ran with emptied,
    # as the driver threaded them -- the `--git-drivers-suppressed` JSON string,
    # or the parsed list. Held RAW and repaired where it is read into the
    # artifact (`tool_axis.reconcile`, via `repair.repair_git_drivers_suppressed`),
    # like every other target-carried block. None when this run did not measure
    # it: a direct synthesize.py call has no driver to ask.
    git_drivers_suppressed: Any = None

    @classmethod
    def load(cls, run_dir, files, verdicts_dir, groups_meta, plans, queue, verdicts,
             git_drivers_suppressed=None, plan_owed=False):
        """main()'s plan stage (WS-0 S3), in its original order: lane
        discipline (#441), fan-out accounting, resume stats, the integrity
        section, scout requests, coverage files. `plans` is the
        load_dispatch_plans_detailed triple and `queue` the
        `integrity.load_verify_queue` pair -- both read once by main() because
        ToolAxis.load / FindingSet.load need a piece of each first (#146/C1:
        never load the plans twice).
        `verdicts` is the FindingSet's dict, threaded through resume_stats so
        the verdicts dir is read once. `plan_owed` is the driver's `--plan-owed`
        (SEC-377944137, #1832), passed straight to integrity_section -- False
        for a caller with no driver to ask."""
        plan_lists, plans_seen, invalid_plans = plans
        queue_obj, invalid_verify_queue = queue
        plan = [e for pl in plan_lists for e in pl]
        out_of_scope = out_of_scope_findings(files, plan)
        if out_of_scope and out_of_scope["count"]:
            print("synthesize: %d finding(s) cite files OUTSIDE their group's "
                  "assigned file list (#441) -- reviewers left their lane; see "
                  "meta.coverage.out_of_scope" % out_of_scope["count"],
                  file=sys.stderr)
        fan_out = group_runner.fan_out_coverage(plan) if plan else None
        resume = group_runner.resume_stats(plan, queue_obj, verdicts_dir, _verdicts=verdicts)
        integrity = integrity_mod.integrity_section(
            plan_lists, files, run_dir, plans_seen, invalid_plans, invalid_verify_queue,
            plan_owed=plan_owed)
        scout_requested, scout_profiles_seen = load_scout_requests(run_dir)
        # 5.0 (matrix Sec5.1): auto-discover <run_dir>/coverage-<group>.json the
        # same way groups.json/scout-*.json are -- fed to audit_floor_cells in
        # reconcile along with the ingested paths.
        coverages = coverage_io.load_coverage_files(run_dir)
        return cls(groups_meta=groups_meta, fan_out=fan_out,
                   scout_requested=sorted(scout_requested),
                   scout_profiles_seen=scout_profiles_seen, out_of_scope=out_of_scope,
                   coverages=coverages, integrity=integrity, resume=resume,
                   test_inventory=load_test_inventory(run_dir),
                   git_drivers_suppressed=git_drivers_suppressed)


# One source for the per-group dispatch-plan filename glob (#681): synthesize
# reconciles findings against, and derives coverage from, every plan file the
# fan-out wrote. Both call sites join it against their own base dir.
DISPATCH_PLAN_GLOB = "dispatch-plan*.json"

# #5.0-16: the resumable driver emits ONE dedicated plan under this name. It
# matches DISPATCH_PLAN_GLOB (so reconcile/coverage/snapshot see its out_files)
# but declares matrix (group, domain) cells -- findings-<group>-<domain>.json --
# not the 4.x panel-review shape. It is the only dispatch plan the pipeline
# writes, and plan_contract.driver_plan_issues is the only contract left to
# validate it against; any OTHER dispatch-plan*.json is rejected as stray.
DRIVER_DISPATCH_PLAN = "dispatch-plan-driver.json"

def engaged_matrix_cells(findings):
    """Matrix (group, domain) cells scoring >= F_p — the cells a primary advisor
    engages. Called BEFORE verdicts are derived, so the score uses the unverified
    evidence factor, the same as phases.verify.verify_execute's own engagement decision.

    `findings` here is the DEDUPED/aggregated list (prepare_for_queue has
    already run), whereas phases.verify.verify_execute/verify_done score
    should_engage_primary on the raw per-cell list (see
    phases.review._load_cell_findings) -- dedup only removes findings, never adds
    them, so the cells this returns are a subset of what the driver engaged,
    never a superset. Safe: verify_done gates synthesize, so every
    driver-engaged cell already has a verdict bundle on disk by the time this
    runs; the discrepancy only shows up as a possible undercount in
    meta.coverage.verify_matrix.engaged when exact-duplicate findings collapse."""
    cells: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for f in findings:
        grp, dom = f.get("_group"), f.get("domain")
        if grp is None or dom is None:
            continue
        cells.setdefault((grp, dom), []).append(f)
    return {key for key, cf in cells.items() if score_gate.should_engage_primary(cf)}

def _finding_owed_verification(finding, engaged):
    """Was this finding owed an advisor verdict? A matrix finding is owed only when
    its cell is engaged (>= F_p); a below-gate cell is skipped by design and its
    unverified findings must NOT force INCONCLUSIVE. A non-matrix (4.x) finding is
    always owed — unchanged behavior."""
    grp, dom = finding.get("_group"), finding.get("domain")
    if grp is not None and dom is not None:
        return (grp, dom) in engaged
    return True

def out_of_scope_findings(findings_paths, plan):
    """#441: count agent findings whose location.file falls outside the FILE
    LIST of the group their findings-file belongs to (per the dispatch plan).

    Reviewers are prompted to stay inside their assignment, but that fence is
    prompt-advisory -- this is the report-side disclosure. Only findings files
    whose name matches GROUP_RE and whose group has a plan entry are checked;
    tool findings and unplanned groups are out of this check's reach.
    Returns {"checked": N, "count": N, "examples": [...]} or None when no
    plan/group could be checked.
    """
    group_files: dict[str | None, set[str]] = {}
    for e in plan or []:
        if isinstance(e, dict) and isinstance(e.get("files"), list):
            group_files.setdefault(e.get("group"), set()).update(
                str(f).replace("\\", "/") for f in e["files"])
    if not group_files:
        return None
    checked = count = 0
    examples: list[dict[str, Any]] = []
    for path in findings_paths or []:
        m = findings_mod.GROUP_RE.match(os.path.basename(str(path)))
        if not m or m.group(1) not in group_files:
            continue
        allowed = group_files[m.group(1)]
        # DAT-1553408299: this is the SECOND read of files the canonical loader
        # (findings.load_findings_detailed) has already read, and it used to
        # agree with that loader about neither the PARSE nor the SHAPE: strict
        # `json.load` reported a clean zero for a fence-wrapped file whose
        # findings the report had ingested (fence wrapping is a property of the
        # return channel -- see phases/runio._load_return_json), RecursionError
        # from a deeply nested one escaped `except (OSError, ValueError)`, and a
        # string/list `location` or a non-list `findings` raised out of
        # PlanInputs.load. Both halves are now the ones that loader uses --
        # `load_json_tolerant` to parse, `normalize_finding` (which pins
        # `location` to a dict and drops it when it names no file) to repair --
        # so these two readers of the same files cannot disagree about what the
        # file IS or about what a row means. Sibling readers in this module
        # still catch only (OSError, ValueError); that pattern is #2081 and is
        # not touched here.
        try:
            with open(path, encoding="utf-8") as fh:
                data = evidence_mod.load_json_tolerant(fh.read())
        except Exception:  # noqa: BLE001 - tolerant by design, like load_findings_detailed
            continue
        raws = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(raws, list):
            continue
        for raw in raws:
            if not isinstance(raw, dict):
                continue
            f = findings_mod.normalize_finding(findings_mod.agent_finding(raw, path))
            loc = f.get("location") or {}
            fpath = evidence_mod.norm_path(loc.get("file"))
            if not fpath:
                continue
            checked += 1
            if fpath not in allowed:
                count += 1
                if len(examples) < 10:
                    examples.append({"group": m.group(1), "file": fpath})
    return {"checked": checked, "count": count, "examples": examples}

def load_dispatch_plans_detailed(panopticon_dir=".panopticon"):
    """Return (valid plans, files seen, invalid plan diagnostics).

    #run10: dropped `groups_path`/`root`. Both existed only to feed the 4.x
    panel plan's groups.json cross-validation (assignment_issues/output_issues),
    retired with the roles it keyed on."""
    plans = []
    invalid = []
    paths = sorted(glob.glob(os.path.join(panopticon_dir, DISPATCH_PLAN_GLOB)))
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError) as exc:
            invalid.append({"file": path, "reason": "unreadable: %s" % exc})
            continue
        # #5.0-16: route by filename. dispatch-plan-driver.json carries the
        # matrix domain-cell shape, validated by driver_plan_issues; a malformed
        # one lands in `invalid` (=> invalid_dispatch_plans => INCONCLUSIVE).
        #
        # #run10: every OTHER dispatch-plan*.json used to be validated as a 4.x
        # per-group panel plan. That contract was keyed on the retired
        # panel_review/lens_sweep roles, so it rejected every plan the pipeline
        # can write and accepted only plans nothing can emit -- retired with
        # them. The branch's OTHER job was to fail closed on a stray
        # dispatch-plan-*.json dropped into the artifacts dir, and that is kept
        # explicitly: an unrecognized plan file is still INCONCLUSIVE, never
        # silently ignored.
        if os.path.basename(path) == DRIVER_DISPATCH_PLAN:
            issues = plan_contract.driver_plan_issues(plan)
        else:
            issues = ["unrecognized dispatch-plan file (expected %s)"
                      % DRIVER_DISPATCH_PLAN]
        if issues:
            invalid.append({"file": path, "reason": "; ".join(issues)})
            continue
        plans.append(plan)
    return plans, len(paths), invalid

def load_dispatch_plans(panopticon_dir=".panopticon"):
    """Load every per-group dispatch plan file as a list of per-file plan
    lists. Tolerant: unreadable/malformed plan files are skipped."""
    plans = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, DISPATCH_PLAN_GLOB))):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(plan, list):
            plans.append(plan)
    return plans

def derive_tool_policy_mode(panopticon_dir=".panopticon", plans=None):
    """Derive the run's tool-policy posture from dispatch plan files.

    unknown: no usable plan file was found — posture undetermined (distinct
    from advisory, which is a plan we DID read that enforced nothing).
    enforced: every entry across every plan is enforced; mixed: some are;
    advisory: a plan exists but none are. Pass `plans` (per-file plan lists,
    as returned by load_dispatch_plans) to skip re-reading the files a caller
    already loaded.
    """
    if plans is None:
        plans = load_dispatch_plans(panopticon_dir)
    if not plans:
        return "unknown"
    flags = [bool(e.get("enforced")) for plan in plans
             for e in plan if isinstance(e, dict)]
    if flags and all(flags):
        return "enforced"
    if any(flags):
        return "mixed"
    return "advisory"


def load_groups_json(path):
    """The run's groups.json as a dict, or {} when there is no file at `path`,
    it cannot be read, or it is not a JSON object -- tolerant by design (never
    abort a run); the two failure modes are announced on stderr.

    The file is target-writable, and five of its fields are type-pinned by the
    time they reach the artifact, so the dict is normalized HERE rather than by
    the caller (#1639 P15 fix round 3, R2-6): repairing at the read is what
    makes a second caller safe by construction. It lived at the caller for one
    round only because this module was two lines under its ceiling.
    """
    if not (path and os.path.isfile(path)):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            gj = json.load(fh)
    except (OSError, ValueError) as e:
        print("synthesize: could not read %s (%s); ignoring" % (path, e), file=sys.stderr)
        return {}
    if not isinstance(gj, dict):
        print("synthesize: %s is not a JSON object; ignoring" % path, file=sys.stderr)
        return {}
    return repair_mod.repair_groups_json(gj)


PANEL_TOOLS_CONTEXT = "panel-tools-context.json"


def load_panel_tools_context(run_dir):
    """`{"with": n, "without": m}` over <run_dir>/panel-tools-context.json.

    #1637 P08 ruling 5. The driver's review phase stamps every dispatch entry
    with whether tool output was on disk as its prompt was rendered, and
    merges the per-cell answers into that file as each batch goes out. This
    counts them, so the report can say how many panels actually saw scanner
    evidence -- run-13's 85 panels reviewed with none, and the report had no
    field in which to say so.

    Fail-closed to two zeroes on anything unreadable, and on the file being
    absent: this lives under `.panopticon`, which a hostile target can
    pre-commit, and "nothing measured" must read as a measurable zero rather
    than as a traceback or an invented figure. A run that dispatched no panel
    at all reports the same two zeroes, correctly.
    """
    counts = {"with": 0, "without": 0}
    try:
        with open(os.path.join(run_dir, PANEL_TOOLS_CONTEXT), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return counts
    cells = body.get("cells") if isinstance(body, dict) else None
    if not isinstance(cells, dict):
        return counts
    for saw_tools in cells.values():
        counts["with" if saw_tools is True else "without"] += 1
    return counts


TEST_INVENTORY = "panel-test-inventory.json"

INVENTORY_STATES = ("complete", "empty", "split")


def load_test_inventory(run_dir):
    """`{unit: state}` over <run_dir>/panel-test-inventory.json (#1638 P13).

    The review phase records, per REVIEW UNIT (the config entry a chunked
    `<name>_N` was split out of, so the key names a group the operator can
    find), whether that unit's prompts were built from a `complete`, `empty`
    or `split` inventory; this reads it back so `meta.coverage.test_inventory`
    can say which `TST` coverage claims rest on one nobody could trust.

    Fail-closed to `{}` on an absent or unreadable file, and any state outside
    `INVENTORY_STATES` is DROPPED rather than carried: this lives under
    `.panopticon`, which a hostile target can pre-commit, and an invented
    state in the artifact is worse than a missing group.
    """
    out: dict[str, str] = {}
    try:
        with open(os.path.join(run_dir, TEST_INVENTORY), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return out
    groups = body.get("groups") if isinstance(body, dict) else None
    if not isinstance(groups, dict):
        return out
    for name, state in groups.items():
        if isinstance(name, str) and state in INVENTORY_STATES:
            out[name] = state
    return out


def load_scout_requests(run_dir):
    """(tools requested, profiles seen) across <run_dir>/scout-*.json. #471: a
    scout can return tools:[] -- a silent decline of the tool layer -- so the
    profile count is recorded separately and the decline is announced."""
    requested: set[str] = set()
    profiles_seen = 0
    for sp in glob.glob(os.path.join(run_dir, "scout-*.json")):
        try:
            with open(sp, encoding="utf-8") as fh:
                sd = evidence_mod.load_json_tolerant(fh.read())
        except (OSError, ValueError):  # tolerant by design: never abort a run
            continue
        if not isinstance(sd, dict):
            continue
        profiles_seen += 1
        tools = sd.get("tools")
        if isinstance(tools, list):
            requested.update(t for t in tools if isinstance(t, str))
    if profiles_seen and not requested:
        print("synthesize: %d scout profile(s) requested NO tools (tools:[]) "
              "-- the tool layer ran on default triggers only, not scout "
              "guidance" % profiles_seen, file=sys.stderr)
    return requested, profiles_seen


# #1701: the security mode under which the name-based drops are the GATE's
# business and not only the report's -- the same constant `security_gate.py`
# keys its own `--security redteam` branch on.
REDTEAM = "redteam"


def gate_security_mode(args):
    """The gate's controller-carried mode, also published in report metadata."""
    return REDTEAM if getattr(args, "security", None) == REDTEAM else "standard"


def gate_counts_suppressed(args):
    """Does this run's gate count what a directory-NAME exclusion dropped?

    #1740: three rules feed that set -- vendored, virtualenv-by-name and the
    fixture corpus -- and the answer is the same for all of them, because the
    evidence is the same: a conventional directory name and nothing else.

    #1701, item-14 principle: the answer is read from `args.security`, which
    `phases/synthesize.py` threads verbatim off the run MANIFEST -- the
    controller's own write-once record. NOT `RunConfig.security_mode`, which
    falls back to `groups.json` when the flag is absent: that file lives in the
    target's `.panopticon/`, and a target that can choose the mode can choose
    to have its vendored findings ignored, which is the whole defect inverted.
    """
    return gate_security_mode(args) == REDTEAM


def ingest_tool_findings(args):
    """The --tools-dir ingest (WS-0 S3): (raw tool findings, per-adapter
    dispositions, tools_ran, the #1578 `{segment: count}` of name-based drops
    -- the findings themselves stay suppressed -- the #1701 subset of those
    findings this run's GATE must still count, and the #1740 `{globs, count}`
    of what the OPERATOR's own `--tools-exclude` policy took off the axis). tools_ran is None when
    --tools-dir wasn't supplied -- reconcile infers build_executing_tools then;
    an empty set would ASSERT "no build-executing tool ran" from an absence of
    evidence (the inversion #450 was about). A "failed" disposition (empty /
    unparseable / no-adapter) is excluded from tools_ran, so
    build_executing_tools can no longer name an adapter that ran empty.

    #1701: under `--security redteam` a finding may not be dropped on the
    strength of a conventional DIRECTORY NAME, so the drops come back as
    gate-only CANDIDATES (`security_gate.evaluate`'s `findings + suppressed`,
    for the driver's own gate). They are normalized exactly as the kept tool
    findings are -- `normalize_finding`, so severity, panel and location answer
    the gate identically -- and they are never added to `tool_findings`, which
    is what keeps them out of the report body.

    Candidates, not the gated set: fix round 1 F1. The `--severity` floor is
    applied HERE, the same place and with the same arithmetic
    `FindingSet.prepare` applies it to the kept findings, because a run told to
    look only at CRITICAL must not have a HIGH gate it from behind a directory
    name. The delta / `gate_scope` filter is applied where the real population
    gets it, in `verdicts.resolve_findings`. The `{segment: count}` returned
    here stays the FULL ingest tally either way; `reconcile` splits it into what
    the gate counted and what stayed suppressed from it, so the two published
    numbers still sum to what stderr and `security_gate` print.
    """
    if not args.tools_dir:
        default_tools = os.path.join(".panopticon", "tools")
        if os.path.isdir(default_tools) and os.listdir(default_tools):
            print("synthesize: %s appears un-ingested — pass --tools-dir %s to "
                  "include tool findings in this report"
                  % (default_tools, default_tools), file=sys.stderr)
    if not (args.tools_dir and os.path.isdir(args.tools_dir)):
        return [], {}, None, None, [], excluded_block(args, 0)
    dropped: list[dict[str, Any]] = []     # #1578/#1740: filled with the name-based drops, for the count
    excluded: list[dict[str, Any]] = []    # #1740 fix round 2: the operator's own glob drops
    tool_findings, dispositions = ingest_tools.ingest_dir_detailed(
        args.tools_dir, None, exclude_globs=args.tools_exclude,
        include_fixtures=args.include_fixtures, suppressed_out=dropped,
        excluded_out=excluded)
    gated = []
    if gate_counts_suppressed(args):
        gated = [findings_mod.normalize_finding(f) for f in dropped]
        if args.severity and args.severity != "all":
            # Same expression as FindingSet.prepare's floor, deliberately: the
            # gate-counted set is filtered by the flags the kept set is filtered
            # by, or it is not "the same finding, counted the same way".
            threshold = evidence_mod.SEV_ORDER.index(args.severity.upper())
            gated = [f for f in gated if evidence_mod.sev_rank(f) <= threshold]
    return (tool_findings, dispositions,
            tool_axis_mod.tools_ran_from_dispositions(dispositions),
            ingest_tools.suppressed_counts(dropped), gated,
            excluded_block(args, len(excluded)))


def excluded_block(args, count):
    """`{"globs": [...], "count": N}` -- the exclusion POLICY this ingest ran
    under and what it took off the tool axis (#1740 fix round 2).

    Published on every report, empty included, because the globs are the
    disclosure: `exclude_paths:` is authored by the repository under review and
    now scopes the scanners, the report and the gate, so a `['**']` that
    empties the tool axis has to be visible in `report.json` itself -- not only
    in `groups.json`, `tools-manifest.json` and a stderr line nobody keeps. A
    glob that matched nothing this run is still published: it scoped the run,
    and a reader comparing two runs needs to see it.
    """
    return {"globs": [str(g) for g in (getattr(args, "tools_exclude", None) or [])],
            "count": int(count)}
