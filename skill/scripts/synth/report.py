"""build_report: assemble and validate the CodeReviewReport."""
import sys
from dataclasses import dataclass, field

try:
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    from _version import __version__
import scripts.evidence as evidence_mod
import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.ocrdb as ocrdb
from . import findings as findings_mod
from . import delta as delta_mod
from . import grading as grading_mod
from . import plan as plan_mod
from . import cost as cost_mod
from . import verdicts as verdicts_mod
from . import validate_schema as validate_schema_mod


# Format version of the report DOCUMENT itself (the meta/summary/groups/findings
# envelope), stamped top-level like every sibling artifact (findings-envelope,
# x0x-report, tool-manifest, dispatch-request ...). Distinct from meta.version
# (the panopticon release) and meta.ocrdb_version (the code bundle): the report
# envelope evolves on its own clock -- 5.1 added meta.cost/meta.integrity/
# summary.health/summary.delta with no change to the finding shape. Bump this
# only on a report-envelope format change. Absent (legacy pre-5.1 reports) reads
# as version 0. #run7 DAT-F2A: gives the cross-run readers (reconcile.load_report,
# the html compare view, per-run-folder A/B) a discriminator before per-run
# folders make cross-version report reads routine.
REPORT_SCHEMA_VERSION = 1

# #1639 P15 fix round 2 (F2): what `models_used[].role` says when the finding
# does not say. `role` is pinned `type: string`, and the old None reached the
# artifact and ended the run -- on an ordinary payload (`provenance.model` with
# no `discovered_by`), which means an agent could deny a paid-for run its result
# by omitting a field. There is no documented default role in any producer
# contract, so the honest word is the one that says nobody recorded it.
UNKNOWN_ROLE = "unknown"


def _role_from_discovered_by(discovered_by):
    """Map a provenance discovered_by value to a model role.

    Never None: see UNKNOWN_ROLE. A non-string value is not a role either --
    "who found this" is a name, and `str({...})` would publish a dict's repr as
    one.
    """
    if not discovered_by or not isinstance(discovered_by, str):
        return UNKNOWN_ROLE
    if discovered_by.startswith("agent:"):
        return discovered_by.split(":", 1)[1] or UNKNOWN_ROLE
    return discovered_by

def _collect_models_used(findings):
    """Collect unique model/version/role triples from agent findings.

    Tool findings (model is null) are skipped. Agent findings contribute their
    provenance model/version plus a role derived from discovered_by. Advisor
    confirmations contribute the confirming model with role 'advisor'.
    """
    seen = set()
    out = []
    for f in findings:
        prov = f.get("provenance") or {}
        model = prov.get("model")
        version = prov.get("model_version")
        # Skip tool and other entries without a model identifier.
        if not model:
            continue
        role = _role_from_discovered_by(prov.get("discovered_by"))
        if role == UNKNOWN_ROLE:
            print("synthesize: %s: provenance.model %r with no usable "
                  "discovered_by; models_used role recorded as %r"
                  % (f.get("id") or "?", model, UNKNOWN_ROLE), file=sys.stderr)
        # Dedup by (model, role): agents self-report model_version
        # inconsistently (F-CAL-3), which produced duplicate entries.
        key = (model, role)
        if key in seen:
            continue
        seen.add(key)
        entry = {"model": model, "role": role}
        if version:
            entry["version"] = version
        out.append(entry)
        confirmed_by_model = prov.get("confirmed_by_model")
        if confirmed_by_model:
            advisor_key = (confirmed_by_model, None, "advisor")
            if advisor_key not in seen:
                seen.add(advisor_key)
                out.append({"model": confirmed_by_model, "role": "advisor"})
    return out

@dataclass(frozen=True)
class RunConfig:
    """What the operator asked for (WS-0 S2): the target, the gate policy and
    the review's mode labels. Defaults are the omitted build_report keyword's
    meaning."""
    target: str
    fail_on: str
    timestamp: str
    review_type: str = "repo"
    security_mode: str = "standard"
    gate_unverified: bool = False
    max_verify: int | None = None
    gate_scope: str = "on-diff"
    # 5.1 surface 2: the posture VERBATIM off the artifact, so a consumer can
    # diff it across runs. Not summarised -- `detail` is what tells a reader
    # which of several refutation reasons applied on this run.
    host_capabilities: dict = field(default_factory=dict)
    # #1637 P08 ruling 5: `{"with": n, "without": m}` over this run's review
    # cells -- how many panels were shown scanner evidence and how many were
    # not. Counted by plan_mod.load_panel_tools_context off the driver's own
    # per-cell tally; {} only when a caller predates the field.
    panel_tools_context: dict = field(default_factory=dict)
    # #1637 P08 F2: True when this run started with the tool scan enabled and
    # had it switched off mid-flight. Distinct from `flags.tools is False`,
    # which is equally true of a run that never had tools -- a weaker claim.
    tools_disabled_mid_run: bool = False

    @classmethod
    def from_args(cls, args, groups_json, timestamp, host_capabilities=None,
                  panel_tools_context=None, tools_disabled_mid_run=False):
        """The CLI flags resolved against the run's groups.json (WS-0 S3):
        an explicit --changes wins over a discovered mode (a groups.json mode
        must not flip an explicitly-requested changes review back to repo);
        --security wins over the file's security_mode; both default to
        repo / standard. `groups_json` is {} when there is no readable file.
        `host_capabilities` is the parsed host-capabilities.json artifact (or
        {} when absent/corrupt); the caller reads it, this classmethod only
        threads it through."""
        review_type = "changes" if args.changes else "repo"
        if not args.changes:
            review_type = findings_mod.MODE_TO_REVIEW_TYPE.get(groups_json.get("mode"),
                                                               review_type)
        security_mode = args.security
        if security_mode is None:
            security_mode = groups_json.get("security_mode", "standard")
        if security_mode is None:
            security_mode = "standard"
        return cls(target=args.target, fail_on=args.fail_on, timestamp=timestamp,
                   review_type=review_type, security_mode=security_mode,
                   gate_unverified=args.gate_unverified, max_verify=args.max_verify,
                   gate_scope=args.gate_scope,
                   host_capabilities=host_capabilities or {},
                   panel_tools_context=panel_tools_context or {},
                   tools_disabled_mid_run=bool(tools_disabled_mid_run))


@dataclass(frozen=True)
class ReportInputs:
    """Everything build_report reads, grouped by which stage owns it (WS-0
    S2). `run` and `findings` are required; the other four default to their
    "not measured" values so a caller that predates a stage (no dispatch plan,
    no tool layer, no delta, no cost ledger) passes nothing."""
    run: RunConfig
    findings: findings_mod.FindingSet
    delta: delta_mod.DeltaContext = field(default_factory=delta_mod.DeltaContext)
    plan: plan_mod.PlanInputs = field(default_factory=plan_mod.PlanInputs)
    tools: plan_mod.ToolAxis = field(default_factory=plan_mod.ToolAxis)
    cost: cost_mod.CostInputs = field(default_factory=cost_mod.CostInputs)


def build_report(inp):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    The four stages run in dependency order: resolve the findings against
    their verdicts (verdicts), reconcile the dispatch plan and tool layer into
    meta.coverage/meta.integrity (plan), grade and certify (grading), then
    the cost ledger (cost). assemble() lays the sections out in the report's
    key order.
    """
    resolved = verdicts_mod.resolve_findings(inp.findings, inp.delta, inp.run)
    reconciled = plan_mod.reconcile(inp.plan, inp.tools, resolved)
    graded = grading_mod.grade_report(inp.run, resolved, reconciled)
    cost = cost_mod.cost_section(inp.cost, inp.plan.scout_profiles_seen,
                                 resolved.verdict_stats["queued"])
    return assemble(inp.run, resolved, reconciled, graded, cost)


def _host_capabilities_verbatim(host_capabilities):
    """The artifact's `capabilities` map, unchanged, or {} on anything that
    is not readable as one.

    Fail-closed like the rest of this branch's host-evidence handling: an
    artifact that is absent, truncated or tampered with must never surface as
    a fabricated posture, and the "nothing measured" case must be
    distinguishable in shape ({} is diffable; None forces every caller to
    branch on it first).
    """
    if not isinstance(host_capabilities, dict):
        return {}
    caps = host_capabilities.get("capabilities")
    return caps if isinstance(caps, dict) else {}


def _host_capabilities_block(host_capabilities, key):
    """One MAPPING field off the artifact, or {} when it is not readable.

    `{}` rather than None, for `capabilities`' reason: the "nothing measured"
    case stays diffable and no consumer has to branch on None before reading
    it. Fail-closed on every other shape.
    """
    if not isinstance(host_capabilities, dict):
        return {}
    block = host_capabilities.get(key)
    return block if isinstance(block, dict) else {}


def _host_capabilities_field(host_capabilities, key):
    """One scalar field off the artifact, or None when it is not readable.

    `None` -- never a default, never a raise -- on an artifact that is absent,
    not a dict, or simply missing the key. A fabricated `probed_at` would be
    the worst possible answer here: 5.2's entire argument for re-probing on
    every invocation is that setup-time-only evidence is unbounded in age, so
    "measured at 04:05" and "nobody wrote down when" have to stay
    distinguishable. `meta.timestamp` cannot stand in -- that is SYNTHESIS
    time, a different moment from the probe on any resumed run.
    """
    if not isinstance(host_capabilities, dict):
        return None
    return host_capabilities.get(key)


def assemble(run, resolved, reconciled, graded, cost):
    """Lay the computed sections out as the CodeReviewReport envelope. Key
    order is part of the artifact (write_report dumps insertion order)."""
    for f in resolved.findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
        # #1476: dedupe's alias carrier. Internal plumbing for verdict binding,
        # not part of the artifact contract -- stripped here with the others.
        f.pop(evidence_mod.MERGED_IDS_FIELD, None)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "meta": {
            "target": run.target,
            "review_type": run.review_type,
            "timestamp": run.timestamp,
            "version": __version__,
            "ocrdb_version": (ocrdb.BUNDLE_VERSION
                              if resolved.ocrdb_bundle is not None else None),
            "security_mode": run.security_mode,
            "models_used": _collect_models_used(resolved.findings),
            "coverage": reconciled.coverage,
            # #1637 P08 ruling 5: a run whose tool scan skipped still produces
            # a full-looking report, and until now nothing in it said that the
            # panels reviewed blind. Counted, not inferred: the driver stamped
            # each cell as its prompt was rendered. Zeroes on both sides mean
            # no panel was dispatched, which is a different fact from "none saw
            # evidence" and stays distinguishable because `without` is 0 too.
            "tools": {
                "panels_with_scanner_context": {
                    "with": int((run.panel_tools_context or {}).get("with") or 0),
                    "without": int((run.panel_tools_context or {}).get("without") or 0)},
                # F2: stated on EVERY report, `false` included -- the absence
                # of a warning has to mean "measured and did not happen", the
                # same rule surface 3 applies to the host posture.
                "disabled_mid_run": bool(run.tools_disabled_mid_run),
                # #1646: the dependency audit is PARTIAL by construction now --
                # pip-audit is handed a generated requirements list, because
                # resolving an editable/local/VCS/URL requirement runs the
                # reviewed repo's build backend. Which lines were left out
                # rides here, off the runner's manifest (repaired at that read),
                # so "pip-audit: produced" cannot be read as "every declared
                # dependency was checked". `{}` means no manifest -- nothing
                # measured, not nothing dropped.
                "sanitized": reconciled.tools_sanitized},
            "integrity": reconciled.integrity,
            "cost": cost,
            # 5.1 surface 2: the verified host posture, verbatim off the
            # artifact -- host_disclosure.host_of() fails closed (None) on
            # anything that is not a dict with a string "host", so a
            # malformed/absent artifact renders as "nobody looked" here too,
            # never a traceback mid-synthesis. `capabilities` gets the same
            # fail-closed treatment: default {} (not None) so an absent or
            # unreadable artifact reads as "nothing to diff", matching the
            # {} synthesize.py already uses for "absent or corrupt". A dict
            # `capabilities` value survives untouched -- state/by/detail all
            # carried, per capability -- for a consumer diffing runs.
            # `probed_at` and `schema_version` ride along for the same reason
            # and with the same fail-closed treatment (None, never a default):
            # WHEN the posture was measured is part of the posture, and the
            # schema the artifact was written in is what a consumer diffing
            # two runs needs to know it may compare them at all.
            "host_capabilities": {
                "host": host_disclosure.host_of(run.host_capabilities),
                "schema_version": _host_capabilities_field(
                    run.host_capabilities, "schema_version"),
                "probed_at": _host_capabilities_field(
                    run.host_capabilities, "probed_at"),
                "capabilities": _host_capabilities_verbatim(run.host_capabilities),
                # D10 N3: the operational CLI facts ride BESIDE `capabilities`,
                # never inside it, exactly as they do in the artifact -- a
                # consumer diffing two runs' postures must not see a flag that
                # gates nothing as a capability that moved.
                hosts.CLI_FLAGS: _host_capabilities_block(
                    run.host_capabilities, hosts.CLI_FLAGS),
            },
        },
        "summary": graded.summary,
        "groups": graded.groups,
        "findings": resolved.active,
        "discarded_claims": resolved.rejected,
        "cross_panel": {"integration_findings": resolved.integration_findings},
    }


def attach_schema_status(report, errors):
    """Record schema-validation results in the artifact itself.

    Validation stays advisory — a run never aborts — but the count is no longer
    stderr-only, so a downstream consumer (issue tracker, CI) can see that a
    report failed its own schema.
    """
    report.setdefault("meta", {})["schema_errors"] = len(errors)
    return report

def validate_report(report, schema_path=None):
    """Validate report structure and content, returning error and warning lists.

    Two layers, one error list (#1639 P15). FIRST the published Draft 7 schema
    (`skill/reference/report-schema.json`), which is the contract every
    downstream consumer validates against and which this function used to
    ignore entirely -- a report with `meta`, `summary` and `cross_panel` all
    `null` passed here while schema validation rejected all three. THEN the
    hand checks below, which are NOT redundant with it: the schema can express
    shape, but not "an agent-sourced security HIGH needs a CVSS score and an
    exploit scenario", not "no two findings share an id", and not the
    evidence-status vocabulary, because each of those is a policy about
    meaning rather than a fact about structure.

    Schema failure is fail-closed (see `validate_schema`): an uninstallable
    validator or an unreadable schema is an ERROR, never a silent pass.
    `schema_path` overrides which schema file is loaded (tests).
    """
    errors, warnings = [], []
    errors.extend(validate_schema_mod.schema_errors(report, schema_path=schema_path))
    for key in ("meta", "summary", "groups", "findings", "cross_panel"):
        if key not in report:
            errors.append("missing top-level key: %s" % key)
    # `or []`, not a default: a report whose `findings` is explicitly `null` is
    # precisely the shape this function now promises to REPORT on, and
    # `enumerate(None)` would raise instead -- turning a validation answer into
    # a traceback at the moment validation started mattering.
    for i, f in enumerate(report.get("findings") or []):
        if not findings_mod.ID_RE.match(f.get("id", "")):
            errors.append("finding[%d] bad id: %r" % (i, f.get("id")))
        if not f.get("title"):
            errors.append("finding[%d] missing title" % i)
        if not f.get("category"):
            errors.append("finding[%d] missing category" % i)
        if f.get("severity") not in findings_mod.SEVERITIES:
            errors.append("finding[%d] bad severity: %r" % (i, f.get("severity")))
        if f.get("confidence") not in findings_mod.CONFIDENCES:
            errors.append("finding[%d] bad confidence: %r" % (i, f.get("confidence")))
        if f.get("panel") not in findings_mod.VALID_PANELS:
            errors.append("finding[%d] bad panel: %r" % (i, f.get("panel")))
        ev = f.get("evidence") or {}
        if ev.get("status") not in evidence_mod.EVIDENCE_STATUSES:
            errors.append("finding[%d] bad evidence.status: %r" % (i, ev.get("status")))
        loc = f.get("location") or {}
        if not loc.get("file") or loc.get("line_start") is None:
            warnings.append("finding[%d] missing location.file/line_start" % i)
        agent_sourced = not evidence_mod.is_tool_sourced(f)
        if agent_sourced and f.get("panel") in ("security", "redteam") and f.get("severity") in ("CRITICAL", "HIGH"):
            if not f.get("cvss"):
                errors.append("finding[%d] %s %s missing cvss" % (i, f["panel"], f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] %s %s missing exploit_scenario" % (i, f["panel"], f["severity"]))
    id_counts = {}
    for f in report.get("findings") or []:
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings
