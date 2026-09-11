"""build_report: assemble and validate the CodeReviewReport."""
from dataclasses import dataclass, field

try:
    from scripts._version import __version__
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    from _version import __version__
import scripts.evidence as evidence_mod
import scripts.host_disclosure as host_disclosure
import scripts.ocrdb as ocrdb
from . import findings as findings_mod
from . import delta as delta_mod
from . import grading as grading_mod
from . import plan as plan_mod
from . import cost as cost_mod
from . import verdicts as verdicts_mod


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

def _role_from_discovered_by(discovered_by):
    """Map a provenance discovered_by value to a model role."""
    if not discovered_by:
        return None
    discovered_by = str(discovered_by)
    if discovered_by.startswith("agent:"):
        return discovered_by.split(":", 1)[1]
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

    @classmethod
    def from_args(cls, args, groups_json, timestamp, host_capabilities=None):
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
                   host_capabilities=host_capabilities or {})


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

def validate_report(report):
    """Validate report structure and content, returning error and warning lists."""
    errors, warnings = [], []
    for key in ("meta", "summary", "groups", "findings", "cross_panel"):
        if key not in report:
            errors.append("missing top-level key: %s" % key)
    for i, f in enumerate(report.get("findings", [])):
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
    for f in report.get("findings", []):
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings
