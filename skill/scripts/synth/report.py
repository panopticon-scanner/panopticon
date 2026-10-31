"""build_report: assemble and validate the CodeReviewReport."""
import re
from dataclasses import dataclass, field

# #1766 (ARC-11100703): package-qualified, with no fallback arm. A module under
# synth/ is reachable only as `scripts.synth.report`, so `scripts` has already
# resolved before this line runs, and tests/test_layout.py rule 2 forbids the
# flat package import that would be the only way to reach a fallback. The arm
# that used to sit here was dead code wearing a mode's clothes;
# tests/test_module_identity.py now pins that no package module grows another.
from scripts._version import __version__
import scripts.app_trace as app_trace
import scripts.evidence as evidence_mod
import scripts.host_disclosure as host_disclosure
import scripts.inert as inert
import scripts.hosts as hosts
import scripts.ocrdb as ocrdb
import scripts.redact as redact
from . import findings as findings_mod
from . import delta as delta_mod
from . import grading as grading_mod
from . import plan as plan_mod
from . import severity_cap as severity_cap_mod
from . import tool_axis as tool_axis_mod
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

def _unplaceable_by_tool(findings):
    """Counts of active tool findings whose source file could not be placed."""
    counts: dict[str, int] = {}
    for finding in findings:
        source = finding.get("source")
        evidence = finding.get("tool_evidence")
        if (not isinstance(source, str) or not source.startswith("tool:")
                or not isinstance(evidence, dict)
                or evidence.get("path_resolution") != "unresolved"):
            continue
        name = source.removeprefix("tool:")
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


class ReviewScopeError(ValueError):
    """Neither the operator nor the inventory names this review's scope."""


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
    prior_run: str | None = None      # #3271: "host:run_id8", off the driver's argv
    # #1681 Plan 2: what the TARGET's committed `settings:` asked for and what
    # the trust classes let through, off `<run_dir>/config-resolution.json`.
    # {} when there is no driver-written artifact: nothing asked for.
    config: dict = field(default_factory=dict)
    # The gate never inherits its mode from target-written groups.json (#1707).
    gate_security_mode: str = "standard"
    # #3163: the driver supplies the reviewed tree separately from its display
    # name. Standalone callers may still use target as the path when omitted.
    root: str | None = None

    @classmethod
    def from_args(cls, args, groups_json, timestamp, host_capabilities=None,
                  panel_tools_context=None, tools_disabled_mid_run=False, prior_run=None,
                  config=None):
        """The CLI flags resolved against the run's groups.json (WS-0 S3):
        explicit --changes wins over a discovered mode; --repo accepts only
        a missing mode or one mapped to repo. Without either, a missing or unsupported
        groups.json mode refuses the report.
        --security wins over the file's security_mode and defaults to standard.
        `groups_json` is {} when there is no readable file.
        `host_capabilities` is the parsed host-capabilities.json artifact (or
        {} when absent/corrupt); the caller reads it, this classmethod only
        threads it through."""
        if args.changes:
            review_type = "changes"
        elif getattr(args, "repo", False):
            mode = groups_json.get("mode")
            discovered = (findings_mod.MODE_TO_REVIEW_TYPE.get(mode)
                          if isinstance(mode, str) else None)
            if mode is not None and discovered != "repo":
                scope = ("%s scope" % discovered if discovered is not None else
                         "unsupported mode %r" % redact.redact_diagnostic(str(mode), 80))
                raise ReviewScopeError(
                    "review scope refused: declared repo scope conflicts with "
                    "discovered %s" % scope)
            review_type = "repo"
        else:
            mode = groups_json.get("mode")
            if not isinstance(mode, str) or mode not in findings_mod.MODE_TO_REVIEW_TYPE:
                reason = "missing" if mode is None else "unsupported"
                raise ReviewScopeError(
                    "review scope refused: %s groups.json mode; pass --repo to "
                    "declare a repository-wide review, or --changes for a changes review"
                    % reason)
            review_type = findings_mod.MODE_TO_REVIEW_TYPE[mode]
        security_mode = args.security
        if security_mode is None:
            security_mode = groups_json.get("security_mode", "standard")
        if security_mode is None:
            security_mode = "standard"
        return cls(target=args.target, root=args.root,
                   fail_on=args.fail_on, timestamp=timestamp,
                   review_type=review_type, security_mode=security_mode,
                   gate_unverified=args.gate_unverified, max_verify=args.max_verify,
                   gate_scope=args.gate_scope,
                   host_capabilities=host_capabilities or {},
                   panel_tools_context=panel_tools_context or {},
                   tools_disabled_mid_run=bool(tools_disabled_mid_run),
                   prior_run=prior_run if isinstance(prior_run, str) else None,
                   config=config or {},
                   gate_security_mode=plan_mod.gate_security_mode(args))


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
    tools: tool_axis_mod.ToolAxis = field(default_factory=tool_axis_mod.ToolAxis)
    cost: cost_mod.CostInputs = field(default_factory=cost_mod.CostInputs)


def build_report(inp):
    """Build a CodeReviewReport under the two-axis severity x evidence model.

    The four stages run in dependency order: resolve the findings against
    their verdicts (verdicts), reconcile the dispatch plan and tool layer into
    meta.coverage/meta.integrity (plan), grade and certify (grading), then
    the cost ledger (cost). assemble() lays the sections out in the report's
    key order.
    """
    # #1701 fix round 1 (F1): the gate-counted vendored drops are handed to the
    # stage that applies the gate's filters, not appended after it.
    resolved = verdicts_mod.resolve_findings(
        inp.findings, inp.delta, inp.run,
        gated_suppressed=inp.tools.gated_suppressed, groups_meta=inp.plan.groups_meta)
    reconciled = tool_axis_mod.reconcile(inp.plan, inp.tools, resolved, run=inp.run)
    # #2178: grading needs the delta context itself, not only the classified
    # findings -- a zero-range hunk map leaves the on-diff gate scoping
    # against something nobody measured, which is a certification fact.
    graded = grading_mod.grade_report(inp.run, resolved, reconciled,
                                      delta=inp.delta)
    cost = cost_mod.cost_section(inp.cost, inp.plan.scout_profiles_seen,
                                 resolved.verdict_stats["queued"])
    # #2951: the backstop. Findings, verdicts and scanner output are made
    # surrogate-free where they are loaded, because their text is hashed first;
    # everything else a report holds -- a group or file name from the target's
    # tree, the run's own artifacts -- meets its first encoder at a writer, and
    # every writer writes THIS. A report holding none comes back itself.
    return inert.surrogate_free(assemble(inp.run, resolved, reconciled, graded, cost,
                                         models_used=cost_mod.models_used(inp.cost)))


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


def _prior_run(value):
    """`meta.prior_run` (#3271, ruling D2): {host, run_id} off the driver's
    `HOST:RUN_ID8`, or None for anything out of shape."""
    host, _, run_id = (value or "").partition(":")
    if re.fullmatch(r"[a-z][a-z0-9-]{0,31}", host) and re.fullmatch(r"[0-9a-f]{1,8}", run_id):
        return {"host": host, "run_id": run_id}
    return None


def _config_block(config):
    """`meta.config` (#1681 Plan 2, spec §4): what the target's committed
    config asked for, what this run honoured, and what it refused or clamped.

    Always emitted, `{}`/`[]` when there was nothing to say -- meta.tools'
    rule: the absence of a refusal has to mean "measured and did not happen",
    not "this run had no opinion". The values are copied out of a
    target-authored file, so they are DESCRIBED in the published schema
    without being type-pinned by it, for `host_capabilities`' reason: a junk
    config must be readable AS junk, never a lever that makes the report
    fail its own schema. `load_resolution` has already bounded them.
    """
    src = config if isinstance(config, dict) else {}
    return {"requested": dict(src.get("requested") or {}),
            "effective": dict(src.get("effective") or {}),
            "refused": [r for r in (src.get("refused") or []) if isinstance(r, dict)],
            "clamped": [c for c in (src.get("clamped") or []) if isinstance(c, dict)],
            "disclosures": [s for s in (src.get("disclosures") or [])
                            if isinstance(s, str)]}


def _fill_category(finding, bundle):
    """#3368: a reviewer picks a `code`, and is asked for a `category` only on a planted instruction,
    so most findings reach here as `general`. The code already names one. Done here, after citations,
    verdicts, merges and grading, because each of those reads `category`, and a replay's verdicts are
    keyed on ids hashed with `general`. Moving that is #3371. `evidence.finding_fingerprint` reads
    the marker, so the finding keeps the identity it was stamped and filed under."""
    if finding.get("category") != "general":
        return
    named = ocrdb.category_of(bundle, finding.get("code"))
    if named:
        finding["category"] = named
        finding[evidence_mod.CATEGORY_SOURCE] = "catalog"


def assemble(run, resolved, reconciled, graded, cost, models_used=()):
    """Lay the computed sections out as the CodeReviewReport envelope. Key
    order is part of the artifact (write_report dumps insertion order)."""
    for f in resolved.findings:
        f.pop("_group", None)
        f.pop("_repo_root", None)
        if "cvss" in f and f["cvss"] in (None, "", {}):
            del f["cvss"]          # #3162: an empty score is no score -- unscored, not malformed
        _fill_category(f, resolved.ocrdb_bundle)
    unscored = cvss_unscored(resolved.active)
    capped = severity_cap_mod.capped_ids(resolved.active)
    # #3270: every external app this run launched -- the host CLI off
    # host-capabilities.json, docker off the tools manifest -- repaired at both
    # reads (both are target-writable). `meta.apps` is present only when one was.
    apps = app_trace.home_relative(
        app_trace.repair(_host_capabilities_field(run.host_capabilities, "apps"))
        + reconciled.tools_apps)                  # #3271 S2: never the operator's home
    prior = _prior_run(run.prior_run)
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
            "gate_security_mode": run.gate_security_mode,
            "models_used": list(models_used),
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
                "unplaceable": _unplaceable_by_tool(resolved.active),
                # #1646: the dependency audit is PARTIAL by construction now --
                # pip-audit is handed a generated requirements list, because
                # resolving an editable/local/VCS/URL requirement runs the
                # reviewed repo's build backend. Which lines were left out
                # rides here, off the runner's manifest (repaired at that read),
                # so "pip-audit: produced" cannot be read as "every declared
                # dependency was checked". `{}` means no manifest -- nothing
                # measured, not nothing dropped.
                "sanitized": reconciled.tools_sanitized,
                # #1645: "pip-audit: produced" says a scanner ran; it has never
                # said what that scanner could REACH while it ran. The two
                # ONLINE_ONLY adapters used to get Docker's default bridge --
                # every service on the runner's network -- and now get a per-run
                # internal network behind an allowlisting proxy, or do not run
                # at all. This is where the run says which. `{}` means no
                # manifest: nothing measured, not nothing granted.
                "network": reconciled.tools_network,
                # #3270: present only when the runner recorded the image.
                **({"image": reconciled.tools_image} if reconciled.tools_image else {})},
            **({"apps": apps} if apps else {}),
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
            "config": _config_block(run.config),
            **({"prior_run": prior} if prior else {}),
            **({"cvss_unscored": unscored} if unscored else {}),      # #3162
            **({"severity_capped": capped} if capped else {}),        # #3231
        },
        "summary": graded.summary,
        "groups": graded.groups,
        "findings": resolved.active,
        "discarded_claims": resolved.rejected,
        "cross_panel": {"integration_findings": resolved.integration_findings},
    }


def _needs_cvss(f):
    """The findings the reviewer prompt asks to score: agent-sourced security /
    redteam CRITICAL or HIGH. #3162: the same prompt says to OMIT a vector it
    cannot justify, so a missing one is disclosed (`meta.cvss_unscored`), never
    a schema error -- an invented score is worse than none."""
    return (not evidence_mod.is_tool_sourced(f) and f.get("panel") in ("security", "redteam")
            and f.get("severity") in ("CRITICAL", "HIGH"))


def cvss_unscored(findings):
    """#3162: the sorted ids of the findings `_needs_cvss` names that carry none."""
    return sorted(str(f.get("id")) for f in findings if _needs_cvss(f) and not f.get("cvss"))


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
        # #2174: a located finding with no line is the sanctioned whole-file shape (#1522).
        if not loc.get("file"):
            warnings.append("finding[%d] missing location.file" % i)
        if _needs_cvss(f):
            if not f.get("cvss"):      # #3162: disclosed as unscored, not an error
                warnings.append("finding[%d] %s %s has no cvss (meta.cvss_unscored)"
                                % (i, f["panel"], f["severity"]))
            if not f.get("exploit_scenario"):
                errors.append("finding[%d] %s %s missing exploit_scenario" % (i, f["panel"], f["severity"]))
    id_counts: dict[str, int] = {}
    for f in report.get("findings") or []:
        fid = f.get("id")
        if fid:
            id_counts[fid] = id_counts.get(fid, 0) + 1
    for fid, count in id_counts.items():
        if count > 1:
            errors.append("duplicate finding id: %s" % fid)
    return errors, warnings
