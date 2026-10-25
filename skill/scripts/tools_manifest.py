#!/usr/bin/env python3
"""The tools manifest: `tools-manifest.json`'s schema and the ledgers it reads.

The one writer of the SCANNER coverage manifest -- what was selected, what was
produced, what is therefore missing, and the observations published beside them:
the egress each tool was granted, whether every capture went through the
redaction choke point, what the run did with the target's own inline suppression
comments and its `.gitleaksignore`, which configuration file each pinned scanner
ran under, the adapters the gate's globs disqualified, the virtualenv
directories the scan pruned, what an adapter refused to hand its scanner, and
scanner containers whose best-effort cleanup failed. It also distinguishes a
clean automatic language measurement from a language-keyed scanner withheld by
the selection prune.
`security_gate` reads it, the tools phase copies `redacted` out of it and
`synthesize` refuses to certify against another run's, so every key here is a
published contract and the order they are written in is part of it.

NOT `run_manifest.py`, which writes the OTHER manifest -- the review RUN's (host,
run id, review root, baseline) -- and has a `write_manifest` of its own. Two
manifests, two modules, no shared code; `tests/test_run_manifest.py` is that
one's file.

Three of the five posture ledgers live here, beside their only reader: network
(#1645), the gitleaks ignore file and Semgrep's scanner-scope policy. The other
two -- inline suppression and scanner config -- belong to
`scanner_config`, which stages the files they are about. `run_tools` binds all
five back and is where each is cleared at the top of a scan and filled where the
argv is built; a ledger is the SAME dict object either way, so one name is one
ledger. The operational cleanup-failure ledger lives in `tool_capture`, where
the failure happens; this writer reads it after `run_tools` clears it per run.

Separate from `run_tools` because that module was 2215 lines, outside this
repo's own 700-line ratchet, and absorbing every new scanner policy because
nothing pushed back (#1762, ARC-2609514778). This is part 3 of 4 of that split
and it moved the block whole: no key, value, order, byte or message changed, and
`tests/test_tools_manifest.py` compares the exact BYTES of seven manifests --
both security modes, `run_id` set and unset, the eslint coverage read, an
adapter refused its egress and the docker-absent shape -- against a golden
captured before the move.

The arrow points ONE way: nothing here imports `run_tools`, which imports this.
That is why `VENV_MAX_DEPTH` lives here while the walk that reads it back
(`find_virtualenvs`) lives in `venv_scope`, part 4 of the same split, which
imports it from here. Stdlib-only.
"""
import argparse
import glob
import json
import os
import sys

from scripts import safe_write
from scripts import language_detection
from scripts.tolerant_json import depth_checked
# BY NAME, never `from scripts import scanner_config`: `write_manifest`'s
# published `scanner_config=` keyword would shadow a module binding inside the
# function body, so reaching a new constant that way needs a module ALIAS
# (`scanner_config as _scanner_config`) rather than the bare import.
from scripts.scanner_config import _SCANNER_CONFIG_POSTURE, _SUPPRESSION_POSTURE
from scripts.tool_capture import (
    MAX_TOOL_OUTPUT_BYTES, _CONTAINER_CLEANUP_FAILURES, _REDACTED_CAPTURES)
from scripts.tools import egress
from scripts.tools.legacy_sarif import LEGACY_SARIF_TOOLS

# How deep the virtualenv walk that found `excluded_dirs` looked, published as
# `depth_bound` so a reader knows the list is bounded rather than exhaustive. It
# lives HERE, and not with the walk, for the import direction: `run_tools` imports
# this module and never the reverse, and `write_manifest`'s `depth_bound` default
# is bound at `def` time, so the bound cannot be read back across the seam.
# `venv_scope.find_virtualenvs` -- the walk that is actually bounded by it, and
# its other reader -- imports it from here; `run_tools` binds it back for the
# tests that read it there. Venvs live near the root, and that walk is paid on
# every scan.
VENV_MAX_DEPTH = 3
LANGUAGE_DETECTION_SKIPS_MAX = language_detection.SKIPS_MAX

# #3269 SCA: the dependency surface is a separate fact from whether one pinned
# scanner can parse it. These six ecosystems are exactly the offline databases
# baked for osv-scanner; the broader marker table keeps an unaudited manifest
# visible instead of making truthful OSV selection weaken the coverage gate.
DEPENDENCY_AUDIT_ECOSYSTEMS = frozenset(
    {"go", "java", "javascript", "python", "ruby", "rust", "unknown"})
DEPENDENCY_AUDIT_TOOLS = frozenset({
    "bundler-audit", "cargo-audit", "dependency-check",
    "npm-audit", "osv-scanner", "pip-audit",
})
_DEPENDENCY_AUDIT_MARKERS = {
    "go": ("go.mod", "go.sum"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
             "buildscript-gradle.lockfile", "gradle/verification-metadata.xml"),
    "javascript": ("package.json", "package-lock.json", "npm-shrinkwrap.json",
                   "pnpm-lock.yaml", "yarn.lock"),
    "python": ("Pipfile", "Pipfile.lock", "pdm.lock", "poetry.lock",
               "pyproject.toml", "requirements.txt"),
    "ruby": ("Gemfile", "Gemfile.lock"),
    "rust": ("Cargo.toml", "Cargo.lock"),
}


def dependency_audit_applicable(target):
    """Sorted ecosystems with a root dependency surface in *target*.

    This deliberately recognizes manifests a dedicated offline adapter cannot
    parse. That mismatch is the receipt's purpose: applicable with no produced
    SCA output is visible and certification-sinking, never silently "clean".
    """
    found = {ecosystem for ecosystem, markers in _DEPENDENCY_AUDIT_MARKERS.items()
             if any(os.path.isfile(os.path.join(target, marker)) for marker in markers)}
    if next(glob.iglob(os.path.join(target, "requirements*.txt")), None):
        found.add("python")
    return sorted(found)


# What egress each tool was granted this run, keyed by tool name (#1645). Same
# construction and the same reason as `tool_capture._REDACTED_CAPTURES`:
# `run_tools()` clears it and fills it WHERE THE ARGV IS BUILT, so the manifest
# reports what the runner observed itself doing -- take the flags away and the
# claim goes with them, rather than a `proxied:` string surviving as an
# intention nothing enforces. Values are `"none"`, `"proxied:<allowlist>"` or
# the fail-closed `"excluded:online egress unavailable"`
# (scripts.tools.egress).
_NETWORK_POSTURE: dict[str, str] = {}

# Only a produced Gitleaks capture may carry this observation. Filled from the
# mount kept alive during its launch, then filtered to produced in write_manifest.
_IGNORE_FILE_POSTURE: dict[str, str] = {}

# The Semgrep argv policy that first removes the pin's four default test-path
# exclusions. The manifest records it from the command actually launched so a
# workflow can expand an older baseline by scanning its exact commit once.
SEMGREP_SCOPE_POLICY = "test-paths-v1"
_SCANNER_SCOPE_POSTURE: dict[str, str] = {}


def canonical_output_name(tool):
    """The one capture basename the runner writes for an adapter."""
    suffix = ".sarif" if tool in LEGACY_SARIF_TOOLS else ".json"
    return "%s%s" % (tool, suffix)


def output_receipt(manifest, expected_run_id=None, required=False):
    """Validate and return a manifest's exact run-owned output basenames.

    ``None`` preserves legacy/direct callers whose manifest predates the
    receipt. A driver-bound caller passes ``required=True`` and fails closed.
    """
    if not isinstance(manifest, dict):
        raise ValueError("tools manifest is not an object")
    if (expected_run_id is not None
            and manifest.get("run_id") != expected_run_id):
        raise ValueError("tools manifest run_id does not match this run")
    outputs = manifest.get("outputs")
    if outputs is None:
        if required:
            raise ValueError("tools manifest has no output receipt")
        return None
    produced = manifest.get("produced")
    if (not isinstance(produced, list)
            or any(not isinstance(tool, str) or not tool for tool in produced)):
        raise ValueError("tools manifest produced list is malformed")
    if (not isinstance(outputs, list)
            or any(not isinstance(name, str) or not name
                   or os.path.basename(name) != name for name in outputs)
            or len(set(outputs)) != len(outputs)):
        raise ValueError("tools manifest output receipt is malformed")
    expected = sorted(canonical_output_name(tool) for tool in produced)
    if sorted(outputs) != expected:
        raise ValueError("tools manifest output receipt is not the canonical output set")
    return tuple(sorted(outputs))


def _record_semgrep_scope(tool, cmd, policy_args):
    """Record v1 only when every scanner-owned scope argument reached argv."""
    if tool == "semgrep" and all(arg in cmd for arg in policy_args):
        _SCANNER_SCOPE_POSTURE[tool] = SEMGREP_SCOPE_POLICY


def validate_scanner_scope(data):
    """Return the optional scanner-scope map after validating its safe shape."""
    scope = data.get("scanner_scope", {})
    if (not isinstance(scope, dict)
            or any(not isinstance(k, str) or not k or not isinstance(v, str)
                   or not v or "\n" in k + v or "\r" in k + v
                   or k not in data.get("produced", [])
                   or k not in data.get("selected", [])
                   for k, v in scope.items())):
        raise ValueError("scanner manifest scanner_scope is malformed")
    return scope


def semgrep_scope_transition_needed(current_manifest, base_manifest):
    """Whether an exact base rescan is needed for Semgrep's v1 scope."""
    current = current_manifest.get("scanner_scope", {}).get("semgrep")
    previous = base_manifest.get("scanner_scope", {}).get("semgrep")
    return (current == SEMGREP_SCOPE_POLICY and previous is None
            and "semgrep" in current_manifest.get("selected", [])
            and "semgrep" in current_manifest.get("produced", [])
            and "semgrep" in base_manifest.get("selected", [])
            and "semgrep" in base_manifest.get("produced", []))


def _read_scope_manifest(path):
    """Read the bounded common manifest shape used by the rollout helper."""
    try:
        with open(path, "rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("scanner manifest exceeds 1000000 bytes")
        data = json.loads(raw)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("cannot read scanner manifest %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ValueError("scanner manifest is not an object: %s" % path)
    for key in ("selected", "produced", "missing"):
        if (not isinstance(data.get(key), list)
                or any(not isinstance(value, str) for value in data[key])):
            raise ValueError("scanner manifest %s is malformed: %s" % (path, key))
    if set(data["missing"]) != set(data["selected"]) - set(data["produced"]):
        raise ValueError("scanner manifest missing set is inconsistent: %s" % path)
    data["scanner_scope"] = validate_scanner_scope(data)
    return data


def prepare_semgrep_scope_baseline(baseline_dir, baseline_manifest_path,
                                   expanded_dir, expanded_manifest_path):
    """Replace old Semgrep evidence with an exact-base v1 scope capture.

    The expanded capture is made in the same job, with the current controller
    and image, against the commit that supplied the downloaded baseline. The
    manifest marker is published last so an interrupted preparation fails
    strictly instead of claiming coverage the baseline capture did not have.
    """
    baseline = _read_scope_manifest(baseline_manifest_path)
    expanded = _read_scope_manifest(expanded_manifest_path)
    if not semgrep_scope_transition_needed(expanded, baseline):
        raise ValueError("Semgrep scope baseline preparation was not required")
    if (set(expanded["selected"]) != {"semgrep"}
            or set(expanded["produced"]) != {"semgrep"}
            or expanded["missing"]
            or expanded.get("redacted") is not True
            or expanded.get("network", {}).get("semgrep") != "none"
            or expanded.get("exclude_globs", []) != baseline.get("exclude_globs", [])):
        raise ValueError("expanded Semgrep baseline has a different scan policy")
    source = os.path.join(expanded_dir, "semgrep.sarif")
    destination = os.path.join(baseline_dir, "semgrep.sarif")
    try:
        if os.path.islink(source):
            raise ValueError("expanded Semgrep capture is a symlink")
        with open(source, "rb") as stream:
            raw = stream.read(MAX_TOOL_OUTPUT_BYTES + 1)
        if len(raw) > MAX_TOOL_OUTPUT_BYTES:
            raise ValueError("expanded Semgrep capture exceeds the output cap")
        text = raw.decode("utf-8")
        sarif = json.loads(depth_checked(text))                # #2959
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("cannot read expanded Semgrep capture: %s" % exc) from exc
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise ValueError("expanded Semgrep capture is not SARIF")
    baseline["scanner_scope"] = dict(baseline.get("scanner_scope", {}))
    baseline["scanner_scope"]["semgrep"] = SEMGREP_SCOPE_POLICY
    for key in ("network", "suppression_comments", "scanner_config"):
        if not isinstance(baseline.get(key, {}), dict):
            raise ValueError("baseline scanner manifest is malformed: %s" % key)
        baseline[key] = dict(baseline.get(key, {}))
        if "semgrep" in expanded.get(key, {}):
            baseline[key]["semgrep"] = expanded[key]["semgrep"]
    safe_write.publish_texts([
        (baseline_manifest_path, baseline_manifest_path + ".scope.tmp",
         json.dumps(baseline, indent=2) + "\n"),
        (destination, destination + ".scope.tmp", text),
    ])
    return baseline


def _excluded_dir_row(d):
    """One `excluded_dirs` row for the manifest.

    #1740: `skipped` is the whole point of the row under redteam -- a name-only
    venv is DETECTED and scanned anyway. True for a caller that passed
    `find_virtualenvs` output directly, which is the pre-#1740 meaning of this
    list. #1839: `note` is present only when the runner had a reason of its own
    for scanning a directory it detected -- a marker with no environment under
    it, or a name no exclusion pattern can express -- so an operator reading
    `skipped: false` under `standard` is not left to guess which.
    """
    row = {"path": str(d["path"]), "reason": str(d["reason"]),
           "skipped": bool(d.get("skipped", True))}
    if d.get("note"):
        row["note"] = str(d["note"])
    return row


def write_manifest(path, selected, written, excluded_scope=(), run_id=None,
                   excluded_dirs=(), depth_bound=VENV_MAX_DEPTH, sanitized=None,
                   network=None, exclude_globs=(), suppression_comments=None,
                   scanner_config=None, ignore_files=None, scanner_scope=None,
                   cleanup_failures=None, language_detection_skips=None,
                   withheld=(), image=None, apps=None, dependency_applicable=None):
    """Write the exact selected/produced scanner set for coverage gating.

    `withheld` (#3265) names applicable adapters the operator did not enable:
    roslyn-secguard without --allow-target-build. Never in `selected`, so an
    adapter that is off by default is never `missing` and never sinks coverage;
    omitted when nothing was withheld, so every other manifest is unchanged.

    `excluded_scope` names adapters that were applicable but whose entire
    surface fell under the gate's --exclude globs; they are disclosed (never
    required), and are kept out of `selected` so the missing-set invariant
    holds.

    `excluded_dirs` (#1638 P09) are the virtualenv directories this scan
    DETECTED, as ``{"path", "reason", "skipped"[, "note"]}`` rows -- so a report can say
    what was pruned and on what evidence (`pyvenv.cfg` or the conventional
    name) rather than leaving a silent hole in the scanned surface. #1740:
    `skipped` is what separates the two, because under `--security redteam` a
    name-only directory is detected and scanned anyway; it defaults to True, so
    a caller handing `find_virtualenvs` output straight in still publishes this
    list's pre-#1740 meaning. `depth_bound` is how deep
    the walk that found them looked: the list is what the SCANNERS were told to
    skip, and ingest drops virtualenv findings at any depth, so a reader knows
    the list is bounded rather than exhaustive. Additive: both fields are new in
    this schema version and every consumer reads them optionally, so an older
    manifest without them still loads.

    `sanitized` (#1646) is what an adapter refused to hand its scanner, per
    adapter: `{"pip-audit": {"source", "kept", "dropped": [{"line", "reason"}],
    "hashes_stripped"}}`. pip-audit is now given a GENERATED requirements file
    holding only bare PEP 508 lines, because resolving an editable/local/VCS/URL
    requirement runs the reviewed repo's build backend -- so the dependency
    audit can be PARTIAL, and this is where it says by how much and which lines.
    Stated on every manifest, `{}` included, so its absence cannot be read as
    "nothing was dropped" on a run that never measured.

    `exclude_globs` (#1740 fix round 1) are the `--exclude` path globs this
    scan was given -- the driver passes the repository's committed
    `exclude_paths:`, CI passes its own. `excluded_scope` beside it names the
    ADAPTERS those globs disqualified; this is the policy itself, so a reader
    can tell "no adapter was excluded" from "no policy was applied". Stated on
    every manifest, `[]` included, like `sanitized`.

    `file_coverage` carries bounded scanner file facts derived from the exact
    written capture. Partial source coverage leaves produced/missing unchanged;
    ingestion independently derives the same facts for legacy raw arrays.

    `redacted` (#1639 P11) says whether every capture this run wrote went
    through the redaction choke point, read off the ledger
    `tool_capture._redact_capture` keeps -- an observation, so replacing the
    choke point with identity makes the claim go false rather than leaving a
    stale `true` behind. The tools phase copies it into `tools-ran.json`.

    `suppression_comments` (#1839) is what this run does with an inline
    suppression comment in the target's own source, per tool: `"ignored"` where
    the pinned scanner's knob for it was passed (`--security redteam`),
    `"honoured"` where the comment stood -- `standard` is an operator scanning
    their own repository, and where no knob exists at the pin it is a residual;
    this repository's own CI (`security.yml` and the fork-PR
    `security-fork.yml`) scans in `redteam`, so nothing target-authored is
    honoured on either check -- and
    `"n/a"` for a tool whose argv honours no such comment at all. A tool with no
    row was not ASSESSED, which is deliberately not the same claim as `n/a`.
    Defaults to the ledger `run_tools()` filled while building each argv -- an
    observation, like `redacted` and `network`. For a FLAG-lever tool (bandit,
    gitleaks) that observation is the argv itself, so taking the flag away makes
    the claim change rather than leaving an intention behind; for an INGEST-lever
    tool (`scanner_config.SUPPRESSION_INGEST_LEVER`, semgrep today) the argv
    decides nothing and the row follows the run's mode, which is what does. This
    row is about COMMENTS only. `ignore_files` separately records the source-root
    `.gitleaksignore` observed at launch: `honoured` for a target file allowed
    under standard, `neutralised` for the redteam empty-file mount, and
    `absent` when no file exists. Only a produced Gitleaks scan gets a row.
    An explicit map follows the same observation override pattern as
    `suppression_comments`; it is still filtered to produced Gitleaks.

    One row is true for a reason that is NOT on the argv, and this is the
    schema of record, so it says so: semgrep's. At the pin the scanner reports
    a `# nosemgrep`'d result whether or not `--disable-nosem` is passed, so the
    row is RECORDED from the mode (fix round 2: reading it off the belt flag
    would publish `honoured` for a redteam run the moment the belt came off)
    and the INGEST enforces it --
    `ingest_tools.ingest_dir_detailed` drops those results under `standard` and
    publishes the count per tool as `suppressed_in_source`, which is where a
    reader sees HOW MUCH a honoured comment cost. `run_tools` never sees that
    number: this manifest is written before anything is ingested.

    `scanner_config` (#1839) is which configuration file each pinned scanner ran
    under: `"scanner-owned"` for a constant of ours staged in a scratch, and
    `"target .bandit (its skips and tests)"` for the one case the owner ruling
    of 2026-09-25 leaves with the operator -- a `.bandit` committed to the repository being scanned,
    honoured under `standard` and never under `redteam`. Same construction as
    `network` above: read off the argv the runner built.

    `network` (#1645) is the egress each tool was given: `"none"` for the
    `--network none` containers, `"proxied:<allowlist>"` for an ONLINE_ONLY
    adapter that ran behind this run's proxy, and `"excluded:online egress
    unavailable"` for one that could not be given an egress path and was
    therefore NOT run. "pip-audit: produced" has never said what that scanner
    could reach while it ran, and this is where the answer goes. Defaults to
    the ledger `run_tools()` filled while building each argv -- an observation,
    like `redacted` -- and an explicit value is for a caller that did not run
    the loop. The third posture also MOVES the adapter: it leaves `selected`
    for `excluded_scope`, the shape the gate already reads as "applicable, not
    required by scope, disclosed"; the network refusal independently prevents
    coverage certification. An adapter left in both lists would read as a
    required scanner that went missing (and `security_gate` rejects the
    overlap outright).

    `scanner_scope` records a scanner-owned coverage policy observed on the
    launched argv. Its Semgrep v1 value marks the first policy that restores
    real test paths after disabling the target and embedded ignore files, and
    lets CI request an exact-base transition scan instead of waiving findings.

    `cleanup_failures` records a scanner container the best-effort timeout
    cleanup could not prove stopped, keyed by tool with a bounded, redacted
    `{kind, detail}` row. It defaults to the capture ledger populated at the
    same point as the stderr diagnostic and is omitted when no failure occurred;
    old manifests therefore remain readable without inventing a measurement.

    `language_detection_skips` (#3247) records the bounded language/tool rows
    auto-detection saw only under #1138's selection-pruned directories. ``[]``
    means measured clean; ``None`` omits the field when explicit CLI selection
    bypassed detection.

    `dependency_applicable` (#3269 SCA) enables the dependency-audit receipt.
    Applicability is an ecosystem enum measured from the target; selected and
    produced are derived here from the dedicated SCA adapters and this writer's
    exact output receipt. Trivy is intentionally not one: an empty generic
    filesystem SARIF does not prove that a dependency manifest was audited.
    ``None`` preserves direct/legacy callers that did not make the measurement;
    production `run_tools` always supplies it.
    """
    network = {str(k): str(v) for k, v in
               (_NETWORK_POSTURE if network is None else network).items()}
    refused = sorted(t for t, posture in network.items()
                     if posture.startswith(egress.EXCLUDED_PREFIX))
    selected = [t for t in selected if t not in set(refused)]
    excluded_scope = list(excluded_scope) + refused
    selected = list(dict.fromkeys(str(tool) for tool in selected))
    observed_cleanup = (_CONTAINER_CLEANUP_FAILURES
                        if cleanup_failures is None else cleanup_failures)
    cleanup = {
        str(tool): {"kind": row["kind"], "detail": row["detail"]}
        for tool, row in (observed_cleanup or {}).items()
        if (str(tool) in selected and isinstance(row, dict)
            and isinstance(row.get("kind"), str) and row["kind"]
            and isinstance(row.get("detail"), str) and row["detail"])
    }
    outputs = sorted({os.path.basename(p) for p in written})
    produced = sorted({os.path.splitext(name)[0] for name in outputs})
    observed_ignore_files = (_IGNORE_FILE_POSTURE if ignore_files is None
                             else ignore_files)
    observed_scope = (_SCANNER_SCOPE_POSTURE if scanner_scope is None
                      else scanner_scope)
    file_coverage = {}
    for capture_path in written:
        if os.path.basename(capture_path) == "eslint-security.json":
            from scripts.tools.eslint_security import file_coverage as eslint_coverage
            try:
                with open(capture_path, "rb") as capture:
                    data = capture.read(MAX_TOOL_OUTPUT_BYTES + 1)
                if len(data) <= MAX_TOOL_OUTPUT_BYTES:
                    file_coverage["eslint-security"] = eslint_coverage(json.loads(depth_checked(data)))
            except (OSError, ValueError):
                pass  # ingestion retains the whole-capture failure path
    payload = {"schema_version": 1, "run_id": run_id,
               "file_coverage": file_coverage,
               "selected": selected, "produced": produced,
               "outputs": outputs,
               "missing": sorted(set(selected) - set(produced)),
               # #1639 P11 F5: what the runner OBSERVED, not what it intends --
               # every capture written this run passed
               # `tool_capture._redact_capture`. False when nothing was written
               # (there is nothing to vouch for) and false if any capture
               # reached disk without the pass, so the phase can copy the
               # answer into `tools-ran.json` instead of asserting another
               # module's behaviour with a literal.
               "redacted": bool(produced) and all(
                   tool in _REDACTED_CAPTURES for tool in produced),
               "excluded_scope": sorted(dict.fromkeys(str(t) for t in excluded_scope)),
               "network": network,
               "suppression_comments": {
                   str(k): str(v) for k, v in
                   (_SUPPRESSION_POSTURE if suppression_comments is None
                    else suppression_comments).items()},
               "ignore_files": {"gitleaks": observed_ignore_files["gitleaks"]}
               if ("gitleaks" in produced
                   and isinstance(observed_ignore_files.get("gitleaks"), str)
                   and observed_ignore_files["gitleaks"] in
                   ("honoured", "neutralised", "absent")) else {},
               "scanner_config": {
                   str(k): str(v) for k, v in
                   (_SCANNER_CONFIG_POSTURE if scanner_config is None
                    else scanner_config).items()},
               "scanner_scope": {
                   str(k): str(v) for k, v in observed_scope.items()
                   if k in produced and k in selected},
               "sanitized": dict(sanitized or {}),
               "exclude_globs": [str(g) for g in exclude_globs or ()],
               "excluded_dirs": [_excluded_dir_row(d) for d in excluded_dirs or ()],
               "depth_bound": depth_bound}
    if dependency_applicable is not None:
        ecosystems = DEPENDENCY_AUDIT_ECOSYSTEMS - {"unknown"}
        payload["dependency_audit"] = {
            "applicable": sorted({value for value in dependency_applicable
                                  if value in ecosystems}),
            "selected": sorted(set(selected) & DEPENDENCY_AUDIT_TOOLS),
            "produced": sorted(set(produced) & DEPENDENCY_AUDIT_TOOLS),
        }
    if language_detection_skips is not None:
        rows = list(language_detection_skips)
        assert len(rows) <= LANGUAGE_DETECTION_SKIPS_MAX
        assert all(language_detection.valid_skip_row(row) for row in rows)
        payload["language_detection_skips"] = [dict(row) for row in rows]
    output_receipt(payload, expected_run_id=run_id, required=True)
    if cleanup:
        payload["cleanup_failures"] = cleanup
    held = sorted({str(t) for t in withheld} - set(selected))
    if held:                   # #3265: absent when nothing was withheld, like cleanup
        payload["withheld"] = held
    # #3270: the tools image's identity and docker's app record, from
    # run_tools.main; absent on a direct caller, so every other manifest is
    # byte-identical. `tools_image.repair`/`app_trace.repair` re-read them.
    if image is not None:
        payload["image"] = dict(image)
    if apps:
        payload["apps"] = [dict(app) for app in apps]
    # #1735: the driver points --manifest at `<run folder>/tools-manifest.json`,
    # inside the reviewed tree. Confine before the makedirs (a symlinked
    # intermediate would be traversed by it) and never open through a link.
    safe_write.confine_artifact_path(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with safe_write.open_w_nofollow(path) as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return payload


def manifest_cli(argv=None):
    parser = argparse.ArgumentParser(description="manage scanner-scope manifests")
    commands = parser.add_subparsers(dest="command", required=True)
    needed = commands.add_parser("semgrep-scope-transition-needed")
    needed.add_argument("--current-manifest", required=True)
    needed.add_argument("--baseline-manifest", required=True)
    prepare = commands.add_parser("prepare-semgrep-scope-baseline")
    prepare.add_argument("--baseline-dir", required=True)
    prepare.add_argument("--baseline-manifest", required=True)
    prepare.add_argument("--expanded-dir", required=True)
    prepare.add_argument("--expanded-manifest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "semgrep-scope-transition-needed":
            current = _read_scope_manifest(args.current_manifest)
            baseline = _read_scope_manifest(args.baseline_manifest)
            print("true" if semgrep_scope_transition_needed(current, baseline)
                  else "false")
        else:
            prepare_semgrep_scope_baseline(
                args.baseline_dir, args.baseline_manifest,
                args.expanded_dir, args.expanded_manifest)
    except ValueError as exc:
        print("tools-manifest: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(manifest_cli())
