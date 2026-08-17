"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import argparse
import dataclasses
import glob as _glob
import json
import os
import shutil
import subprocess
import sys

# #5.0-01: when run directly (`python3 skill/scripts/driver.py run ...`, the
# documented entrypoint) the package roots are not on sys.path, so the
# `import scripts.*` below crash with ModuleNotFoundError. Bootstrap the same
# roots _child_env() puts on PYTHONPATH for subprocesses. Idempotent under
# pytest, whose conftest already provides them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # skill/scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # skill

import yaml

import scripts.coverage_model as coverage_model
import scripts.diff_map as diff_map
import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.groups_schema as groups_schema
import scripts.ocrdb as ocrdb
import scripts.run_manifest as run_manifest
import scripts.score_gate as score_gate
import scripts.setup_flow as setup_flow
import scripts.synthesize as synthesize

CHECKPOINT_KINDS = ("scout", "review", "verify", "scan")

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


class DriverError(Exception):
    """A hard phase failure. main() converts it to a status:'error' result."""


def _script(name):
    return os.path.join(_SCRIPTS_DIR, name)


def _child_env():
    """Env for subprocessed panopticon CLIs. They do `import scripts.*` (a
    namespace package) plus BARE imports of both skill/scripts modules (e.g.
    `import evidence`) and repo-root scripts/ modules (e.g. `import file_issues`),
    so PYTHONPATH must mirror tests/conftest.py exactly: skill, skill/scripts,
    and <repo>/scripts."""
    scripts_dir = _SCRIPTS_DIR                         # .../skill/scripts
    skill_dir = os.path.dirname(scripts_dir)           # .../skill
    repo_root = os.path.dirname(skill_dir)             # .../panopticon
    repo_scripts = os.path.join(repo_root, "scripts")  # .../panopticon/scripts
    env = dict(os.environ)
    parts = [skill_dir, scripts_dir, repo_scripts]
    env["PYTHONPATH"] = os.pathsep.join(
        parts + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


def _pano(review_root, *parts):
    return os.path.join(review_root, ".panopticon", *parts)


def _abs_file_list(review_root, files):
    """Bullet list of files absolutized against review_root (#975): the reviewer
    subagent inherits the HOST's cwd, not review_root/the --pr worktree, so a
    bare-relative path resolves against the wrong tree. File-list specific — do
    NOT route tests or other bullet lists through this; they stay repo-relative."""
    return "\n".join(
        "- " + os.path.abspath(os.path.join(review_root, f)) for f in files
    ) or "- (no files)"


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path


def _json_parses(path):
    return _load_json(path) is not None


def load_committed_groups(review_root):
    """Parse the committed groups.yml via groups_schema (P1). A MISSING file is
    an error (the driver run requires a committed matrix — `panopticon setup`
    produces it), not an empty success."""
    path = _pano(review_root, "groups.yml")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}, ["no committed groups.yml at %s — run `panopticon setup` first"
                    % path]
    except (OSError, yaml.YAMLError) as exc:
        return {}, ["groups.yml unreadable: %s" % exc]
    return groups_schema.parse_groups(doc if isinstance(doc, dict) else {})


def discovery_done(review_root, manifest):
    return _json_parses(_pano(review_root, "groups.json"))


def discovery_execute(review_root, manifest):
    _groups, errors = load_committed_groups(review_root)
    if errors:
        raise DriverError("discovery: " + "; ".join(errors))
    out = _pano(review_root, "groups.json")
    cmd = [sys.executable, _script("discovery.py"), "--repo-scan",
           "--security", manifest.get("security_mode", "standard"),
           review_root, "--out", out]
    scope = manifest.get("scope") or {"mode": "repo"}
    mode = scope.get("mode")
    if mode == "changed":
        cmd += ["--scope-changed"]
    elif mode == "files":
        cmd += ["--scope-files"] + list(scope.get("target") or [])
    else:
        _scope_arg = {"file": "--scope-file", "directory": "--scope-dir",
                      "group": "--scope-group"}.get(mode)
        if _scope_arg and scope.get("target"):
            cmd += [_scope_arg, scope["target"]]
    if manifest.get("base"):
        cmd += ["--base", manifest["base"]]
    if manifest.get("pr_base"):
        cmd += ["--pr-base", manifest["pr_base"]]
    _dc = (manifest.get("flags") or {}).get("diff_context")
    if _dc is not None:
        cmd += ["--diff-context", str(_dc)]
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    if not _json_parses(out):
        raise DriverError(
            "discovery: discovery --repo-scan produced no groups.json "
            "(rc=%s): %s" % (proc.returncode, (proc.stderr or proc.stdout)[:400]))
    return PhaseResult(kind="advanced", message="discovery: groups.json written")


def resolve_review_root(target, base=None, pr=None, runner=subprocess.run):
    """Resolve the single review root, pinned once in the manifest (spec §5).

    - pr given: acquire the deterministic PR worktree (diff_map); its path is
      the root.
    - git repo: `git rev-parse --show-toplevel` from the target.
    - non-git: the target directory itself.
    Returns (review_root, worktree, pr_base): worktree is the PR worktree to
    release at validate (else None); pr_base is the PR's base branch as read
    by the acquire (else None), for `run()` to pin as the manifest base.
    """
    if pr is not None:
        info = diff_map.acquire_pr(pr, repo=target, runner=runner)
        return info["worktree"], info["worktree"], info["base"]
    target = os.path.abspath(target)
    start = target if os.path.isdir(target) else os.path.dirname(target)
    try:
        proc = runner(["git", "-C", start, "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            return os.path.realpath(proc.stdout.strip()), None, None
    except OSError:
        pass
    return (start if os.path.isdir(start) else target), None, None


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    kind: str        # "deterministic" | "checkpoint" | "mixed"
    done: object     # callable(review_root, manifest) -> bool
    execute: object  # callable(review_root, manifest) -> PhaseResult


@dataclasses.dataclass
class PhaseResult:
    kind: str                     # "advanced" | "checkpoint"
    checkpoint: str = None        # scout|review|verify (iff kind == "checkpoint")
    group: str = None
    dispatch_request: str = None  # absolute path (iff checkpoint)
    message: str = ""


def _first_not_done(phases, review_root, manifest):
    for phase in phases:
        if not phase.done(review_root, manifest):
            return phase
    return None


def run_engine(review_root, manifest, phases, max_steps=None):
    """Advance the state machine from disk. Repeatedly executes the first
    not-done phase until a checkpoint stops it or every phase is done. Returns a
    status dict; never exits (the CLI owns process exit).

    The cursor is recomputed every iteration, so a mixed phase that advances one
    unit at a time is simply re-selected until its done() is satisfied.
    """
    advanced = []
    # Progress guard: a buggy phase that returns "advanced" but never satisfies
    # done() would spin forever. Cap the work and fail loudly. The bound is far
    # above any real (phase-count + group-count) unit total.
    if max_steps is None:
        max_steps = 10000
    for _ in range(max_steps):
        phase = _first_not_done(phases, review_root, manifest)
        if phase is None:
            return {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None,
                    "advanced": advanced, "message": "all phases complete"}
        result = phase.execute(review_root, manifest)
        if result.kind == "checkpoint":
            return {"status": "checkpoint", "phase": phase.name,
                    "checkpoint": result.checkpoint, "group": result.group,
                    "dispatch_request": result.dispatch_request,
                    "advanced": advanced,
                    "message": result.message or ("%s checkpoint" % result.checkpoint)}
        if phase.name not in advanced:
            advanced.append(phase.name)
    raise RuntimeError(
        "driver engine exceeded %d steps without completing — a phase returned "
        "'advanced' without satisfying its done() predicate" % max_steps)


def emit_status(status, stream=None):
    """Print the status JSON and return the process exit code: 0 for
    checkpoint/complete, 1 for error. The CLI does `sys.exit(emit_status(...))`."""
    (stream or sys.stdout).write(json.dumps(status) + "\n")
    return 1 if status.get("status") == "error" else 0


def write_dispatch_request(review_root, run_id, checkpoint, group, entries):
    """Write the single per-(group, checkpoint) dispatch-request.json and return
    its ABSOLUTE path. Host-agnostic: entries carry only neutral fields and any
    paths inside them must already be absolute (spec §4). The request is rolling
    — the durable state is the entries' out_files, not this file."""
    if checkpoint not in CHECKPOINT_KINDS:
        raise ValueError("unknown checkpoint kind: %r" % checkpoint)
    request = {"schema_version": 1, "run_id": run_id, "checkpoint": checkpoint,
               "group": group, "entries": list(entries)}
    path = os.path.join(review_root, ".panopticon", "dispatch-request.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(request, fh, indent=2)
    return os.path.abspath(path)


def load_dispatch_request(review_root):
    """The parsed .panopticon/dispatch-request.json (or None if absent/invalid).
    The host reads req['entries'] to install the write-guard
    (write_guard_hook.install(entries)) and to dispatch the checkpoint's cells."""
    return _load_json(_pano(review_root, "dispatch-request.json"))


def _discovered_groups(review_root):
    """(name, files) per group from discovery's groups.json."""
    data = _load_json(_pano(review_root, "groups.json")) or {}
    return [(g.get("name"), g.get("files") or [])
            for g in (data.get("groups") or [])
            if isinstance(g, dict) and g.get("name")]


def _scout_entry(review_root, manifest, group, files, host):
    """One host-agnostic scout dispatch entry (spec §4). The scout body +
    tool-policy line come from dispatch.render_prompt; the assignment is
    appended. Enforcement is host-declared (claude registers panopticon-scout)."""
    body = dispatch.render_prompt("scout.md", {}, host)
    security = manifest.get("security_mode", "standard")
    file_list = _abs_file_list(review_root, files)
    prompt = (body
              + "\n\n## Assignment\n\nGroup: %s\nSecurity mode: %s\n\nFiles:\n%s\n"
                % (group, security, file_list)
              + "\nReturn the ScopeProfile JSON for this group.")
    enforced = host == "claude"
    return {"id": "scout-%s" % group,
            "agent": dispatch.registered_agent_name("scout.md") if enforced else None,
            "enforced": enforced,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(_pano(review_root, "scout-%s.json" % group))}


def coverage_done(review_root, manifest):
    # Vacuously done when discovery produced no groups (empty target); otherwise
    # done once every discovered group has a coverage file. (Evaluated only after
    # discovery, an earlier phase, so groups.json is already present.)
    return all(_json_parses(_pano(review_root, "coverage-%s.json" % g))
               for g, _ in _discovered_groups(review_root))


def coverage_execute(review_root, manifest):
    """Per group: emit the scout checkpoint (streamed) if its output is absent,
    else compute coverage as floor widened by the scout's valid domains.
    Returns after one unit of work; the engine re-selects coverage until
    every group has a coverage file."""
    matrix, _errors = load_committed_groups(review_root)
    host = manifest.get("host", "claude")
    for group, files in _discovered_groups(review_root):
        if _json_parses(_pano(review_root, "coverage-%s.json" % group)):
            continue
        scout_path = _pano(review_root, "scout-%s.json" % group)
        if not _json_parses(scout_path):
            entry = _scout_entry(review_root, manifest, group, files, host)
            req = write_dispatch_request(review_root, manifest["run_id"],
                                         "scout", group, [entry])
            return PhaseResult(kind="checkpoint", checkpoint="scout", group=group,
                               dispatch_request=req,
                               message="scout checkpoint for group %s" % group)
        # scout landed -> widen coverage by the scout's valid domains (P4 bridge)
        scout = _load_json(scout_path) or {}
        raw = scout.get("domains") or []
        spec = matrix.get(group) or {}
        floor = spec.get("floor", set())
        # net against floor here so disclosure["scout_added"] reports only the
        # genuinely NEW domains (a domain already on the floor isn't "added").
        scout_added = {d for d in raw if d in groups_schema.DOMAINS} - set(floor)
        scout_invalid = sorted(set(raw) - groups_schema.DOMAINS)
        effective, disclosure = coverage_model.effective_panels(
            floor, scout_added, spec.get("exclude", set()))
        _write_json(_pano(review_root, "coverage-%s.json" % group), {
            "group": group,
            "floor": disclosure["floor"],
            "excluded": disclosure["excluded"],
            "scout_added": disclosure["scout_added"],   # new domains, exclude-netted
            "scout_invalid": scout_invalid,             # dropped, disclosed
            "effective": sorted(effective),
            "scout_file": os.path.abspath(scout_path),
            "run_id": manifest["run_id"],
        })
        return PhaseResult(kind="advanced",
                           message="coverage: group %s (floor+scout)" % group)
    return PhaseResult(kind="advanced", message="coverage: complete")


def tools_done(review_root, manifest):
    return _json_parses(_pano(review_root, "tools-ran.json"))


def tools_execute(review_root, manifest):
    if (manifest.get("flags") or {}).get("tools") is False:
        _write_json(_pano(review_root, "tools-ran.json"),
                    {"ran": False, "skipped": True, "note": "tools disabled (--no-tools)",
                     "returncode": None, "run_id": manifest["run_id"]})
        return PhaseResult(kind="advanced", message="tools: skipped (--no-tools)")
    out_dir = _pano(review_root, "tools")
    cmd = [sys.executable, _script("run_tools.py"), "--target", review_root,
           "--out", out_dir, "--deps"]
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    produced = os.path.isdir(out_dir) and bool(os.listdir(out_dir))
    note = "" if produced else ((proc.stderr or "").strip()[:300] or "no tool output produced")
    _write_json(_pano(review_root, "tools-ran.json"),
                {"ran": produced, "skipped": not produced, "note": note,
                 "returncode": proc.returncode, "run_id": manifest["run_id"]})
    if not produced:
        sys.stderr.write("driver: tool scan produced no output — %s\n" % note)
    return PhaseResult(kind="advanced",
                       message="tools: %s" % ("produced output" if produced
                                              else "SKIPPED — " + note))


def _effective_domains(review_root, group):
    cov = _load_json(_pano(review_root, "coverage-%s.json" % group)) or {}
    return list(cov.get("effective") or [])


def _cell_done(review_root, manifest, group, domain):
    data = _load_json(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
        return False
    meta = data.get("_panopticon")
    return (isinstance(meta, dict) and meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group)


def _render_menu(bundle, domain):
    lines = ["%s %s (%s)" % (m["code"], m["name"], m["severity"])
             for m in ocrdb.domain_menu(bundle, domain)]
    return "\n".join(lines) or "(no OCRDb bundle vendored — use general %s judgment)" % domain


def _cell_entry(review_root, manifest, group, domain, files, tests, host, bundle):
    file_list = _abs_file_list(review_root, files)
    test_list = "\n".join("- " + t for t in tests) or "- (no tests)"
    out_file = os.path.abspath(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    prompt = dispatch.render_prompt("domain-panel.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "tests": test_list, "security_mode": manifest.get("security_mode", "standard"),
        "menu": _render_menu(bundle, domain), "run_id": manifest["run_id"],
        "out_file": out_file}, host)
    enforced = host == "claude"
    return {"id": "review-%s-%s" % (group, domain),
            "agent": dispatch.registered_agent_name("domain-panel.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


def _load_cell_findings(review_root, manifest, group, domain):
    """The cell's reviewer findings, normalized + id-assigned exactly as
    synthesize.load_findings does, or None when the cell file is absent/mismatched.
    Ids match synthesize's so the advisor's finding_id echo binds at synthesis.

    Strips synthesize.AGENT_FORBIDDEN_FIELDS (source/reinforced/corroborated/
    corroborated_by/evidence) before normalizing, mirroring synthesize.load_findings:
    a raw panel finding must never carry a self-asserted `evidence.status` into
    score_gate.should_engage_primary, or a forged "rejected" (factor 0.0) would
    let a finding duck the F_p gate entirely.

    verify_execute/verify_done feed this RAW per-cell list straight into
    score_gate.should_engage_primary -- no cross-cell dedup. synthesize's own
    engagement check (engaged_matrix_cells) scores the deduped/aggregated list
    produced by prepare_for_queue instead, so synth-engaged is a subset of
    driver-engaged, never the reverse. This is a bounded, safe discrepancy:
    verify_done gates synthesize (every driver-engaged cell already has a
    bundle before synthesize runs), but meta.coverage.verify_matrix.engaged can
    undercount when exact-duplicate findings collapse in dedup."""
    if not _cell_done(review_root, manifest, group, domain):
        return None
    data = _load_json(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    out = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        raw = dict(f)
        for k in synthesize.AGENT_FORBIDDEN_FIELDS:
            raw.pop(k, None)
        nf = synthesize.normalize_finding(raw)
        if not synthesize.ID_RE.match(nf.get("id") or ""):
            nf["id"] = evidence.matrix_finding_id(nf)
        out.append(nf)
    return out


def _verify_out_file(review_root, group, domain, stage):
    suffix = "-backup" if stage == "backup" else ""
    return os.path.abspath(_pano(review_root, "verdicts",
                                 "verdicts-%s-%s%s.json" % (group, domain, suffix)))


def _verify_cell_done(review_root, manifest, group, domain, stage):
    data = _load_json(_verify_out_file(review_root, group, domain, stage))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return False
    meta = data.get("_panopticon") or {}
    return (meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group
            and meta.get("stage", "primary") == stage)


def _render_findings(cell):
    """The cell's claims as a compact JSON array the advisor adjudicates."""
    slim = [{"id": f["id"], "code": f.get("code"), "severity": f["severity"],
             "title": f["title"], "category": f.get("category"),
             "location": f.get("location"), "description": f.get("description", "")}
            for f in cell]
    return json.dumps(slim, indent=2)


def _verify_entry(review_root, manifest, group, domain, files, cell, host, bundle, stage):
    file_list = _abs_file_list(review_root, files)
    out_file = _verify_out_file(review_root, group, domain, stage)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(cell), "menu": _render_menu(bundle, domain),
        "run_id": manifest["run_id"], "stage": stage, "out_file": out_file}, host)
    # #975: pin the review root for the advisor too. Unlike the scout/panel file
    # list above, the findings JSON's `location` fields are carried verbatim from
    # the panel's raw claims and stay repo-relative on disk (_render_findings) —
    # Part A's abspath can't reach into that payload. The advisor inherits the
    # HOST's cwd (the user's checkout), never review_root/the --pr worktree, so
    # without this header a relative `location` resolves against the wrong tree.
    prompt = ("Repo root: %s\nEvery relative path in the claims below resolves "
              "against this root -- read files THERE, never in your session's "
              "default checkout.\n\n%s" % (os.path.abspath(review_root), prompt))
    enforced = host == "claude"
    return {"id": "verify-%s-%s-%s" % (group, domain, stage),
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


def review_done(review_root, manifest):
    groups = _discovered_groups(review_root)
    if not groups:
        return True   # vacuous (no groups)
    return all(_cell_done(review_root, manifest, g, d)
               for g, _ in groups for d in _effective_domains(review_root, g))


def review_execute(review_root, manifest):
    host = manifest.get("host", "claude")
    bundle = ocrdb.load_bundle()
    # group tests come from the committed matrix (parse_groups tests field)
    matrix, _errors = load_committed_groups(review_root)
    for group, files in _discovered_groups(review_root):
        domains = _effective_domains(review_root, group)
        pending = [d for d in domains if not _cell_done(review_root, manifest, group, d)]
        if not pending:
            continue
        tests = sorted((matrix.get(group) or {}).get("tests") or [])
        entries = [_cell_entry(review_root, manifest, group, d, files, tests, host, bundle)
                   for d in pending]
        req = write_dispatch_request(review_root, manifest["run_id"], "review", group, entries)
        return PhaseResult(kind="checkpoint", checkpoint="review", group=group,
                           dispatch_request=req,
                           message="review: %d cell(s) for group %s" % (len(entries), group))
    return PhaseResult(kind="advanced", message="review: all cells complete")


def verify_execute(review_root, manifest):
    os.makedirs(_pano(review_root, "verdicts"), exist_ok=True)
    host = manifest.get("host", "claude")
    bundle = ocrdb.load_bundle()
    # PRIMARY round: one advisor per engaged (>= F_p), not-yet-verified cell,
    # streamed per group (first group with pending work emits, like review_execute).
    for group, files in _discovered_groups(review_root):
        pending = []
        for domain in _effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue   # unreviewed, or below-gate: unverified + disclosed at synth
            if _verify_cell_done(review_root, manifest, group, domain, "primary"):
                continue
            pending.append((domain, cell))
        if pending:
            entries = [_verify_entry(review_root, manifest, group, d, files, c,
                                     host, bundle, "primary") for d, c in pending]
            req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                         group, entries)
            return PhaseResult(kind="checkpoint", checkpoint="verify", group=group,
                               dispatch_request=req,
                               message="verify: %d primary advisor(s) for group %s"
                               % (len(entries), group))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(review_root, manifest, host, bundle)
    if backup is not None:
        return backup
    return PhaseResult(kind="advanced", message="verify: all cells verified")


def verify_done(review_root, manifest):
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue
            if not _verify_cell_done(review_root, manifest, group, domain, "primary"):
                return False
    return _verify_backup_done(review_root, manifest)


def _cell_backup_findings(review_root, manifest, group, domain):
    """The cell's primary-CONFIRMED findings that sit in a category scoring
    >= F_b on primary-stage evidence — the adversarial backup's scope. [] when
    the primary bundle is absent or no category clears F_b."""
    cell = _load_cell_findings(review_root, manifest, group, domain)
    if not cell:
        return []
    primary = _load_json(_verify_out_file(review_root, group, domain, "primary"))
    if not (isinstance(primary, dict) and isinstance(primary.get("verdicts"), list)):
        return []
    by_fid = {str(v.get("finding_id")): v for v in primary["verdicts"]
              if isinstance(v, dict) and v.get("finding_id")}
    for f in cell:
        f["evidence"] = evidence.derive_evidence(f, by_fid.get(str(f["id"])))
    by_cat = {}
    for f in cell:
        by_cat.setdefault(f.get("category") or "general", []).append(f)
    out = []
    for cat_findings in by_cat.values():
        if score_gate.should_summon_backup(cat_findings):
            out += [f for f in cat_findings
                    if (f["evidence"].get("status") == "advisor_confirmed")]
    return out


def _verify_backup_execute(review_root, manifest, host, bundle):
    for group, files in _discovered_groups(review_root):
        pending = []
        for domain in _effective_domains(review_root, group):
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if not scope:
                continue
            if _verify_cell_done(review_root, manifest, group, domain, "backup"):
                continue
            pending.append((domain, scope))
        if pending:
            entries = [_verify_entry(review_root, manifest, group, d, files, c,
                                     host, bundle, "backup") for d, c in pending]
            req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                         group, entries)
            return PhaseResult(kind="checkpoint", checkpoint="verify", group=group,
                               dispatch_request=req,
                               message="verify: %d backup advisor(s) for group %s"
                               % (len(entries), group))
    return None


def _verify_backup_done(review_root, manifest):
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            if _cell_backup_findings(review_root, manifest, group, domain) \
                    and not _verify_cell_done(review_root, manifest, group, domain, "backup"):
                return False
    return True


def synthesize_done(review_root, manifest):
    return _json_parses(_pano(review_root, "report.json"))


def synthesize_execute(review_root, manifest):
    findings = sorted(_glob.glob(_pano(review_root, "findings-*.json")))
    verdicts_dir = _pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = _pano(review_root, "report.json")
    flags = manifest.get("flags") or {}
    cmd = [sys.executable, _script("synthesize.py"),
           "--out", report,
           "--groups", _pano(review_root, "groups.json"),
           "--security", manifest.get("security_mode", "standard"),
           "--verdicts-dir", verdicts_dir]
    if (_load_json(_pano(review_root, "tools-ran.json")) or {}).get("ran"):
        cmd += ["--tools-dir", _pano(review_root, "tools")]
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity"),
                      ("--gate-scope", "gate_scope")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    diff_hunks = _pano(review_root, "diff-hunks.json")
    if os.path.isfile(diff_hunks):
        cmd += ["--diff-hunks", diff_hunks]
    if flags.get("diff_context") is not None:
        cmd += ["--diff-context", str(flags["diff_context"])]
    cmd += findings
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    # A failing gate exits non-zero but still writes the report — that is a valid
    # outcome, not a driver error. Only an ABSENT report is a failure.
    if not _json_parses(report):
        raise DriverError("synthesize produced no report.json (rc=%s): %s"
                          % (proc.returncode, (proc.stderr or proc.stdout)[:400]))
    return PhaseResult(kind="advanced", message="synthesize: report.json written")


def capture_tree_baseline(review_root, runner=subprocess.run):
    """Snapshot the clean-tree baseline once (run start). No-op for a non-git
    target (returns None)."""
    baseline = _pano(review_root, "tree-baseline.txt")
    if os.path.exists(baseline):
        return baseline
    proc = runner(["git", "-C", review_root, "status", "--porcelain"],
                  capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with open(baseline, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    return baseline


def _delta_path(line):
    """The current working-tree path from a porcelain v1 line 'XY <path>'.
    For a rename ('R  old -> new') the DESTINATION is what matters."""
    path = line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path


def _tree_delta(review_root, runner):
    """NEW porcelain lines (vs. baseline) whose path is outside .panopticon/.
    Empty when there is no baseline (non-git) — nothing to compare."""
    try:
        with open(_pano(review_root, "tree-baseline.txt"), encoding="utf-8") as fh:
            baseline = set(fh.read().splitlines())
    except OSError:
        return []
    proc = runner(["git", "-C", review_root, "status", "--porcelain"],
                  capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    new = set(proc.stdout.splitlines()) - baseline
    # NEW/changed porcelain lines whose FIRST PATH COMPONENT is not `.panopticon`
    # (a real boundary check: '.panopticon-evil.py' is NOT under .panopticon/).
    return sorted(line for line in new
                  if _delta_path(line).split("/", 1)[0] != ".panopticon")


def validate_done(review_root, manifest):
    data = _load_json(_pano(review_root, "validate.json"))
    return (isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
            and data.get("tree_clean") is True)


def validate_execute(review_root, manifest, runner=subprocess.run):
    delta = _tree_delta(review_root, runner)
    # The PR worktree (when review_root IS the worktree) is released by run()
    # AFTER the run completes, NOT here: releasing mid-machine would delete the
    # review root (report.json + manifest) and break cursor derivation. (Ruling A)
    _write_json(_pano(review_root, "validate.json"),
                {"run_id": manifest["run_id"], "tree_clean": not delta,
                 "unexpected_changes": delta})
    if delta:
        raise DriverError("validate: reviewer side effects outside .panopticon/: "
                          + "; ".join(delta[:10]))
    return PhaseResult(kind="advanced", message="validate: clean tree")


def _finalize_worktree(review_root, manifest):
    """On a completed --pr run, review_root IS the disposable worktree. Surface
    report.json to the caller's target .panopticon/ BEFORE releasing the worktree
    so the deliverable survives disposal (spec §4: no leak + report available).
    Best-effort surface; release is tolerant. No-op when there is no worktree."""
    worktree = manifest.get("worktree")
    if not worktree:
        return
    target = manifest.get("target") or review_root
    src = _pano(review_root, "report.json")
    dst = _pano(target, "report.json")
    if os.path.realpath(src) != os.path.realpath(dst) and os.path.isfile(src):
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
        except OSError:
            pass
    diff_map.release_worktree(worktree, repo=target)


SETUP_MANIFEST = "setup-manifest.json"


def _setup_manifest_path(review_root):
    return _pano(review_root, SETUP_MANIFEST)


def load_setup_manifest(review_root):
    return _load_json(_setup_manifest_path(review_root))


def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _setup_scan_entry(review_root, prompt):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file.

    Unlike scout/panel/advisor roles, setup-scan is NEVER enforced: it is not in
    dispatch.ROLE_FILES, so no `panopticon-setup-scan` shell is ever registered
    for any host — dispatching it as "enforced" would ask the host to invoke a
    subagent that doesn't exist. It is read-only + return-persist by template
    tool_policy (Read/Grep/Glob only), so a plain general-purpose dispatch is
    sufficient and safe.
    """
    return {"id": "setup-scan",
            "agent": None,
            "enforced": False,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(_pano(review_root, "setup-proposal.json"))}


def scan_done(review_root, manifest):
    return (_json_parses(_pano(review_root, "setup-proposal.json"))
            or _json_parses(_pano(review_root, "setup-complete.json")))


def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    setup_flow.provision(review_root)
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host)   # Task 3
    brief_path = setup_flow.render_scan_brief(review_root, vocab)
    entry = _setup_scan_entry(review_root, _read_text(brief_path))
    req = write_dispatch_request(review_root, manifest["run_id"], "scan", None, [entry])
    return PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, message="setup-scan checkpoint")


def ingest_done(review_root, manifest):
    return (os.path.isfile(_pano(review_root, "groups.yml.draft"))
            or _json_parses(_pano(review_root, "setup-complete.json")))


def ingest_execute(review_root, manifest):
    res = setup_flow.ingest_proposal(review_root)
    if not res["ok"]:
        raise DriverError("ingest: " + "; ".join(res["errors"]))
    return PhaseResult(kind="advanced",
                       message="setup: draft written %s" % res["draft"])


SETUP_PHASES = (
    Phase("scan", "checkpoint", scan_done, scan_execute),
    Phase("ingest", "deterministic", ingest_done, ingest_execute),
)


_SETUP_ARTIFACTS = ("setup-scan-brief.md", "setup-proposal.json",
                    "groups.yml.draft", "setup-complete.json", SETUP_MANIFEST)


def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed groups.yml."""
    for name in _SETUP_ARTIFACTS:
        try:
            os.remove(_pano(review_root, name))
        except OSError:
            pass


def _scan_fallback(review_root, manifest, host):
    """Vocab-absent path (parity with orchestrator.run_setup): flat top-dir seed
    + readiness gate, then a fallback-complete marker so both setup phases'
    done-predicates are satisfied -> run_engine completes without a checkpoint
    and without entering ingest."""
    path, created, names = setup_flow.seed_flat_manifest(review_root)
    checks = setup_flow.readiness(review_root, host=host)
    gaps = [c[0] for c in checks if c[1] is False]
    _write_json(_pano(review_root, "setup-complete.json"), {
        "mode": "fallback", "seed": path, "created": created, "groups": names,
        "readiness": [[c[0], c[1], c[2]] for c in checks],
        "gaps": gaps, "run_id": manifest["run_id"]})
    msg = ("setup: vocab-absent fallback — flat seed %s; readiness %s"
           % (path, "OK" if not gaps else "gaps: " + ", ".join(gaps)))
    return PhaseResult(kind="advanced", message=msg)


def _drop_stale_fallback_marker(review_root):
    """A vocab-absent run wrote a mode:"fallback" setup-complete.json. Once the
    vocabulary is available again, that marker is stale — a real scan should
    supersede the flat seed. Remove it so the engine re-scans (self-healing; no
    --reset needed). No-op when there is no fallback marker or vocab is still
    absent."""
    marker = _load_json(_pano(review_root, "setup-complete.json"))
    if not (isinstance(marker, dict) and marker.get("mode") == "fallback"):
        return
    _vocab, present = setup_flow.load_bundled_vocabulary(None)
    if present:
        try:
            os.remove(_pano(review_root, "setup-complete.json"))
        except OSError:
            pass


def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it."""
    review_root, _wt, _pr = resolve_review_root(args.target, runner=runner)
    if getattr(args, "reset", False):
        _clear_setup_artifacts(review_root)               # Task 3
    _drop_stale_fallback_marker(review_root)
    manifest = load_setup_manifest(review_root)
    if manifest is None:
        manifest = {"schema_version": 1, "run_id": run_manifest.new_run_id(),
                    "target": os.path.abspath(args.target),
                    "host": args.host or _DEFAULTS["host"],
                    "vocabulary_path": None}
        _write_json(_setup_manifest_path(review_root), manifest)
    try:
        result = run_engine(review_root, manifest, phases)
    except DriverError as exc:
        return _error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(_pano(review_root, "groups.yml.draft")):
            result["message"] = ("setup complete — review .panopticon/groups.yml.draft, "
                                 "move it to .panopticon/groups.yml, and commit")
        else:
            msg = ("setup complete — vocab-absent fallback seeded a flat "
                  ".panopticon/groups.yml; review, edit, and commit it")
            gaps = (_load_json(_pano(review_root, "setup-complete.json")) or {}).get("gaps") or []
            if gaps:
                msg += (" — readiness gaps: %s (fix before running a review)"
                       % ", ".join(gaps))
            result["message"] = msg
    return result


_DEFAULTS = {"host": "claude", "security": "standard"}

_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and
                # silently delta-scope (or content-check) the next run.
                "diff-hunks.json", "out-file-hashes.json")

PHASES = (
    Phase("discovery", "deterministic", discovery_done, discovery_execute),
    Phase("coverage", "mixed", coverage_done, coverage_execute),
    Phase("tools", "deterministic", tools_done, tools_execute),
    Phase("review", "checkpoint", review_done, review_execute),
    Phase("verify", "mixed", verify_done, verify_execute),
    Phase("synthesize", "deterministic", synthesize_done, synthesize_execute),
    Phase("validate", "deterministic", validate_done, validate_execute),
)


def _cli_flags(args):
    tools = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    return {"fail_on": args.fail_on, "severity": args.severity,
            "gate_scope": args.gate_scope, "diff_context": args.diff_context,
            "tools": tools,
            "include_fixtures": True if args.include_fixtures else None}


def _scope_from_args(args):
    """The {mode,target} scope implied by -f/-d/-g, or None if none was given
    (a bare re-invocation with no scope opinion — mirrors host/security_mode/
    base/flags: None never conflicts in conflicting_flags, and build_manifest
    defaults a None scope to {"mode":"repo","target":None} itself)."""
    if getattr(args, "scope_file", None):
        return {"mode": "file", "target": args.scope_file}
    if getattr(args, "scope_dir", None):
        return {"mode": "directory", "target": args.scope_dir}
    if getattr(args, "scope_group", None):
        return {"mode": "group", "target": args.scope_group}
    if getattr(args, "scope_changed", False):
        return {"mode": "changed", "target": None}
    if getattr(args, "scope_files", None):
        return {"mode": "files", "target": list(args.scope_files)}
    return None


def _clear_run_artifacts(review_root):
    """Remove the manifest's derived artifacts for --reset. NEVER touches
    groups.yml (the committed matrix)."""
    pano = _pano(review_root)
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(pano, pat)):
            try:
                os.remove(path)
            except OSError:
                pass
    for sub in ("tools", "verdicts"):
        shutil.rmtree(os.path.join(pano, sub), ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb in ("run", "next"):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, choices=["claude", "generic"])
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        p.add_argument("--fail-on", default=None)
        p.add_argument("--severity", default=None)
        p.add_argument("--gate-scope", default=None)
        p.add_argument("--diff-context", type=int, default=None)
        p.add_argument("--tools", action="store_true")
        p.add_argument("--no-tools", action="store_true")
        p.add_argument("--include-fixtures", action="store_true")
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("-f", "--file", dest="scope_file", default=None)
        scope.add_argument("-d", "--directory", dest="scope_dir", default=None)
        scope.add_argument("-g", "--group", dest="scope_group", default=None)
        scope.add_argument("-c", "--changes", dest="scope_changed",
                           action="store_true")
        scope.add_argument("--files", dest="scope_files", nargs="+", default=None)
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, choices=["claude", "generic"])
    sp.add_argument("--reset", action="store_true")
    return parser


def _error_status(message):
    return {"status": "error", "phase": None, "checkpoint": None, "group": None,
            "dispatch_request": None, "advanced": [], "message": message}


def run(args, runner=subprocess.run, phases=PHASES):
    review_root, worktree, pr_base = resolve_review_root(
        args.target, base=args.base, pr=args.pr, runner=runner)
    if args.pr is not None:
        # A PR is a changed-files delta by definition. manifest["base"] holds the
        # user's EXPLICIT override only (anti-drift key); the gh-detected PR base
        # flows separately via manifest["pr_base"] -> orchestrator --pr-base, so
        # resolve_base applies its origin/<base> preference (#947 / spec §4 L51).
        base = args.base
        scope = {"mode": "changed", "target": None}
    else:
        base = args.base
        scope = _scope_from_args(args)
    if args.reset:
        run_manifest.reset_run(review_root)
        _clear_run_artifacts(review_root)
    manifest = run_manifest.load_manifest(review_root)
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        _clear_run_artifacts(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or _DEFAULTS["host"],
            security_mode=args.security or _DEFAULTS["security"],
            base=base, flags=_cli_flags(args), worktree=worktree,
            scope=scope, pr=args.pr, pr_base=pr_base)
        run_manifest.write_manifest(review_root, manifest)
    else:
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
            base=base, flags=_cli_flags(args), scope=scope, pr=args.pr)
        if conflicts:
            return _error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    capture_tree_baseline(review_root, runner=runner)
    try:
        result = run_engine(review_root, manifest, phases)
    except DriverError as exc:
        return _error_status(str(exc))
    if result.get("status") == "complete":
        _finalize_worktree(review_root, manifest)
    return result


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verb == "setup":
        return emit_status(run_setup_flow(args))
    return emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
