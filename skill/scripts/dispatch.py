#!/usr/bin/env python3
"""Build a DispatchPlan from a ScopeProfile."""
import argparse
import functools
import hashlib
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depth_planner
import model_resolver
import plan_contract
from orchestrator import panels_in_priority_order


TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            os.pardir, "agents")

_FM_SCALAR_RE = re.compile(r"^([a-z_]+):\s*(.*)$")
_FM_LIST_RE = re.compile(r"^\s{2}(allowed|forbidden):\s*\[([^\]]*)\]\s*$")


def parse_template_frontmatter(text, source="<template>"):
    """Parse the constrained host-neutral template frontmatter.

    Expected shape (inline flow lists only):
        ---
        name: scout
        description: ...
        tool_policy:
          allowed: [Read, Grep, Glob]
          forbidden: [Edit, Write, Agent]
        ---
    Fail-fast by design: templates are shipped assets, so any deviation is a
    bug — raise ValueError naming the source rather than degrade.
    """
    if not text.startswith("---"):
        raise ValueError("%s: template has no frontmatter block" % source)
    end = text.find("\n---", 3)
    if end == -1:
        raise ValueError("%s: unterminated frontmatter block" % source)
    header = text[3:end].strip("\n")
    body = text[end + len("\n---"):].lstrip("\n")
    meta = {"tool_policy": {}}
    in_policy = False
    for line in header.splitlines():
        if not line.strip():
            continue
        m = _FM_LIST_RE.match(line)
        if m and in_policy:
            items = [x.strip() for x in m.group(2).split(",") if x.strip()]
            meta["tool_policy"][m.group(1)] = items
            continue
        m = _FM_SCALAR_RE.match(line)
        if not m:
            raise ValueError("%s: cannot parse frontmatter line %r" % (source, line))
        key, value = m.group(1), m.group(2).strip()
        if key == "tool_policy":
            in_policy = True
            continue
        in_policy = False
        meta[key] = value
    for required in ("name", "description"):
        if not meta.get(required):
            raise ValueError("%s: frontmatter missing %r" % (source, required))
    for required in ("allowed", "forbidden"):
        if required not in meta["tool_policy"]:
            raise ValueError("%s: tool_policy missing %r list" % (source, required))
    return meta, body


def load_template(role_file):
    """Load and parse an agent template by basename (e.g. 'scout.md').

    Cached per resolved path: templates are shipped, immutable assets, and the
    per-entry render loops (one advisor prompt per verify-queue entry, one
    reviewer prompt per plan entry) would otherwise re-read and re-parse the
    same file once per entry. Callers must treat the returned (meta, body) as
    read-only."""
    return _load_template_cached(os.path.join(TEMPLATE_DIR, role_file), role_file)


@functools.lru_cache(maxsize=None)
def _load_template_cached(path, role_file):
    if not os.path.isfile(path):
        raise ValueError("template not found: %s (looked in %s)" % (role_file, TEMPLATE_DIR))
    with open(path, encoding="utf-8") as fh:
        return parse_template_frontmatter(fh.read(), source=role_file)


PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")

ROLE_FILES = {"scout": "scout.md", "panel_review": "panel-review.md",
              "lens_sweep": "lens-sweep.md", "advisor": "advisor.md",
              "domain_panel": "domain-panel.md",
              "domain_advisor": "domain-advisor.md"}
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
CODEX_HOME = os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex"))
CODEX_AGENTS_DIR = os.path.join(CODEX_HOME, "agents")

# Roles whose findings gate merge/release decisions (#275). If either lacks a
# registered enforcement shell, its tool policy is prompt-advisory only --
# a general-purpose agent reading untrusted repo content would have full
# Bash/Edit/Write. main() refuses to emit such a plan by default.
REVIEWER_ROLES = {"panel_review", "lens_sweep", "domain_panel"}
PANEL_LENSES = {
    "code": ["structure", "correctness", "style"],
    "test": ["coverage", "test_quality", "test_design"],
    "security": ["known_vulns", "injection", "novel"],
    "architecture": ["architecture"],
    "database": ["database"],
    "redteam": ["redteam"],
}

# Emission is deterministic policy — ambient PANOPTICON_MODEL_* overrides apply
# to per-run dispatch plans, never to persisted registrations.
EMIT_MODEL_POLICY = {"claude": {"scout": "haiku", "lens_sweep": "haiku",
                                 "panel_review": "sonnet", "advisor": "opus",
                                 "domain_panel": "sonnet",
                                 "domain_advisor": "opus"}}

_CHARTER = (
    "You are panopticon's `%s` reviewer (a registered enforcement shell).\n"
    "Follow the dispatched task message exactly — it contains your full\n"
    "instructions for this run. Your tool restrictions are host-enforced:\n"
    "you may use only %s and must never attempt %s.\n"
    "Return your result as the task message instructs.\n")

_CODEX_CHARTER = (
    "You are panopticon's `%s` reviewer. Follow the dispatched task message "
    "exactly; it contains your full instructions for this run. Your Codex "
    "sandbox is read-only. Use shell commands only for read-only exploration, "
    "never execute target code, never access the network, and return the exact "
    "JSON shape requested by the task.\n")


def registered_agent_name(role_file):
    """panopticon-<stem>, e.g. scout.md -> panopticon-scout."""
    return "panopticon-" + role_file[:-len(".md")]


def registered_agent_filename(host, role_file):
    """Host-native filename for one registered enforcement profile."""
    suffix = ".toml" if host == "codex" else ".md"
    return registered_agent_name(role_file) + suffix


def emit_host_agents(host, out_dir):
    """Generate host-native registered agent files (enforcement shells).

    Frontmatter carries the enforceable surface (name, description, tools,
    model); the body is a short charter. The rendered prompt still arrives as
    the task message at dispatch time — registration changes what an agent MAY
    do, never what it is asked to do. Fail-fast on template errors (shipped
    assets); idempotent for unchanged templates.
    """
    if host not in ("claude", "kimi", "codex"):
        raise ValueError("emit-host-agents: unsupported host %r (claude|kimi|codex)" % host)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for role, role_file in sorted(ROLE_FILES.items()):
        meta, _body = load_template(role_file)
        tp = meta["tool_policy"]
        agent = registered_agent_name(role_file)
        charter = _CHARTER % (role, ", ".join(tp["allowed"]),
                      ", ".join(tp["forbidden"]))
        if host == "claude":
            model = EMIT_MODEL_POLICY.get("claude", {}).get(role)
            fm = ["---", "name: %s" % agent,
                  "description: %s" % meta["description"],
                  "tools: %s" % ", ".join(tp["allowed"])]
            if model:
                fm.append("model: %s" % model)
            fm.append("---")
        elif host == "kimi":
            # Override-free by design (see EMIT_MODEL_POLICY above): the tier
            # comes from model-profiles.yml so it cannot drift from what
            # resolve_model returns at dispatch time.
            preference = model_resolver.registration_model("kimi", role) or "primary"
            fm = (["---", "name: %s" % agent,
                   "description: %s" % meta["description"],
                   "whenToUse: %s" % meta["description"],
                   "override: false",
                   "model_preference: %s" % preference,
                   "tools:"]
                  + ["  - %s" % t for t in tp["allowed"]]
                  + ["disallowedTools:"]
                  + ["  - %s" % t for t in tp["forbidden"]]
                  + ["---"])
        else:
            cfg = model_resolver.registration_config("codex", role)
            lines = ["name = %s" % json.dumps(agent),
                     "description = %s" % json.dumps(meta["description"])]
            if cfg.get("model"):
                lines.append("model = %s" % json.dumps(cfg["model"]))
            if cfg.get("model_reasoning_effort"):
                lines.append("model_reasoning_effort = %s"
                             % json.dumps(cfg["model_reasoning_effort"]))
            lines.extend(["sandbox_mode = \"read-only\"",
                          "developer_instructions = %s"
                          % json.dumps(_CODEX_CHARTER % role)])
        path = os.path.join(out_dir, registered_agent_filename(host, role_file))
        with open(path, "w", encoding="utf-8") as fh:
            if host == "codex":
                fh.write("\n".join(lines) + "\n")
            else:
                fh.write("\n".join(fm) + "\n\n" + charter)
        written.append(path)
    return written


def _tool_policy_line(meta, host=None):
    tp = meta["tool_policy"]
    if host == "codex":
        return ("\n## Tool policy\n\nThe Codex runner enforces a read-only "
                "sandbox and captures your final JSON itself. You may use shell "
                "commands only to read or search files. Never execute target "
                "code, run builds or tests, access the network, spawn agents, "
                "or attempt any filesystem mutation.\n")
    return ("\n## Tool policy\n\nYour only tools are %s. "
             "You must not use %s under any circumstances.\n"
             % (", ".join(tp["allowed"]), ", ".join(tp["forbidden"])))


def render_prompt(role_file, mapping, host=None):
    """Render a role template into a dispatchable prompt.

    Brace-safe two-step replacement: placeholders are first swapped for unique
    sentinel tokens, then sentinels for values — so values containing
    '{placeholder}' syntax pass through literally. Fail-fast: any known-token
    placeholder left unfilled, and any {token} in the template that is not in
    mapping, is an error naming the template and token. JSON/regex braces in
    template bodies are ignored because the detector matches only
    single-word lowercase tokens.
    """
    meta, body = load_template(role_file)
    if role_file in ("panel-review.md", "lens-sweep.md"):
        mapping = dict(mapping)
        for key, value in _delivery_fields(
                host, mapping.get("out_file", ""), role_file).items():
            mapping.setdefault(key, value)
    tokens = set(PLACEHOLDER_RE.findall(body))
    missing = sorted(t for t in tokens if t not in mapping)
    if missing:
        raise ValueError("%s: no value for placeholder(s): %s"
                          % (role_file, ", ".join(missing)))
    rendered = body
    sentinels = {}
    for i, tok in enumerate(sorted(tokens)):
        sentinel = "\x00PANOPTICON%d\x00" % i
        sentinels[sentinel] = str(mapping[tok])
        rendered = rendered.replace("{%s}" % tok, sentinel)
    for sentinel, value in sentinels.items():
        rendered = rendered.replace(sentinel, value)
    return rendered + _tool_policy_line(meta, host)


def _detect_host():
    """Best-effort host detection from environment.

    Fallback only — the orchestrating agent should pass --host explicitly.
    """
    warning = "WARNING: host detected from environment; pass --host explicitly for stable behavior"
    if os.environ.get("CODEX_SANDBOX") or os.environ.get("CODEX_SANDBOX_NETWORK_DISABLED"):
        print(warning, file=sys.stderr)
        return "codex"
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        print(warning, file=sys.stderr)
        return "kimi"
    if os.environ.get("CLAUDECODE") or any(
            k.startswith("CLAUDE_CODE_") for k in os.environ):
        print(warning, file=sys.stderr)
        return "claude"
    return "generic"


def agent_name(role):
    """Unenforced agent name for a role: its template basename sans '.md'.

    (Replaces a parallel AGENT_NAME dict whose every value was exactly this
    derivation from ROLE_FILES.)"""
    return ROLE_FILES[role][:-len(".md")]


def _registration_dir(host, agents_dir):
    """Explicit dir wins; otherwise fall back to the host's default agents dir.

    Unknown hosts return ``None``.
    """
    if agents_dir:
        return agents_dir
    if host == "claude":
        return CLAUDE_AGENTS_DIR
    if host == "kimi":
        return KIMI_AGENTS_DIR
    if host == "codex":
        return CODEX_AGENTS_DIR
    return None


def _is_registered(reg_dir, role_file, host=None):
    """Check if a role is registered in the registration directory."""
    return bool(reg_dir) and os.path.isfile(
        os.path.join(reg_dir, registered_agent_filename(host, role_file)))


def _artifact_token(value, label):
    """Return a filename-safe plan token or reject the untrusted profile."""
    value = str(value or "")
    if (not value or value in (".", "..") or os.path.isabs(value)
            or "/" in value or "\\" in value
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise ValueError("unsafe %s %r: artifact names cannot contain paths or controls"
                         % (label, value))
    return value


def _lens_token(value):
    """Return a prompt/filename-safe flexible lens identifier."""
    value = str(value or "")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
        raise ValueError("unsafe lens %r: use lowercase letters, digits, and underscores"
                         % value)
    return value


def _panel_lenses(scope_profile, panel_name):
    """Validated scout lenses plus every deterministic baseline lens."""
    raw = (scope_profile.get("lenses") or {}).get(panel_name, [])
    if not isinstance(raw, list):
        raise ValueError("ScopeProfile lenses.%s must be a list" % panel_name)
    by_name = {}
    extras = []
    for lens in raw:
        if not isinstance(lens, dict):
            raise ValueError("ScopeProfile lens entries must be objects")
        item = dict(lens)
        name = _lens_token(item.get("name"))
        item["name"] = name
        if name not in by_name:
            by_name[name] = item
            extras.append(name)
    ordered = []
    baseline = PANEL_LENSES.get(panel_name, [])
    for name in baseline:
        ordered.append(by_name.get(name, {
            "name": name, "spawn": False, "priority": 99,
            "depth_threshold": "shallow"}))
    ordered.extend(by_name[name] for name in extras if name not in baseline)
    return ordered


def load_group_assignment(groups_path, group_name):
    """Load one authoritative group assignment from discovery output."""
    try:
        with open(groups_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read groups artifact %s: %s" % (groups_path, exc))
    groups = data.get("groups") if isinstance(data, dict) else None
    if not isinstance(groups, list):
        raise ValueError("groups artifact %s has no groups list" % groups_path)
    matches = [group for group in groups
               if isinstance(group, dict) and group.get("name") == group_name]
    if len(matches) != 1 or not isinstance(matches[0].get("files"), list):
        raise ValueError("groups artifact must contain exactly one %r group"
                         % group_name)
    assignment = dict(matches[0])
    files = assignment["files"]
    if not all(isinstance(path, str) and path for path in files):
        raise ValueError("group %r has malformed files" % group_name)
    panels = assignment.get("panels")
    if not isinstance(panels, list) or not all(isinstance(panel, str) for panel in panels):
        raise ValueError("group %r has malformed panels" % group_name)
    assignment["security_mode"] = data.get("security_mode", "standard")
    return assignment


def load_group_files(groups_path, group_name):
    """Backward-compatible files-only view of an authoritative assignment."""
    return load_group_assignment(groups_path, group_name)["files"]


def _delivery_fields(host, out_file, role_file, run_id=None, group=None,
                     panel=None, lens=None):
    if host == "codex":
        return {
            "delivery_contract": (
                'Return ONLY a raw JSON object `{"findings": [...]}` as your '
                "final message. Do not write it yourself; the trusted Codex runner "
                "validates and atomically publishes that response to `%s`." % out_file),
            "side_effect_boundary": (
                "Perform NO file writes, GitHub writes, repository mutations, "
                "dispatches, credential access, or target-code execution. The "
                "Codex runner enforces a read-only sandbox."),
        }
    if run_id is None:
        delivery = (
            'Write your findings as a raw JSON object `{"findings": [...]}` to `%s`, '
            "then return a one-line confirmation as your final message. Write ONLY "
            "that file — the write-guard hook blocks any other path." % out_file)
    else:
        metadata = json.dumps(
            {"producer": "reviewer_self_write", "run_id": run_id,
             "role": ("lens_sweep" if role_file == "lens-sweep.md"
                      else "domain_panel" if role_file == "domain-panel.md"
                      else "panel_review"),
             "panel": panel, "lens": lens, "group": group},
            separators=(",", ":"))
        delivery = (
            'Write a raw JSON object `{"findings": [...], "_panopticon": %s}` to `%s`, '
            "then return a one-line confirmation as your final message. Write ONLY "
            "that file — the write-guard hook blocks any other path."
            % (metadata, out_file))
    if role_file == "lens-sweep.md":
        boundary = "Do not perform GitHub writes, repo mutations, or credential mints."
    else:
        boundary = (
            "Write ONLY your findings file at `%s`. Perform NO GitHub writes, NO "
            "repo mutations, NO dispatches, NO credential mints, and NO OTHER "
            "file writes — the write-guard hook enforces this." % out_file)
    return {"delivery_contract": delivery, "side_effect_boundary": boundary}


def build_plan(scope_profile, host=None, model_overrides=None, agents_dir=None,
               root=None, codex_exec=False, run_id=None,
               authoritative_files=None, authoritative_group=None,
               authoritative_panels=None, authoritative_depth=None,
               authoritative_security_mode=None,
               scope_bound=False):
    """Return a DispatchPlan: list of agent invocations.

    Each invocation has:
    - role: lens_sweep | panel_review
    - agent: Kimi Code custom agent name (or registered name if enforced)
    - model: resolved model config dict
    - panel: panel name
    - lens: lens name (for lens_sweep only)
    - files: list of files to review
    - group: group name
    - depth: panel depth
    - enforced: boolean, true if this role is registered in agents_dir
    - lenses: list of non-spawned lens names (for panel_review only)
    - out_file: ABSOLUTE path where the agent should write findings

    ``out_file`` is rooted at *root* (default: the current working directory,
    i.e. the run's repo/worktree root) and emitted ABSOLUTE (#935). A reviewer
    subagent whose cwd differs from the orchestrator's -- common on some hosts,
    and guaranteed once #449's ``--pr`` worktree is in play -- would otherwise
    resolve a repo-relative out_file against the wrong root: the write lands in
    the wrong place and the write-guard (which realpaths its allowlist and the
    incoming write) denies it with no useful signal. An absolute path resolves
    identically from any cwd, so the reviewer write, the guard allowlist, and
    group_runner's done-check all agree on one location.
    """
    host = host or _detect_host()
    # Codex review plans are always executed through the trusted read-only
    # adapter. Keeping this implicit prevents a `--host codex` plan from
    # rendering return-JSON prompts that codex_runner then refuses (#4.3.0).
    codex_exec = host == "codex" or codex_exec
    if codex_exec and host != "codex":
        raise ValueError("codex_exec requires host='codex'")
    run_id = run_id or uuid.uuid4().hex
    overrides = model_overrides or {}
    group_name = _artifact_token(scope_profile.get("group", "unknown"), "group")
    if authoritative_group is not None and group_name != authoritative_group:
        raise ValueError("ScopeProfile group %r differs from expected group %r"
                         % (group_name, authoritative_group))
    files = scope_profile.get("files", [])
    if not isinstance(files, list) or not all(isinstance(path, str) for path in files):
        raise ValueError("ScopeProfile files must be a list of strings")
    if authoritative_files is not None:
        if len(files) != len(authoritative_files) or set(files) != set(authoritative_files):
            raise ValueError("ScopeProfile files differ from authoritative group %r"
                             % group_name)
        files = list(authoritative_files)
        scope_bound = True
    depth = scope_profile.get("depth", "standard")
    depth_order = {"shallow": 0, "standard": 1, "deep": 2}
    if depth not in depth_order:
        raise ValueError("ScopeProfile has invalid depth %r" % depth)
    root = os.path.abspath(root) if root else os.getcwd()
    artifact_dir = plan_contract.artifact_root(root)
    plan = []
    panels = scope_profile.get("panels")
    if not isinstance(panels, list) or not panels:
        raise ValueError("ScopeProfile must schedule at least one panel")
    if authoritative_panels is not None:
        omitted = sorted(set(authoritative_panels) - set(panels))
        if omitted:
            raise ValueError("ScopeProfile omits authoritative panel(s): %s"
                             % ", ".join(omitted))
    if (authoritative_depth is not None
            and depth_order.get(authoritative_depth, 99) > depth_order[depth]):
        raise ValueError("ScopeProfile depth %r is below authoritative depth %r"
                         % (depth, authoritative_depth))
    profile_security = scope_profile.get("security_mode", "standard")
    if (authoritative_security_mode is not None
            and profile_security != authoritative_security_mode):
        raise ValueError("ScopeProfile security_mode %r differs from authoritative %r"
                         % (profile_security, authoritative_security_mode))
    scope_sha256 = None
    if scope_bound:
        scope_sha256 = plan_contract.assignment_digest({
            "name": group_name,
            "files": authoritative_files if authoritative_files is not None else files,
            "panels": authoritative_panels if authoritative_panels is not None else panels,
            "depth": authoritative_depth if authoritative_depth is not None else depth,
            "security_mode": (authoritative_security_mode
                              if authoritative_security_mode is not None
                              else profile_security),
        })

    # Compute registration directory once
    reg_dir = _registration_dir(host, agents_dir)

    # Pre-compute enforcement status for each role to avoid triple stat calls
    panel_enforced = codex_exec or _is_registered(
        reg_dir, ROLE_FILES["panel_review"], host)
    lens_enforced = codex_exec or _is_registered(
        reg_dir, ROLE_FILES["lens_sweep"], host)
    panel_agent = (registered_agent_name(ROLE_FILES["panel_review"])
                   if panel_enforced else agent_name("panel_review"))
    lens_agent = (registered_agent_name(ROLE_FILES["lens_sweep"])
                  if lens_enforced else agent_name("lens_sweep"))

    for panel_name in panels_in_priority_order(panels):
        panel_name = _artifact_token(panel_name, "panel")
        if panel_name not in plan_contract.PANELS:
            raise ValueError("unsupported panel %r" % panel_name)
        panel_lenses = _panel_lenses(scope_profile, panel_name)
        planner_profile = dict(scope_profile)
        planner_profile["lenses"] = dict(scope_profile.get("lenses") or {})
        planner_profile["lenses"][panel_name] = panel_lenses
        spawned = depth_planner.plan_lenses(planner_profile, panel_name)
        spawned_set = set(spawned)
        non_spawned = [lens["name"] for lens in panel_lenses if lens["name"] not in spawned_set]

        # main panel reviewer
        panel_out_file = os.path.join(
            artifact_dir,
            "findings-%s-%s-panel_review.json" % (group_name, panel_name))
        # #975: the PROMPT's file list is rendered ABSOLUTE (worktree-rooted).
        # A dispatched subagent inherits the session cwd, so relative paths
        # made reviewers read the session-root checkout instead of the PR
        # worktree -- the read-side mirror of #935. entry["files"] stays
        # repo-relative (the out_of_scope checker and swarm routing key on it).
        files_abs = [os.path.join(root, f) for f in files]
        panel_mapping = {
            "panel": panel_name, "group": group_name,
            "file_list": ", ".join(files_abs),
            "depth": depth,
            "security_mode": profile_security,
            "lenses": "\n".join("- %s" % n for n in non_spawned) or "- (all lenses)",
            "out_file": panel_out_file,
        }
        panel_mapping.update(_delivery_fields(
            host, panel_out_file, "panel-review.md", run_id, group_name,
            panel_name, None))
        panel_entry = {
            "role": "panel_review",
            "agent": panel_agent,
            "enforced": panel_enforced,
            "model": model_resolver.resolve_model(host, "panel_review", overrides),
            "panel": panel_name,
            "lens": None,
            "files": files,
            "group": group_name,
            "depth": depth,
            "security_mode": profile_security,
            "lenses": non_spawned,
            "out_file": panel_out_file,
            "prompt": render_prompt(ROLE_FILES["panel_review"], panel_mapping, host),
            "run_id": run_id,
            "scope_bound": scope_bound,
            "scope_sha256": scope_sha256,
        }
        if codex_exec:
            panel_entry.update({"execution": "codex_exec", "delivery": "return_json",
                                "run_id": run_id})
        plan.append(panel_entry)

        # mechanical lens sweeps
        for lens_name in spawned:
            lens_name = _lens_token(lens_name)
            sweep_out_file = os.path.join(
                artifact_dir,
                "findings-%s-%s-lens_sweep-%s.json" % (group_name, panel_name, lens_name))
            sweep_mapping = {
                "panel": panel_name, "group": group_name,
                "file_list": ", ".join(files_abs),
                "security_mode": scope_profile.get("security_mode", "standard"),
                "depth": depth, "lens": lens_name,
                "out_file": sweep_out_file,
            }
            sweep_mapping.update(_delivery_fields(
                host, sweep_out_file, "lens-sweep.md", run_id, group_name,
                panel_name, lens_name))
            sweep_entry = {
                "role": "lens_sweep",
                "agent": lens_agent,
                "enforced": lens_enforced,
                "model": model_resolver.resolve_model(host, "lens_sweep", overrides),
                "panel": panel_name,
                "lens": lens_name,
                "files": files,
                "group": group_name,
                "depth": depth,
                "security_mode": profile_security,
                "out_file": sweep_out_file,
                "prompt": render_prompt(ROLE_FILES["lens_sweep"], sweep_mapping, host),
                "run_id": run_id,
                "scope_bound": scope_bound,
                "scope_sha256": scope_sha256,
            }
            if codex_exec:
                sweep_entry.update({"execution": "codex_exec", "delivery": "return_json",
                                    "run_id": run_id})
            plan.append(sweep_entry)

    return plan


def emit_plan(plan, fh=None):
    fh = fh or sys.stdout
    json.dump(plan, fh, indent=2)
    fh.write("\n")


def render_advisor_prompts(queue_path, out_dir):
    """Render one advisor prompt per verify-queue entry to out_dir.

    Deterministic replacement for the orchestrating agent hand-rendering
    claim JSON into the advisor template. The queue is OUR artifact but is
    parsed fail-fast anyway (a corrupt queue means an upstream bug).
    """
    try:
        with open(queue_path, encoding="utf-8") as fh:
            queue = json.load(fh)
    except (OSError, ValueError) as e:
        raise ValueError("cannot read verify queue %s: %s" % (queue_path, e))
    if not isinstance(queue, dict):
        raise ValueError("verify queue %s is not a JSON object" % queue_path)
    entries = queue.get("entries")
    if not isinstance(entries, list):
        raise ValueError("verify queue %s has no entries list" % queue_path)
    run_id = queue.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("verify queue %s has no run_id" % queue_path)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("verify queue %s: malformed entry (not an object)" % queue_path)
        queue_id = entry.get("queue_id")
        finding = entry.get("finding")
        if not queue_id or not isinstance(finding, dict):
            raise ValueError("verify queue %s: malformed entry %r"
                             % (queue_path, entry.get("queue_id")))
        if not isinstance(queue_id, str):
            raise ValueError("verify queue %s: non-string queue_id %r"
                             % (queue_path, queue_id))
        # queue_id is a finding_fingerprint (16 hex chars; #443) plus an
        # optional -<n> collision suffix from evidence.build_verify_queue.
        # No separators, no dots, no traversal -- strictly tighter than the
        # old positional NNN-ID pattern it replaces.
        # \A...\Z, not ^...$: in Python `$` also matches just BEFORE a trailing
        # newline, so "<16 hex>\n" would clear the guard and then be
        # interpolated straight into a filename below.
        if not re.match(r"\A[0-9a-f]{16}(-[0-9]+)?\Z", queue_id):
            raise ValueError("verify queue %s: unsafe queue_id %r"
                             % (queue_path, queue_id))
        claim = json.dumps(finding, indent=2, ensure_ascii=False)
        prompt = render_prompt("advisor.md", {"claim_json": claim})
        prompt = ("Verification run id: %s\nEcho it as the top-level JSON field "
              "`run_id` in your verdict.\n\n%s" % (run_id, prompt))
        # #975: pin the review root. Advisors inherit the session cwd, so a
        # relative location in the claim resolved against the wrong checkout
        # when the session root diverged from the tree under review.
        prompt = ("Repo root: %s\nEvery relative path in the claim below "
                  "resolves against this root -- read files THERE, never in "
                  "your session's default checkout.\n\n%s"
                  % (os.path.abspath(os.getcwd()), prompt))
        path = os.path.join(out_dir, "%s.md" % queue_id)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(prompt)
        written.append(path)
    return written


_KIMI_UNENFORCED_PROFILE = {
    "panel_review": "coder",
    "lens_sweep": "explore",
    "scout": "explore",
    "advisor": "plan",
}


def _kimi_subagent_type(entry, reg_dir=None, verify=False):
    """Map a plan entry to a Kimi subagent_type.

    Registered/enforced entries use the panopticon-* shell. Unenforced entries
    fall back to a built-in Kimi profile so the dispatch is always valid.

    `enforced` is a snapshot taken by build_plan when the plan was written, and
    a plan is a persisted artifact re-read by a later invocation — registration
    can be removed in between. With `verify=True` the flag is re-checked
    against `reg_dir` at emit time, because a stale `enforced: true` would
    claim host-enforced tool restrictions that no longer exist.
    """
    if entry.get("enforced"):
        if verify and not _is_registered(reg_dir, ROLE_FILES.get(entry.get("role"), "")):
            print("dispatch: %s no longer registered in %s; "
                  "downgrading to an unenforced profile"
                  % (entry.get("agent"), reg_dir), file=sys.stderr)
        else:
            return entry.get("agent")
    return _KIMI_UNENFORCED_PROFILE.get(entry.get("role"), "coder")


def _swarm_routing(entry):
    """Where this entry's result must be written, and what produced it.

    AgentSwarm's items[] carries prompts only, so the orchestrator would
    otherwise have to re-derive the grouping and trust item order to know which
    out_file each result belongs to. This block is index-aligned with items[]
    and makes that mapping explicit.
    """
    return {"out_file": entry.get("out_file"), "role": entry.get("role"),
            "panel": entry.get("panel"), "lens": entry.get("lens"),
            "group": entry.get("group")}


def _swarm_description(entry):
    parts = [entry.get("role", "review")]
    panel = entry.get("panel")
    lens = entry.get("lens")
    group = entry.get("group", "unknown")
    if panel:
        parts.append(panel)
    if lens:
        parts.append(lens)
    parts.append("for group %s" % group)
    return " ".join(parts)


def emit_kimi_swarm(plan, agents_dir=None, verify_registration=False):
    """Convert a DispatchPlan into Kimi Agent/AgentSwarm batches.

    Entries with the same (subagent_type, model) are batched via AgentSwarm;
    singletons become Agent calls. Each entry's fully rendered prompt is
    passed as the task string, using AgentSwarm's {{item}} placeholder.

    Every batch carries `routing`, index-aligned with `items` (or a single
    dict for an Agent call): the orchestrator writes each returned result to
    its entry's `out_file`, and the prompts alone cannot say which is which.

    Pass `verify_registration=True` to re-check each enforced entry against
    the live registration directory instead of trusting the plan's snapshot.
    """
    if not isinstance(plan, list):
        raise ValueError("dispatch plan must be a list of entries, got %s"
                         % type(plan).__name__)
    reg_dir = _registration_dir("kimi", agents_dir) if verify_registration else None
    grouped = {}
    for entry in plan:
        if not isinstance(entry, dict):
            raise ValueError("dispatch plan entry must be an object, got %r" % (entry,))
        model_cfg = entry.get("model")
        if model_cfg is not None and not isinstance(model_cfg, dict):
            raise ValueError("dispatch plan entry %r: model must be an object"
                             % entry.get("role"))
        agent = _kimi_subagent_type(entry, reg_dir, verify_registration)
        model = (model_cfg or {}).get("model")
        grouped.setdefault((agent, model), []).append(entry)

    batches = []
    for (agent, model), entries in grouped.items():
        if len(entries) == 1:
            entry = entries[0]
            batches.append({
                "tool": "Agent",
                "subagent_type": agent,
                "model": model,
                "description": _swarm_description(entry),
                "prompt": entry.get("prompt", ""),
                "routing": _swarm_routing(entry),
            })
        else:
            batches.append({
                "tool": "AgentSwarm",
                "subagent_type": agent,
                "model": model,
                "description": _swarm_description(entries[0]) + " (batch)",
                "prompt_template": "{{item}}",
                "items": [e.get("prompt", "") for e in entries],
                "routing": [_swarm_routing(e) for e in entries],
            })
    return {"batches": batches}


def _gate_unenforced(plan, allow, reg_dir=None):
    """Reviewer roles in `plan` that lack a registered enforcement shell.

    Returns (ok, unenforced): `unenforced` is the sorted set of REVIEWER_ROLES
    present in `plan` with a falsy `enforced` flag (missing/null reads as
    unenforced -- fail-safe, same rule as build_plan's own gate); `ok` is True
    when there is nothing to gate on, or the caller passed `allow`. A non-list
    `plan` gates on nothing here -- the caller's own JSON/shape validation
    (e.g. emit_kimi_swarm's ValueError) is responsible for that failure mode.

    When `reg_dir` is given, the stored `enforced` flag is re-verified against
    live registration (#649): a plan built while a reviewer was registered
    carries `enforced: true`, but registration can be removed before the plan
    is turned into a swarm manifest in a later invocation. Such an entry is
    folded into `unenforced` too, so the gate refuses / warns / acks on the
    ACTUAL emit-time posture rather than a stale snapshot -- matching the live
    downgrade emit_kimi_swarm(verify_registration=True) performs anyway.

    Shared by the plan-emit path and --emit-kimi-swarm (#275/I3) so the two
    cannot drift apart the way disclosure and enforcement did before this.
    """
    entries = plan if isinstance(plan, list) else []
    unenforced = set()
    for e in entries:
        if not (isinstance(e, dict) and e.get("role") in REVIEWER_ROLES):
            continue
        if not e.get("enforced"):
            unenforced.add(e["role"])
        elif reg_dir is not None and not _is_registered(
                reg_dir, ROLE_FILES.get(e["role"], "")):
            unenforced.add(e["role"])
    unenforced = sorted(unenforced)
    return (not unenforced or allow), unenforced


def _unenforced_refusal_message(unenforced, context="plan"):
    action = "emit swarm manifest" if context == "swarm" else "emit plan"
    return ("dispatch: refusing to %s — unenforced reviewer role(s): %s.\n"
            "Tool policy would be prompt-advisory only (full Bash/Edit/Write on a "
            "general-purpose agent reading untrusted repo content).\n"
            "The write-guard backstops only Write/Edit/NotebookEdit, NOT Bash, so "
            "it cannot close this gap (#680).\n"
            "Register enforcement shells first:  python3 skill/scripts/dispatch.py "
            "--emit-host-agents <host>\n"
            "Or accept the risk explicitly with --allow-unenforced."
            % (action, ", ".join(unenforced)))


def plan_content_hash(plan):
    """Canonical sha256 of a plan's entry list (#493 R2): formatting- and
    file-layout-independent, so an ack can bind to the plan CONTENT it
    acknowledged and synthesize can detect a stale or flipped plan."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_plan(plan, host=None, agents_dir=None, ack=None,
                authoritative_assignment=None, strict=False, root=None):
    """Dispatch-time plan re-verification (#493 R1).

    The emission-time gate cannot see an on-disk edit made AFTER emission
    (an "enforced": true->false flip, a role swap). Re-check each reviewer
    entry against the LIVE registration dir and return a list of violation
    strings; empty means the plan still holds the posture it was emitted
    with. An unenforced reviewer entry is a violation UNLESS a matching
    (hash-bound) ack acknowledges exactly this plan's content.
    """
    resolved_host = host or _detect_host()
    reg_dir = _registration_dir(resolved_host, agents_dir)
    acked = bool(ack and ack.get("acknowledged")
                 and ack.get("plan_sha256") == plan_content_hash(plan))
    if not isinstance(plan, list) or not plan:
        return ["plan is not a non-empty JSON array"]
    problems = []
    if strict:
        problems.extend(plan_contract.plan_issues(plan))
        if authoritative_assignment is None:
            problems.append("no authoritative groups.json assignment supplied")
        else:
            problems.extend(plan_contract.assignment_issues(
                plan, authoritative_assignment))
        problems.extend(plan_contract.output_issues(plan, root or os.getcwd()))
        if problems:
            return problems
    for i, e in enumerate(plan):
        if not isinstance(e, dict):
            problems.append("entry %d is not an object" % i)
            continue
        if e.get("role") not in REVIEWER_ROLES:
            continue
        if e.get("scope_bound") is not True:
            problems.append("entry %d (%s): reviewer scope is not bound to groups.json"
                            % (i, e.get("role")))
        if e.get("execution") == "codex_exec":
            if e.get("delivery") != "return_json" or not e.get("run_id"):
                problems.append(
                    "entry %d (%s): incomplete codex_exec runner metadata"
                    % (i, e.get("role")))
            continue
        live = _is_registered(reg_dir, ROLE_FILES[e["role"]], resolved_host)
        if e.get("enforced") and not live:
            problems.append(
                "entry %d (%s/%s): enforced:true but no registered shell -- "
                "on-disk flip or lost registration" % (i, e.get("role"), e.get("agent")))
        elif not e.get("enforced") and not acked:
            problems.append(
                "entry %d (%s): unenforced reviewer with no matching ack "
                "for THIS plan content" % (i, e.get("role")))
    return problems


def _write_unenforced_ack(unenforced, plan=None):
    """Record an --allow-unenforced acceptance in .panopticon/unenforced-ack.json.

    Records that the write-guard does NOT backstop Bash-based writes in this
    mode (#680): an unenforced reviewer holds full Bash, and the session-wide
    write-guard covers only Write/Edit/NotebookEdit, so the operator is
    accepting that a prompt-injected reviewer could write via the shell with
    the guard never consulted. The real control is an enforced shell.

    Raises OSError on failure; callers must catch it and fail closed (a
    write error right before a plan/manifest emission must never surface as
    a bare traceback -- see the M1 guard)."""
    os.makedirs(".panopticon", exist_ok=True)
    with open(os.path.join(".panopticon", "unenforced-ack.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"acknowledged": True, "roles": unenforced,
                   # #493 R2: bind the ack to the exact plan content it
                   # acknowledged; synthesize treats a non-matching ack as
                   # stale (reports false + a stderr note).
                   "plan_sha256": plan_content_hash(plan) if plan is not None else None,
                   "write_guard_covers_bash": False,
                   "note": ("unenforced reviewers hold Bash; the write-guard "
                            "backstops only Write/Edit/NotebookEdit, so a "
                            "shell-based write bypasses it. Use enforced "
                            "shells to close this.")},
                  fh, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("profile", nargs="?", default=None, help="Path to ScopeProfile JSON")
    ap.add_argument("--host", default=None,
                    help="Host platform: claude|kimi|codex|generic (any model-profiles.yml host key accepted)")
    ap.add_argument("--out", default=None, help="Write DispatchPlan JSON to this file")
    ap.add_argument("--render-advisor", metavar="QUEUE", default=None,
                    help="Render advisor prompts from a verify-queue JSON into --out DIR")
    ap.add_argument("--emit-kimi-swarm", metavar="PLAN", default=None,
                    help="Read a DispatchPlan JSON and emit a Kimi Agent/AgentSwarm manifest to --out")
    ap.add_argument("--emit-host-agents", metavar="HOST",
                    choices=["claude", "kimi", "codex"], default=None)
    ap.add_argument("--verify-plan", metavar="PLAN", action="append", default=None,
                    help="Re-verify emitted plan file(s) against the LIVE "
                         "registration dir before fan-out (#493): exits 1 on "
                         "an enforced->unregistered flip or an unenforced "
                         "reviewer whose ack does not hash-match the plan")
    ap.add_argument("--agents-dir", default=None,
                    help="Directory containing registered agent .md files")
    ap.add_argument("--groups", default=None,
                    help="Authoritative groups.json artifact; binds the scout's files "
                         "to its discovery-assigned group")
    ap.add_argument("--group-name", default=None,
                    help="Expected group name from the orchestrator assignment; required "
                         "with --groups")
    ap.add_argument("--allow-unenforced", action="store_true",
                    help="Emit the plan even when reviewer roles lack a registered "
                         "enforcement shell (tool policy becomes prompt-advisory); "
                         "records the acceptance in .panopticon/unenforced-ack.json")
    ap.add_argument("--codex-exec", action="store_true",
                    help="Compatibility alias; --host codex automatically uses the "
                        "trusted read-only codex_exec runner")
    ap.add_argument("--model-lens-sweep", default=None)
    ap.add_argument("--model-panel-review", default=None)
    ap.add_argument("--model-advisor", default=None)
    args = ap.parse_args(argv)

    if args.emit_host_agents:
        defaults = {"claude": CLAUDE_AGENTS_DIR, "kimi": KIMI_AGENTS_DIR,
                "codex": CODEX_AGENTS_DIR}
        out_dir = args.out or defaults[args.emit_host_agents]
        try:
            written = emit_host_agents(args.emit_host_agents, out_dir)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        for p in written:
            print(p)
        return 0

    if args.render_advisor:
        if not args.out:
            print("dispatch: --render-advisor requires --out DIR", file=sys.stderr)
            return 2
        try:
            written = render_advisor_prompts(args.render_advisor, args.out)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        print("rendered %d advisor prompt(s) -> %s" % (len(written), args.out))
        return 0
    if args.emit_kimi_swarm:
        if not args.out:
            print("dispatch: --emit-kimi-swarm requires --out", file=sys.stderr)
            return 2
        try:
            with open(args.emit_kimi_swarm, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError) as e:
            print("dispatch: cannot read plan %s: %s" % (args.emit_kimi_swarm, e), file=sys.stderr)
            return 1
        # Gate against LIVE registration, not the plan's stored snapshot (#649):
        # a plan built with enforced:true whose shells were unregistered since
        # must refuse / warn+ack here, not silently downgrade inside emit.
        swarm_reg_dir = _registration_dir("kimi", args.agents_dir)
        ok, unenforced = _gate_unenforced(plan, args.allow_unenforced, swarm_reg_dir)
        if unenforced:
            if not ok:
                print(_unenforced_refusal_message(unenforced, context="swarm"), file=sys.stderr)
                return 1
            print("dispatch: WARNING — emitting swarm manifest with unenforced reviewer role(s): %s "
                  "(acknowledged via --allow-unenforced)" % ", ".join(unenforced),
                  file=sys.stderr)
        try:
            swarm = emit_kimi_swarm(plan, agents_dir=args.agents_dir,
                                    verify_registration=True)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(swarm, fh, indent=2)
                fh.write("\n")
        except OSError as e:
            print("dispatch: cannot write swarm manifest: %s" % e, file=sys.stderr)
            return 1
        if unenforced:
            try:
                _write_unenforced_ack(unenforced, plan)
            except OSError as e:
                print("dispatch: cannot record unenforced ack: %s" % e, file=sys.stderr)
                return 1
        print("wrote Kimi swarm manifest (%d batch(es)) -> %s" % (len(swarm["batches"]), args.out))
        return 0
    if args.verify_plan:
        ack = None
        try:
            with open(os.path.join(".panopticon", "unenforced-ack.json"),
                      encoding="utf-8") as fh:
                ack = json.load(fh)
        except (OSError, ValueError):
            ack = None
        bad = 0
        groups_path = args.groups or os.path.join(".panopticon", "groups.json")
        for pth in args.verify_plan:
            try:
                with open(pth, encoding="utf-8") as fh:
                    plan = json.load(fh)
            except (OSError, ValueError) as e:
                print("verify-plan: cannot read %s: %s" % (pth, e), file=sys.stderr)
                bad += 1
                continue
            assignment = None
            if args.group_name:
                try:
                    assignment = load_group_assignment(groups_path, args.group_name)
                except ValueError as e:
                    print("verify-plan: %s: %s" % (pth, e), file=sys.stderr)
                    bad += 1
                    continue
            problems = verify_plan(
                plan, host=args.host, agents_dir=args.agents_dir, ack=ack,
                authoritative_assignment=assignment, strict=True,
                root=os.path.dirname(os.path.dirname(os.path.abspath(groups_path))))
            for prob in problems:
                print("verify-plan: %s: %s" % (pth, prob), file=sys.stderr)
            bad += len(problems)
            if not problems:
                print("verify-plan: %s: OK (%d entries)" % (pth, len(plan)))
        return 1 if bad else 0
    if not args.profile:
        ap.error(
            "profile is required unless --render-advisor, --emit-host-agents, "
            "or --emit-kimi-swarm is given"
        )

    try:
        with open(args.profile, encoding="utf-8") as fh:
            profile = json.load(fh)
    except FileNotFoundError:
        print("dispatch: profile not found: %s" % args.profile, file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print("dispatch: invalid JSON in profile %s: %s" % (args.profile, e), file=sys.stderr)
        return 1

    overrides = {}
    if args.model_lens_sweep:
        overrides["lens_sweep"] = args.model_lens_sweep
    if args.model_panel_review:
        overrides["panel_review"] = args.model_panel_review
    if args.model_advisor:
        overrides["advisor"] = args.model_advisor

    authoritative_files = None
    assignment = None
    groups_path = args.groups
    if groups_path is None:
        default_groups = os.path.join(".panopticon", "groups.json")
        if os.path.isfile(default_groups):
            groups_path = default_groups
    if groups_path is None:
        print("dispatch: no authoritative groups.json; run discovery with "
              "--out .panopticon/groups.json and pass --group-name", file=sys.stderr)
        return 2
    if not args.group_name:
        print("dispatch: --groups requires --group-name", file=sys.stderr)
        return 2
    try:
        assignment = load_group_assignment(groups_path, args.group_name)
        authoritative_files = assignment["files"]
    except ValueError as e:
        print("dispatch: %s" % e, file=sys.stderr)
        return 1

    try:
        plan = build_plan(profile, host=args.host, model_overrides=overrides,
                  agents_dir=args.agents_dir, codex_exec=args.codex_exec,
                  authoritative_files=authoritative_files,
                  authoritative_group=args.group_name,
                  authoritative_panels=assignment["panels"],
                  authoritative_depth=assignment.get("depth"),
                  authoritative_security_mode=assignment["security_mode"],
                  scope_bound=groups_path is not None)
    except ValueError as e:
        print("dispatch: %s" % e, file=sys.stderr)
        return 1

    ok, unenforced = _gate_unenforced(plan, args.allow_unenforced)
    if unenforced:
        if not ok:
            print(_unenforced_refusal_message(unenforced), file=sys.stderr)
            return 1
        print("dispatch: WARNING — emitting plan with unenforced reviewer role(s): %s "
              "(acknowledged via --allow-unenforced)" % ", ".join(unenforced),
              file=sys.stderr)

    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            print("dispatch: cannot create output directory %s: %s" % (out_dir, e), file=sys.stderr)
            return 1
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                emit_plan(plan, fh)
        except OSError as e:
            print("dispatch: cannot write output file %s: %s" % (args.out, e), file=sys.stderr)
            return 1
    else:
        emit_plan(plan)
    if unenforced:
        try:
            _write_unenforced_ack(unenforced)
        except OSError as e:
            print("dispatch: cannot record unenforced ack: %s" % e, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
