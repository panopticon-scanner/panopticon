#!/usr/bin/env python3
"""Build a DispatchPlan from a ScopeProfile."""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depth_planner
import model_resolver
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
    """Load and parse an agent template by basename (e.g. 'scout.md')."""
    path = os.path.join(TEMPLATE_DIR, role_file)
    if not os.path.isfile(path):
        raise ValueError("template not found: %s (looked in %s)" % (role_file, TEMPLATE_DIR))
    with open(path, encoding="utf-8") as fh:
        return parse_template_frontmatter(fh.read(), source=role_file)


PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")

ROLE_FILES = {"scout": "scout.md", "panel_review": "panel-review.md",
              "lens_sweep": "lens-sweep.md", "advisor": "advisor.md"}
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")

# Roles whose findings gate merge/release decisions (#275). If either lacks a
# registered enforcement shell, its tool policy is prompt-advisory only --
# a general-purpose agent reading untrusted repo content would have full
# Bash/Edit/Write. main() refuses to emit such a plan by default.
REVIEWER_ROLES = {"panel_review", "lens_sweep"}

# Emission is deterministic policy — ambient PANOPTICON_MODEL_* overrides apply
# to per-run dispatch plans, never to persisted registrations.
EMIT_MODEL_POLICY = {"claude": {"scout": "haiku", "lens_sweep": "haiku",
                                 "panel_review": "sonnet", "advisor": "opus"}}

_CHARTER = (
    "You are panopticon's `%s` reviewer (a registered enforcement shell).\n"
    "Follow the dispatched task message exactly — it contains your full\n"
    "instructions for this run. Your tool restrictions are host-enforced:\n"
    "you may use only %s and must never attempt %s.\n"
    "Return your result as the task message instructs.\n")


def registered_agent_name(role_file):
    """panopticon-<stem>, e.g. scout.md -> panopticon-scout."""
    return "panopticon-" + role_file[:-len(".md")]


def emit_host_agents(host, out_dir):
    """Generate host-native registered agent files (enforcement shells).

    Frontmatter carries the enforceable surface (name, description, tools,
    model); the body is a short charter. The rendered prompt still arrives as
    the task message at dispatch time — registration changes what an agent MAY
    do, never what it is asked to do. Fail-fast on template errors (shipped
    assets); idempotent for unchanged templates.
    """
    if host not in ("claude", "kimi"):
        raise ValueError("emit-host-agents: unsupported host %r (claude|kimi)" % host)
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
        else:
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
        path = os.path.join(out_dir, agent + ".md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(fm) + "\n\n" + charter)
        written.append(path)
    return written


def _tool_policy_line(meta):
    tp = meta["tool_policy"]
    return ("\n## Tool policy\n\nYour only tools are %s. "
             "You must not use %s under any circumstances.\n"
             % (", ".join(tp["allowed"]), ", ".join(tp["forbidden"])))


def render_prompt(role_file, mapping):
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
    return rendered + _tool_policy_line(meta)


def _detect_host():
    """Best-effort host detection from environment.

    Fallback only — the orchestrating agent should pass --host explicitly.
    """
    warning = "WARNING: host detected from environment; pass --host explicitly for stable behavior"
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        print(warning, file=sys.stderr)
        return "kimi"
    if os.environ.get("CLAUDECODE") or any(
            k.startswith("CLAUDE_CODE_") for k in os.environ):
        print(warning, file=sys.stderr)
        return "claude"
    return "generic"


AGENT_NAME = {
    "scout": "scout",
    "panel_review": "panel-review",
    "lens_sweep": "lens-sweep",
    "advisor": "advisor",
}


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
    return None


def _is_registered(reg_dir, role_file):
    """Check if a role is registered in the registration directory."""
    return bool(reg_dir) and os.path.isfile(
        os.path.join(reg_dir, registered_agent_name(role_file) + ".md"))


def build_plan(scope_profile, host=None, model_overrides=None, agents_dir=None):
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
    - out_file: where the agent should write findings
    """
    host = host or _detect_host()
    overrides = model_overrides or {}
    group_name = scope_profile.get("group", "unknown")
    files = scope_profile.get("files", [])
    depth = scope_profile.get("depth", "standard")
    plan = []

    # Compute registration directory once
    reg_dir = _registration_dir(host, agents_dir)

    # Pre-compute enforcement status for each role to avoid triple stat calls
    panel_enforced = _is_registered(reg_dir, ROLE_FILES["panel_review"])
    lens_enforced = _is_registered(reg_dir, ROLE_FILES["lens_sweep"])
    panel_agent = (registered_agent_name(ROLE_FILES["panel_review"])
                   if panel_enforced else AGENT_NAME["panel_review"])
    lens_agent = (registered_agent_name(ROLE_FILES["lens_sweep"])
                  if lens_enforced else AGENT_NAME["lens_sweep"])

    for panel_name in panels_in_priority_order(scope_profile.get("panels", [])):
        spawned = depth_planner.plan_lenses(scope_profile, panel_name)
        panel_lenses = scope_profile.get("lenses", {}).get(panel_name, [])
        spawned_set = set(spawned)
        non_spawned = [lens["name"] for lens in panel_lenses if lens["name"] not in spawned_set]

        # main panel reviewer
        panel_out_file = ".panopticon/findings-%s-%s-panel_review.json" % (group_name, panel_name)
        plan.append({
            "role": "panel_review",
            "agent": panel_agent,
            "enforced": panel_enforced,
            "model": model_resolver.resolve_model(host, "panel_review", overrides),
            "panel": panel_name,
            "lens": None,
            "files": files,
            "group": group_name,
            "depth": depth,
            "lenses": non_spawned,
            "out_file": panel_out_file,
            "prompt": render_prompt(AGENT_NAME["panel_review"] + ".md", {
                "panel": panel_name, "group": group_name,
                "file_list": ", ".join(files),
                "security_mode": scope_profile.get("security_mode", "standard"),
                "depth": depth,
                "lenses": "\n".join("- %s" % n for n in non_spawned) or "- (all lenses)",
                "out_file": panel_out_file,
            }),
        })

        # mechanical lens sweeps
        for lens_name in spawned:
            sweep_out_file = ".panopticon/findings-%s-%s-lens_sweep-%s.json" % (group_name, panel_name, lens_name)
            plan.append({
                "role": "lens_sweep",
                "agent": lens_agent,
                "enforced": lens_enforced,
                "model": model_resolver.resolve_model(host, "lens_sweep", overrides),
                "panel": panel_name,
                "lens": lens_name,
                "files": files,
                "group": group_name,
                "depth": depth,
                "out_file": sweep_out_file,
                "prompt": render_prompt(AGENT_NAME["lens_sweep"] + ".md", {
                    "panel": panel_name, "group": group_name,
                    "file_list": ", ".join(files),
                    "security_mode": scope_profile.get("security_mode", "standard"),
                    "depth": depth, "lens": lens_name,
                    "out_file": sweep_out_file,
                }),
            })

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


def _gate_unenforced(plan, allow):
    """Reviewer roles in `plan` that lack a registered enforcement shell.

    Returns (ok, unenforced): `unenforced` is the sorted set of REVIEWER_ROLES
    present in `plan` with a falsy `enforced` flag (missing/null reads as
    unenforced -- fail-safe, same rule as build_plan's own gate); `ok` is True
    when there is nothing to gate on, or the caller passed `allow`. A non-list
    `plan` gates on nothing here -- the caller's own JSON/shape validation
    (e.g. emit_kimi_swarm's ValueError) is responsible for that failure mode.

    Shared by the plan-emit path and --emit-kimi-swarm (#275/I3) so the two
    cannot drift apart the way disclosure and enforcement did before this.
    """
    entries = plan if isinstance(plan, list) else []
    unenforced = sorted({e["role"] for e in entries
                         if isinstance(e, dict) and e.get("role") in REVIEWER_ROLES
                         and not e.get("enforced")})
    return (not unenforced or allow), unenforced


def _unenforced_refusal_message(unenforced):
    return ("dispatch: refusing to emit plan — unenforced reviewer role(s): %s.\n"
            "Tool policy would be prompt-advisory only (full Bash/Edit/Write on a "
            "general-purpose agent reading untrusted repo content).\n"
            "Register enforcement shells first:  python3 skill/scripts/dispatch.py "
            "--emit-host-agents <host>\n"
            "Or accept the risk explicitly with --allow-unenforced."
            % ", ".join(unenforced))


def _write_unenforced_ack(unenforced):
    """Record an --allow-unenforced acceptance in .panopticon/unenforced-ack.json.

    Raises OSError on failure; callers must catch it and fail closed (a
    write error right before a plan/manifest emission must never surface as
    a bare traceback -- see the M1 guard)."""
    os.makedirs(".panopticon", exist_ok=True)
    with open(os.path.join(".panopticon", "unenforced-ack.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"acknowledged": True, "roles": unenforced}, fh, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("profile", nargs="?", default=None, help="Path to ScopeProfile JSON")
    ap.add_argument("--host", default=None,
                    help="Host platform: claude|kimi|generic (any model-profiles.yml host key accepted)")
    ap.add_argument("--out", default=None, help="Write DispatchPlan JSON to this file")
    ap.add_argument("--render-advisor", metavar="QUEUE", default=None,
                    help="Render advisor prompts from a verify-queue JSON into --out DIR")
    ap.add_argument("--emit-kimi-swarm", metavar="PLAN", default=None,
                    help="Read a DispatchPlan JSON and emit a Kimi Agent/AgentSwarm manifest to --out")
    ap.add_argument("--emit-host-agents", metavar="HOST", choices=["claude", "kimi"], default=None)
    ap.add_argument("--agents-dir", default=None,
                    help="Directory containing registered agent .md files")
    ap.add_argument("--allow-unenforced", action="store_true",
                    help="Emit the plan even when reviewer roles lack a registered "
                         "enforcement shell (tool policy becomes prompt-advisory); "
                         "records the acceptance in .panopticon/unenforced-ack.json")
    ap.add_argument("--model-lens-sweep", default=None)
    ap.add_argument("--model-panel-review", default=None)
    ap.add_argument("--model-advisor", default=None)
    args = ap.parse_args(argv)

    if args.emit_host_agents:
        out_dir = args.out or (CLAUDE_AGENTS_DIR if args.emit_host_agents == "claude"
                               else KIMI_AGENTS_DIR)
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
        ok, unenforced = _gate_unenforced(plan, args.allow_unenforced)
        if unenforced:
            if not ok:
                print(_unenforced_refusal_message(unenforced), file=sys.stderr)
                return 1
            try:
                _write_unenforced_ack(unenforced)
            except OSError as e:
                print("dispatch: cannot record unenforced ack: %s" % e, file=sys.stderr)
                return 1
            print("dispatch: WARNING — emitting plan with unenforced reviewer role(s): %s "
                  "(acknowledged via --allow-unenforced)" % ", ".join(unenforced),
                  file=sys.stderr)
        try:
            swarm = emit_kimi_swarm(plan, agents_dir=args.agents_dir,
                                    verify_registration=True)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(swarm, fh, indent=2)
            fh.write("\n")
        print("wrote Kimi swarm manifest (%d batch(es)) -> %s" % (len(swarm["batches"]), args.out))
        return 0
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

    try:
        plan = build_plan(profile, host=args.host, model_overrides=overrides,
                          agents_dir=args.agents_dir)
    except ValueError as e:
        print("dispatch: %s" % e, file=sys.stderr)
        return 1

    ok, unenforced = _gate_unenforced(plan, args.allow_unenforced)
    if unenforced:
        if not ok:
            print(_unenforced_refusal_message(unenforced), file=sys.stderr)
            return 1
        try:
            _write_unenforced_ack(unenforced)
        except OSError as e:
            print("dispatch: cannot record unenforced ack: %s" % e, file=sys.stderr)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
