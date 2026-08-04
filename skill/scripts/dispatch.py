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
            fm = (["---", "name: %s" % agent,
                   "description: %s" % meta["description"], "tools:"]
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

    Fallback only — the orchestrating agent should pass --host explicitly
    (it knows what it is; these env vars are not all documented contracts).
    """
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        return "kimi"
    if os.environ.get("CLAUDECODE") or any(
            k.startswith("CLAUDE_CODE_") for k in os.environ):
        return "claude"
    return "generic"


AGENT_NAME = {
    "scout": "scout",
    "panel_review": "panel-review",
    "lens_sweep": "lens-sweep",
    "advisor": "advisor",
}


def build_plan(scope_profile, host=None, model_overrides=None):
    """Return a DispatchPlan: list of agent invocations.

    Each invocation has:
    - role: lens_sweep | panel_review
    - agent: Kimi Code custom agent name
    - model: resolved model config dict
    - panel: panel name
    - lens: lens name (for lens_sweep only)
    - files: list of files to review
    - group: group name
    - depth: panel depth
    - lenses: list of non-spawned lens names (for panel_review only)
    - out_file: where the agent should write findings
    """
    host = host or _detect_host()
    overrides = model_overrides or {}
    group_name = scope_profile.get("group", "unknown")
    files = scope_profile.get("files", [])
    depth = scope_profile.get("depth", "standard")
    plan = []

    for panel_name in scope_profile.get("panels", []):
        spawned = depth_planner.plan_lenses(scope_profile, panel_name)
        panel_lenses = scope_profile.get("lenses", {}).get(panel_name, [])
        spawned_set = set(spawned)
        non_spawned = [lens["name"] for lens in panel_lenses if lens["name"] not in spawned_set]

        # main panel reviewer
        panel_out_file = ".panopticon/findings-%s-%s-panel_review.json" % (group_name, panel_name)
        plan.append({
            "role": "panel_review",
            "agent": AGENT_NAME["panel_review"],
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
                "agent": AGENT_NAME["lens_sweep"],
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
        # {3,}: %03d is minimum-width, so 1000+ entries yield 4+ digits.
        if not re.match(r"^[0-9]{3,}-[A-Za-z0-9_-]+$", queue_id):
            raise ValueError("verify queue %s: unsafe queue_id %r"
                             % (queue_path, queue_id))
        claim = json.dumps(finding, indent=2, ensure_ascii=False)
        prompt = render_prompt("advisor.md", {"claim_json": claim})
        path = os.path.join(out_dir, "%s.md" % queue_id)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(prompt)
        written.append(path)
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("profile", nargs="?", default=None, help="Path to ScopeProfile JSON")
    ap.add_argument("--host", default=None,
                    help="Host platform: claude|kimi|generic (any model-profiles.yml host key accepted)")
    ap.add_argument("--out", default=None, help="Write DispatchPlan JSON to this file")
    ap.add_argument("--render-advisor", metavar="QUEUE", default=None,
                    help="Render advisor prompts from a verify-queue JSON into --out DIR")
    ap.add_argument("--emit-host-agents", metavar="HOST", choices=["claude", "kimi"], default=None)
    ap.add_argument("--model-lens-sweep", default=None)
    ap.add_argument("--model-panel-review", default=None)
    ap.add_argument("--model-advisor", default=None)
    args = ap.parse_args(argv)

    if args.emit_host_agents:
        out_dir = args.out or (CLAUDE_AGENTS_DIR if args.emit_host_agents == "claude" else None)
        if not out_dir:
            print("dispatch: --emit-host-agents kimi requires --out DIR", file=sys.stderr)
            return 2
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
    if not args.profile:
        ap.error("profile is required unless --render-advisor is given")

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
        plan = build_plan(profile, host=args.host, model_overrides=overrides)
    except ValueError as e:
        print("dispatch: %s" % e, file=sys.stderr)
        return 1

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
