#!/usr/bin/env python3
"""Agent-template rendering and host enforcement-shell registration.

Renders the host-neutral role templates in `skill/agents/` into dispatch
prompts (`render_prompt`, `render_advisor_prompts`) and registers the
host-native enforcement shells (`emit_host_agents`). The 4.x DispatchPlan
builder this module was named for was retired in #1441; the resumable driver
builds its own matrix-cell plan and calls `render_prompt` directly.
"""
import argparse
import functools
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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

ROLE_FILES = {"scout": "scout.md", "advisor": "advisor.md",
              "domain_panel": "domain-panel.md",
              "domain_advisor": "domain-advisor.md"}
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
CODEX_HOME = os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex"))
CODEX_AGENTS_DIR = os.path.join(CODEX_HOME, "agents")

# #run10: REVIEWER_ROLES lived here -- the roles whose findings gate
# merge/release decisions (#275), consulted by the plan emitter and verifier to
# refuse a plan whose reviewers had no registered enforcement shell. Both are
# retired, and the live owner of that check is setup_flow's `_driver_roles`
# readiness probe, which carries its own drift guard against ROLE_FILES. A
# second, unread copy of the set here could only rot out of step with it.

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
            # #1036: model_resolver is the single owner of the role->model map
            # for every host (kimi/codex already source from it). registration_
            # model is override-free (profiles + hardcoded fallback only, never
            # PANOPTICON_MODEL_*), so emission stays deterministic policy — env
            # overrides shape a run's dispatch plan, never a persisted shell.
            model = model_resolver.registration_model("claude", role)
            fm = ["---", "name: %s" % agent,
                  "description: %s" % meta["description"],
                  "tools: %s" % ", ".join(tp["allowed"])]
            if model:
                fm.append("model: %s" % model)
            fm.append("---")
        elif host == "kimi":
            # Override-free by design (registration_model, like the claude
            # branch): the tier comes from model-profiles.yml so it cannot drift
            # from what resolve_model returns at dispatch time.
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














def main(argv=None):
    # #run10: the parser carried a `profile` positional and --verify-plan,
    # --groups, --group-name, --allow-unenforced, --codex-exec and
    # --model-advisor. Every one of them served build_plan/emit_plan or the 4.x
    # plan verifier and was parsed but never read once those were retired;
    # --allow-unenforced still advertised that it "records the acceptance in
    # .panopticon/unenforced-ack.json" after the writer was deleted. main()
    # already errored on anything but the three real actions, so dropping them
    # is behaviour-preserving.
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("--host", default=None,
                    help="Host platform: claude|kimi|codex|generic (any model-profiles.yml host key accepted)")
    ap.add_argument("--out", default=None,
                    help="Output directory for --render-advisor")
    ap.add_argument("--render-advisor", metavar="QUEUE", default=None,
                    help="Render advisor prompts from a verify-queue JSON into --out DIR")
    ap.add_argument("--emit-host-agents", metavar="HOST",
                    choices=["claude", "kimi", "codex"], default=None)
    ap.add_argument("--agents-dir", default=None,
                    help="Directory containing registered agent .md files")
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
    ap.error("nothing to do: pass --render-advisor or --emit-host-agents")


if __name__ == "__main__":
    sys.exit(main())
