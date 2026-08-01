#!/usr/bin/env python3
"""Build a DispatchPlan from a ScopeProfile."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depth_planner
import model_resolver


def _detect_host():
    """Best-effort host detection from environment."""
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        return "kimi"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE"):
        return "claude"
    return "kimi"


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
        non_spawned = [l["name"] for l in panel_lenses if l["name"] not in spawned_set]

        # main panel reviewer
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
            "out_file": ".panopticon/findings-%s-%s-panel_review.json" % (group_name, panel_name),
        })

        # mechanical lens sweeps
        for lens_name in spawned:
            plan.append({
                "role": "lens_sweep",
                "agent": AGENT_NAME["lens_sweep"],
                "model": model_resolver.resolve_model(host, "lens_sweep", overrides),
                "panel": panel_name,
                "lens": lens_name,
                "files": files,
                "group": group_name,
                "depth": depth,
                "out_file": ".panopticon/findings-%s-%s-lens_sweep-%s.json" % (group_name, panel_name, lens_name),
            })

    return plan


def emit_plan(plan, fh=None):
    fh = fh or sys.stdout
    json.dump(plan, fh, indent=2)
    fh.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("profile", help="Path to ScopeProfile JSON")
    ap.add_argument("--host", default=None, help="Host platform (kimi, claude, openrouter)")
    ap.add_argument("--out", default=None, help="Write DispatchPlan JSON to this file")
    ap.add_argument("--model-lens-sweep", default=None)
    ap.add_argument("--model-panel-review", default=None)
    ap.add_argument("--model-advisor", default=None)
    args = ap.parse_args(argv)

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

    plan = build_plan(profile, host=args.host, model_overrides=overrides)

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
