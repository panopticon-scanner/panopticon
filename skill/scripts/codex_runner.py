#!/usr/bin/env python3
"""Run a Panopticon DispatchPlan through isolated ``codex exec`` workers.

Codex itself receives read-only access to the target and returns structured JSON.
This trusted adapter validates that JSON, stamps plan identity, and atomically
publishes each findings file. Model output never writes review artifacts directly.
"""
import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scripts.group_runner as group_runner


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(
    os.path.dirname(SCRIPT_DIR), "reference", "findings-envelope-schema.json")
DEFAULT_INSTRUCTIONS = os.path.join(
    os.path.dirname(SCRIPT_DIR), "reference", "codex-runner-instructions.md")
DEFAULT_TIMEOUT = 1800


def _toml_string(value):
    """Encode a string for a ``codex -c key=value`` override."""
    return json.dumps(str(value), ensure_ascii=False)


def _within(root, path):
    try:
        return os.path.commonpath([os.path.realpath(root), os.path.realpath(path)]) \
            == os.path.realpath(root)
    except (OSError, TypeError, ValueError):
        return False


def validate_entry(entry, root):
    """Validate one runner-owned plan entry and return its output path."""
    if not isinstance(entry, dict):
        raise ValueError("dispatch plan entry must be an object")
    if entry.get("execution") != "codex_exec" or entry.get("delivery") != "return_json":
        raise ValueError("entry is not a codex_exec return_json task")
    if not entry.get("run_id"):
        raise ValueError("codex_exec entry has no run_id")
    if entry.get("role") not in ("panel_review", "lens_sweep"):
        raise ValueError("unsupported codex_exec role %r" % entry.get("role"))
    if not isinstance(entry.get("prompt"), str) or not entry["prompt"].strip():
        raise ValueError("codex_exec entry has no prompt")
    out_file = entry.get("out_file")
    if not isinstance(out_file, str) or not os.path.isabs(out_file):
        raise ValueError("codex_exec out_file must be absolute")
    artifact_root = os.path.join(os.path.realpath(root), ".panopticon")
    if os.path.islink(out_file) or not _within(artifact_root, out_file):
        raise ValueError("codex_exec out_file escapes the target artifact directory")
    return out_file


def build_command(entry, root, output_path, schema=DEFAULT_SCHEMA,
                  instructions=DEFAULT_INSTRUCTIONS, codex="codex"):
    """Build the fail-closed ``codex exec`` argv for one plan entry."""
    validate_entry(entry, root)
    model_cfg = entry.get("model") if isinstance(entry.get("model"), dict) else {}
    command = [
        codex, "exec", "--ephemeral", "--strict-config",
        "--sandbox", "read-only", "--ask-for-approval", "never",
        "--ignore-user-config", "--ignore-rules",
        "--output-schema", os.path.abspath(schema),
        "--output-last-message", output_path,
    ]
    if model_cfg.get("model"):
        command.extend(["--model", str(model_cfg["model"])])
    overrides = [
        "features.hooks=false",
        "features.multi_agent=false",
        "features.apps=false",
        "features.remote_plugin=false",
        "features.memories=false",
        "features.goals=false",
        "features.shell_snapshot=false",
        "features.skill_mcp_dependency_install=false",
        'web_search="disabled"',
        'personality="none"',
        'history.persistence="none"',
        "allow_login_shell=false",
        'shell_environment_policy.inherit="core"',
        "shell_environment_policy.ignore_default_excludes=false",
        "projects.%s.trust_level=\"untrusted\"" % _toml_string(os.path.realpath(root)),
        "model_instructions_file=%s" % _toml_string(os.path.abspath(instructions)),
    ]
    effort = model_cfg.get("model_reasoning_effort")
    if effort:
        overrides.append("model_reasoning_effort=%s" % _toml_string(effort))
    for override in overrides:
        command.extend(["--config", override])
    command.append("-")
    return command


def validate_envelope(data, entry, root):
    """Validate result fields that JSON Schema cannot bind to this plan entry."""
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("Codex response is not a findings envelope")
    expected_role = entry.get("role")
    expected_panel = entry.get("panel")
    expected_lens = entry.get("lens")
    for index, finding in enumerate(data["findings"]):
        if not isinstance(finding, dict):
            raise ValueError("finding %d is not an object" % index)
        if finding.get("source_role") != expected_role:
            raise ValueError("finding %d has source_role %r, expected %r"
                             % (index, finding.get("source_role"), expected_role))
        if finding.get("panel") != expected_panel:
            raise ValueError("finding %d has panel %r, expected %r"
                             % (index, finding.get("panel"), expected_panel))
        if expected_role == "lens_sweep" and finding.get("lens") != expected_lens:
            raise ValueError("finding %d has lens %r, expected %r"
                             % (index, finding.get("lens"), expected_lens))
        location = finding.get("location")
        rel = location.get("file") if isinstance(location, dict) else None
        if not isinstance(rel, str) or os.path.isabs(rel):
            raise ValueError("finding %d location.file must be repository-relative" % index)
        candidate = os.path.join(root, rel)
        if not _within(root, candidate):
            raise ValueError("finding %d location.file escapes the target" % index)
    data["_panopticon"] = {
        "producer": "codex_exec",
        "run_id": entry.get("run_id"),
        "role": expected_role,
        "panel": expected_panel,
        "lens": expected_lens,
        "group": entry.get("group"),
    }
    return data


def validate_schema(data, schema_path):
    """Validate against the bundled schema when jsonschema is installed."""
    try:
        import jsonschema
    except ImportError:
        return
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    try:
        jsonschema.validate(instance=data, schema=schema)
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        raise ValueError("Codex response failed findings schema: %s" % exc.message) from exc


def run_entry(entry, root, schema=DEFAULT_SCHEMA, instructions=DEFAULT_INSTRUCTIONS,
              codex="codex", timeout=DEFAULT_TIMEOUT, runner=subprocess.run):
    """Execute, validate, and atomically publish one Codex plan entry."""
    out_file = validate_entry(entry, root)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=".codex-result-", suffix=".json", dir=os.path.dirname(out_file))
    os.close(fd)
    try:
        command = build_command(entry, root, temp_path, schema, instructions, codex)
        result = runner(
            command, input=entry["prompt"], text=True, capture_output=True,
            cwd=root, timeout=timeout)
        if getattr(result, "returncode", 1) != 0:
            stderr = (getattr(result, "stderr", "") or "").strip()
            raise RuntimeError("codex exec exited %s%s" % (
                result.returncode, (": " + stderr[-1000:]) if stderr else ""))
        try:
            with open(temp_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise RuntimeError("codex exec produced invalid JSON: %s" % exc) from exc
        validate_schema(data, schema)
        data = validate_envelope(data, entry, root)
        with open(temp_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, out_file)
        return out_file
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def load_plan(path):
    try:
        with open(path, encoding="utf-8") as fh:
            plan = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read dispatch plan %s: %s" % (path, exc)) from exc
    if not isinstance(plan, list):
        raise ValueError("dispatch plan must be a JSON array")
    return plan


def run_plan(plan, root, schema=DEFAULT_SCHEMA, instructions=DEFAULT_INSTRUCTIONS,
             codex="codex", max_workers=4, timeout=DEFAULT_TIMEOUT,
             runner=subprocess.run):
    """Run pending Codex entries concurrently and return a completion tally."""
    root = os.path.realpath(root)
    pending = group_runner.pending_entries(plan)
    for entry in pending:
        validate_entry(entry, root)
    if not pending:
        return {"planned": len(plan), "skipped": len(plan), "completed": 0,
                "failed": []}
    failures = []
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_entry = {
            pool.submit(run_entry, entry, root, schema, instructions, codex,
                        timeout, runner): entry
            for entry in pending
        }
        for future in concurrent.futures.as_completed(future_to_entry):
            entry = future_to_entry[future]
            try:
                future.result()
                completed += 1
            except Exception as exc:  # noqa: BLE001 - aggregate every worker failure
                failures.append({"out_file": entry.get("out_file"), "error": str(exc)})
    return {"planned": len(plan), "skipped": len(plan) - len(pending),
            "completed": completed, "failed": failures}


def main(argv=None):
    parser = argparse.ArgumentParser(description="run a Panopticon plan with codex exec")
    parser.add_argument("plan", help="DispatchPlan JSON produced with --host codex --codex-exec")
    parser.add_argument("--root", default=".", help="target repository/worktree root")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA)
    parser.add_argument("--instructions", default=DEFAULT_INSTRUCTIONS)
    parser.add_argument("--codex", default="codex", help="Codex CLI executable")
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    if args.max_workers < 1:
        parser.error("--max-workers must be >= 1")
    if args.timeout < 1:
        parser.error("--timeout must be >= 1")
    if shutil.which(args.codex) is None:
        print("codex_runner: Codex CLI not found: %s" % args.codex, file=sys.stderr)
        return 1
    try:
        plan = load_plan(args.plan)
        tally = run_plan(plan, args.root, args.schema, args.instructions,
                         args.codex, args.max_workers, args.timeout)
    except (OSError, ValueError) as exc:
        print("codex_runner: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(tally, indent=2))
    return 1 if tally["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
