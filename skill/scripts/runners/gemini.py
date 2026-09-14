"""The Gemini headless runner (spec 4.4): one `agy -p` per entry, usage from the JSON envelope."""
import json
import os
import subprocess

import scripts.runners.base as base

class Runner(base.HostRunner):
    CLI = "agy"
    mode = "headless"
    default_concurrency = 8

    def __init__(self, host="gemini", runner=subprocess.run):
        super().__init__(host)
        self.runner = runner
        self.review_root = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry

    def prepare(self, run_dir, review_root):
        """Write <run_dir>/.agents/hooks.json for read/write confinement."""
        self.review_root = os.path.abspath(review_root)
        self.run_dir = os.path.abspath(run_dir)
        os.makedirs(run_dir, exist_ok=True)
        
        # Setup hooks.json for Panopticon confinement
        agents_dir = os.path.join(self.run_dir, ".agents")
        os.makedirs(agents_dir, exist_ok=True)
        hooks_file = os.path.join(agents_dir, "hooks.json")
        
        # The hook script is in the repo: skill/scripts/gemini_guard.py
        hook_cmd = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "gemini_guard.py"))
            
        hooks_data = {
            "panopticon-guard": {
                "PreToolUse": [
                    {
                        "matcher": "view_file|grep_search|find_by_name|list_dir|run_command|write_to_file",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"{sys.executable} {hook_cmd}"
                            }
                        ]
                    }
                ]
            }
        }
        with open(hooks_file, "w", encoding="utf-8") as f:
            json.dump(hooks_data, f, indent=2)

    def command(self, entry, max_turns):
        """The argv for one entry.
        """
        cmd = [self.CLI, "-p", "--output-format", "json",
               "--dangerously-skip-permissions"]
        
        if entry.get("enforced") and entry.get("agent"):
            cmd += ["--agent", entry["agent"]]
        elif entry.get("model"):
            cmd += ["--model", entry["model"]]
            
        # Add the target repo as workspace so agy can reach it
        cmd += ["--add-dir", self.review_root]
                
        cmd.append(entry["prompt"])
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode):
        try:
            data = json.loads(stdout or "")
        except ValueError:
            return base.RunResult.failed(entry_id, "agy -p printed no JSON envelope (exit %s)" % returncode)
        if not isinstance(data, dict):
            return base.RunResult.failed(entry_id, "agy -p envelope is not an object")
        
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        
        # Determine model
        model = None  # Maybe agy returns it in usage or not?
        
        denials = []
        text = data.get("response") if isinstance(data.get("response"), str) else ""
        error = None
        if returncode != 0:
            error = "agy -p exited %s: %s" % (returncode, text[:200])
        elif data.get("status") != "SUCCESS":
            error = "agy -p reported non-SUCCESS status: %s" % str(data.get("status"))
            
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text if error is None else "",
                               usage=usage, cost_usd=None, model=model,
                               session_id=data.get("conversation_id"), denials=denials, error=error)

    def run_entry(self, entry, env):
        run_env = dict(os.environ)
        run_env.update(env)
        # Drop AGY_SESSION to avoid nesting failure if we were in one
        run_env.pop("AGY_SESSION", None)
        run_env.pop("GEMINI_SESSION", None)
        
        # Tell gemini_guard.py where the scope and allowlist are
        run_env["PANOPTICON_READ_SCOPE"] = os.path.join(self.review_root, ".panopticon", "read-scope.json")
        run_env["PANOPTICON_WRITE_ALLOWLIST"] = os.path.join(self.review_root, ".panopticon", "write-allowlist.json")
        
        cmd = self.command(entry, self.max_turns)
        try:
            # Run in run_dir so agy loads .agents/hooks.json from there!
            proc = self.runner(cmd, cwd=self.run_dir, env=run_env, capture_output=True,
                                text=True, timeout=self.entry_timeout)
        except subprocess.TimeoutExpired:
            return base.RunResult.failed(entry.get("id"), "agy -p timed out after %ss" % self.entry_timeout)
        except OSError as exc:
            return base.RunResult.failed(entry.get("id"), "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:
            return base.RunResult.failed(entry.get("id"),
                                          "agy -p launch raised %s: %s" % (type(exc).__name__, exc))
        return self.parse_envelope(entry.get("id"), proc.stdout, proc.returncode)
