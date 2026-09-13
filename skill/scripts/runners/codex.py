"""One confined Codex launch; dispatch and persistence belong to the loop."""
import json
import os
import subprocess

from scripts import codex_host
import scripts.runners.base as base


# The launcher, as a MODULE attribute rather than a default argument, so a
# single monkeypatch can refuse every un-injected launch in the suite (the
# autouse `_no_live_codex_launches` fixture in tests/conftest.py does exactly
# that). A default argument is bound at import and cannot be swapped.
DEFAULT_RUNNER = subprocess.run


class Runner(base.HostRunner):
    host = "codex"
    default_concurrency = 4
    # The seam's identity, mirrored from what codex_host.command() actually
    # emits: `codex exec ... --json` is what prints the JSONL envelope
    # parse_envelope reads. test_the_seam_names_its_cli_and_the_flags_that_
    # print_the_envelope binds these two constants to that argv.
    CLI = "codex"
    ENVELOPE_FLAGS = ("exec", "--json")
    # `codex exec` has no turn cap; an entry is bounded by --entry-timeout.
    HONOURS_MAX_TURNS = False

    def __init__(self, host="codex", runner=None):
        super().__init__(host)
        self.runner = DEFAULT_RUNNER if runner is None else runner
        self.run_dir = None
        self.review_root = None
        self.entry_timeout = 1800

    def prepare(self, run_dir, review_root):
        # Codex is enforced-only (I-1). Refuse here, once, rather than letting
        # every entry fail its three launches on a missing shell: `prepare`
        # runs before the first batch, so the loop reports one `error` naming
        # the remedy instead of 3xN launches naming an entry id.
        codex_host.require_registered_shells()
        self.run_dir = os.path.abspath(run_dir)
        self.review_root = os.path.abspath(review_root)

    @staticmethod
    def parse_envelope(entry_id, stdout, returncode):
        """Parse exec's JSONL, retaining measured usage even on failed turns.

        Cached input is a SUBSET of Codex input_tokens. The shared ledger sums
        disjoint fields, so subtract it before mapping to cache_read_input_tokens.
        Codex does not report dollars: never turn an unknown cost into zero or
        infer it from a pricing table. Likewise, don't invent a returned model
        identity from the model requested on argv.
        """
        text, session_id, model, error = "", None, None, None
        usage, denials, completed = {}, [], False
        try:
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event is not an object")
                kind = event.get("type")
                if kind == "thread.started":
                    session_id = event.get("thread_id")
                elif kind == "turn.completed":
                    completed = True
                    if text:
                        # M-2: a `turn.failed`/`error` event the turn then
                        # RECOVERED from is not a failed entry. Leaving it set
                        # cost a retry and a strike against the three-launch
                        # cap for a turn that produced its final message. A
                        # failure AFTER this point still fails, because it
                        # sets `error` again below.
                        error = None
                    reported = event.get("usage")
                    if reported is None or reported == {}:
                        continue
                    if not isinstance(reported, dict):
                        raise ValueError("usage is not an object")
                    values = {}
                    for field in ("input_tokens", "cached_input_tokens", "output_tokens"):
                        value = reported.get(field, 0)
                        if type(value) is not int or value < 0:
                            raise ValueError("invalid %s" % field)
                        values[field] = value
                    cached = values["cached_input_tokens"]
                    if cached > values["input_tokens"]:
                        raise ValueError("cached tokens exceed total input")
                    for field, value in {
                        "input_tokens": values["input_tokens"] - cached,
                        "cache_read_input_tokens": cached,
                        "output_tokens": values["output_tokens"],
                        "cache_creation_input_tokens": 0,
                    }.items():
                        usage[field] = usage.get(field, 0) + value
                elif kind in ("turn.failed", "error"):
                    error = str(event.get("error") or event.get("message") or kind)
                elif kind == "item.completed":
                    item = event.get("item") or {}
                    if not isinstance(item, dict):
                        raise ValueError("item is not an object")
                    if item.get("type") == "agent_message":
                        # Commentary may precede the final JSON object.
                        text = item.get("text", "")
                        if not isinstance(text, str):
                            raise ValueError("agent message is not text")
                    elif item.get("type") == "mcp_tool_call":
                        result = item.get("result") or {}
                        # Native exec omits MCP isError from the result and
                        # marks the completed item's status failed instead.
                        if (item.get("status") == "failed" or item.get("error")
                                or (isinstance(result, dict) and result.get("isError"))):
                            denials.append(item)
            if returncode:
                error = error or "codex exited with status %s" % returncode
            elif not completed:
                error = error or "codex returned no turn.completed event"
            elif not text:
                error = error or "codex returned no final message"
        except (TypeError, ValueError) as exc:
            error = "invalid Codex JSONL: %s" % exc
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text,
                         usage=usage, cost_usd=None, model=model,
                         session_id=session_id, denials=denials, error=error)

    def run_entry(self, entry, env):
        entry_id = entry.get("id", "") if isinstance(entry, dict) else ""
        command = None
        try:
            if self.run_dir is None or self.review_root is None:
                raise ValueError("Codex runner was not prepared")
            child_env = dict(os.environ)
            child_env.update(env)
            if not entry_id or child_env.get(base.ENV_ENTRY_ID) != entry_id:
                raise ValueError("missing or mismatched Codex entry binding")
            if entry.get("delivery") != "return_json":
                raise ValueError("Codex requires delivery: return_json; it cannot self-write")
            command = codex_host.command(entry, child_env, self.review_root, self.run_dir,
                                         runner=self.runner)
            codex_host.validate_command(command, child_env, self.review_root)
            proc = self.runner(command, input=entry["prompt"], text=True,
                             capture_output=True, cwd=self.review_root,
                             env=child_env, timeout=self.entry_timeout)
            return self.parse_envelope(entry_id, proc.stdout, proc.returncode)
        except subprocess.TimeoutExpired:
            return base.RunResult.failed(entry_id, "codex timed out after %ss" % self.entry_timeout)
        except Exception as exc:
            return base.RunResult.failed(entry_id, "%s: %s" % (type(exc).__name__, exc))
        finally:
            if command is not None:
                codex_host.cleanup_command(command)
