"""One confined Codex launch; dispatch and persistence belong to the loop."""
import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any

from scripts import codex_host
import scripts.runners.base as base
import scripts.runners.schema as schema_argv_rules


# The launcher, as a MODULE attribute rather than a default argument, so a
# single monkeypatch can refuse every un-injected launch in the suite (the
# autouse `_no_live_codex_launches` fixture in tests/conftest.py does exactly
# that). A default argument is bound at import and cannot be swapped.
#
# #1575: None is the SENTINEL for "this runner's own `HostRunner.launch`" --
# a process-group-aware Popen that registers its child, so a family-side
# timeout reaches the workers `codex exec` spawns and not just its own pid.
# The attribute keeps its name and its place (LAUNCH_SEAMS, the AST walk in
# tests/test_host_launch_guard.py); only its value changed.
DEFAULT_RUNNER = None


def _usage_fields(reported):
    """Validate a completed turn before adding its disjoint token counts."""
    if reported is None or reported == {}:
        return {}
    if not isinstance(reported, dict):
        raise ValueError("usage is not an object")
    values = {}
    for name in ("input_tokens", "cached_input_tokens", "output_tokens"):
        value = reported.get(name, 0)
        if type(value) is not int or value < 0:
            raise ValueError("invalid %s" % name)
        values[name] = value
    cached = values["cached_input_tokens"]
    if cached > values["input_tokens"]:
        raise ValueError("cached tokens exceed total input")
    return {"input_tokens": values["input_tokens"] - cached,
            "cache_read_input_tokens": cached,
            "output_tokens": values["output_tokens"],
            "cache_creation_input_tokens": 0}


@dataclass
class _EnvelopeState:
    """Measured fields and ordering needed to distinguish recovery from commentary."""

    text: Any = ""
    session_id: Any = None
    error: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    denials: list[dict] = field(default_factory=list)
    completed: bool = False
    host_error: Any = None
    text_seq: int = -1
    error_seq: int = -1

    def _completed_turn(self, event):
        self.completed = True
        if self.text and self.text_seq > self.error_seq:
            # A final message AFTER the failure can recover it. Commentary
            # before it cannot; a subsequent failure sets the error again.
            self.error = self.host_error = None
        for name, value in _usage_fields(event.get("usage")).items():
            self.usage[name] = self.usage.get(name, 0) + value

    def _completed_item(self, event, sequence):
        item = event.get("item") or {}
        if not isinstance(item, dict):
            raise ValueError("item is not an object")
        if item.get("type") == "agent_message":
            self.text = item.get("text", "")
            if not isinstance(self.text, str):
                raise ValueError("agent message is not text")
            self.text_seq = sequence
        elif item.get("type") == "mcp_tool_call":
            result = item.get("result") or {}
            # Native exec can mark the item failed without MCP isError.
            if (item.get("status") == "failed" or item.get("error")
                    or (isinstance(result, dict) and result.get("isError"))):
                self.denials.append(item)

    def accept(self, event, sequence):
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        kind = event.get("type")
        if kind == "thread.started":
            self.session_id = event.get("thread_id")
        elif kind == "turn.completed":
            self._completed_turn(event)
        elif kind in ("turn.failed", "error"):
            # Only the host's own failure event feeds outage classification.
            self.host_error = event.get("error") or event.get("message") or kind
            self.error = str(self.host_error)
            self.error_seq = sequence
        elif kind == "item.completed":
            self._completed_item(event, sequence)

    def finish(self, returncode):
        if returncode:
            self.error = self.error or "codex exited with status %s" % returncode
        elif not self.completed:
            self.error = self.error or "codex returned no turn.completed event"
        elif not self.text:
            self.error = self.error or "codex returned no final message"

    def result(self, entry_id, stderr):
        if self.host_error is None and self.error is not None and (stderr or "").strip():
            # A refusal before exec emits JSONL can leave only host stderr.
            self.host_error = stderr.strip()
        return base.RunResult(
            entry_id=entry_id, ok=self.error is None, text=self.text,
            usage=self.usage, cost_usd=None, model=None,
            session_id=self.session_id, denials=self.denials, error=self.error,
            host_error=self.host_error,
            stderr=base.stderr_head(stderr) if self.error is not None else None)


class Runner(base.HostRunner):
    host = "codex"
    default_concurrency = 4
    # The seam's identity, mirrored from what codex_host.command() actually
    # emits: `codex exec ... --json` is what prints the JSONL envelope
    # parse_envelope reads. test_the_seam_names_its_cli_and_the_flags_that_
    # print_the_envelope binds these two constants to that argv.
    CLI = "codex"
    ENVELOPE_FLAGS = ("exec", "--json")
    # D10 ruling 3: `codex exec --output-schema <FILE>` ("Path to a JSON Schema
    # file describing the model's final response shape"). One owner for the
    # token itself: `codex_host.SCHEMA_FLAG`, which is what builds the argv.
    OUTPUT_SCHEMA_FLAG = (codex_host.SCHEMA_FLAG,)
    # Where that flag is DOCUMENTED: `codex exec --help`. The top-level
    # `codex --help` lists subcommands, so a probe reading it would record
    # "not advertised" for a CLI that takes the flag perfectly well (D10 N1).
    # The subcommand is ENVELOPE_FLAGS' own first token, spelled once.
    HELP_ARGV = (ENVELOPE_FLAGS[0], "--help")
    # `codex exec` has no turn cap; an entry is bounded by --entry-timeout.
    HONOURS_MAX_TURNS = False

    def __init__(self, host="codex", runner=None):
        super().__init__(host)
        self.runner = self.launcher(runner, DEFAULT_RUNNER)
        self.run_dir = None
        self.review_root = None
        self.entry_timeout = 1800

    def prepare(self, run_dir, review_root):
        # Codex is enforced-only (I-1). Refuse here, once, rather than letting
        # every entry fail its three launches on a missing shell: `prepare`
        # runs before the first batch, so the loop reports one `error` naming
        # the remedy instead of 3xN launches naming an entry id.
        #
        # Except under `--setup`, whose only entry is `setup-scan`. Since
        # #1737 that entry DOES name a shell -- `panopticon-setup-scan`,
        # whenever this host's posture proves enforcement -- and `_shell`
        # reads it from the registration directory like any other role's. What
        # keeps the stand-down is the other posture: on a machine that has not
        # run `--emit-host-agents codex`, the entry is built unenforced with no
        # `agent` and launches off safety_config() alone, behind the operator's
        # `--allow-unenforced`. That is how a fresh machine starts, so refusing
        # up front here would break the documented first command for the sake
        # of a shell that launch never asks for.
        if self.namespace != base.SETUP_NAMESPACE:
            codex_host.require_registered_shells()
        self.run_dir = os.path.abspath(run_dir)
        self.review_root = os.path.abspath(review_root)

    @staticmethod
    def parse_envelope(entry_id, stdout, returncode, stderr=None):
        """Parse exec's JSONL, retaining measured usage even on failed turns.

        Cached input is a SUBSET of Codex input_tokens. The shared ledger sums
        disjoint fields, so subtract it before mapping to cache_read_input_tokens.
        Codex does not report dollars: never turn an unknown cost into zero or
        infer it from a pricing table. Likewise, don't invent a returned model
        identity from the model requested on argv.
        """
        state = _EnvelopeState()
        try:
            for sequence, line in enumerate(stdout.splitlines()):
                if line.strip():
                    state.accept(json.loads(line), sequence)
            state.finish(returncode)
        except (TypeError, ValueError) as exc:
            state.error = "invalid Codex JSONL: %s" % exc
        return state.result(entry_id, stderr)

    def run_entry(self, entry, env):
        entry_id = entry.get("id", "") if isinstance(entry, dict) else ""
        command = None
        try:
            if self.run_dir is None or self.review_root is None:
                raise ValueError("Codex runner was not prepared")
            # #1626 I2: through the seam's ONE env preparation
            # (`base.HostRunner.launch_env`), which for Codex IS exactly this
            # -- os.environ plus the overlay -- so there is no override, only
            # the shared call. A probe that needs the same environment now has
            # somewhere to get it.
            child_env = self.launch_env(env)
            if not entry_id or child_env.get(base.ENV_ENTRY_ID) != entry_id:
                raise ValueError("missing or mismatched Codex entry binding")
            if entry.get("delivery") != "return_json":
                raise ValueError("Codex requires delivery: return_json; it cannot self-write")
            # #1720: the same allowlist every family applies. This family
            # looks its shell up by NAME in a TOML registry (`codex_host._shell`
            # already refuses a name that is not `panopticon-[a-z0-9-]+` and
            # opens it O_NOFOLLOW), so a foreign name could not traverse -- it
            # failed later, as an unreadable registration file, which reads as
            # a broken machine rather than as a request that named an agent
            # this driver never registered.
            if entry.get("enforced") and base.registered_agent(
                    entry, roles=self.roles) is None:
                return base.refuse_unregistered_agent(entry, roles=self.roles)
            command = codex_host.command(entry, child_env, self.review_root, self.run_dir,
                                         runner=self.runner,
                                         schema_argv=schema_argv_rules.schema_argv(
                                             self.OUTPUT_SCHEMA_FLAG, entry))
            codex_host.validate_command(command, child_env, self.review_root)
            # #1657 step 2 / CX-9: the child's PROCESS cwd is the same
            # run-owned scratch `--cd` names, never the review root. A codex
            # launch discovers `AGENTS.md`, `.codex/skills`, `.agents/skills`
            # and `.codex/config.toml` by walking up from a root the spike
            # could not pin down read-only; pointing both at one empty
            # directory outside the target settles it. `launch_cwd` takes the
            # value from codex_host's own registry, not from argv.
            proc = self.runner(command, input=entry["prompt"], text=True,
                             capture_output=True, cwd=codex_host.launch_cwd(command),
                             env=child_env, timeout=self.entry_timeout)
            return self.parse_envelope(entry_id, proc.stdout, proc.returncode,
                                       stderr=proc.stderr)
        except subprocess.TimeoutExpired as exc:
            # D10 ruling 5: exec's envelope is a line per event, so a killed
            # launch's stdout still holds every `turn.completed` usage line it
            # printed. Summed by the ordinary parser (one owner for that
            # arithmetic, cached-input subtraction included) and recorded: those
            # tokens were spent, and `Ledger.usage_document` counts failed rows.
            partial = base.partial_output(exc)
            return base.RunResult.failed(entry_id, "codex timed out after %ss" % self.entry_timeout,
                                          usage=self.parse_envelope(entry_id, partial, 0).usage,
                                          stderr=base.stderr_head(getattr(exc, "stderr", None)),
                                          text=partial)
        except Exception as exc:
            return base.RunResult.failed(entry_id, "%s: %s" % (type(exc).__name__, exc))
        finally:
            if command is not None:
                codex_host.cleanup_command(command)
