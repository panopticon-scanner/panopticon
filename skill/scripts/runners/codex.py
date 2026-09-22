"""One confined Codex launch; dispatch and persistence belong to the loop."""
import json
import os
import subprocess

from scripts import codex_host
import scripts.runners.base as base
import scripts.runners.schema as schema_argv_rules


# The launcher, as a MODULE attribute rather than a default argument, so a
# single monkeypatch can refuse every un-injected launch in the suite (the
# autouse `_no_live_codex_launches` fixture in tests/conftest.py does exactly
# that). A default argument is bound at import and cannot be swapped.
DEFAULT_RUNNER = subprocess.run
# The loop's value for `runner.namespace` under `--setup` (runners/base.py).
SETUP_NAMESPACE = "setup"


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
        self.runner = DEFAULT_RUNNER if runner is None else runner
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
        if self.namespace != SETUP_NAMESPACE:
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
        text, session_id, model, error = "", None, None, None
        usage: dict[str, int] = {}
        denials = []
        completed = False
        host_error = None          # #1623: only the host's own failure event fills this
        # N-I3: WHEN each was last set, so a recovery can be told from
        # commentary. Every agent_message overwrites `text`, and commentary
        # legitimately precedes the final JSON, so "text is non-empty" does
        # not mean "this turn produced its final message".
        text_seq, error_seq = -1, -1
        try:
            for sequence, line in enumerate(stdout.splitlines()):
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
                    if text and text_seq > error_seq:
                        # M-2: a `turn.failed`/`error` event the turn then
                        # RECOVERED from is not a failed entry. Leaving it set
                        # cost a retry and a strike against the three-launch
                        # cap for a turn that produced its final message.
                        # N-I3: only when the final message arrived AFTER the
                        # failure. Commentary before it is not a recovery, and
                        # a failure after this point still fails, because it
                        # sets `error` again below.
                        error = host_error = None
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
                    # #1623: THIS is the host talking -- the harness's own
                    # failure event, not an agent_message -- so it is the one
                    # thing on this stream the outage classifier may read.
                    host_error = event.get("error") or event.get("message") or kind
                    error = str(host_error)
                    error_seq = sequence
                elif kind == "item.completed":
                    item = event.get("item") or {}
                    if not isinstance(item, dict):
                        raise ValueError("item is not an object")
                    if item.get("type") == "agent_message":
                        # Commentary may precede the final JSON object.
                        text = item.get("text", "")
                        if not isinstance(text, str):
                            raise ValueError("agent message is not text")
                        text_seq = sequence
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
        if host_error is None and error is not None and (stderr or "").strip():
            # The outage shape #1623 names for this family: the rate limit is
            # refused before `exec` prints a single JSONL event, so the only
            # thing the host said is on stderr.
            host_error = stderr.strip()
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text,
                         usage=usage, cost_usd=None, model=model,
                         session_id=session_id, denials=denials, error=error,
                         host_error=host_error,
                         # #1732: the same stream, kept as a FIELD as well. It
                         # reaches the classifier only through `host_error`
                         # above, whose rules are unchanged.
                         stderr=base.stderr_head(stderr) if error is not None else None)

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
