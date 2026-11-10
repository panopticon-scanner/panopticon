"""Headless runner for the `gemini` (`@google/gemini-cli`) host family (#3494).

Launches each review entry in a dedicated `gemini -p` subprocess with:
- `GEMINI_CLI_HOME` and `HOME` pointed at the isolated per-run home built by
  `runners.gemini_home`, with inherited `GEMINI_*` and `GEMINI_CLI_*` env vars
  scrubbed (except `ALLOWED_GEMINI_ENV_KEYS`)
- `cwd` pointed at `<gemini_home>/workspace` (which carries a `.git` ceiling)
- `--output-format json` for structured JSON telemetry and response envelopes
- `--approval-mode yolo` for non-interactive headless execution (subordinate to
  both our `BeforeTool` hook and Tier 5 `--admin-policy` allow/deny + catch-all
  rules)
- `--admin-policy <panopticon-<role>.toml>` for Tier 5 role tool-allowlist enforcement
- `--include-directories <review_root>` so `read_file`/`grep_search`/`glob`/`list_directory`
  can pass `WorkspaceContext.isPathReadable` (`validateToolParamValues`) from
  `<gemini_home>/workspace` while our `BeforeTool` hook (`gemini_guard_hook.py`)
  enforces per-entry `read-scope.json` and `write-allowlist.json`
- `-m <slug>` for role-resolved model binding
- `-p <escaped_prompt>` with every `@` escaped as `\\@` so `handleAtCommand` /
  `parseAllAtCommands` never invokes `ReadManyFilesTool` outside `PolicyEngine`
  and `BeforeTool`
"""
import json
import os
import re
import subprocess
import tempfile

import scripts.gemini_guard_hook as gemini_guard_hook
import scripts.hosts as hosts
import scripts.redact as redact
import scripts.runners.base as base
import scripts.runners.gemini_home as gemini_home
import scripts.runners.outage as outage


DEFAULT_RUNNER = None

_SAFE_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")
_UNESCAPED_AT_RE = re.compile(r"(?<!\\)@")
_NOISY_STDERR_LINE_RE = re.compile(
    r"^(?:YOLO mode is enabled\b|Loaded cached credentials\b|"
    r"Ripgrep is not available\b|Attempt \d+ failed\b)",
    re.I,
)

ALLOWED_GEMINI_ENV_KEYS = frozenset({
    "GEMINI_API_KEY",
    "GEMINI_API_KEY_AUTH_MECHANISM",
})

KNOWN_MODELS = frozenset({
    "gemini-4-carbon",
    "gemini-4-argon",
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-pro-preview",
    "gemini-3.1-pro-preview-customtools",
    "gemini-3.1-flash-lite",
    "gemini-3.1-flash-lite-preview",
    "gemini-3-pro-preview",
    "gemini-3-flash",
    "gemini-3-flash-preview",
    "gemma-4-31b-it",
    "gemma-4-26b-a4b-it",
    "auto",
    "pro",
    "flash",
    "flash-lite",
    "auto-gemini-3",
})

EXIT_CODE_NAMES = {
    41: "FatalAuthenticationError",
    42: "FatalInputError",
    44: "FatalSandboxError",
    52: "FatalConfigError",
    53: "FatalTurnLimitedError",
    54: "FatalToolExecutionError",
    173: "HTTP 429 rate-limit/quota (429 mod 256)",
}
HOST_FAILURE_EXIT_CODES = frozenset({41, 173})


def escape_prompt_at_tokens(prompt):
    """Escape every unescaped `@` as `\\@` so `@google/gemini-cli`'s
    `parseAllAtCommands` (`(?<!\\\\)@${AT_COMMAND_PATH_REGEX_SOURCE}` in
    `chunk-3PF5QBBI.js`) treats all `@` tokens in `-p` as literal text and never
    invokes `ReadManyFilesTool` before `PolicyEngine` / `BeforeTool`."""
    return _UNESCAPED_AT_RE.sub(r"\\@", prompt)


def _validate_flag_value(value, label):
    if not isinstance(value, str) or not value or value.startswith("-") \
            or not _SAFE_TOKEN_RE.match(value):
        raise ValueError("invalid gemini %s value: %r" % (label, value))
    return value


def _safe_int(value):
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _extract_usage_and_model(doc):
    """Extract usage telemetry and actual model slug from structured JSON fields only.

    Per `@google/gemini-cli` `UiTelemetryService.processApiResponse`
    (`chunk-32XQ54AJ.js:12551892`), `stats.models[<slug>].tokens` carries:
    - `prompt`: total prompt tokens (`promptTokenCount`, includes cached)
    - `cached`: cached prompt tokens (`cachedContentTokenCount`)
    - `input`: `Math.max(0, prompt - cached)` (already disjoint from `cached`)
    - `candidates`: output candidate tokens (`candidatesTokenCount`)
    - `thoughts`: thinking tokens (`thoughtsTokenCount`, separate from `candidates`)
    - `tool`: `toolUsePromptTokenCount` (server-side tool-use prompt tokens;
      0 for local tool executions, included by the API in `totalTokenCount`)
    - `total`: total token count (`totalTokenCount`)

    We map:
    - `input_tokens = input` (or `max(0, prompt - cached)` if `input` is absent)
    - `cache_read_input_tokens = cached`
    - `cache_creation_input_tokens = 0`
    - `output_tokens = candidates + thoughts` (so `USAGE_FIELDS` captures all
      generated output + thinking tokens without double-counting)
    - `thinking_tokens = thoughts`
    - `total_tokens = total or (input_tokens + output_tokens + cache_read_input_tokens)`
    """
    usage = {}
    model = doc.get("model") if isinstance(doc.get("model"), str) and doc.get("model") else None
    raw_usage = doc.get("usage")
    if isinstance(raw_usage, dict):
        inp = _safe_int(raw_usage.get("input_tokens"))
        out = _safe_int(raw_usage.get("output_tokens"))
        cache_read = (_safe_int(raw_usage.get("cache_read_input_tokens"))
                      or _safe_int(raw_usage.get("cache_read_tokens")))
        cache_write = (_safe_int(raw_usage.get("cache_creation_input_tokens"))
                       or _safe_int(raw_usage.get("cache_write_tokens")))
        thinking = (_safe_int(raw_usage.get("thinking_tokens"))
                    or _safe_int(raw_usage.get("reasoning_tokens")))
        total = (_safe_int(raw_usage.get("total_tokens"))
                or (inp + out + cache_read))
        usage = {
            "input_tokens": inp,
            "output_tokens": out,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_write,
            "cache_read_tokens": cache_read,
            "thinking_tokens": thinking,
            "total_tokens": total,
        }
    stats = doc.get("stats")
    models = stats.get("models") if isinstance(stats, dict) else None
    if isinstance(models, dict) and models:
        inp = out = cache_read = thinking = total = 0
        for slug, mdata in models.items():
            if model is None and isinstance(slug, str) and slug:
                model = slug
            tok = mdata.get("tokens") if isinstance(mdata, dict) else None
            if isinstance(tok, dict):
                m_cached = _safe_int(tok.get("cached"))
                if "input" in tok and tok.get("input") is not None:
                    m_inp = _safe_int(tok.get("input"))
                else:
                    m_inp = max(0, _safe_int(tok.get("prompt")) - m_cached)
                m_cand = _safe_int(tok.get("candidates"))
                m_thoughts = _safe_int(tok.get("thoughts"))
                inp += m_inp
                out += m_cand + m_thoughts
                cache_read += m_cached
                thinking += m_thoughts
                total += _safe_int(tok.get("total"))
        if not usage:
            usage = {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": 0,
                "cache_read_tokens": cache_read,
                "thinking_tokens": thinking,
                "total_tokens": total or (inp + out + cache_read),
            }
    return usage, model


def _extract_error(raw_err):
    if isinstance(raw_err, str) and raw_err.strip():
        return redact.redact(raw_err.strip())
    if isinstance(raw_err, dict):
        msg = raw_err.get("message") or raw_err.get("type")
        if isinstance(msg, str) and msg.strip():
            return redact.redact(msg.strip())
    return None


def _stderr_diagnosis(stderr):
    """Extract the structured `[ERROR]` JSON payload or the non-banner tail of
    `stderr` (up to `base.STDERR_HEAD` chars, redacted) so startup banners never
    crowd out the real failure reason at the end of `stderr`."""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    if not isinstance(stderr, str) or not stderr.strip():
        return None
    err_idx = stderr.rfind("[ERROR]")
    if err_idx >= 0:
        brace_idx = stderr.find("{", err_idx)
        if brace_idx >= 0:
            try:
                parsed = json.loads(stderr[brace_idx:].strip())
                if isinstance(parsed, dict):
                    nested = parsed.get("error")
                    err_obj = nested if isinstance(nested, dict) else parsed
                    parts = []
                    for key in ("type", "code", "message"):
                        val = err_obj.get(key)
                        if val not in (None, ""):
                            parts.append("%s: %s" % (key, val) if key != "message" else str(val))
                    if parts:
                        summary = redact.redact("[ERROR] " + " | ".join(parts))
                        return summary[:base.STDERR_HEAD]
            except ValueError:
                pass
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    kept = [ln for ln in lines if not _NOISY_STDERR_LINE_RE.match(ln)] or lines
    joined = "\n".join(kept)
    tail = joined[-base.STDERR_HEAD:] if len(joined) > base.STDERR_HEAD else joined
    return redact.redact(tail)[:base.STDERR_HEAD]


def _exit_label(returncode):
    name = EXIT_CODE_NAMES.get(returncode)
    return "%s (%s)" % (returncode, name) if name else str(returncode)


def parse_envelope(raw, returncode=0, stderr=None, *, entry_id=""):
    """Parse `gemini -p --output-format json` stdout into a `base.RunResult`."""
    raw_text = raw if isinstance(raw, str) else ""
    err_text = redact.redact(stderr.strip()) if isinstance(stderr, str) and stderr.strip() else ""
    diagnosis = _stderr_diagnosis(stderr)
    forced_class = outage.HOST_FAILURE if returncode in HOST_FAILURE_EXIT_CODES else None
    doc = None
    if raw_text.strip():
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                doc = parsed
        except ValueError:
            doc = None

    if doc is None:
        detail = diagnosis or "no JSON envelope on stdout"
        reason = ("gemini -p exited %s: %s" % (_exit_label(returncode), detail)
                  if returncode != 0 else "gemini -p returned non-JSON stdout")
        safe_raw = redact.redact(raw_text[:200]) if returncode != 0 and raw_text else ""
        return base.RunResult(
            entry_id=entry_id, ok=False, text=safe_raw,
            usage={}, cost_usd=None, model=None, session_id=None, denials=[],
            error=reason, host_error=err_text or reason or None, stderr=diagnosis,
            failure_class=forced_class,
            host_error_from_stderr=bool(err_text))

    usage, model = _extract_usage_and_model(doc)
    session_id = doc.get("session_id") or doc.get("conversation_id")
    session_id = session_id if isinstance(session_id, str) else None

    structured = doc.get("structured_output")
    response = doc.get("response")
    if isinstance(structured, (dict, list)):
        text = json.dumps(structured)
    elif isinstance(response, str):
        text = response
    else:
        text = ""

    denials = []
    raw_denials = doc.get("denied_actions")
    if isinstance(raw_denials, list):
        for item in raw_denials:
            if isinstance(item, dict):
                tool = item.get("action") or item.get("display_name") or "unknown"
                denials.append({"tool": str(tool), "args": item})

    status = doc.get("status")
    host_error = _extract_error(doc.get("error"))
    ok = (returncode == 0) and (status in ("SUCCESS", None)) and not host_error
    if not ok:
        reason = (host_error
                  or diagnosis
                  or ("gemini status %r (exit %s)" % (status, _exit_label(returncode))))
        return base.RunResult(
            entry_id=entry_id, ok=False, text=text, usage=usage, cost_usd=None,
            model=model, session_id=session_id, denials=denials,
            error="gemini -p exited %s: %s" % (_exit_label(returncode), reason),
            host_error=host_error or err_text or reason or None, stderr=diagnosis,
            failure_class=forced_class,
            host_error_from_stderr=bool(not host_error and err_text))

    return base.RunResult(
        entry_id=entry_id, ok=True, text=text, usage=usage, cost_usd=None,
        model=model, session_id=session_id, denials=denials, error=None)


class Runner(base.HostRunner):
    CLI = "gemini"
    ENVELOPE_FLAGS = ("-p", "--output-format")
    OUTPUT_SCHEMA_FLAG = ()
    HONOURS_MAX_TURNS = False
    mode = "headless"
    default_concurrency = 4

    def __init__(self, host="gemini", runner=None):
        super().__init__(host)
        self.runner = self.launcher(runner, DEFAULT_RUNNER)
        self.gemini_home = None
        self.run_home = None
        self.user_home = None
        self.workspace_dir = None
        self.run_dir = None
        self.review_root = None
        self.registration_dir = None
        self.system_config_dir = None
        self.max_turns = 60
        self.entry_timeout = 1800

    def prepare(self, run_dir, review_root=None, *, registration_dir=None):
        self.run_dir = os.path.abspath(run_dir)
        self.review_root = os.path.abspath(review_root or run_dir)
        if registration_dir is not None:
            self.registration_dir = os.path.abspath(registration_dir)
        os.makedirs(self.run_dir, exist_ok=True)
        if self.gemini_home is not None and os.path.isdir(self.gemini_home):
            return
        self.user_home = os.path.expanduser("~")
        read_scope = os.path.join(self.run_dir, base.SCOPE_FILE)
        write_allowlist = os.path.join(self.run_dir, base.ALLOWLIST_FILE)
        self.gemini_home = gemini_home.build(
            read_scope, write_allowlist,
            user_home=self.user_home,
            review_root=self.review_root)
        self.run_home = self.gemini_home
        self.workspace_dir = gemini_home.workspace_dir(self.gemini_home)

    def teardown(self, status=None):
        if self.gemini_home is not None:
            gemini_home.teardown(self.gemini_home, status)
            if status == "complete":
                self.gemini_home = None
                self.run_home = None
                self.workspace_dir = None

    def launch_env(self, overlay=None):
        run_env = super().launch_env(overlay)
        for key in list(run_env):
            if (key.startswith("GEMINI_") or key == "GEMINI_CLI") \
                    and key not in ALLOWED_GEMINI_ENV_KEYS \
                    and key != gemini_guard_hook.ENV_DENIAL_LOG:
                run_env.pop(key, None)
        if self.gemini_home:
            run_env["HOME"] = self.gemini_home
            run_env["GEMINI_CLI_HOME"] = self.gemini_home
        run_env["NO_COLOR"] = "1"
        return run_env

    def _shell_path(self, entry):
        name = base.registered_agent(entry, roles=self.roles)
        if name is None:
            return None
        spec = hosts.spec(self.host)
        directory = (self.registration_dir
                     or (spec.registration_dir if spec else ""))
        if not directory:
            return None
        root = os.path.realpath(directory)
        real = os.path.realpath(os.path.join(directory, "%s.toml" % name))
        return real if (real == root or real.startswith(root + os.sep)) else None

    def _include_dirs_argv(self, entry):
        dirs: list[str] = []
        if self.review_root:
            dirs.append(self.review_root)
        if self.run_dir and not any(gemini_home._inside(self.run_dir, d) for d in dirs):
            dirs.append(self.run_dir)
        out_file = entry.get("out_file") if isinstance(entry, dict) else None
        if isinstance(out_file, str) and out_file.strip():
            out_dir = os.path.dirname(os.path.abspath(out_file))
            if out_dir and not any(gemini_home._inside(out_dir, d) for d in dirs):
                dirs.append(out_dir)
        argv: list[str] = []
        for d in dirs:
            argv.extend(["--include-directories", d])
        return argv

    def command(self, entry, model=None):
        prompt = entry.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("gemini entry %r has no prompt" % (entry.get("id"),))
        hazards = gemini_home.system_policy_hazards(
            env={}, system_config_dir=self.system_config_dir)
        if hazards:
            raise RuntimeError("gemini system policy hazard: %s" % "; ".join(hazards))
        cmd = [
            self.CLI,
            "--output-format", "json",
            "--approval-mode", "yolo",
        ]
        if entry.get("enforced"):
            name = base.registered_agent(entry, roles=self.roles)
            if name is None:
                raise RuntimeError(base.UNREGISTERED_AGENT
                                   % redact.redact(str(entry.get("agent"))[:200]))
            shell = self._shell_path(entry)
            if shell is None:
                raise RuntimeError("enforcement policy path for %r could not be resolved"
                                   % (name,))
            cmd.extend(["--admin-policy", shell])
        elif self.gemini_home:
            cmd.extend(["--admin-policy", gemini_home.unenforced_policy_path(self.gemini_home)])
        cmd.extend(self._include_dirs_argv(entry))
        eff_model = model if model is not None else entry.get("model")
        if eff_model is not None:
            cmd.extend(["-m", _validate_flag_value(eff_model, "-m")])
        cmd.extend(["-p", escape_prompt_at_tokens(prompt)])
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode=0, stderr=None):
        return parse_envelope(stdout, returncode=returncode, stderr=stderr,
                              entry_id=entry_id)

    def _read_hook_denials(self, log_path):
        denials: list[dict] = []
        if not log_path or not os.path.isfile(log_path):
            return denials
        try:
            with open(log_path, encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict):
                        denials.append(rec)
        except OSError:
            pass
        return denials

    def run_entry(self, entry, env):
        entry_id = entry.get("id")
        if self.gemini_home is None:
            return base.RunResult.failed(
                entry_id, "the gemini runner was not prepared before run_entry")
        if entry.get("enforced"):
            if base.registered_agent(entry, roles=self.roles) is None:
                return base.refuse_unregistered_agent(entry, roles=self.roles)
            shell = self._shell_path(entry)
            if shell is None or not os.path.isfile(shell):
                return base.RunResult.failed(
                    entry_id, "enforcement shell not registered for %r "
                    "(run dispatch.py --emit-host-agents gemini)" % entry.get("agent"))
        eff_model = entry.get("model")
        if eff_model is not None and eff_model not in KNOWN_MODELS:
            return base.RunResult.failed(
                entry_id, "entry model %r is not in gemini's known model catalogue"
                % eff_model)
        launcher = (DEFAULT_RUNNER
                    if (self.runner == self.launch and DEFAULT_RUNNER is not None)
                    else self.launcher(self.runner, DEFAULT_RUNNER))
        fd, denial_log = tempfile.mkstemp(
            prefix="denials-", suffix=".jsonl", dir=self.gemini_home)
        os.close(fd)
        result = None
        proc = None
        try:
            child_env = self.launch_env(env)
            hazard = gemini_home.auth_hazard(env=child_env, real_user_home=self.user_home)
            if hazard:
                return base.RunResult.failed(
                    entry_id, hazard, host_error=hazard,
                    failure_class=outage.HOST_FAILURE)
            child_env[gemini_guard_hook.ENV_DENIAL_LOG] = denial_log
            cmd = self.command(entry, eff_model)
            proc = launcher(
                cmd, cwd=self.workspace_dir, env=child_env,
                capture_output=True, text=True, timeout=self.entry_timeout)
        except base.LaunchRefused:
            raise
        except subprocess.TimeoutExpired as exc:
            result = base.RunResult.failed(
                entry_id, "gemini -p timed out after %ss" % self.entry_timeout,
                text=base.partial_output(exc),
                stderr=_stderr_diagnosis(getattr(exc, "stderr", None)))
        except OSError as exc:
            result = base.RunResult.failed(
                entry_id,
                redact.redact("could not launch %s: %s" % (self.CLI, exc)))
        except Exception as exc:  # noqa: BLE001 -- spec 4.4: run_entry never raises
            result = base.RunResult.failed(
                entry_id,
                redact.redact("gemini -p launch raised %s: %s" % (type(exc).__name__, exc)))
        finally:
            hook_denials = self._read_hook_denials(denial_log)
            try:
                os.unlink(denial_log)
            except OSError:
                pass

        if result is None:
            result = self.parse_envelope(
                entry_id, getattr(proc, "stdout", ""),
                getattr(proc, "returncode", 1),
                stderr=getattr(proc, "stderr", None))
        if hook_denials:
            result.denials = list(result.denials or []) + hook_denials
        return result
