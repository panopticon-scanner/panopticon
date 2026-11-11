"""Headless runner for the `agy` (Google Antigravity CLI) host family (#3493).

Launches each review entry in a dedicated `agy -p` subprocess with:
- `HOME` pointed at the isolated per-run home built by `runners.agy_home`
- `cwd` pointed at `<agy_home>/workspace` (which carries a `.git` ceiling)
- `--disable-slash-commands` to stop `/skill` and slash-command expansion of the `-p` prompt
- `--agent <shell>` for enforced entries
- `--model <slug>` for role-resolved model binding
- `--json-schema <inline_json>` for structured JSON output when advertised
"""
import json
import os
import re
import subprocess
import tempfile

import scripts.agy_guard_hook as agy_guard_hook
import scripts.hosts as hosts
import scripts.redact as redact
import scripts.runners.agy_home as agy_home
import scripts.runners.base as base
import scripts.runners.schema as schema


DEFAULT_RUNNER = None

_SAFE_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")
_NESTED_MARKERS = ("ANTIGRAVITY_CLI", "ANTIGRAVITY_CLI_ALIAS")

# The 4.6 and GPT-OSS rows retire on 2026-11-18; keep them until that date so
# currently supported Free/Plus runs do not fail closed a week early.
# models-verified: 2026-11-11 https://antigravity.google/docs/models https://antigravity.google/docs/enterprise
KNOWN_MODELS = frozenset({
    "gemini-4-carbon",
    "gemini-4-argon",
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.1-pro-preview",
    "gemini-3.8-flash-lite",
    "gemini-3.8-flash-low",
    "gemini-3.8-flash-medium",
    "gemini-3.8-flash-high",
    "gemini-4-argon-low",
    "gemini-4-argon-high",
    "claude-sonnet-5-5",
    "claude-sonnet-5-5-low",
    "claude-sonnet-5-5-medium",
    "claude-sonnet-5-5-high",
    "claude-sonnet-5-5-max",
    "claude-opus-5-5",
    "claude-opus-5-5-low",
    "claude-opus-5-5-medium",
    "claude-opus-5-5-high",
    "claude-opus-5-5-max",
    # Retire after 2026-11-18, matching the provider removal date above.
    "claude-sonnet-4-6",
    "claude-opus-4-6-thinking",
    "gpt-oss-120b-medium",
})


def _validate_flag_value(value, label):
    if not isinstance(value, str) or not value or value.startswith("-") \
            or not _SAFE_TOKEN_RE.match(value):
        raise ValueError("invalid agy %s value: %r" % (label, value))
    return value


def _sanitize_gemini_schema(obj):
    """Strip non-string `enum`/`const` keywords that Gemini's FunctionDeclaration
    converter rejects with HTTP 400 (`enum[0]: cannot be empty`)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "enum" and isinstance(v, list) \
                    and not all(isinstance(x, str) for x in v):
                continue
            if k == "const" and not isinstance(v, str):
                continue
            out[k] = _sanitize_gemini_schema(v)
        return out
    if isinstance(obj, list):
        return [_sanitize_gemini_schema(x) for x in obj]
    return obj


def _safe_int(value):
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _extract_usage_and_model(doc):
    usage = {}
    model = doc.get("model") if isinstance(doc.get("model"), str) else None
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
                 or (inp + out + cache_read + thinking))
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
                inp += _safe_int(tok.get("input"))
                out += _safe_int(tok.get("candidates"))
                cache_read += _safe_int(tok.get("cached"))
                thinking += _safe_int(tok.get("thoughts"))
                total += _safe_int(tok.get("total"))
        if not usage:
            usage = {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": 0,
                "cache_read_tokens": cache_read,
                "thinking_tokens": thinking,
                "total_tokens": total or (inp + out + cache_read + thinking),
            }
    return usage, model


def parse_envelope(raw, returncode=0, stderr=None, *, entry_id=""):
    """Parse `agy -p --output-format json` stdout into a `base.RunResult`."""
    raw_text = raw if isinstance(raw, str) else ""
    err_text = redact.redact(stderr.strip()) if isinstance(stderr, str) and stderr.strip() else ""
    diagnosis = base.stderr_head(stderr)
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
        reason = ("agy -p exited %s: %s" % (returncode, detail)
                  if returncode != 0 else "agy -p returned non-JSON stdout")
        return base.RunResult(
            entry_id=entry_id, ok=False, text=raw_text if returncode != 0 else "",
            usage={}, cost_usd=None, model=None, session_id=None, denials=[],
            error=reason, host_error=err_text or None, stderr=diagnosis,
            host_error_from_stderr=bool(err_text))

    usage, model = _extract_usage_and_model(doc)
    session_id = doc.get("conversation_id") or doc.get("session_id")
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
    raw_err = doc.get("error")
    host_error = redact.redact(raw_err) if isinstance(raw_err, str) and raw_err else None
    ok = (returncode == 0) and (status in ("SUCCESS", None)) and not host_error
    if not ok:
        reason = (host_error
                  or diagnosis
                  or ("agy status %r (exit %s)" % (status, returncode)))
        return base.RunResult(
            entry_id=entry_id, ok=False, text=text, usage=usage, cost_usd=None,
            model=model, session_id=session_id, denials=denials,
            error="agy -p exited %s: %s" % (returncode, reason),
            host_error=host_error or err_text or None, stderr=diagnosis,
            host_error_from_stderr=bool(not host_error and err_text))

    return base.RunResult(
        entry_id=entry_id, ok=True, text=text, usage=usage, cost_usd=None,
        model=model, session_id=session_id, denials=denials, error=None)


class Runner(base.HostRunner):
    CLI = "agy"
    ENVELOPE_FLAGS = ("-p", "--output-format")
    OUTPUT_SCHEMA_FLAG = ("--json-schema",)
    HONOURS_MAX_TURNS = False
    mode = "headless"
    default_concurrency = 4

    def __init__(self, host="agy", runner=None):
        super().__init__(host)
        self.runner = self.launcher(runner, DEFAULT_RUNNER)
        self.agy_home = None
        self.run_home = None
        self.workspace_dir = None
        self.run_dir = None
        self.review_root = None
        self.registration_dir = None
        self.max_turns = 60
        self.entry_timeout = 1800

    def prepare(self, run_dir, review_root=None, *, registration_dir=None):
        self.run_dir = os.path.abspath(run_dir)
        self.review_root = os.path.abspath(review_root or run_dir)
        if registration_dir is not None:
            self.registration_dir = os.path.abspath(registration_dir)
        os.makedirs(self.run_dir, exist_ok=True)
        if self.agy_home is not None and os.path.isdir(self.agy_home):
            return
        read_scope = os.path.join(self.run_dir, base.SCOPE_FILE)
        write_allowlist = os.path.join(self.run_dir, base.ALLOWLIST_FILE)
        self.agy_home = agy_home.build(
            read_scope, write_allowlist,
            review_root=self.review_root,
            registration_dir=self.registration_dir)
        self.run_home = self.agy_home
        self.workspace_dir = agy_home.workspace_dir(self.agy_home)

    def teardown(self, status=None):
        if self.agy_home is not None:
            agy_home.teardown(self.agy_home, status)
            if status == "complete":
                self.agy_home = None
                self.run_home = None
                self.workspace_dir = None

    def launch_env(self, overlay=None):
        run_env = super().launch_env(overlay)
        if self.agy_home:
            run_env["HOME"] = self.agy_home
        run_env["NO_COLOR"] = "1"
        for marker in _NESTED_MARKERS:
            run_env.pop(marker, None)
        return run_env

    def _shell_path(self, entry):
        name = base.registered_agent(entry, roles=self.roles)
        if name is None:
            return None
        directory = (self.registration_dir
                     or (os.path.join(self.agy_home, ".gemini", "config", "agents")
                         if self.agy_home else hosts.spec(self.host).registration_dir))
        root = os.path.realpath(directory)
        real = os.path.realpath(os.path.join(directory, "%s.md" % name))
        return real if (real == root or real.startswith(root + os.sep)) else None

    def _schema_argv(self, entry):
        argv = schema.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry, inline=True)
        if len(argv) == 2:
            try:
                doc = _sanitize_gemini_schema(json.loads(argv[1]))
                return [argv[0], json.dumps(doc, separators=(",", ":"))]
            except ValueError:
                pass
        return argv

    def command(self, entry, model=None):
        prompt = entry.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("agy entry %r has no prompt" % (entry.get("id"),))
        cmd = [
            self.CLI,
            "--output-format", "json",
            "--disable-slash-commands",
        ]
        if entry.get("enforced"):
            name = base.registered_agent(entry, roles=self.roles)
            if name is None:
                raise RuntimeError(base.UNREGISTERED_AGENT
                                   % redact.redact(str(entry.get("agent"))[:200]))
            cmd.extend(["--agent", name])
        eff_model = model if model is not None else entry.get("model")
        if eff_model is not None:
            cmd.extend(["--model", _validate_flag_value(eff_model, "--model")])
        cmd.extend(self._schema_argv(entry))
        cmd.extend(["-p", prompt])
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
        if self.agy_home is None:
            return base.RunResult.failed(
                entry_id, "the agy runner was not prepared before run_entry")
        if entry.get("enforced"):
            if base.registered_agent(entry, roles=self.roles) is None:
                return base.refuse_unregistered_agent(entry, roles=self.roles)
            shell = self._shell_path(entry)
            if shell is None or not os.path.isfile(shell):
                return base.RunResult.failed(
                    entry_id, "enforcement shell not registered for %r "
                    "(run dispatch.py --emit-host-agents agy)" % entry.get("agent"))
        eff_model = entry.get("model")
        if eff_model is not None and eff_model not in KNOWN_MODELS:
            return base.RunResult.failed(
                entry_id, "entry model %r is not in agy's known model catalogue"
                % eff_model)
        launcher = (DEFAULT_RUNNER
                    if (self.runner == self.launch and DEFAULT_RUNNER is not None)
                    else self.launcher(self.runner, DEFAULT_RUNNER))
        fd, denial_log = tempfile.mkstemp(
            prefix="denials-", suffix=".jsonl", dir=self.agy_home)
        os.close(fd)
        result = None
        proc = None
        try:
            child_env = self.launch_env(env)
            child_env[agy_guard_hook.ENV_DENIAL_LOG] = denial_log
            cmd = self.command(entry, eff_model)
            proc = launcher(
                cmd, cwd=self.workspace_dir, env=child_env,
                capture_output=True, text=True, timeout=self.entry_timeout)
        except base.LaunchRefused:
            raise
        except subprocess.TimeoutExpired as exc:
            result = base.RunResult.failed(
                entry_id, "agy -p timed out after %ss" % self.entry_timeout,
                text=base.partial_output(exc),
                stderr=base.stderr_head(getattr(exc, "stderr", None)))
        except OSError as exc:
            result = base.RunResult.failed(
                entry_id,
                redact.redact("could not launch %s: %s" % (self.CLI, exc)))
        except Exception as exc:  # noqa: BLE001 -- spec 4.4: run_entry never raises
            result = base.RunResult.failed(
                entry_id,
                redact.redact("agy -p launch raised %s: %s" % (type(exc).__name__, exc)))
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
