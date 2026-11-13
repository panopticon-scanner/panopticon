"""Headless runner for the `agy` (Google Antigravity CLI) host family (#3493).

Launches each review entry in a dedicated `agy -p` subprocess with:
- the operator's real `HOME`, so agy reaches its own Keychain sign-in (#3613)
- `--gemini_dir <run>/gemini` leading the argv: agy's configuration for this run
  only, built by `runners.agy_home`, in place of ``~/.gemini``
- `cwd` pointed at `<run>/workspace` (which carries a `.git` ceiling)
- `--disable-slash-commands` to stop `/skill` and slash-command expansion of the `-p` prompt
- `--agent <shell>` for enforced entries
- `--model <slug>` for role-resolved model binding
- `--effort <level>` when the role carries an effort (#3564)
- `--json-schema <inline_json>` for structured JSON output when advertised
"""
import json
import os
import re
import subprocess
import sys
import tempfile

import scripts.agy_guard_hook as agy_guard_hook
import scripts.hosts as hosts
import scripts.model_resolver as model_resolver
import scripts.redact as redact
import scripts.runners.agy_home as agy_home
import scripts.runners.base as base
import scripts.runners.children as children
import scripts.runners.outage as outage
import scripts.runners.schema as schema


DEFAULT_RUNNER = None

_SAFE_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._:-]+\Z")
_NESTED_MARKERS = ("ANTIGRAVITY_CLI", "ANTIGRAVITY_CLI_ALIAS")

# The 4.6 and GPT-OSS rows retire on 2026-11-18; keep them until that date so
# currently supported Free/Plus runs do not fail closed a week early. The Carbon
# effort slugs are listed by `agy models` on the Headless page (#3550); never a default.
# models-verified: 2026-11-11 https://antigravity.google/docs/models https://antigravity.google/docs/enterprise https://antigravity.google/docs/cli/headless/
KNOWN_MODELS = frozenset({
    "gemini-4-carbon",
    "gemini-4-carbon-low",
    "gemini-4-carbon-medium",
    "gemini-4-carbon-high",
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


# #3564: the documented `agy --effort` levels, owned by the resolver beside its tables.
AGY_EFFORTS = model_resolver.AGY_EFFORTS
_combined_slug = model_resolver.names_effort


# #3576: agy's print-mode auth fallback, in the order it logs it (owner capture, agy 1.5.6):
#   Print mode: not authenticated, trying silent auth
#   Print mode: silent auth failed
#   Print mode: triggering interactive OAuth
#   consumerOAuth: starting OAuth flow
# The child is ended at the first line after silent auth fails, before a browser opens.
# A documented "no terminal" run should exit instead (https://antigravity.google/docs/cli/headless/),
# but children already run with no stdin and their own session, and still reached it.
INTERACTIVE_AUTH = re.compile(
    rb"Print mode: silent auth failed|triggering interactive OAuth|consumerOAuth: starting OAuth")


# #3582: a key-route launch tries the entry's own model, then its profile ladder
# (`fallbacks: {key: [...]}`, bound into the entry by model_resolver.entry_policy),
# against the route's live `agy models` list. #3576's Carbon -> Argon (High) choice is
# that ladder's first rung. Every substitution is recorded; an explicit
# PANOPTICON_MODEL_* override and a strict run carry no ladder.
FALLBACK_REASON = "not listed on route %s"
_MODEL_ID = re.compile(r"[a-z0-9][a-z0-9.\-]*")
MODELS_TIMEOUT = 60

# #3613: the fail-closed preflight `prepare()` runs before any entry launches.
# The turn is real and minimal: the default model (on the key route, its bound
# default), no --effort and no agent shell, so agy runs its default agent and any
# tool call meets the guard hook (owner ruling R3, 2026-11-13).
PREFLIGHT_PROMPT = "Reply with the single word OK."
PREFLIGHT_TIMEOUT = 180
KEY_ROUTE_DEFAULT = "gemini-4-argon-high"   # pinned to the Carbon roles' first key rung
NOT_SIGNED_IN = "You are not logged into Antigravity"
BROWSER_ENV = ("BROWSER", "/usr/bin/false")


class AgyPreflightRefused(RuntimeError):
    """The run's agy configuration could not be proven in effect (#3613)."""


def listed_models(stdout):
    """The model names `agy models` lists: each line's first field, when it is an ID."""
    names = set()
    for line in (stdout or "").splitlines():
        fields = line.split()
        if fields and _MODEL_ID.fullmatch(fields[0]):
            names.add(fields[0])
    return frozenset(names)


def key_route_model(model, effort, listed, explicit=False, ladder=()):
    """(name, substitution) for a key-route launch, or ValueError (#3576, #3582).

    That route takes no `--effort`: the level is part of the name. The name must be
    one `agy models` lists for the route; else the first listed rung of the entry's
    `ladder` is bound and `substitution` records it. Nothing off the ladder is ever
    tried, and an explicit override has no ladder."""
    if not model:
        raise ValueError("agy key route needs a model, and the entry names none (#3576)")
    name = "%s-%s" % (model, effort) if effort else model
    if name in listed:
        return name, None
    rungs = () if explicit else tuple(ladder or ())
    for rung, candidate in enumerate(rungs, start=1):
        if candidate in listed:
            return candidate, {"requested": name, "bound": candidate, "route": "key",
                               "rung": rung, "reason": FALLBACK_REASON % "key"}
    raise ValueError(
        "agy key route lists no model %r (configured %s%s)%s (#3576, #3582)"
        % (name, model, " at effort %s" % effort if effort else "",
           "; an explicit PANOPTICON_MODEL_* override is never substituted" if explicit
           else ("; nor any fallback (%s)" % ", ".join(rungs) if rungs
                 else "; no fallback ladder applies (strict run, or none in the profile)")))


def reached_interactive_auth(stderr):
    """Whether a finished child's stderr shows agy's interactive-auth fallback (#3576)."""
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", "replace")
    return isinstance(stderr, bytes) and bool(INTERACTIVE_AUTH.search(stderr))


def auth_stopped(entry_id, exc):
    """The failed entry for a child ended on its interactive-auth line (#3576)."""
    return base.RunResult.failed(
        entry_id, "agy -p was stopped before it could open a browser sign-in: "
        + agy_home.AUTH_UNREACHABLE,
        host_error=agy_home.AUTH_UNREACHABLE, failure_class=outage.HOST_FAILURE,
        stderr=base.stderr_head(getattr(exc, "stderr", None)))


# #3550: why an agy ledger row's `model` is null. The `--output-format json` envelope's
# documented fields are conversation_id, status, response, error, duration_seconds,
# num_turns, structured_output, json_schema and usage -- no model
# (https://antigravity.google/docs/cli/headless/, read 2026-11-11).
NO_ANSWERING_MODEL = (
    "agy's JSON envelope reports no answering model, so each ledger row records the bound "
    "`requested_model` (and `requested_effort`) with `model` null, and usage has no per-model "
    "split; headless agy exits non-zero rather than fall back from --model "
    "(https://antigravity.google/docs/cli/headless/)")


def _validate_flag_value(value, label):
    if not isinstance(value, str) or not value or value.startswith("-") \
            or not _SAFE_TOKEN_RE.match(value):
        raise ValueError("invalid agy %s value: %r" % (label, value))
    return value


def effort_argv(effort, model):
    """`["--effort", <level>]` for an entry's effort, `[]` for none (#3564).

    Refused: a level `agy --effort` does not document, an effort with no model
    to apply it to, and an effort beside a model that already names one
    (`gemini-4-argon-high`), so a combined slug is never sent with the flag."""
    if effort is None:
        return []
    if effort not in AGY_EFFORTS:
        raise ValueError("agy effort %r is not one of %s" % (effort, ", ".join(AGY_EFFORTS)))
    if model is None:
        raise ValueError("agy effort %r has no model to apply to" % effort)
    if _combined_slug(model):
        raise ValueError("agy model %r already names an effort; refusing --effort %s beside it"
                         % (model, effort))
    return ["--effort", _validate_flag_value(effort, "--effort")]


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
        self.auth_route = None
        self.key_models: frozenset = frozenset()

    def _launch_callable(self):
        return (DEFAULT_RUNNER
                if (self.runner == self.launch and DEFAULT_RUNNER is not None)
                else self.launcher(self.runner, DEFAULT_RUNNER))

    def _agy(self, *args):
        """An agy argv for this run: `--gemini_dir` always leads (#3613)."""
        return [self.CLI, *agy_home.gemini_dir_argv(self.agy_home), *args]

    def _list_models(self):
        """The models the key route offers, from one `agy models` (#3576).

        Refused when it fails or lists nothing: no entry may launch on a route
        whose models are unknown."""
        try:
            proc = self._launch_callable()(
                self._agy("models"), cwd=self.workspace_dir, env=self.launch_env(),
                capture_output=True, text=True, timeout=MODELS_TIMEOUT,
                stop_on=INTERACTIVE_AUTH)
        except children.HostStopped as exc:
            raise agy_home.AgyAuthUnreachable(
                agy_home.AUTH_UNREACHABLE + agy_home.STEP_TAG % "models: interactive auth") from exc
        except subprocess.TimeoutExpired as exc:
            raise AgyPreflightRefused(
                "`agy models` timed out after %ss (#3613)%s"
                % (MODELS_TIMEOUT, agy_home.STEP_TAG % "models: timeout")) from exc
        names = listed_models(getattr(proc, "stdout", ""))
        if getattr(proc, "returncode", 1) != 0 or not names:
            raise agy_home.AgyAuthUnreachable(
                "`agy models` on the API-key route %s, so no entry can be bound to a "
                "listed model (#3576)%s"
                % ("exited %s" % getattr(proc, "returncode", 1)
                   if getattr(proc, "returncode", 1) != 0 else "listed no models",
                   agy_home.STEP_TAG % "models: listing"))
        return names

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
        route = agy_home.auth_route(self._parent_env())
        self.agy_home = agy_home.build(
            read_scope, write_allowlist,
            review_root=self.review_root,
            registration_dir=self.registration_dir, route=route)
        self.run_home = self.agy_home
        self.workspace_dir = agy_home.workspace_dir(self.agy_home)
        self.auth_route = route
        try:
            if route == "key":
                self.key_models = self._list_models()
            self._preflight()
        except BaseException:
            # A refused run leaves no run directory behind (#3613).
            self.teardown("complete")
            raise

    def _preflight(self):
        """Fail closed before any entry launches (#3613).

        1. `--gemini_dir` took effect: `agy agents` lists exactly the shells this
           run links, and agy's own log under the run loaded our hooks.json.
        2. One minimal real turn proves the route signs in. Auth trouble raises
           AgyAuthUnreachable (naming the key route when a key is set but not
           chosen); anything else raises AgyPreflightRefused. Nothing falls back."""
        launch, env, parent = self._launch_callable(), self.launch_env(), self._parent_env()
        try:
            proc = launch(self._agy("agents"), cwd=self.workspace_dir, env=env,
                          capture_output=True, text=True, timeout=MODELS_TIMEOUT,
                          stop_on=INTERACTIVE_AUTH)
        except children.HostStopped as exc:
            raise agy_home.unreachable(parent, "agents: interactive auth") from exc
        except subprocess.TimeoutExpired as exc:
            raise AgyPreflightRefused(
                "`agy agents` timed out after %ss (#3613)%s"
                % (MODELS_TIMEOUT, agy_home.STEP_TAG % "agents: timeout")) from exc
        out = getattr(proc, "stdout", "") or ""
        expected = agy_home.expected_agents(self.agy_home)
        listed = agy_home.listed_agents(out)
        if getattr(proc, "returncode", 1) != 0 or "[project]" in out or listed != expected:
            raise AgyPreflightRefused(
                "`agy %s <run>/gemini agents` %s; expected exactly %s, listed %s. "
                "--gemini_dir is undocumented and may have changed (#3613)%s"
                % (agy_home.GEMINI_DIR_FLAG,
                   "exited %s" % getattr(proc, "returncode", 1)
                   if getattr(proc, "returncode", 1) != 0 else "did not isolate the shells",
                   sorted(expected), sorted(listed)[:20], agy_home.STEP_TAG % "agents: shells"))
        proven, why = agy_home.hook_load_proven(self.agy_home)
        if not proven:
            raise AgyPreflightRefused(why + agy_home.STEP_TAG % "agents: hook-load proof")
        argv = ["--output-format", "json", "--disable-slash-commands"]
        if self.auth_route == "key":
            if KEY_ROUTE_DEFAULT not in self.key_models:
                raise AgyPreflightRefused(
                    "`agy models` on the API-key route does not list %s, the route's "
                    "default (#3576, #3613)%s"
                    % (KEY_ROUTE_DEFAULT, agy_home.STEP_TAG % "turn: key-route default"))
            argv += ["--model", KEY_ROUTE_DEFAULT]
        try:
            proc = launch(self._agy(*argv, "-p", PREFLIGHT_PROMPT), cwd=self.workspace_dir,
                          env=env, capture_output=True, text=True, timeout=PREFLIGHT_TIMEOUT,
                          stop_on=INTERACTIVE_AUTH)
        except children.HostStopped as exc:
            raise agy_home.unreachable(parent, "turn: interactive auth (stopped)") from exc
        except subprocess.TimeoutExpired as exc:
            raise AgyPreflightRefused(
                "agy's preflight turn timed out after %ss (#3613)%s%s"
                % (PREFLIGHT_TIMEOUT, self._key_hint(parent),
                   agy_home.STEP_TAG % "turn: timeout")) from exc
        stdout, stderr = getattr(proc, "stdout", "") or "", getattr(proc, "stderr", "") or ""
        # #3620: auth is judged from THIS turn's own output, never from agy's run log --
        # `agy agents` writes the not-logged-in line there without signing in, and the
        # turn reuses that same log file, so a log scan refused every signed-in run.
        for step, seen in (("turn: interactive auth on stderr", reached_interactive_auth(stderr)),
                           ("turn: not-logged-in on stdout", NOT_SIGNED_IN in stdout),
                           ("turn: not-logged-in on stderr", NOT_SIGNED_IN in stderr)):
            if seen:
                raise agy_home.unreachable(parent, step)
        result = parse_envelope(stdout, getattr(proc, "returncode", 1), stderr,
                                entry_id="agy-preflight")
        if not result.ok:
            raise AgyPreflightRefused("agy's preflight turn failed: %s (#3613)%s%s"
                                      % (redact.redact(str(result.error))[:400],
                                         self._key_hint(parent),
                                         agy_home.STEP_TAG % "turn: envelope"))

    def _key_hint(self, parent):
        """R2: on the sign-in route with a key set, every failed turn names the key
        route, however the turn failed (#3617 review N2)."""
        if self.auth_route == "key" or not (parent.get(agy_home.KEY_ENV) or "").strip():
            return ""
        return agy_home.KEY_NOT_CHOSEN

    def teardown(self, status=None):
        if self.agy_home is not None:
            agy_home.teardown(self.agy_home, status)
            if status == "complete":
                self.agy_home = None
                self.run_home = None
                self.workspace_dir = None

    def _parent_env(self, overlay=None):
        """The environment before this runner's child preparation: what the
        operator chose, read for the route and for the key-route hint."""
        return super().launch_env(overlay)

    def launch_env(self, overlay=None):
        run_env = super().launch_env(overlay)
        # #3613: HOME stays the operator's; agy's configuration moves with
        # --gemini_dir. No child may open a browser.
        run_env[BROWSER_ENV[0]] = BROWSER_ENV[1]
        # R2 enforced, not trusted to agy's precedence: off the key route the child
        # never holds the key, so an expired sign-in cannot fall back to it.
        if self.auth_route != "key":
            run_env.pop(agy_home.KEY_ENV, None)
        run_env["NO_COLOR"] = "1"
        for marker in _NESTED_MARKERS:
            run_env.pop(marker, None)
        return run_env

    def _shell_path(self, entry):
        name = base.registered_agent(entry, roles=self.roles)
        if name is None:
            return None
        directory = (self.registration_dir
                     or (agy_home.agents_dir(self.agy_home)
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
            *(agy_home.gemini_dir_argv(self.agy_home) if self.agy_home else []),
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
        cmd.extend(effort_argv(entry.get("effort"), eff_model))
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
        try:
            effort_argv(entry.get("effort"), eff_model)
        except ValueError as exc:
            return base.RunResult.failed(entry_id, redact.redact(str(exc)))
        launch_entry, launch_model, bound_model, substitution = entry, eff_model, None, None
        if self.auth_route == "key":
            ladders = entry.get("fallbacks")
            try:
                bound_model, substitution = key_route_model(
                    eff_model, entry.get("effort"), self.key_models,
                    explicit=bool(entry.get("model_override")),
                    ladder=(ladders.get("key") if isinstance(ladders, dict) else None) or ())
            except ValueError as exc:
                return base.RunResult.failed(entry_id, str(exc), host_error=str(exc),
                                             failure_class=outage.HOST_FAILURE)
            launch_entry = {k: v for k, v in entry.items() if k != "effort"}
            launch_model = bound_model
            if substitution is not None:
                print("agy: entry %s: %s %s; bound fallback %s (rung %d) (#3582)"
                      % (entry_id, substitution["requested"], substitution["reason"],
                         bound_model, substitution["rung"]), file=sys.stderr, flush=True)
        launcher = self._launch_callable()
        fd, denial_log = tempfile.mkstemp(
            prefix="denials-", suffix=".jsonl", dir=self.agy_home)
        os.close(fd)
        result = None
        proc = None
        try:
            child_env = self.launch_env(env)
            child_env[agy_guard_hook.ENV_DENIAL_LOG] = denial_log
            cmd = self.command(launch_entry, launch_model)
            proc = launcher(
                cmd, cwd=self.workspace_dir, env=child_env,
                capture_output=True, text=True, timeout=self.entry_timeout,
                stop_on=INTERACTIVE_AUTH)
        except base.LaunchRefused:
            raise
        except children.HostStopped as exc:
            result = auth_stopped(entry_id, exc)
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

        if result is None and reached_interactive_auth(getattr(proc, "stderr", None)):
            # A child that printed the line and exited before the watch saw it.
            result = auth_stopped(entry_id, proc)
        if result is None:
            result = self.parse_envelope(
                entry_id, getattr(proc, "stdout", ""),
                getattr(proc, "returncode", 1),
                stderr=getattr(proc, "stderr", None))
        if hook_denials:
            result.denials = list(result.denials or []) + hook_denials
        result.bound_model = bound_model
        result.model_substitution = substitution
        return result
