#!/usr/bin/env python3
"""Resolve reviewer role + host to a concrete model identifier."""
from typing import Any
import json
import os
import re
import sys

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_bootstrap.py"))
from scripts import _version
from scripts import hosts


def _load_profiles():
    """Load model profiles from reference/model-profiles.yml.

    Falls back to hardcoded defaults when PyYAML is missing or the profile file
    cannot be read/parsed; a warning is emitted to stderr so configuration
    problems are not silently ignored.
    """
    path = _version.reference_path("model-profiles.yml")
    try:
        import yaml
    except ImportError:
        print("WARNING: PyYAML not installed; using hardcoded model profiles",
              file=sys.stderr)
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except OSError as e:
        print("WARNING: cannot read model profiles %s: %s; using hardcoded fallback"
              % (path, e), file=sys.stderr)
        return {}
    except yaml.YAMLError as e:
        print("WARNING: model profiles %s contains invalid YAML: %s; using hardcoded fallback"
              % (path, e), file=sys.stderr)
        return {}


_PROFILES = None


def _profiles():
    global _PROFILES
    if _PROFILES is None:
        _PROFILES = _load_profiles()
    return _PROFILES


# These mirror skill/reference/model-profiles.yml for every role in
# dispatch.ROLE_FILES, and test_model_resolver pins that parity: a role present
# in the YAML but missing here silently resolved to the generic per-host default
# whenever the YAML could not be read.
#
# #run10: the tables carried lens_sweep/panel_review -- roles nothing can request
# since #1441 -- while MISSING domain_panel/domain_advisor for kimi and codex,
# the roles that replaced them. Only the claude table had been updated (#1036).
# So a YAML-less kimi run resolved its domain_advisor to primary/131072 instead
# of k3/524288: the adjudication role, on a weaker model with a quarter of the
# context, silently.
# #1737 R-F4-2: `setup_scan` is an EXPLICIT inherit row in all three tables and
# in model-profiles.yml, never an omission and never an exemption from the
# parity test below. `model: None` is what docs/guide/host-capabilities.md
# defines as
# "inherit the session's model": `driver setup` is a one-off, judgement-heavy
# classification and the operator's own session model is the policy. Registering
# the shell (#1737) must not quietly move it onto a role tier, so the emitters
# write no model line for it and the model-binding probes read None-on-both-sides
# as agreement rather than as a shell that binds nothing.
_KIMI_FALLBACK: dict[str, dict[str, Any]] = {
    "scout": {"model": "primary", "alias": "k3-256k",
              "max_context_size": 131072, "max_output_size": 16384},
    "advisor": {"model": "secondary", "alias": "k3.1-pro",
                "max_context_size": 524288, "max_output_size": 32768},
    "domain_panel": {"model": "secondary", "alias": "k3.1-pro",
                     "max_context_size": 131072, "max_output_size": 16384},
    "domain_advisor": {"model": "secondary", "alias": "k3.1-pro",
                       "max_context_size": 524288, "max_output_size": 32768},
    "setup_scan": {"model": None},
}
_CLAUDE_FALLBACK = {
    "scout": {"model": "claude-haiku-5-5"},
    "advisor": {"model": "claude-haiku-5-5"},  # #1029: tool-advisor is narrow
    # #1036: the 5.0 matrix roles, moved here so model_resolver is the single
    # owner of the claude role->model map (dispatch's emit path used to keep a
    # duplicate EMIT_MODEL_POLICY dict — #1029 had to edit both).
    "domain_panel": {"model": "claude-sonnet-5-5"},
    "domain_advisor": {"model": "claude-opus-5-5"},
    "setup_scan": {"model": None},
}
_CODEX_FALLBACK = {
    "scout": {"model": "gpt-6-luna", "model_reasoning_effort": "medium"},
    "advisor": {"model": "gpt-6.1-sol", "model_reasoning_effort": "high"},
    "domain_panel": {"model": "gpt-6.1-sol", "model_reasoning_effort": "high"},
    "domain_advisor": {"model": "gpt-6.1-sol", "model_reasoning_effort": "high"},
    "setup_scan": {"model": None},
}
_AGY_FALLBACK: dict[str, dict[str, Any]] = {
    "scout": {"model": "gemini-3.8-flash-medium", "tier": "flash"},
    "advisor": {"model": "gemini-3.8-flash-medium", "tier": "flash"},
    # #3564: Carbon takes its effort as `--effort`, never as a `-high` slug.
    "domain_panel": {"model": "gemini-4-carbon", "effort": "high", "tier": "pro"},
    "domain_advisor": {"model": "gemini-4-carbon", "effort": "high", "tier": "pro"},
    "setup_scan": {"model": None},
}
# Google Gemini lineup: `gemini-4-carbon` is the flagship reasoning model and
# `gemini-3.8-flash` is the current stable Flash model (verified in the marked
# source-of-truth profile table).
_GEMINI_FALLBACK: dict[str, dict[str, Any]] = {
    "scout": {"model": "gemini-3.8-flash"},
    "advisor": {"model": "gemini-3.8-flash"},
    "domain_panel": {"model": "gemini-4-carbon"},
    "domain_advisor": {"model": "gemini-4-carbon"},
    "setup_scan": {"model": None},
}


def _hardcoded_fallback(host, role):
    """Last-resort role->model mapping when profiles are unavailable.

    A host the registry does not know, or a known host with no table of its
    own, resolves to model=None -- "inherit the session's model". Never
    silently assume another host's tiers (#1344: the registry is now the one
    definition of which hosts exist).
    """
    if hosts.spec(host) is None:
        return {"model": None}
    if host == "kimi":
        return _KIMI_FALLBACK.get(role, {"model": "primary",
                                         "alias": "k3-256k",
                                         "max_context_size": 131072,
                                         "max_output_size": 8192})
    if host == "claude":
        return _CLAUDE_FALLBACK.get(role, {"model": "claude-sonnet-5-5"})
    if host == "codex":
        return _CODEX_FALLBACK.get(role, {"model": "gpt-6.1-sol",
                                          "model_reasoning_effort": "medium"})
    if host == "agy":
        return _AGY_FALLBACK.get(role, {"model": "gemini-4-carbon", "effort": "high",
                                         "tier": "pro"})
    if host == "gemini":
        return _GEMINI_FALLBACK.get(role, {"model": "gemini-3.8-flash"})
    return {"model": None}


def _env_override(role):
    """Parse PANOPTICON_MODEL_<ROLE> env var.

    Supports two forms:
    - plain string model id: "k3"
    - JSON object: '{"model":"k3","max_context_size":524288}'
    """
    env_key = "PANOPTICON_MODEL_%s" % role.upper()
    env_value = os.environ.get(env_key)
    if not env_value:
        return None
    env_value = env_value.strip()
    if env_value.startswith("{"):
        try:
            return json.loads(env_value)
        except ValueError:
            # Object-shaped input is a configuration attempt, not a model ID.
            # Do not echo the value: environment overrides may contain secrets.
            raise ValueError("%s must contain a valid JSON object" % env_key) from None
    return {"model": env_value}


def is_effort_word(value):
    """#2879: a reasoning effort is a short lowercase word (`low`, `xhigh`), or not one.

    The one shape check, for an override here and for whatever effort a Codex
    launch binds (codex_host.command), which also reads target-writable entries."""
    return isinstance(value, str) and re.fullmatch(r"[a-z]{1,32}", value) is not None


# #3564: the levels `agy --effort` accepts (https://antigravity.google/docs/cli/commands/effort/,
# read 2026-11-11). `xhigh` and `max` exist only on models that publish them; the CLI
# rejects a level the model lacks by name, so this is the documented superset.
AGY_EFFORTS = ("low", "medium", "high", "xhigh", "max")
# Each host's effort key; the other host's key would be silently dropped (#3571 review).
_EFFORT_KEYS = {"codex": "model_reasoning_effort", "agy": "effort"}


def names_effort(model):
    """Whether an agy model ID already names an effort (`gemini-4-argon-high`)."""
    return isinstance(model, str) and any(model.endswith("-" + level) for level in AGY_EFFORTS)


def effort_key_problem(host, cfg):
    """Why `cfg` carries an effort `host` would drop or refuse, or None (#3571 review).

    The values are never echoed: an override may hold anything."""
    if not isinstance(cfg, dict):
        return None
    for other_host, key in _EFFORT_KEYS.items():
        if key in cfg and host is not None and host != other_host:
            return ("carries %s, which only %s reads; %s would run at its default effort"
                    % (key, other_host, host))
    if "effort" in cfg:
        if cfg["effort"] not in AGY_EFFORTS:
            return "effort must be one of %s" % ", ".join(AGY_EFFORTS)
        if not cfg.get("model"):
            return "effort is set with no model to apply it to"
        if names_effort(cfg.get("model")):
            return "effort is set beside a model ID that already names one"
    return None


def validate_env_overrides(host=None):
    """Check every live role before a driver run can probe or dispatch.

    `host` is the run's host when the driver knows it; the cross-host effort keys
    are refused then, and again at use by `entry_policy` for a resumed run."""
    # The fallback table is pinned to dispatch.ROLE_FILES by the resolver tests.
    # It also includes setup_scan, used by `driver loop --setup`.
    for role in _CLAUDE_FALLBACK:
        override = _env_override(role)
        if (isinstance(override, dict) and "model_reasoning_effort" in override
                and not is_effort_word(override["model_reasoning_effort"])):
            # Named, never echoed, like the malformed-object refusal above.
            raise ValueError("PANOPTICON_MODEL_%s: model_reasoning_effort must be a "
                             "lowercase word" % role.upper())
        problem = effort_key_problem(host, override)
        if problem:
            raise ValueError("PANOPTICON_MODEL_%s: %s" % (role.upper(), problem))


_KIMI_TIERS = ("primary", "secondary")
# Concrete Kimi aliases predate the primary/secondary contract and are still
# valid in an agent file's model_preference — just not as a dispatch value.
# Keep the previous generation here for explicit compatibility while the
# profile itself selects the current fixed IDs.
_KIMI_ALIAS_TIER = {
    "k3-256k": "primary",
    "kimi-for-coding": "primary",
    "k3.1-pro": "secondary",
    "k3": "secondary",
}


def registration_config(host, role):
    """Role -> deterministic config for PERSISTED registration files.

    Deliberately override-free: it consults reference/model-profiles.yml and
    the hardcoded fallback only, never PANOPTICON_MODEL_* or CLI overrides.
    Emission is deterministic policy — an ambient override must shape a single
    run's dispatch plan, never a file left on disk for every future run.
    """
    profiles = _profiles()
    cfg = ((profiles.get("hosts") or {}).get(host) or {}).get(role)
    if not isinstance(cfg, dict):
        cfg = _hardcoded_fallback(host, role)
    return dict(cfg)


def registration_model(host, role):
    """Role -> model identifier for persisted registration files."""
    return registration_config(host, role).get("model")


def _normalize_kimi_model(cfg, role):
    """Force a Kimi dispatch value into the primary/secondary contract.

    Kimi's Agent/AgentSwarm `model` parameter accepts only those two tiers, so
    an override naming a concrete alias (`k3.1-pro` for reviewer roles) would
    otherwise reach the manifest and fail at dispatch time.
    """
    model = cfg.get("model")
    if model in _KIMI_TIERS:
        return cfg
    if model is None:
        # #1737: None is not a wrong alias, it is the explicit "inherit the
        # session's model" policy (R-F4-2). The runner already reads it that
        # way -- `runners/kimi.py` binds `-m` only `if entry.get("model")` --
        # so coercing it to a tier here would be this module overruling a
        # decision the profile states, and the stderr warning would name a
        # drift that never happened.
        return cfg
    mapped = _KIMI_ALIAS_TIER.get(model)
    out = dict(cfg)
    if mapped:
        out["model"] = mapped
        out.setdefault("alias", model)
        return out
    fallback = _KIMI_FALLBACK.get(role, {}).get("model", "primary")
    print("model_resolver: %r is not a Kimi dispatch tier (primary|secondary); "
          "using %r for role %s" % (model, fallback, role), file=sys.stderr)
    out["model"] = fallback
    return out


def resolve_model(host, role, cli_overrides=None):
    """Resolve a host + role to a model config dict.

    Precedence (highest first):
    1. cli_overrides[role]
    2. PANOPTICON_MODEL_<ROLE> environment variable
    3. host default in reference/model-profiles.yml
    4. hardcoded fallback

    Returns dict with at least {"model": ...} and optional keys
    like "max_context_size", "max_output_size", "model_reasoning_effort" when configured.

    On Kimi the result is normalized to the primary/secondary dispatch
    contract, since every override path above can otherwise supply a value
    Kimi's Agent/AgentSwarm tool will reject.
    """
    cfg = _resolve_raw(host, role, cli_overrides)
    if host == "kimi":
        return _normalize_kimi_model(cfg, role)
    return cfg


def entry_policy(host, role):
    """#2879: the resolved fields a dispatch entry carries (phases/requests.bound_policy).

    The model on every host; on Codex the reasoning effort beside it, which
    codex_host binds at launch (M-7), and on agy its `effort`, which the runner
    passes as `--effort` (#3564). The host name is decided here, in the
    resolver that owns the per-host tables, never in a phase."""
    cfg = resolve_model(host, role)
    if host in _EFFORT_KEYS:
        # #3571 review: refused at use too, for a resumed run that named no --host.
        problem = effort_key_problem(host, cfg)
        if problem:
            raise ValueError("model policy for %s %s %s" % (host, role, problem))
    extra = {"codex": ("model_reasoning_effort",), "agy": ("effort",)}.get(host, ())
    return {"model": cfg.get("model"), **{key: cfg[key] for key in extra if cfg.get(key)}}


def _as_model_dict(v):
    return v if isinstance(v, dict) else {"model": v}


def _resolve_raw(host, role, cli_overrides=None):
    """resolve_model's precedence chain, before host-specific normalization."""
    if cli_overrides and role in cli_overrides:
        return _as_model_dict(cli_overrides[role])

    env_override = _env_override(role)
    if env_override:
        return env_override

    profiles = _profiles()
    host_defaults = (profiles.get("hosts") or {}).get(host) or {}
    if role in host_defaults:
        return _as_model_dict(host_defaults[role])

    return _hardcoded_fallback(host, role)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "kimi"
    role = sys.argv[2] if len(sys.argv) > 2 else "domain_panel"
    print(resolve_model(host, role))
