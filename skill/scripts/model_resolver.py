#!/usr/bin/env python3
"""Resolve reviewer role + host to a concrete model identifier."""
import os
import sys


def _load_profiles():
    """Load model profiles from reference/model-profiles.yml.

    Falls back to hardcoded defaults when PyYAML is missing or the profile file
    cannot be read/parsed; a warning is emitted to stderr so configuration
    problems are not silently ignored.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", "model-profiles.yml")
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


_KIMI_FALLBACK = {
    "scout": {"model": "primary", "alias": "kimi-for-coding",
              "max_context_size": 131072, "max_output_size": 16384},
    "lens_sweep": {"model": "primary", "alias": "kimi-for-coding",
                   "max_context_size": 131072, "max_output_size": 8192},
    "panel_review": {"model": "secondary", "alias": "k3",
                     "max_context_size": 131072, "max_output_size": 16384},
    "advisor": {"model": "secondary", "alias": "k3",
                "max_context_size": 524288, "max_output_size": 32768},
}
_CLAUDE_FALLBACK = {
    "scout": {"model": "haiku"},
    "lens_sweep": {"model": "haiku"},
    "panel_review": {"model": "sonnet"},
    "advisor": {"model": "opus"},
}
_CODEX_FALLBACK = {
    "scout": {"model": "gpt-5.6-luna", "model_reasoning_effort": "medium"},
    "lens_sweep": {"model": "gpt-5.6-luna", "model_reasoning_effort": "medium"},
    "panel_review": {"model": "gpt-5.6-terra", "model_reasoning_effort": "high"},
    "advisor": {"model": "gpt-5.6", "model_reasoning_effort": "high"},
}


def _hardcoded_fallback(host, role):
    """Last-resort role->model mapping when profiles are unavailable.

    Unknown hosts resolve to model=None, meaning "inherit the session's
    model" — never silently assume kimi.
    """
    if host == "kimi":
        return _KIMI_FALLBACK.get(role, {"model": "primary", "alias": "kimi-for-coding",
                                         "max_context_size": 131072,
                                         "max_output_size": 8192})
    if host == "claude":
        return _CLAUDE_FALLBACK.get(role, {"model": "sonnet"})
    if host == "codex":
        return _CODEX_FALLBACK.get(role, {"model": "gpt-5.6-terra",
                                          "model_reasoning_effort": "medium"})
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
            import json
            return json.loads(env_value)
        except ValueError:
            pass
    return {"model": env_value}


_KIMI_TIERS = ("primary", "secondary")
# Concrete Kimi aliases predate the primary/secondary contract and are still
# valid in an agent file's model_preference — just not as a dispatch value.
_KIMI_ALIAS_TIER = {"kimi-for-coding": "primary", "k3": "secondary"}


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
    an override naming a concrete alias (`k3` was this very role's alias
    before the tiers existed) would otherwise reach the manifest and fail at
    dispatch time.
    """
    model = cfg.get("model")
    if model in _KIMI_TIERS:
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

    Returns dict with at least {"model": ..., "max_context_size": ..., "max_output_size": ...}

    On Kimi the result is normalized to the primary/secondary dispatch
    contract, since every override path above can otherwise supply a value
    Kimi's Agent/AgentSwarm tool will reject.
    """
    cfg = _resolve_raw(host, role, cli_overrides)
    if host == "kimi":
        return _normalize_kimi_model(cfg, role)
    return cfg


def _resolve_raw(host, role, cli_overrides=None):
    """resolve_model's precedence chain, before host-specific normalization."""
    if cli_overrides and role in cli_overrides:
        override = cli_overrides[role]
        if isinstance(override, dict):
            return override
        return {"model": override}

    env_override = _env_override(role)
    if env_override:
        return env_override

    profiles = _profiles()
    host_defaults = (profiles.get("hosts") or {}).get(host) or {}
    if role in host_defaults:
        cfg = host_defaults[role]
        if isinstance(cfg, dict):
            return cfg
        return {"model": cfg}

    return _hardcoded_fallback(host, role)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "kimi"
    role = sys.argv[2] if len(sys.argv) > 2 else "panel_review"
    print(resolve_model(host, role))
