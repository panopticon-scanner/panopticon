#!/usr/bin/env python3
"""Resolve reviewer role + host to a concrete model identifier."""
import os
import sys


def _load_profiles():
    """Load model profiles from reference/model-profiles.yml."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", "model-profiles.yml")
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


_PROFILES = None


def _profiles():
    global _PROFILES
    if _PROFILES is None:
        _PROFILES = _load_profiles()
    return _PROFILES


def _hardcoded_fallback(role):
    return {
        "scout": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
        "lens_sweep": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 8192},
        "panel_review": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
        "advisor": {"model": "k3", "max_context_size": 524288, "max_output_size": 32768},
    }.get(role, {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 8192})


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


def resolve_model(host, role, cli_overrides=None):
    """Resolve a host + role to a model config dict.

    Precedence (highest first):
    1. cli_overrides[role]
    2. PANOPTICON_MODEL_<ROLE> environment variable
    3. host default in reference/model-profiles.yml
    4. hardcoded fallback

    Returns dict with at least {"model": ..., "max_context_size": ..., "max_output_size": ...}
    """
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

    return _hardcoded_fallback(role)


def role_config(role):
    """Return role metadata (description) from profiles."""
    profiles = _profiles()
    return (profiles.get("roles") or {}).get(role) or {}


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "kimi"
    role = sys.argv[2] if len(sys.argv) > 2 else "panel_review"
    print(resolve_model(host, role))
