"""Provenance helpers for panopticon findings."""
from __future__ import annotations


def tool_provenance(adapter_name: str, reasoning: str | None = None) -> dict:
    return {
        "discovered_by": f"tool:{adapter_name}",
        "expanded_by": None,
        "confirmed_by": f"tool:{adapter_name}",
        "model": None,
        "model_version": None,
        "confirmation_status": "TOOL",
        "confirmation_reasoning": reasoning or f"Reported by static-analysis tool {adapter_name}",
    }


def agent_provenance(role: str, model: str, model_version: str,
                     confirmed: bool = False) -> dict:
    return {
        "discovered_by": f"agent:{role}",
        "expanded_by": None,
        "confirmed_by": None,
        "model": model,
        "model_version": model_version,
        "confirmation_status": "CONFIRMED" if confirmed else "UNVERIFIED",
        "confirmation_reasoning": None,
    }


def merge_provenance(base: dict, expansion: dict) -> dict:
    """Return a new provenance where base is the discoverer and expansion is the expander."""
    merged = dict(base)
    merged["expanded_by"] = expansion.get("discovered_by")
    # Prefer the most recent model/version for display.
    if expansion.get("model"):
        merged["model"] = expansion["model"]
        merged["model_version"] = expansion.get("model_version")
    return merged
