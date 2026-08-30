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

# #run10: agent_provenance / merge_provenance lived here. merge_provenance
# existed to record "lens_sweep discovered it, panel_review expanded it" -- the
# retired two-stage review itself (#1441) -- and agent_provenance was its input.
# Neither had a caller outside tests/test_provenance.py. tool_provenance above
# is the live one (tools/base.attach_tool_provenance, tools/sarif_utils).
