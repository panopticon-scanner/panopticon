"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json

import scripts.tools.sarif_utils as su


class LegacySarifAdapter:
    def __init__(self, name: str):
        self.name = name

    @property
    def prefix(self) -> str:
        return su.PREFIX.get(self.name, "TL")

    def is_applicable(self, target: str) -> bool:
        return True

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("legacy SARIF tools are invoked by run_tools.py directly")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        sarif = json.loads(raw)
        return su.sarif_to_findings(sarif, self.name, group, self.prefix)
