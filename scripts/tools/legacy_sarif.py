"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import ingest_tools as it


class LegacySarifAdapter:
    def __init__(self, name: str):
        self.name = name
        self.prefix = it.PREFIX.get(name, "TL")

    def is_applicable(self, target: str) -> bool:
        return True

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("legacy SARIF tools are invoked by run_tools.py directly")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        sarif = json.loads(raw)
        return it.sarif_to_findings(sarif, self.name, group, self.prefix)
