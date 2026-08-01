"""npm-audit adapter (placeholder for Task 3)."""
from __future__ import annotations


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("npm-audit adapter not yet implemented")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        raise NotImplementedError("npm-audit adapter not yet implemented")
