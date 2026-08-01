"""pip-audit adapter (placeholder for Task 2)."""
from __future__ import annotations


class PipAuditAdapter:
    name = "pip-audit"
    prefix = "PA"

    def is_applicable(self, target: str) -> bool:
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("pip-audit adapter not yet implemented")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        raise NotImplementedError("pip-audit adapter not yet implemented")
