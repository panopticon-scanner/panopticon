"""osv-scanner adapter (placeholder for Task 4)."""
from __future__ import annotations


class OsvScannerAdapter:
    name = "osv-scanner"
    prefix = "OS"

    def is_applicable(self, target: str) -> bool:
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("osv-scanner adapter not yet implemented")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        raise NotImplementedError("osv-scanner adapter not yet implemented")
