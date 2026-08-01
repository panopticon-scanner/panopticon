"""eslint-plugin-security adapter (placeholder for Task 5)."""
from __future__ import annotations


class EslintSecurityAdapter:
    name = "eslint-security"
    prefix = "ESS"

    def is_applicable(self, target: str) -> bool:
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("eslint-security adapter not yet implemented")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        raise NotImplementedError("eslint-security adapter not yet implemented")
