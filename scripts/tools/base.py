"""Shared base utilities for tool adapters."""
from __future__ import annotations
import re
from typing import Protocol


SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "severe": "HIGH",
    "important": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "none": "INFO",
}

ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")


def normalize_severity(value: str | None) -> str:
    if not isinstance(value, str):
        return "INFO"
    return SEV_MAP.get(value.lower().strip(), "INFO")


def new_finding_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n:03d}"


class ToolAdapter(Protocol):
    name: str
    prefix: str

    def is_applicable(self, target: str) -> bool:
        ...

    def invoke(self, target: str) -> tuple[bytes, int]:
        ...

    def parse(self, raw: bytes, group: str) -> list[dict]:
        ...
