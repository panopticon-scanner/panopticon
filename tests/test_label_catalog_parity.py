"""Label catalog parity: .github/labels.yml must stay 1:1 with the canonical
taxonomy in skill/scripts/evidence.py."""
import os

import yaml

import scripts.evidence as evidence


LABELS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".github", "labels.yml")


def _load_label_names():
    with open(LABELS_PATH, encoding="utf-8") as fh:
        catalog = yaml.safe_load(fh)
    names = []
    for axis in catalog.values():
        if not isinstance(axis, list):
            continue
        for entry in axis:
            if isinstance(entry, dict) and "name" in entry:
                names.append(entry["name"])
    return names


def _axis_names(prefix):
    return {n for n in _load_label_names() if n.startswith(f"{prefix}:")}


def _normalize(name):
    return name.replace("-", "_").lower()


def test_severity_labels_match_sev_order():
    labels = {_normalize(n.split(":", 1)[1]) for n in _axis_names("severity")}
    canonical = {_normalize(s) for s in evidence.SEV_ORDER}
    assert labels == canonical, f"severity drift: labels={labels} canonical={canonical}"


def test_evidence_labels_match_evidence_statuses():
    labels = {_normalize(n.split(":", 1)[1]) for n in _axis_names("evidence")}
    canonical = {_normalize(s) for s in evidence.EVIDENCE_STATUSES}
    assert labels == canonical, f"evidence drift: labels={labels} canonical={canonical}"


def test_panel_labels_match_panels():
    labels = {_normalize(n.split(":", 1)[1]) for n in _axis_names("panel")}
    canonical = {_normalize(s) for s in evidence.PANELS}
    assert labels == canonical, f"panel drift: labels={labels} canonical={canonical}"
