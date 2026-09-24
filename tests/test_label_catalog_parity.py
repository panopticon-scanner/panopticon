"""Label catalog parity: .github/labels.yml must stay 1:1 with the canonical
taxonomy in skill/scripts/evidence.py."""
import os
import re

import pytest
import yaml

import scripts.evidence as evidence


LABELS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".github", "labels.yml")


def _load_catalog():
    with open(LABELS_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _flatten_entries(catalog):
    if isinstance(catalog, list):
        axes = [catalog]
    elif isinstance(catalog, dict):
        axes = catalog.values()
    else:
        raise ValueError("catalog must be a list or category mapping")
    entries = []
    for axis in axes:
        if not isinstance(axis, list):
            raise ValueError("each category must contain a list")
        for entry in axis:
            if not isinstance(entry, dict):
                raise ValueError("each label must be a mapping")
            entries.append(entry)
    return entries


def _validated_entries(catalog):
    entries = _flatten_entries(catalog)
    if not entries:
        raise ValueError("catalog must contain labels")
    names = set()
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("label name must be nonempty")
        if name in names:
            raise ValueError(f"duplicate label name: {name}")
        names.add(name)
        color = entry.get("color")
        if not isinstance(color, str) or re.fullmatch(r"[0-9a-fA-F]{6}", color) is None:
            raise ValueError(f"invalid color for {name}: {color!r}")
        description = entry.get("description", "")
        if not isinstance(description, str):
            raise ValueError(f"description must be text for {name}")
        normalized = description.replace("\n", " ").strip()
        if len(normalized) > 100:
            raise ValueError(f"description exceeds 100 characters for {name}: "
                             f"{len(normalized)}")
    return entries


def _load_label_names():
    return [entry["name"] for entry in _validated_entries(_load_catalog())]


def _axis_names(prefix):
    return {n for n in _load_label_names() if n.startswith(f"{prefix}:")}


def _normalize(name):
    return name.replace("-", "_").lower()


def test_committed_catalog_data_contract():
    _validated_entries(_load_catalog())


def test_description_boundary_controls():
    entry = {"name": "boundary", "color": "aBc123",
             "description": "  " + "x" * 100 + "\n"}
    assert _validated_entries([entry]) == [entry]
    with pytest.raises(ValueError, match="description exceeds 100 characters"):
        _validated_entries([{**entry, "description": " " + "x" * 101 + " "}])


def test_blank_name_control():
    with pytest.raises(ValueError, match="label name must be nonempty"):
        _validated_entries([{"name": " \t", "color": "abcdef"}])


def test_invalid_color_control():
    with pytest.raises(ValueError, match="invalid color"):
        _validated_entries([{"name": "invalid", "color": "12345g"}])


def test_duplicate_name_control_across_categories():
    entry = {"name": "same", "color": "abcdef"}
    with pytest.raises(ValueError, match="duplicate label name"):
        _validated_entries({"one": [entry], "two": [{**entry}]})


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
