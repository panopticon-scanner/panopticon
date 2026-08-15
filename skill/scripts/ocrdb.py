"""Read access to the vendored OCRDb domain catalog — the 5.0 review-matrix
finding-code source. Pure: loads the pinned bundle and answers domain-menu /
code-validation queries. Tolerant degrade-to-None when the bundle is absent (the
review then runs code-less = 4.x behavior); a present-but-malformed bundle is a
LOUD ValueError, never a silent no-code run. Mirrors citations.load_cwe_catalog.
See docs/superpowers/specs/2026-08-15-panopticon-5.0-review-matrix-design.md §4.
"""
import json
import os

BUNDLE_VERSION = "0.3.1"
_BUNDLE_NAME = "ocrdb-%s.json" % BUNDLE_VERSION

# The 10 OCRDb domains -> the legacy 6-panel axis (evidence.PANELS), so a
# domain-scoped finding still segments in the panel-graded report (Task 2 uses
# this to back-fill `panel`). Domains with no legacy equivalent bucket to "code".
DOMAIN_TO_PANEL = {
    "SEC": "security", "COD": "code", "ARC": "architecture",
    "TST": "test", "DAT": "database",
    "QAL": "code", "AGT": "code", "OPS": "code", "ACC": "code", "LNG": "code",
}


def _bundle_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", _BUNDLE_NAME)


DEFAULT_BUNDLE_PATH = _bundle_path()


def load_bundle(path=None):
    """The parsed OCRDb bundle dict, or None if the vendored file is absent.
    A present-but-malformed bundle raises ValueError (loud)."""
    path = path or _bundle_path()
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)   # corrupt JSON -> JSONDecodeError (a ValueError)
    if not (isinstance(data, dict) and isinstance(data.get("domains"), dict)):
        raise ValueError("OCRDb bundle %s malformed: missing 'domains' map" % path)
    return data


def domain_menu(bundle, domain):
    """The domain's entries as [{code, name, severity, cwe}], sorted by code.
    [] for an unknown domain or a None/non-dict bundle."""
    if not isinstance(bundle, dict):
        return []
    dom = (bundle.get("domains") or {}).get(domain) or {}
    entries = dom.get("entries") or {}
    menu = []
    for code in sorted(entries):
        entry = entries[code] or {}
        menu.append({"code": code,
                     "name": entry.get("name", ""),
                     "severity": entry.get("default_severity", "MEDIUM"),
                     "cwe": entry.get("cwe") or []})
    return menu


def domain_of(code):
    """The domain prefix of a code ('SEC-A1A' -> 'SEC'), or None."""
    if not isinstance(code, str) or "-" not in code:
        return None
    return code.split("-", 1)[0]


def validate_code(bundle, code):
    """True iff `code` is a real entry in the bundle. A synthetic '<DOM>-X0X'
    fallback code is NOT a real entry (returns False) — that is the catalog-gap
    signal synthesize counts."""
    if not isinstance(bundle, dict) or not code:
        return False
    dom = domain_of(code)
    if not dom:
        return False
    entries = ((bundle.get("domains") or {}).get(dom) or {}).get("entries") or {}
    return code in entries


def domain_fallback(domain):
    """The catalog-gap fallback code for a domain: '<DOM>-X0X'."""
    return "%s-X0X" % domain
