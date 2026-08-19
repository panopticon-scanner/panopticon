#!/usr/bin/env python3
"""Citation enrichment for panopticon findings: CWE validation, OWASP
derivation, reduced-SSVC decisioning, and opt-in EPSS lookup. Stdlib-only.
"""
import logging
import json
import os
import re
import sys
import urllib.parse
import urllib.request

try:
    from scripts import _version
    from scripts._version import __version__
    from scripts.evidence import is_tool_sourced
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    import _version
    from _version import __version__
    from evidence import is_tool_sourced

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
SSVC_MODEL = "deployer-reduced"

CATEGORY_CWE_OVERRIDES = {
    "injection": "CWE-89",
    "xss": "CWE-79",
    "auth": "CWE-287",
    "crypto": "CWE-327",
    "config": "CWE-16",
    "logging": "CWE-778",
    "headers": "CWE-693",
    "csrf": "CWE-352",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
    "sql_injection": "CWE-89",
}


def _catalog_path():
    return _version.reference_path("cwe-catalog.json")


def load_cwe_catalog(path=None):
    """Load CWE catalog with CWE definitions, OWASP mappings, and OWASP Top 10.
    Tolerant by design: a missing or malformed catalog degrades to empty maps
    (with a stderr warning) rather than aborting the whole synthesis run."""
    try:
        with open(path or _catalog_path(), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        print("citations: CWE catalog unavailable (%s); continuing without it" % e,
              file=sys.stderr)
        data = {}
    return {
        "cwe": data.get("cwe", {}),
        "cwe_owasp": data.get("cwe_owasp", {}),
        "owasp_top10": data.get("owasp_top10", []),
    }


def validate_cwe(cwe_id, catalog, tool_sourced=False):
    """Validate and normalize a CWE ID against the catalog."""
    if not isinstance(cwe_id, str) or not CWE_RE.match(cwe_id):
        return None
    cwe_id = cwe_id.upper()
    name = catalog["cwe"].get(cwe_id)
    if name is not None:
        return {"id": cwe_id, "name": name, "verified": True}
    return {"id": cwe_id, "name": None, "verified": bool(tool_sourced)}


def normalize_cwe_entries(entries, catalog, tool_sourced=False):
    """Normalize a mixed list of CWE strings/dicts to validated dicts.

    Dict entries are preserved as-is; string entries are validated against
    the catalog. Invalid or malformed entries are dropped.
    """
    out = []
    for entry in entries:
        if isinstance(entry, dict):
            out.append(entry)
        elif isinstance(entry, str):
            v = validate_cwe(entry, catalog, tool_sourced=tool_sourced)
            if v:
                out.append(v)
    return out


def derive_owasp(cwe_ids, asserted, catalog):
    """Derive OWASP mappings from CWE IDs and asserted OWASP tags."""
    out = []
    for cid in cwe_ids:
        mapped = catalog["cwe_owasp"].get(cid)
        if mapped and mapped not in out:
            out.append(mapped)
    for a in (asserted or []):
        if a in catalog["owasp_top10"] and a not in out:
            out.append(a)
    return out


_EXPLOIT = {"none": 0, "poc": 1, "active": 2}
_EXPOSURE = {"small": 0, "controlled": 1, "open": 2}
_IMPACT = {"low": 0, "medium": 1, "high": 2, "very_high": 3}


def ssvc_decide(exploitation, exposure, impact):
    """Return SSVC decision (Act/Attend/Track) from exploitation, exposure, impact levels."""
    if exploitation is None or exposure is None or impact is None:
        return None
    try:
        e = _EXPLOIT[str(exploitation).lower()]
        x = _EXPOSURE[str(exposure).lower()]
        i = _IMPACT[str(impact).lower()]
    except KeyError:
        return None
    score = e + x + i
    if score >= 5 or (e == 2 and i >= 2):
        return "Act"
    if score <= 1:
        return "Track"
    return "Attend"


def _load_cache(cache_path):
    try:
        with open(cache_path, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache_path, cache):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


def epss_lookup(cves, cache_path, opener=None):
    """Look up EPSS scores for CVEs via FIRST.org API with local caching."""
    if opener is None:
        opener = urllib.request.urlopen
    cache = _load_cache(cache_path)
    out = {}
    dirty = False
    for cve in cves:
        if not isinstance(cve, str) or not CVE_RE.match(cve):
            continue
        cve = cve.upper()
        if cve in cache:
            out[cve] = cache[cve]
            continue
        try:
            url = "https://api.first.org/data/v1/epss?cve=" + urllib.parse.quote(cve)
            req = urllib.request.Request(url, headers={"User-Agent": "panopticon/%s" % __version__})
            with opener(req, timeout=8) as resp:
                payload = json.loads(resp.read(1000000))
            rows = payload.get("data") or []
            if not rows:
                continue
            row = rows[0]
            entry = {
                "cve": cve,
                "score": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "as_of": row.get("date", ""),
                "source": "FIRST.org",
            }
            out[cve] = entry
            cache[cve] = entry
            dirty = True
        except Exception as e:  # noqa: BLE001 - lookup is best-effort by design
            logging.warning("EPSS network failure or error for %s: %s", cve, e)
            continue
    if dirty:
        _save_cache(cache_path, cache)
    return out


def _derive_cwe_from_category(category, catalog):
    cid = CATEGORY_CWE_OVERRIDES.get(str(category).lower().replace(" ", "_").replace("-", "_"))
    if cid and cid in catalog["cwe"]:
        return {"id": cid, "name": catalog["cwe"][cid], "verified": False, "derived": True}
    return None


def _compute_citation_quality(citations, finding_cvss=None):
    if not isinstance(citations, dict) or not citations:
        return "minimal" if finding_cvss else "none"
    cwe_list = citations.get("cwe") or []
    has_verified_real_cwe = any(
        isinstance(c, dict) and c.get("verified") and not c.get("derived")
        for c in cwe_list
    )
    has_derived_cwe = any(isinstance(c, dict) and c.get("derived") for c in cwe_list)
    has_owasp = bool(citations.get("owasp"))
    has_cve = bool(citations.get("cve"))
    has_cvss = bool(citations.get("cvss")) or bool(finding_cvss)
    if (has_verified_real_cwe or has_owasp) and (has_cve or has_cvss):
        return "full"
    if has_verified_real_cwe or has_owasp:
        return "partial"
    if has_derived_cwe or citations or finding_cvss:
        return "minimal"
    return "none"


def _raw_cwe_ids(raw):
    ids = []
    entries = raw.get("cwe")
    entries = entries if isinstance(entries, list) else []
    for entry in entries:
        if isinstance(entry, dict):
            cid = entry.get("id")
        else:
            cid = entry
        if isinstance(cid, str):
            ids.append(cid)
    return ids


def enrich_citations(findings, catalog, epss_enabled=False, cache_path=None, opener=None):
    """Enrich findings with validated CWE, OWASP, SSVC, and optional EPSS citations."""
    all_cves = set()
    for f in findings:
        raw = f.get("citations")
        if not isinstance(raw, dict):
            raw = {}
        try:
            tool_sourced = is_tool_sourced(f)
            clean = {}
            cwe_objs = []
            for entry in raw.get("cwe") if isinstance(raw.get("cwe"), list) else []:
                if isinstance(entry, dict):
                    cid = entry.get("id")
                    if isinstance(cid, str):
                        v = validate_cwe(cid, catalog, tool_sourced=tool_sourced)
                        if v:
                            if entry.get("derived"):
                                v["derived"] = True
                                v["verified"] = False
                            elif "verified" in entry:
                                v["verified"] = entry["verified"]
                            cwe_objs.append(v)
                elif isinstance(entry, str):
                    v = validate_cwe(entry, catalog, tool_sourced=tool_sourced)
                    if v:
                        cwe_objs.append(v)
            if cwe_objs:
                clean["cwe"] = cwe_objs
            owasp_raw = raw.get("owasp")
            owasp = derive_owasp([c["id"] for c in cwe_objs],
                                 owasp_raw if isinstance(owasp_raw, list) else [], catalog)
            if owasp:
                clean["owasp"] = owasp
            ssvc_raw = raw.get("ssvc")
            inputs = ssvc_raw.get("inputs") if isinstance(ssvc_raw, dict) else {}
            inputs = inputs if isinstance(inputs, dict) else {}
            decision = ssvc_decide(inputs.get("exploitation"), inputs.get("exposure"), inputs.get("impact"))
            if decision:
                clean["ssvc"] = {"decision": decision, "model": SSVC_MODEL, "inputs": inputs}
            cve_raw = raw.get("cve")
            cves = [c.upper() for c in (cve_raw if isinstance(cve_raw, list) else [])
                    if isinstance(c, str) and CVE_RE.match(c)]
            if cves:
                clean["cve"] = cves
                all_cves.update(cves)
            if not clean.get("cwe") and f.get("category"):
                derived = _derive_cwe_from_category(f["category"], catalog)
                if derived:
                    clean["cwe"] = [derived]
            if raw.get("epss"):
                clean["epss"] = raw["epss"]
            f["citation_quality"] = _compute_citation_quality(clean, f.get("cvss"))
            if clean:
                f["citations"] = clean
            else:
                f.pop("citations", None)
        except Exception as e:  # noqa: BLE001 - citation enrichment must never abort synthesis
            print("citation enrich error (finding %s): %s" % (f.get("id"), e), file=sys.stderr)
            f.pop("citations", None)
            f["citation_quality"] = "none"

    if epss_enabled and all_cves:
        scores = epss_lookup(sorted(all_cves), cache_path or ".panopticon/epss-cache.json",
                             opener=opener)
        for f in findings:
            c = f.get("citations")
            if not c or "cve" not in c:
                continue
            hits = [scores[cve] for cve in c["cve"] if cve in scores]
            if hits:
                c["epss"] = hits
