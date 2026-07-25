#!/usr/bin/env python3
"""Citation enrichment for panopticon findings: CWE validation, OWASP
derivation, reduced-SSVC decisioning, and opt-in EPSS lookup. Stdlib-only.
"""
import json
import os
import re
import sys
import urllib.parse
import urllib.request

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
SSVC_MODEL = "deployer-reduced"


def _catalog_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", "cwe-catalog.json")


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
            req = urllib.request.Request(url, headers={"User-Agent": "panopticon/3.0.0"})
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
        except Exception:  # noqa: BLE001 - lookup is best-effort by design
            continue
    if dirty:
        _save_cache(cache_path, cache)
    return out


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
            f.pop("citations", None)
            continue
        try:
            tool_sourced = str(f.get("source", "")).startswith("tool:")
            clean = {}
            cwe_objs = []
            for cid in _raw_cwe_ids(raw):
                v = validate_cwe(cid, catalog, tool_sourced=tool_sourced)
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
            if clean:
                f["citations"] = clean
            else:
                f.pop("citations", None)
        except Exception as e:  # noqa: BLE001 - citation enrichment must never abort synthesis
            print("citation enrich error (finding %s): %s" % (f.get("id"), e), file=sys.stderr)
            f.pop("citations", None)

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
