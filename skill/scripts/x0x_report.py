"""Emit an X0XReport (see skill/reference/x0x-report-schema.json) from a review's
findings — the ``<DOM>-X0X`` / ``ZZZ-X0X`` catalog-gap findings packaged as
candidate records for OCRDb's new-code adjudication pool (ingested downstream,
e.g. the OCRDb website).

MECHANICAL by design: it clusters occurrences of the same anti-pattern under one
candidate and carries the reviewer's finding as-is. It does NOT adjudicate — the
gap *rationale* (why no code fit) and the disposition *verdict*
(new_code / refine_existing / retire / boundary / not_a_gap) are pool decisions,
not emitter output, so this emitter omits them (the schema leaves both optional and
``additionalProperties`` open). Capturing a reviewer-supplied ``would_file_as`` on
X0X findings is a separate, reviewer-side follow-on.
"""
import re

SCHEMA_VERSION = 1

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_WS_RE = re.compile(r"\s+")
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def is_fallback(code):
    """True iff ``code`` is a ``<DOM>-X0X`` / ``ZZZ-X0X`` catalog-gap fallback."""
    return bool(code) and str(code).endswith("-X0X")


def _slug(text):
    s = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return s or None


def _cwes(finding):
    """Best-effort CWE scrape. Findings carry no structured CWE (``references`` are
    free-text evidence strings), so pull ``CWE-<n>`` out of the finding's text,
    deduped in first-seen order. Usually empty for an X0X gap."""
    blob = " ".join(str(finding.get(k) or "") for k in ("title", "description", "impact"))
    blob += " " + " ".join(str(r) for r in (finding.get("references") or []))
    out = []
    for c in _CWE_RE.findall(blob):
        if c not in out:
            out.append(c)
    return out


def _occurrence(finding):
    """An occurrence record, or None when the finding has no file (schema requires
    ``file`` on every occurrence)."""
    loc = finding.get("location") or {}
    if not loc.get("file"):
        return None
    o = {"file": loc["file"]}
    if loc.get("line_start") is not None:
        o["line_start"] = loc["line_start"]
    if loc.get("line_end") is not None:
        o["line_end"] = loc["line_end"]
    if finding.get("id"):
        o["finding_id"] = finding["id"]
    return o


def _domain(finding):
    dom = (finding.get("domain")
           or (str(finding.get("code", "")).split("-")[0] or "ZZZ"))
    # #run7 COD-C2D: OCRDb domains/codes are uppercase by convention, but the
    # value flows in verbatim from synthesize (no case-fold upstream). Fold it so
    # "SEC" and "sec" cluster into ONE candidate instead of splitting on the key
    # (the title half is already lowercased). Also normalizes the emitted
    # candidate's `domain`, which reuses this value.
    return str(dom).upper()


def build_candidates(findings):
    """Cluster the X0X fallback findings into candidate records. Cluster key =
    ``(domain, normalized-title)``: the same anti-pattern titled the same way
    merges into one candidate with many occurrences; distinct titles stay
    separate. (Semantic clustering is a future refinement.)"""
    clusters = {}  # (domain, key) -> [findings], insertion-ordered
    for f in findings:
        if not is_fallback(f.get("code")):
            continue
        title = f.get("short_title") or f.get("title") or ""
        norm = _WS_RE.sub(" ", title.strip().lower())
        key = (_domain(f), norm if norm else f.get("id", ""))
        clusters.setdefault(key, []).append(f)

    candidates = []
    for (domain, _), fs in clusters.items():
        occurrences = [o for o in (_occurrence(f) for f in fs) if o is not None]
        if not occurrences:          # schema: occurrences has minItems 1
            continue
        # the most severe finding leads the candidate's summary/severity/name
        lead = max(fs, key=lambda f: _SEV_ORDER.get(str(f.get("severity") or "").upper(), -1))
        cwe = []
        for f in fs:
            for c in _cwes(f):
                if c not in cwe:
                    cwe.append(c)
        cand = {
            "domain": domain,
            "fallback_code": lead.get("code"),
            "summary": lead.get("short_title") or lead.get("title") or "",
            "severity": lead.get("severity") or "MEDIUM",
            "recurrence": len(occurrences),
            "occurrences": occurrences,
        }
        name = _slug(lead.get("short_title") or lead.get("title"))
        if name:
            cand["proposed_name"] = name
        if lead.get("description"):
            cand["description"] = lead["description"]
        if cwe:
            cand["cwe"] = cwe
        candidates.append(cand)
    return candidates


def build_report(findings, meta, run_id, panopticon_version=None, target=None):
    """Assemble a schema-valid X0XReport dict for a run's findings. ``run_id`` is
    the driver's ``manifest.run_id`` (the schema requires it; per-run folders now
    supply a real one instead of the prototype's ``derived:`` placeholder)."""
    meta = meta or {}
    if target is None and meta.get("target"):
        target = {"name": str(meta["target"])}
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": {
            "panopticon_version": (panopticon_version or meta.get("version")
                                   or "unknown"),
            "run_id": str(run_id) if run_id else "unknown",
        },
        "ocrdb_version": meta.get("ocrdb_version") or "unknown",
        "candidates": build_candidates(findings),
    }
    if target:
        report["target"] = target
    if meta.get("timestamp"):
        report["generated_at"] = meta["timestamp"]
    return report
