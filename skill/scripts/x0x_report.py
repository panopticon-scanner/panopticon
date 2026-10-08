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
from typing import TYPE_CHECKING
from typing import Any
import json
import re
import sys

if TYPE_CHECKING:
    import scripts.evidence as evidence
    import scripts.inert as inert
    import scripts.ocrdb as ocrdb
    import scripts.redact as redact
    import scripts.report_records as report_records
else:
    try:
        import scripts.evidence as evidence
        import scripts.inert as inert
        import scripts.ocrdb as ocrdb
        import scripts.redact as redact
        import scripts.report_records as report_records
    except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
        import evidence
        import inert
        import ocrdb
        import redact
        import report_records

SCHEMA_VERSION = 1
FAILURE_LOG_SUFFIX = "-failures.json"

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_WS_RE = re.compile(r"\s+")
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_DIAG_MAX = 120          # bound on any agent-authored value in a diagnostic
_PROPOSED_NAME_MAX = 60


def is_fallback(code):
    """True iff ``code`` is a ``<DOM>-X0X`` / ``ZZZ-X0X`` catalog-gap fallback.

    Case-INSENSITIVE, and shared with ``strain_report._is_gap`` (#2236,
    ARC-101960059): this used to be a bare case-sensitive ``endswith``, so
    ``sec-x0x`` was a gap to the strain emitter and an ordinary code here. See
    ``ocrdb.is_fallback_code``.
    """
    return ocrdb.is_fallback_code(code)


def _slug(text):
    s = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return s[:_PROPOSED_NAME_MAX].rstrip("-") or None


def _one_line(value, cap=_DIAG_MAX):
    """One bounded, single-line rendering of an agent-authored value, for a
    diagnostic. Whitespace is collapsed and the cut is MARKED (the rule
    ``phases/review.py::_hit_text`` states: a truncated value must not be able to
    read as a complete one). Returns "" for an absent or whitespace-only value, so
    a caller can fall back. Callers render the result with ``%r``, which is what
    makes a control character inert."""
    text = " ".join(str(value or "").split())
    return (text[:cap - 1] + "\u2026") if len(text) > cap else text


def _redacted_one_line(value, cap=_DIAG_MAX):
    """Redact and neutralize before cutting so no partial secret or control
    sequence can survive in a bounded failure-log field."""
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    text = redact.redact_diagnostic(text, len(text))
    text = "".join(
        ("\\x%02x" % ord(ch) if ord(ch) < 0x100 else "\\u%04x" % ord(ch))
        if ord(ch) in inert.INERT_ESCAPE_CODE_POINTS else ch
        for ch in text
    )
    return _one_line(text, cap)


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
    return report_records.occurrence(finding)


def _locus_diagnostic(finding):
    """Name one discarded finding in a bounded, redacted, inert diagnostic."""
    finding_id = _redacted_one_line(finding.get("id")) or "?"
    title = _redacted_one_line(
        finding.get("short_title") or finding.get("title")) or "?"
    diagnostic = "catalog-gap finding %r (%r) has no location.file" % (finding_id, title)
    return redact.redact_diagnostic(diagnostic, 2 * _DIAG_MAX + 100)


def _discard_record(finding):
    """The deterministic sidecar record for one locus-free catalog gap."""
    finding_id = _redacted_one_line(finding.get("id")) or "?"
    return {
        "finding_id": finding_id,
        "reason": "no file locus",
        "diagnostic": _locus_diagnostic(finding),
    }


def _domain(finding):
    """The finding's roster domain: its own ``domain`` field if it has one, else
    the prefix of its ``code``.

    The claim is resolved HERE and validated by ``ocrdb.clamp_domain`` -- which
    takes a domain, not a code, so a hyphenated claim (``DAT-C1B``,
    ``SEC-NOPE``) is clamped and disclosed rather than re-split into the domain
    before its first hyphen. ``strain_report`` holds a code and goes through
    ``ocrdb.roster_domain``, the wrapper around the same clamp (#2236). Two
    properties that predate the sharing and still hold:

    * #run7 COD-C2D — the value flows in verbatim from synthesize (no case-fold
      upstream), so it is upper-cased, and "SEC" and "sec" cluster into ONE
      candidate instead of splitting on the key (the title half is already
      lowercased).
    * #1639 P15 F1 — this value IS the published ``candidates[].domain`` and the
      x0x schema pins it to the roster, so an off-roster prefix is clamped to the
      ZZZ sentinel and disclosed. The prefix of an agent's ``code`` is not a
      domain just because it looks like one. ``codes.py`` normally rewrites such
      a code upstream; this is the same answer at this artifact's own boundary,
      because the X0X schema is a SECOND published contract and the repair pass
      reads only the first.
    """
    # The `or ZZZ` default is not a rejected claim: a finding with no `domain`
    # and no `code` claims no domain, which IS the sentinel, so it reaches
    # `clamp_domain` already normalized and is not disclosed.
    dom = (finding.get("domain")
           or (ocrdb.domain_prefix(str(finding.get("code", "")))
               or ocrdb.UNKNOWN_DOMAIN))

    def _disclose(claim):
        print("x0x: %r: domain %r is not an OCRDb domain; filing the candidate "
              "under %s" % (_one_line(finding.get("id")) or "?",
                            _one_line(claim, 40), ocrdb.UNKNOWN_DOMAIN),
              file=sys.stderr)

    return ocrdb.clamp_domain(dom, disclose=_disclose)


def _lead(cluster):
    """The most severe finding in a cluster — it leads the candidate's
    summary/severity/name, and names the cluster in a diagnostic. Equal severities
    use stable finding identity rather than input order."""
    return max(
        cluster,
        key=lambda finding: (
            _SEV_ORDER.get(str(finding.get("severity") or "").upper(), -1),
            evidence.finding_fingerprint(finding),
            _canonical(finding),
        ),
    )


def _canonical(value):
    """A stable total-order key for JSON-originated report values."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), default=str)


def _candidate_order(item):
    """The consumer's total candidate order, with the cluster key as its tie-break."""
    cluster_key, candidate = item
    severity = str(candidate.get("severity") or "").upper()
    return (
        -_SEV_ORDER.get(severity, -1),
        str(candidate.get("domain") or ""),
        str(candidate.get("proposed_name") or ""),
        tuple(str(part) for part in cluster_key),
    )


def _partition_fallbacks(findings):
    """Split fallback findings into representable rows and sidecar failures."""
    located = []
    discarded = []
    fallbacks = sorted(
        (finding for finding in findings if is_fallback(finding.get("code"))),
        key=_canonical,
    )
    for finding in fallbacks:
        if _occurrence(finding) is None:
            discarded.append(_discard_record(finding))
        else:
            located.append(finding)
    return located, sorted(discarded, key=_canonical)


def _build_candidates(fallbacks):
    """Cluster already-located fallback findings into candidate records."""
    clusters: dict[tuple[str, str], list[dict[str, Any]]] = {}  # (domain, key) -> [findings]
    for f in fallbacks:
        title = f.get("short_title") or f.get("title") or ""
        norm = _WS_RE.sub(" ", title.strip().lower())
        key = (_domain(f), norm if norm else str(f.get("id") or ""))
        clusters.setdefault(key, []).append(f)

    candidates = []
    for cluster_key, fs in clusters.items():
        domain, _ = cluster_key
        occurrences = sorted(
            (_occurrence(f) for f in fs),
            key=_canonical,
        )
        lead = _lead(fs)
        cwe = sorted({c for f in fs for c in _cwes(f)})
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
        candidates.append((cluster_key, cand))
    return [candidate for _, candidate in sorted(candidates, key=_candidate_order)]


def build_candidates(findings):
    """Cluster the X0X fallback findings into candidate records. Cluster key =
    ``(domain, normalized-title)``: the same anti-pattern titled the same way
    merges into one candidate with many occurrences; distinct titles stay
    separate. (Semantic clustering is a future refinement.)

    The returned candidate array has a total, input-independent order. A
    fallback finding without a file is excluded because the occurrence schema
    cannot represent it; :func:`build_emission` returns the matching failure-log
    records used by the synthesizer."""
    located, _discarded = _partition_fallbacks(findings)
    return _build_candidates(located)


def _report(candidates, meta, run_id, panopticon_version=None, target=None):
    """Assemble an X0X report around a pre-built candidate array."""
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
        "candidates": candidates,
    }
    if target:
        report["target"] = target
    if meta.get("timestamp"):
        report["generated_at"] = meta["timestamp"]
    return report


def build_report(findings, meta, run_id, panopticon_version=None, target=None):
    """Assemble a schema-valid X0XReport dict for a run's findings. ``run_id`` is
    the driver's ``manifest.run_id`` (the schema requires it; per-run folders now
    supply a real one instead of the prototype's ``derived:`` placeholder)."""
    return _report(build_candidates(findings), meta, run_id,
                   panopticon_version=panopticon_version, target=target)


def build_emission(findings, meta, run_id, panopticon_version=None, target=None):
    """Return ``(X0X report, failure log or None)`` for one synthesis run.

    Locus-free fallback findings stay in the main Panopticon report but cannot
    enter X0X's occurrence-bearing candidate set. Each is recorded in the
    deterministic sidecar; a clean emission returns ``None`` so the caller can
    remove any stale sidecar from an earlier run.
    """
    located, discarded = _partition_fallbacks(findings)
    report = _report(_build_candidates(located), meta, run_id,
                     panopticon_version=panopticon_version, target=target)
    failure_log = {"discarded_findings": discarded} if discarded else None
    return report, failure_log


def failure_log_path(x0x_path):
    """Return the JSON failure-log path beside an X0X artifact."""
    stem = x0x_path[:-len(".json")] if x0x_path.endswith(".json") else x0x_path
    return stem + FAILURE_LOG_SUFFIX
