"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import contextvars
import os

from .base import (as_list, cve_ids, has_any_file, make_finding, normalize_severity,
                   omit_none, parse_json_bytes, run_tool, scratch_cwd,
                   target_root_cv)

# The manifest THIS invocation audited, target-relative (#1649). A ContextVar
# for the reason pip_audit carries one: ADAPTERS holds a single shared adapter
# object, so instance state would let a second invoke overwrite the first
# invocation's answer before its output was parsed.
_manifest_path_cv: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "npm_audit_manifest_path", default=None)

# npm reads npm-shrinkwrap.json in preference to package-lock.json, so the
# order here is the order npm resolves in -- and it is ONE list, read by both
# `is_applicable` (may we audit this target) and `_manifest` (what did we
# audit), which is what stopped them disagreeing.
LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json")
# The last resort, for a caller that hands over bytes and NO tree: npm audit
# needs a lockfile, and this is the name the adapter has always written. Every
# real route names a tree -- ingest through `target_root_cv`, the in-process
# one (capture_goldens) through `invoke` -- so this is a guess of last resort
# and not an answer to rely on.
DEFAULT_MANIFEST = "package-lock.json"


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return has_any_file(target, *LOCKFILES)

    def _manifest(self, target: str) -> str:
        """The manifest `npm audit` actually reads for *target*, target-relative.

        Never a path that is not in the target: a shrinkwrap-only project is
        located at its shrinkwrap, and `package.json` is the last resort for a
        target that `is_applicable` would not have accepted at all.
        """
        for name in LOCKFILES:
            if os.path.isfile(os.path.join(target, name)):
                return name
        return "package.json"

    def invoke(self, target: str) -> tuple[bytes, int]:
        # Recorded where the choice is MADE, so parse cannot name a different
        # file from the one audited (#1649).
        _manifest_path_cv.set(self._manifest(target))
        cmd = ["npm", "audit", "--json", "--prefix", target]
        # #1877: npm reads an `.npmrc` from the WORKING DIRECTORY as well as
        # from `--prefix`, and that file can set `registry`, `script-shell`
        # and `ignore-scripts` -- so the cwd is never the target. `--prefix`
        # already names the project by path, so argv is byte-unchanged.
        with scratch_cwd("npm-audit-cwd-") as cwd:
            return run_tool(cmd, timeout=300, cwd=cwd)

    def _located_at(self) -> str:
        """The manifest this parse's findings are located at.

        Two routes, because a real scan runs `invoke` and `parse` in DIFFERENT
        PROCESSES (#1649): run_tools dispatches the adapter as
        `docker run ... _run_adapter.py`, which only invokes, and `ingest_tools`
        parses the captured bytes back on the host. So the answer is resolved
        wherever the tree is actually in reach -- from `invoke`'s own choice
        when the two share a process (capture_goldens), and otherwise from the
        target root ingest names around its parse.
        """
        chosen = _manifest_path_cv.get()
        if chosen:
            return chosen
        root = target_root_cv.get()
        return self._manifest(root) if root else DEFAULT_MANIFEST

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        if not isinstance(data, dict):
            raise ValueError("npm audit output is not a report object")
        if "error" in data:
            error = data["error"]
            if isinstance(error, dict):
                detail = ": ".join(str(error[key]) for key in ("code", "summary")
                                   if error.get(key))
            else:
                detail = str(error)
            raise ValueError(f"npm audit error: {detail or 'unknown error'}")
        if not any(key in data for key in ("advisories", "vulnerabilities")):
            if data.get("message"):
                raise ValueError(f"npm audit error: {data['message']}")
            raise ValueError("npm audit output has no advisories or vulnerabilities report")
        for key in ("advisories", "vulnerabilities"):
            if key in data and not isinstance(data[key], dict):
                raise ValueError(f"npm audit {key} is not an object")
        # Resolved ONCE per parse, not per finding: it stats the target root.
        manifest = self._located_at()
        out = []
        n = 1

        # Legacy npm audit output (npm < 7 / auditReportVersion 1).
        for adv in data.get("advisories", {}).values():
            out.append(self._finding_from(
                n, group, manifest,
                name=adv.get("module_name"),
                versions_title=adv.get("vulnerable_versions", ""),
                versions_evidence=adv.get("vulnerable_versions"),
                severity_raw=adv.get("severity"),
                title=adv.get("title", "vulnerability"),
                description=adv.get("overview", "No description provided."),
                remediation=f"Upgrade to a fixed version: {adv.get('patched_versions', 'see advisory')}",
                url=adv.get("url"),
                cves=adv.get("cves"),
                rule_id=str(adv.get("id")) if adv.get("id") is not None else None,
                fixed_version=adv.get("patched_versions"),
            ))
            n += 1

        # Current npm audit output (auditReportVersion 2+).
        for vuln in data.get("vulnerabilities", {}).values():
            fix = vuln.get("fixAvailable")
            fixed_version = fix.get("version") if isinstance(fix, dict) else None
            for via in self._advisories(vuln):
                out.append(self._finding_from(
                    n, group, manifest,
                    name=vuln.get("name"),
                    versions_title=vuln.get("range", ""),
                    versions_evidence=vuln.get("range"),
                    severity_raw=via.get("severity") or vuln.get("severity"),
                    title=via.get("title", "vulnerability"),
                    description=via.get("title", "No description provided."),
                    remediation=f"Upgrade to a fixed version: {fixed_version or 'see advisory'}",
                    url=via.get("url"),
                    cves=via.get("cves"),
                    rule_id=str(via.get("source")) if via.get("source") is not None else None,
                    fixed_version=fixed_version,
                ))
                n += 1

        return out

    def _finding_from(self, n, group, manifest, *, name, versions_title, versions_evidence,
                       severity_raw, title, description, remediation, url, cves,
                       rule_id, fixed_version) -> dict:
        """Assemble one npm-audit finding shared by both the legacy (v1
        advisories) and current (v2 vulnerabilities) report loops.

        Each caller does its own report-version-specific field extraction and
        passes the resolved values in; this only owns the invariant
        make_finding envelope (title/impact template, location, references,
        citations, tool_evidence) so the two near-identical blocks aren't
        duplicated. versions_title/versions_evidence are kept distinct because
        the original code defaulted the title's version segment to "" but left
        tool_evidence's vulnerable_versions as None-when-absent (so omit_none
        drops it) -- collapsing them to one value would change output.

        #1649: `manifest` is the file THIS parse's findings are located at,
        resolved once by `_located_at` -- not a hard-coded package-lock.json.
        `is_applicable` accepts a shrinkwrap too, so every finding on a
        shrinkwrap-only project used to point at a file that is not in the tree
        -- and `location.file` is what source navigation, the advisor's backup
        scope grant (P16) and path-based downstream matching all key on.
        """
        return make_finding(
            self, n, group,
            title=f"{name} {versions_title}: {title}",
            severity=normalize_severity(severity_raw),
            category="dependency_vulnerability",
            location={"file": manifest, "line_start": 1},
            description=description,
            impact=f"Vulnerable Node dependency {name} is used.",
            remediation=remediation,
            references=as_list(url),
            citations={"cve": cve_ids(cves)},
            tool_evidence=omit_none({
                "rule_id": rule_id,
                "package_name": name,
                "vulnerable_versions": versions_evidence,
                "fixed_version": fixed_version,
            }),
        )

    def _advisories(self, vuln: dict) -> list[dict]:
        """Return every advisory from an npm v2 vulnerability's via list.

        ``via`` may contain either advisory dicts or dependency-name strings.
        Strings are transitive chain markers with no CVE, so they are skipped.
        """
        via = vuln.get("via")
        if isinstance(via, dict):
            return [via]
        if isinstance(via, list):
            return [entry for entry in via if isinstance(entry, dict)]
        return []
