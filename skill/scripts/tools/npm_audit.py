"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import contextvars
import os
import stat
import sys

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
# The scratch project `invoke` hands npm as `--prefix` (#2055), and the only
# files it holds: the manifest and the lockfiles npm reads, copied from the
# target. Never the target's `.npmrc`, nor anything else of its.
STAGED_PROJECT = "project"
STAGED_FILES = ("package.json",) + LOCKFILES
# The bound on one staged file (#2055 round 1): npm parses a lockfile whole, so
# one past this is refused, never cut.
MAX_STAGED_BYTES = 64 * 1024 * 1024
# What a refused stage exits with -- `_run_adapter`'s FAIL_RC, and a status
# capture records as the tool's error: halt, never audit without the file.
_REFUSED_RC = 2


def _staged_bytes(path: str) -> bytes | None:
    """The bytes to stage from *path*, or None where it is absent (#2055 round 1).

    Read through no link and opened without blocking, so a target cannot make
    the stage copy a file from outside the boundary (`package-lock.json ->
    ~/.npmrc`) or wait on a FIFO. A present file that is not a regular file of
    the target's own -- a symlink, FIFO, device or directory -- or one past
    MAX_STAGED_BYTES raises ValueError, naming the file and never its content.
    """
    name = os.path.basename(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:              # ELOOP: a symlink, read through by nothing
        raise ValueError("%s cannot be opened as a regular file (%s)" % (name, exc.strerror)) from None
    try:                                # the raw fd first: a directory is no stream at all
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("%s is not a regular file" % name)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_STAGED_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_STAGED_BYTES:
        raise ValueError("%s is over %d bytes" % (name, MAX_STAGED_BYTES))
    return data


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
        # #1877: npm reads an `.npmrc` from the WORKING DIRECTORY as well as
        # from `--prefix`, and that file can set `registry`, `script-shell`
        # and `ignore-scripts` -- so the cwd is never the target.
        # #2055: nor is `--prefix`. npm reads the PROJECT `.npmrc` there, and a
        # committed one can set `omit=dev` (the whole dev tree silently dropped
        # from the audit), `include`, `audit-level` or `registry`; npm has no
        # flag that skips the project file. So npm audits a scratch project,
        # staged with the manifest and the lockfiles it reads and nothing else
        # -- each read through no link (`_staged_bytes`); one that is present
        # but refused fails the tool loudly rather than audit without it.
        with scratch_cwd("npm-audit-cwd-") as cwd:
            project = os.path.join(cwd, STAGED_PROJECT)
            os.mkdir(project)
            try:
                staged = {name: _staged_bytes(os.path.join(target, name)) for name in STAGED_FILES}
            except ValueError as exc:
                print("npm-audit: refusing to stage %s; recording as failed" % exc, file=sys.stderr)
                return b"", _REFUSED_RC
            for name, data in staged.items():
                if data is not None:
                    with open(os.path.join(project, name), "wb") as fh:
                        fh.write(data)
            cmd = ["npm", "audit", "--json", "--prefix", project]
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
                advisory_range = via.get("range")
                affected_range = (advisory_range if advisory_range is not None
                                  else vuln.get("range"))
                out.append(self._finding_from(
                    n, group, manifest,
                    name=vuln.get("name"),
                    versions_title=affected_range if affected_range is not None else "",
                    versions_evidence=affected_range,
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
