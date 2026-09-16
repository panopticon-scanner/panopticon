"""pip-audit adapter for Python dependency CVEs."""
from __future__ import annotations
import contextvars
import glob
import os
import re
import sys
import tempfile
import tomllib

import scripts.redact as redact
from .base import cve_ids, make_finding, normalize_severity, omit_none, parse_json_bytes, run_tool

_manifest_path_cv = contextvars.ContextVar("pip_audit_manifest_path", default=None)


def _deps_from_pyproject(target: str) -> list[str] | None:
    """Static PEP 621 read — never invokes a build backend (#218)."""
    path = os.path.join(target, "pyproject.toml")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    if "dependencies" in (project.get("dynamic") or []):
        return None
    deps = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        deps.extend(extra)
    return deps


# ---------------------------------------------------------------------------
# #1646 (SEC-E3A) / owner ruling D5: sanitize and disclose.
#
# pip-audit RESOLVES what a requirements file names. The syntax admits `-e .`,
# `./local/path`, `git+https://...`, `https://.../x.tar.gz`, `--index-url`,
# `--find-links`, `-r other.txt` and `-c constraints.txt`; resolving any of the
# first four invokes the reviewed repository's PEP 517 metadata/build hooks, so
# handing pip-audit the repo's OWN file ran target code under the scanner
# account -- online, because pip-audit is ONLINE_ONLY. The control is not a
# pip-audit flag (`--no-deps` was the rejected alternative): it is that pip-audit
# is only ever given a file THIS module generated, holding lines that name a
# package and a version and can name nothing else.
#
# Parsed with stdlib `re` per PEP 508 -- deliberately not with `packaging`
# (undeclared, see pyproject.toml) and never by importing `pip`, which would put
# the resolver we are fencing off back inside the process.
# ---------------------------------------------------------------------------

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_EXTRAS = r"\[\s*%s(?:\s*,\s*%s)*\s*\]" % (_NAME, _NAME)
_OP = r"(?:===|==|~=|!=|<=|>=|<|>)"
_VER = r"[A-Za-z0-9][A-Za-z0-9.*+!_-]*"
_SPEC = r"%s\s*%s" % (_OP, _VER)
# A bare PEP 508 requirement: name, optional extras, optional version specifier
# set. No `@ url`, no path, no scheme -- those characters are not in the classes
# above, which is what makes "kept" mean "names a release on an index".
_BARE_REQ = re.compile(r"^(?:%s)(?:\s*%s)?\s*(?:%s(?:\s*,\s*%s)*)?\s*$"
                       % (_NAME, _EXTRAS, _SPEC, _SPEC))
# An environment marker, conservatively: the characters PEP 508's marker grammar
# actually uses. `@`, `/`, `\`, `:` and `#` are NOT here, so a marker can never
# smuggle a URL or a path past the check above.
_MARKER_OK = re.compile(r"^[\sA-Za-z0-9_.()'\"<>=!~,*+-]*$")
_COMMENT = re.compile(r"(^|\s+)#.*$")
_HASH = re.compile(r"\s*--hash[=\s]+\S+")
_INCLUDE = re.compile(r"^(?:-r|--requirement|-c|--constraint)(?:[=\s]+)(\S.*)$")
_EDITABLE = re.compile(r"^(?:-e|--editable)(?:[=\s]|$)")
_VCS = re.compile(r"(?:^|@\s*)(?:git|hg|bzr|svn)\+")
_SCHEME = re.compile(r"(?:^|@\s*)[A-Za-z][A-Za-z0-9+.-]*://")
# A private-index password lives in a dropped `--index-url` line, and the
# dropped lines are published in tools-manifest.json. Mask userinfo at the
# PRODUCER, so no consumer has to remember to.
_USERINFO = re.compile(r"(://)[^/\s@]*:[^/\s@]*@")
_MAX_INCLUDE_DEPTH = 1


def _joined(text):
    r"""The file's logical lines, with `\`-continuations joined the way pip does.

    pip strips the backslashes and concatenates with no separator, so
    `--extra\` + `-index-url https://evil` becomes one option line. Joining
    BEFORE classification is the whole point: a continuation that reassembles
    into an option must be judged as that option, not as two harmless fragments.
    A comment line ends a continuation (pip's own special case), so a trailing
    backslash inside a comment cannot swallow the requirement after it.
    """
    out, buf = [], []
    for raw in str(text or "").splitlines():
        line = raw.rstrip()
        if line.endswith("\\") and not line.lstrip().startswith("#"):
            buf.append(line.strip("\\"))
            continue
        buf.append(line)
        out.append("".join(buf))
        buf = []
    if buf:
        out.append("".join(buf))
    return out


def _safe_to_publish(line):
    """A dropped line as the manifest may carry it: URL credentials masked, then
    the shared secret-pattern pass every other published artifact gets."""
    return redact.redact(_USERINFO.sub(r"\1[REDACTED]@", line))


def sanitize_requirements(text):
    """`(kept, dropped)` for one requirements document.

    `kept` holds the lines that parse as a bare PEP 508 requirement -- verbatim,
    minus any `--hash=` tokens (pip-audit does not need them, and leaving one in
    would put the generated file under `--require-hashes` semantics it cannot
    satisfy). Everything else is `{"line", "reason"}` with one of `editable`,
    `local path`, `vcs url`, `direct url`, `option line`, `include`,
    `unparseable`. Comments and blank lines are simply skipped: they are not
    requirements and nothing was lost by not auditing them.

    `include` is classified, never followed: this function reads no files.
    `sanitize_requirements_file` is the wrapper that resolves `-r`/`-c`.
    """
    kept, dropped = [], []

    def drop(line, reason):
        dropped.append({"line": _safe_to_publish(line), "reason": reason})

    for line in _joined(text):
        line = _COMMENT.sub("", line).strip()
        if not line:
            continue
        line = _HASH.sub("", line).strip()
        if not line:
            continue
        if _EDITABLE.match(line):
            drop(line, "editable")
        elif _INCLUDE.match(line):
            drop(line, "include")
        elif line.startswith("-"):
            drop(line, "option line")
        elif _VCS.search(line):
            drop(line, "vcs url")
        elif _SCHEME.search(line):
            drop(line, "direct url")
        elif line[0] in "./~\\" or "/" in line or "\\" in line:
            drop(line, "local path")
        else:
            head, sep, marker = line.partition(";")
            if _BARE_REQ.match(head.strip()) and (
                    not sep or _MARKER_OK.match(marker)):
                kept.append(line)
            else:
                drop(line, "unparseable")
    return kept, dropped


def _hashes_present(text):
    return bool(_HASH.search(str(text or "")))


def _within(root, path):
    """True iff `path` resolves inside `root` -- realpath, so an in-tree symlink
    out of the repo is caught too (the `runio._confined_to_root` rule, restated
    here because a tool adapter may not import the driver's phase package)."""
    root = os.path.realpath(root)
    full = os.path.realpath(path)
    return full == root or full.startswith(root + os.sep)


def sanitize_requirements_file(path, root):
    """`(kept, dropped, hashes_stripped)` for a requirements file on disk.

    `-r`/`-c` includes are followed ONE level and sanitized the same way, so the
    ordinary `requirements.txt -> -r requirements-base.txt` layout is still
    audited. An include is dropped rather than followed when it resolves outside
    `root` (`include outside target`), when it would be a second level or revisit
    a file already read (`nested include`), or when it cannot be read
    (`include unreadable`). Included lines come FIRST, in include order, which is
    the order pip would have resolved them in.
    """
    seen, hashes = set(), False

    def read(p):
        nonlocal hashes
        with open(p, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        hashes = hashes or _hashes_present(text)
        return text

    def walk(p, depth):
        seen.add(os.path.realpath(p))
        try:
            text = read(p)
        except OSError:
            return [], []
        kept, dropped = sanitize_requirements(text)
        resolved_kept, resolved_dropped = [], []
        base = os.path.dirname(os.path.abspath(p))
        for entry in dropped:
            m = _INCLUDE.match(entry["line"]) if entry["reason"] == "include" else None
            if m is None:
                resolved_dropped.append(entry)
                continue
            target = os.path.join(base, m.group(1).strip().strip('"\''))
            if not _within(root, target):
                resolved_dropped.append(dict(entry, reason="include outside target"))
            elif depth >= _MAX_INCLUDE_DEPTH or os.path.realpath(target) in seen:
                resolved_dropped.append(dict(entry, reason="nested include"))
            elif not os.path.isfile(target):
                resolved_dropped.append(dict(entry, reason="include unreadable"))
            else:
                sub_kept, sub_dropped = walk(target, depth + 1)
                resolved_kept.extend(sub_kept)
                resolved_dropped.extend(sub_dropped)
        return resolved_kept + kept, resolved_dropped

    kept, dropped = walk(path, 0)
    return kept, dropped, hashes


class PipAuditAdapter:
    name = "pip-audit"
    prefix = "PA"

    def is_applicable(self, target: str) -> bool:
        patterns = ["requirements.txt", "requirements*.txt", "pyproject.toml"]
        for pat in patterns:
            path = os.path.join(target, pat)
            if "*" in pat:
                if glob.glob(path):
                    return True
            elif os.path.exists(path):
                return True
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        # --desc takes an optional value; the bare form swallows a following
        # positional path (calibration 2026-08-03: --desc /src -> argparse
        # error, exit 2). Always use the explicit-value form.
        # --progress-spinner=off: some pip-audit builds emit an ANSI progress
        # spinner into stdout ahead of the JSON, which corrupts parsing.
        cmd = ["pip-audit", "--format=json", "--desc=on", "--progress-spinner=off"]
        req = self._find_requirement(target)
        if req:
            # #1646: NEVER `--requirement <the repo's own file>`. pip-audit
            # resolves what that file names, and a requirement form it has to
            # resolve runs the target's build backend. The sanitizer's output
            # is what pip-audit sees; the repo path survives only as the
            # LOCATION findings are reported against, which reads no file.
            _manifest_path_cv.set(req)
            kept, _dropped, _hashes = sanitize_requirements_file(req, target)
        else:
            # Never pass the project directory positionally: resolving a
            # source tree can invoke its PEP 517 build backend (#218).
            deps = _deps_from_pyproject(target)
            if not deps:
                print("pip-audit: no static [project.dependencies] in %s; "
                      "skipping (osv-scanner covers this target)" % target,
                      file=sys.stderr)
                return b'{"dependencies": [], "fixes": []}', 0
            _manifest_path_cv.set(os.path.join(target, "pyproject.toml"))
            # The PEP 621 read is static, but `[project.dependencies]` may
            # itself hold `name @ git+https://...` -- the same build-backend
            # door through a second file. Both branches write a GENERATED file
            # and the same grammar is what makes it safe.
            kept, _dropped = sanitize_requirements("\n".join(deps))
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        try:
            tmp.write("".join(line + "\n" for line in kept))
            tmp.close()
            cmd.extend(["--requirement", tmp.name])
            return run_tool(cmd, timeout=300)
        finally:
            os.unlink(tmp.name)

    def _find_requirement(self, target: str) -> str | None:
        # Prefer the canonical requirements.txt (#707). The glob fallback
        # returns the lexicographically-first match, and '-' (0x2D) sorts
        # before '.' (0x2E), so requirements-dev.txt would otherwise win over
        # requirements.txt and the PRIMARY manifest would go unaudited.
        exact = os.path.join(target, "requirements.txt")
        if os.path.isfile(exact):
            return exact
        matches = sorted(glob.glob(os.path.join(target, "requirements*.txt")))
        return matches[0] if matches else None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            dep_name = dep.get("name") or "unknown"
            dep_version = dep.get("version") or ""
            for vuln in dep.get("vulns", []):
                out.append(make_finding(
                    self, n, group,
                    title=f"{dep_name} {dep_version}: {vuln.get('id', 'vulnerability')}".strip(),
                    severity=normalize_severity(vuln.get("severity") or "MEDIUM"),
                    category="dependency_vulnerability",
                    location={"file": _manifest_path_cv.get() or "requirements.txt", "line_start": 1},
                    description=vuln.get("description", "No description provided."),
                    impact=f"Vulnerable dependency {dep_name}=={dep_version} is used.",
                    remediation=f"Upgrade to a fixed version: {', '.join(vuln.get('fix_versions', [])) or 'see advisory'}",
                    citations={"cve": cve_ids(vuln.get("aliases"))},
                    tool_evidence=omit_none({
                        "rule_id": vuln.get("id"),
                        "package_name": dep_name,
                        "vulnerable_versions": dep_version,
                        "fixed_version": (vuln.get("fix_versions") or [None])[0],
                    }),
                ))
                n += 1
        return out
