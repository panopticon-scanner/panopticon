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
_BARE_REQ = re.compile(r"^(%s)(?:\s*%s)?\s*(?:%s(?:\s*,\s*%s)*)?\s*$"
                       % (_NAME, _EXTRAS, _SPEC, _SPEC))
# An environment marker, conservatively: the characters PEP 508's marker grammar
# actually uses. `@`, `/`, `\`, `:` and `#` are NOT here, so a marker can never
# smuggle a URL or a path past the check above.
# `\S` in the middle, not `*`: an EMPTY marker matched, so `pkg==1.0;` was kept
# -- and `packaging.requirements.Requirement("pkg==1.0;")` raises, while
# pip-audit parses every line of the generated file. One such target line would
# have aborted the entire dependency audit, which is the one thing a GENERATED
# file exists to make impossible (M6).
_MARKER_CHARS = r"[\sA-Za-z0-9_.()'\"<>=!~,*+-]"
_MARKER_OK = re.compile(r"^%s*\S%s*$" % (_MARKER_CHARS, _MARKER_CHARS))
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

# Bounds. `dropped` is TARGET-AUTHORED text on its way into two published
# artifacts (`tools-manifest.json`, then `report.json`), and every sibling path
# in this module is already bounded -- `run_tools.MAX_TOOL_OUTPUT_BYTES` on tool
# stdout, `redact`'s 16 KiB PEM bound. A 50 MB junk requirements file would
# otherwise be read whole (twice: once in the container, once on the host) and
# copied wholesale into both. The read is capped FIRST, so the cost is bounded
# before anything is parsed; the row count and each row's length are capped at
# publication. Every cap is disclosed -- a silent truncation would be a second
# "the audit was partial" nobody is told about.
_MAX_READ_BYTES = 1024 * 1024
_MAX_READ_LINES = 20000
_MAX_DROPPED_ROWS = 200
_MAX_PUBLISHED_CHARS = 200
_ELLIPSIS = "\u2026"
_OUTSIDE = "outside target"

# pip's `ARCHIVE_EXTENSIONS` (`pip._internal.utils.filetypes`, verified against
# pip 26.2.1), hard-coded rather than imported -- importing `pip` would put the
# resolver this module fences off back in-process.
#
# THIS IS NOT COSMETIC. `pip._internal.req.constructors._get_url_from_path`
# calls `is_archive_file(name)` -- a pure SUFFIX match against this tuple --
# BEFORE it considers whether the string looks like a path at all:
#     _looks_like_path('evil.tar.gz') -> False
#     is_archive_file('evil.tar.gz')  -> True
#     install_req_from_line('evil.tar.gz') -> link=file://<cwd>/evil.tar.gz
# So a name with no separator, no leading dot and no scheme -- one the grammar
# above happily reads as `name` -- is resolved by pip as a LOCAL SDIST and has
# its PEP 517 build backend invoked. That is the #1646 chain intact, which is
# why a "no `@`, `/`, `:` in the character classes" argument is not sufficient
# on its own and this list exists.
_ARCHIVE_EXTENSIONS = (".whl", ".zip", ".tar", ".tgz", ".tbz", ".txz", ".tlz",
                       ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tar.lzma")


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
    # M5: pip's `auto_decode` strips a UTF-8 BOM. Without this the first
    # requirement of any file a Windows editor saved is dropped `unparseable`.
    for raw in str(text or "").lstrip("\ufeff").splitlines():
        line = raw.rstrip()
        comment = line.lstrip().startswith("#")
        if line.endswith("\\") and not comment:
            buf.append(line.strip("\\"))
            continue
        # M4: pip PREPENDS a space to a comment line before joining, precisely
        # so the comment is still recognisable afterwards. Appending it raw
        # produced `pkg==1.0# comment`, which `_COMMENT` -- which needs `^` or
        # whitespace before the `#` -- cannot strip, so a correctly pinned
        # dependency was lost as `unparseable`.
        buf.append(" " + line if buf and comment else line)
        out.append("".join(buf))
        buf = []
    if buf:
        out.append("".join(buf))
    return out


def _safe_to_publish(line):
    """A dropped line as the manifest may carry it: URL credentials masked, the
    shared secret-pattern pass every other published artifact gets, then a
    length bound.

    Redact BEFORE truncating: cutting first could split a token into a fragment
    no length-anchored pattern matches, which is the same trap
    `run_tools._redact_capture` names for its own byte cap.
    """
    out = redact.redact(_USERINFO.sub(r"\1[REDACTED]@", line))
    if len(out) > _MAX_PUBLISHED_CHARS:
        out = out[:_MAX_PUBLISHED_CHARS] + _ELLIPSIS
    return out


def _read_bounded(path):
    """`(text, truncated)` -- at most `_MAX_READ_BYTES` and `_MAX_READ_LINES`,
    whichever bites first.

    Bytes are read with an explicit size, so a 10 MB single line never reaches
    memory whole; a byte-truncated tail is dropped back to its last line break,
    because a half-line is not a requirement and publishing one as
    `unparseable` would be noise.
    """
    with open(path, "rb") as fh:
        raw = fh.read(_MAX_READ_BYTES + 1)
    truncated = len(raw) > _MAX_READ_BYTES
    if truncated:
        raw = raw[:_MAX_READ_BYTES]
        cut = raw.rfind(b"\n")
        raw = raw[:cut] if cut > 0 else raw
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    if len(lines) > _MAX_READ_LINES:
        return "\n".join(lines[:_MAX_READ_LINES]), True
    return text, truncated


def _capped(rows):
    """`(rows, n_more)` -- the published rows, bounded, and how many were left
    out. The count is disclosed rather than the list silently shortened."""
    return rows[:_MAX_DROPPED_ROWS], max(0, len(rows) - _MAX_DROPPED_ROWS)


def _source_label(used, rejected):
    """The manifest's `source`, naming any manifest REJECTED for confinement.

    Without it a repo whose `requirements.txt` escapes the tree reads exactly
    like a repo that has none, and the operator cannot tell why the pyproject
    branch ran (C2a).
    """
    if not rejected:
        return used
    note = "%s %s" % (", ".join(rejected), _OUTSIDE)
    return "%s (%s)" % (used, note) if used else note


def _classify(text):
    """`(kept, dropped)` with the dropped lines RAW -- the grammar, and nothing
    else. `sanitize_requirements` masks on the way out; the include follower
    resolves `-r`/`-c` off these originals, so path resolution can never depend
    on the redactor's pattern set (M7).
    """
    kept, dropped = [], []

    def drop(line, reason):
        dropped.append({"line": line, "reason": reason})

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
            match = _BARE_REQ.match(head.strip())
            if not match or (sep and not _MARKER_OK.match(marker)):
                drop(line, "unparseable")
            elif _is_archive_name(match.group(1)):
                # A name pip resolves as a local archive, not a release on an
                # index. Its own reason, not `local path`: nothing about the
                # LINE looks like a path, and an operator reading the manifest
                # needs to know which of the two rules caught it.
                drop(line, "archive name")
            else:
                kept.append(line)
    return kept, dropped


def _published(dropped):
    """The dropped rows as the manifest may carry them."""
    return [{"line": _safe_to_publish(row["line"]), "reason": row["reason"]}
            for row in dropped]


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
    kept, dropped = _classify(text)
    return kept, _published(dropped)


def _requirement_candidate(target):
    """`(path, rejected)` -- the requirements manifest to audit, and the
    repo-relative names of any that were REJECTED for confinement.

    Prefer the canonical requirements.txt (#707). The glob fallback returns the
    lexicographically-first match, and '-' (0x2D) sorts before '.' (0x2E), so
    requirements-dev.txt would otherwise win over requirements.txt and the
    PRIMARY manifest would go unaudited.

    C2(a): every candidate must resolve INSIDE the target. `os.path.isfile`
    follows symlinks, so a repo whose `requirements.txt` points at
    `/home/scanner/.aws/credentials` was opened and read -- and since this
    change publishes every non-conforming line, that read became a host-file
    exfiltration channel into `tools-manifest.json` and `report.json`. It is
    also the one read that happens ON THE HOST, outside the container, because
    the disclosure must survive the docker-absent path. An escaping candidate is
    treated as absent and the NEXT one is considered, so a repo with a symlinked
    `requirements.txt` beside a real `requirements-dev.txt` still gets audited.
    """
    exact = os.path.join(target, "requirements.txt")
    candidates = [exact] if os.path.isfile(exact) else []
    candidates += sorted(glob.glob(os.path.join(target, "requirements*.txt")))
    candidates = list(dict.fromkeys(candidates))   # exact first, no duplicate
    rejected = []
    for candidate in candidates:
        if _within(target, candidate):
            return candidate, rejected
        rejected.append(os.path.relpath(candidate, target))
    return None, rejected


def _is_archive_name(name):
    """True when pip would read `name` as a local archive rather than a project
    name -- a suffix match, case-insensitive, exactly as `is_archive_file` does."""
    lowered = name.lower()
    return any(lowered.endswith(ext) for ext in _ARCHIVE_EXTENSIONS)


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
    """The whole sanitization of one requirements file on disk, as a report:
    `{"kept": [lines], "dropped": [{"line", "reason"}], "hashes_stripped": bool}`.

    `-r`/`-c` includes are followed ONE level and sanitized the same way, so the
    ordinary `requirements.txt -> -r requirements-base.txt` layout is still
    audited. An include is dropped rather than followed when it resolves outside
    `root` (`include outside target`), when it would be a second level or revisit
    a file already read (`nested include`), or when it cannot be read
    (`include unreadable`). Included lines come FIRST, in include order, which is
    the order pip would have resolved them in.

    Resolution runs on the RAW classified lines and masking happens once, at the
    end, on what is actually published (M7): keying path resolution off a
    redacted copy would make the redactor's pattern set load-bearing for
    confinement.
    """
    seen, hashes, truncated = set(), False, False

    def read(p):
        nonlocal hashes, truncated
        text, cut = _read_bounded(p)
        hashes = hashes or _hashes_present(text)
        truncated = truncated or cut
        return text

    def walk(p, depth):
        seen.add(os.path.realpath(p))
        try:
            text = read(p)
        except OSError:
            return [], []
        kept, dropped = _classify(text)
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
    rows, more = _capped(_published(dropped))
    return {"kept": kept, "dropped": rows, "hashes_stripped": hashes,
            "truncated": truncated, "dropped_truncated": more}


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
            kept = sanitize_requirements_file(req, target)["kept"]
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
        # #1646 C1(b): an EMPTY working directory, never the target mount. The
        # image ends `WORKDIR /src` and `/src` IS the reviewed repository, so a
        # cwd-relative name pip decides to resolve as a file finds one. The
        # generated file makes that unreachable through the grammar; this makes
        # it unreachable through the filesystem, so a future grammar gap costs a
        # missed audit rather than a build-backend execution. `--requirement` is
        # an absolute path, so nothing else here depends on the working dir.
        scratch = tempfile.mkdtemp(prefix="pip-audit-cwd-")
        try:
            tmp.write("".join(line + "\n" for line in kept))
            tmp.close()
            cmd.extend(["--requirement", tmp.name])
            return run_tool(cmd, timeout=300, cwd=scratch)
        finally:
            os.unlink(tmp.name)
            os.rmdir(scratch)

    def sanitization_report(self, target: str) -> dict | None:
        """What `invoke` will NOT audit, for the coverage manifest (#1646).

        `{"source": <repo-relative path>, "kept": n, "dropped": [{"line",
        "reason"}], "hashes_stripped": bool}`, or None when no manifest this
        adapter reads is present.

        The runner calls this ON THE HOST, in process, exactly as it calls
        `applicable_files` for `excluded_scope` -- so the disclosure is
        available on the docker-absent path too, where no adapter runs at all.
        It is a pure filesystem read and launches nothing, which is what makes
        that safe; the cost of computing the grammar twice is a re-read of one
        small file.

        `source` is repo-relative: the manifest is published, and an absolute
        path would leak the scanner host's directory layout into it.
        """
        req, rejected = _requirement_candidate(target)
        if req:
            report = sanitize_requirements_file(req, target)
            kept_n = len(report["kept"])
            source = os.path.relpath(req, target)
        else:
            deps = _deps_from_pyproject(target)
            if not deps and not rejected:
                return None
            kept, dropped = sanitize_requirements("\n".join(deps or [])[:_MAX_READ_BYTES])
            rows, more = _capped(dropped)
            report = {"dropped": rows, "hashes_stripped": False,
                      "truncated": False, "dropped_truncated": more}
            kept_n = len(kept)
            source = "pyproject.toml" if deps else ""
        return {"source": _source_label(source, rejected), "kept": kept_n,
                "dropped": report["dropped"],
                "hashes_stripped": report["hashes_stripped"],
                "truncated": report["truncated"],
                "dropped_truncated": report["dropped_truncated"]}

    def _find_requirement(self, target: str) -> str | None:
        return _requirement_candidate(target)[0]

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
