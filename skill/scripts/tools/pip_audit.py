"""pip-audit adapter for Python dependency CVEs."""
from __future__ import annotations
import contextvars
import errno
import glob
import os
import re
import stat
import sys
import tempfile
import tomllib

import scripts.redact as redact
from .base import (cve_ids, make_finding, normalize_severity, omit_none,
                   parse_json_bytes, run_tool, scratch_cwd, target_root_cv)

_manifest_path_cv: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "pip_audit_manifest_path", default=None)

# The last resort, for a caller that hands over bytes and NO tree (#1649).
# Every real route names one: ingest through `target_root_cv`, the in-process
# one through `invoke`.
DEFAULT_MANIFEST = "requirements.txt"


class PyprojectInputError(Exception):
    """A bounded, target-independent reason pyproject.toml cannot be audited."""

    def __init__(self, reason: str, *, truncated: bool = False):
        super().__init__(reason)
        self.truncated = truncated


def _deps_from_pyproject(target: str) -> list[str] | None:
    """Static PEP 621 read — never invokes a build backend (#218)."""
    path = os.path.join(target, "pyproject.toml")
    try:
        # O_NONBLOCK prevents a target FIFO from hanging the scanner while
        # O_NOFOLLOW makes the descriptor check safe against symlink swaps.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PyprojectInputError("pyproject.toml is a symbolic link") from None
        # Some special files (notably Unix sockets) fail open before fstat can
        # inspect the descriptor. lstat classifies only that failed path; a
        # missing or unreadable regular file keeps its ordinary None result.
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            return None
        if stat.S_ISLNK(mode):
            raise PyprojectInputError("pyproject.toml is a symbolic link") from None
        if not stat.S_ISREG(mode):
            raise PyprojectInputError("pyproject.toml is not a regular file") from None
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PyprojectInputError("pyproject.toml is not a regular file")
        if info.st_size > _MAX_READ_BYTES:
            raise PyprojectInputError(
                "pyproject.toml exceeds the 1 MiB read limit", truncated=True)
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns the descriptor from here.
            raw = fh.read(_MAX_READ_BYTES + 1)
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > _MAX_READ_BYTES:
        raise PyprojectInputError(
            "pyproject.toml exceeds the 1 MiB read limit", truncated=True)
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except RecursionError:
        raise PyprojectInputError(
            "pyproject.toml exceeds the TOML nesting limit") from None
    except (ValueError, OSError):
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
# The marker alphabet, and NOTHING else: identifiers, quotes, the comparison
# operators, parentheses, the `and`/`or`/`in`/`not in` keywords (letters), and
# whitespace. Deliberately narrower than PEP 508's `python_str_c`, which admits
# almost every printable character INSIDE a quoted string -- a marker using one
# of those is dropped `unparseable`, which is coverage loss, not a hole.
_MARKER_CHARS = r"[\sA-Za-z0-9_.()'\"<>=!~,*+-]"
# Charset and non-emptiness are SEPARATE tests (fix round 2, F1). M6 forced
# non-emptiness with `^%s*\S%s*$`, which reads "the marker charset, then
# exactly one character that may be ANYTHING, then the marker charset" -- `\S`
# is any non-whitespace character, not any character from the class above. That
# let `@`, `:`, `#` and NUL back in, one apiece, and every such line raises
# InvalidRequirement in packaging while pip-audit parses every line of the
# generated file: one of them in a target's requirements.txt aborts the entire
# dependency audit. That is verbatim the class M6 exists to close, reopened by
# M6's own fix. The charset invariant below is load-bearing, so it is asserted
# as an invariant, not merely exercised by examples.
_MARKER_OK = re.compile(r"^%s*$" % _MARKER_CHARS)
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


def _bounded(data):
    """`(text, truncated)` -- at most `_MAX_READ_BYTES` and `_MAX_READ_LINES`,
    whichever bites first. Accepts bytes (a file read) or str (the PEP 621
    dependency list joined).

    ONE helper for BOTH branches, deliberately (fix round 2, F2). Round 1 bound
    only the requirements branch: `invoke`'s pyproject arm had no bound at all
    and `sanitization_report`'s had a different one -- a character slice with no
    newline rollback -- plus a hard-coded `truncated: False`. On 120,000
    dependencies `invoke` wrote all 120,000 into the generated file while the
    manifest claimed `kept: 65536, truncated: false`: the guarantee that the
    read is capped before anything is parsed did not hold, `kept` measured
    nothing, and a published field asserted the opposite of what had happened.
    Two call sites with two bounds is how that happens; one helper is the fix.

    A byte-truncated tail is dropped back to its last line break, because a
    half-line is not a requirement and publishing one as `unparseable` would be
    noise -- and a character slice could cut a dependency mid-string and
    manufacture exactly that row.
    """
    raw = data if isinstance(data, bytes) else str(data or "").encode("utf-8", "replace")
    truncated = len(raw) > _MAX_READ_BYTES
    if truncated:
        # Keep only COMPLETE lines (F9). `rpartition` is the whole rule: it
        # yields "" when the last newline is at byte 0 and when there is no
        # newline at all, which the previous `cut > 0` guard did not -- it kept
        # the entire 1 MiB partial tail in both cases, and that tail was then
        # classified and published as a truncated `unparseable` row, exactly
        # the noise the rollback exists to prevent.
        raw, _sep, _tail = raw[:_MAX_READ_BYTES].rpartition(b"\n")
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    if len(lines) > _MAX_READ_LINES:
        return "\n".join(lines[:_MAX_READ_LINES]), True
    return text, truncated


def _read_bounded(path):
    """`_bounded` over a file, reading with an explicit size so a 10 MB single
    line never reaches memory whole."""
    with open(path, "rb") as fh:
        return _bounded(fh.read(_MAX_READ_BYTES + 1))


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
            if not match or (sep and (not marker.strip()
                                      or not _MARKER_OK.match(marker))):
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
    candidates = [exact] + sorted(glob.glob(os.path.join(target, "requirements*.txt")))
    # `lexists`, not `isfile`: a DANGLING symlink is a path entry that exists
    # and has to be judged, and `isfile` is false for one (F8). Filtering on
    # `isfile` here ran the F5 check ahead of confinement, so
    # `requirements.txt -> /nonexistent/outside/creds` reported as "no
    # manifest" -- the exact reading C2(a) exists to make impossible.
    candidates = [c for c in dict.fromkeys(candidates) if os.path.lexists(c)]
    rejected = []
    for candidate in candidates:
        if not _within(target, candidate):
            rejected.append(os.path.relpath(candidate, target))
        elif os.path.isfile(candidate):
            return candidate, rejected
        # Confined but not a regular file -- a DIRECTORY named
        # `requirements-x.txt` (F5), or an in-tree symlink whose target is
        # gone. Not a candidate, and not an escape either, so nothing to
        # disclose: it is simply not a manifest.
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
            try:
                deps = _deps_from_pyproject(target)
            except PyprojectInputError as exc:
                print("pip-audit: %s" % exc, file=sys.stderr)
                return b"", 2
            if not deps:
                print("pip-audit: no static [project.dependencies] in %s; "
                      "skipping (osv-scanner covers this target)" % target,
                      file=sys.stderr)
                return b'{"dependencies": [], "fixes": []}', 0
            _manifest_path_cv.set(os.path.join(target, "pyproject.toml"))
            # The PEP 621 read is static, but `[project.dependencies]` may
            # itself hold `name @ git+https://...` -- the same build-backend
            # door through a second file. Both branches write a GENERATED file
            # and the same grammar is what makes it safe -- and the same bound,
            # so what is written here is what `sanitization_report` counts (F2).
            text, _truncated = _bounded("\n".join(deps))
            kept, _dropped = sanitize_requirements(text)
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        # #1646 C1(b): an EMPTY working directory, never the target mount. The
        # image ends `WORKDIR /src` and `/src` IS the reviewed repository, so a
        # cwd-relative name pip decides to resolve as a file finds one. The
        # generated file makes that unreachable through the grammar; this makes
        # it unreachable through the filesystem, so a future grammar gap costs a
        # missed audit rather than a build-backend execution. `--requirement` is
        # an absolute path, so nothing else here depends on the working dir.
        # (#1877 moved the scratch itself into `base.scratch_cwd`, F3's
        # rmtree-not-rmdir reasoning with it -- it is the helper's reason now,
        # for all eleven adapters rather than this one.)
        try:
            with scratch_cwd("pip-audit-cwd-") as scratch:
                tmp.write("".join(line + "\n" for line in kept))
                tmp.close()
                cmd.extend(["--requirement", tmp.name])
                return run_tool(cmd, timeout=300, cwd=scratch)
        finally:
            os.unlink(tmp.name)

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
            try:
                deps = _deps_from_pyproject(target)
            except PyprojectInputError as exc:
                return {"source": _source_label("pyproject.toml", rejected),
                        "kept": 0,
                        "dropped": [{"line": "pyproject.toml", "reason": str(exc)}],
                        "hashes_stripped": False, "truncated": exc.truncated,
                        "dropped_truncated": 0}
            if not deps and not rejected:
                return None
            text, truncated = _bounded("\n".join(deps or []))
            kept, dropped = sanitize_requirements(text)
            rows, more = _capped(dropped)
            report = {"dropped": rows, "hashes_stripped": False,
                      "truncated": truncated, "dropped_truncated": more}
            kept_n = len(kept)
            source = "pyproject.toml" if deps else ""
        return {"source": _source_label(source, rejected), "kept": kept_n,
                "dropped": report["dropped"],
                "hashes_stripped": report["hashes_stripped"],
                "truncated": report["truncated"],
                "dropped_truncated": report["dropped_truncated"]}

    def _find_requirement(self, target: str) -> str | None:
        return _requirement_candidate(target)[0]

    def _located_at(self) -> str:
        """The manifest this parse's findings are located at.

        Two routes, because a real scan runs `invoke` and `parse` in DIFFERENT
        PROCESSES (#1649): run_tools dispatches the adapter as
        `docker run ... _run_adapter.py`, which only invokes, and `ingest_tools`
        parses the captured bytes back on the host. `invoke`'s own choice is
        used when the two share a process; otherwise the same choice is made
        again from the target root ingest names around its parse -- and
        repo-RELATIVE there, which is the shape `location.file` carries
        everywhere downstream (the fixture prune and every exclude glob match
        against it).
        """
        chosen = _manifest_path_cv.get()
        if chosen:
            return chosen
        root = target_root_cv.get()
        if not root:
            return DEFAULT_MANIFEST
        req = self._find_requirement(root)
        if req:
            return os.path.relpath(req, root)
        # `invoke`'s other branch: no requirements file, audit the PEP 621 deps.
        if os.path.isfile(os.path.join(root, "pyproject.toml")):
            return "pyproject.toml"
        return DEFAULT_MANIFEST

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        # Resolved ONCE per parse, not per finding: it stats the target root.
        manifest = self._located_at()
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
                    location={"file": manifest, "line_start": 1},
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
