"""Classify dependency advisories against the reviewed Cargo project (#3593).

Cargo workspace and local path packages have no ``source`` in Cargo.lock. An
exact scanner package/version match against only those entries turns the claim
from "a third-party dependency is used" into "this project version is affected"
before the advisor queue is built. Ambiguity and unreadable input fail closed
onto the ordinary advisor path.
"""
import os
import re
import tomllib

from scripts import evidence, safe_write
from scripts.tools import ADVISORY_ADAPTERS
from scripts.tools.base import inert_text
from scripts.tools.sarif_utils import SECRET_KIND


# Cargo.lock is controller input to the exact first-party package check, not
# scanner output. An overlarge lock simply keeps the advisor in the loop.
MAX_CARGO_LOCK_BYTES = 8 * 1024 * 1024
_TRIVY_PACKAGE = re.compile(
    r"(?:^|\s)Package:\s*(\S+)\s+Installed Version:\s*(\S+)(?:\s|$)")

PackageOrigins = dict[tuple[str, str], set[str]]
OriginCache = dict[str, PackageOrigins]


def _cargo_lock_path(target_root, finding):
    """Return a confined Cargo.lock path for *finding*, else None."""
    location = finding.get("location")
    rel = location.get("file") if isinstance(location, dict) else None
    if not isinstance(rel, str):
        return None
    # Finding paths use `/`; on POSIX a backslash is a literal filename byte
    # (#2988), while on Windows it is the platform separator.
    rel = rel.replace(os.sep, "/")
    while rel.startswith("./"):
        rel = rel[2:]
    if (not rel or rel.startswith("/") or os.path.basename(rel) != "Cargo.lock"
            or any(part in ("", ".", "..") for part in rel.split("/"))):
        return None
    root = os.path.realpath(target_root)
    candidate = os.path.realpath(os.path.join(root, *rel.split("/")))
    try:
        if os.path.commonpath((root, candidate)) != root:
            return None
    except ValueError:
        return None
    return candidate


def _cargo_package_origins(path, cache):
    """Map Cargo package identities to their lockfile origin classes."""
    if path in cache:
        return cache[path]
    origins: PackageOrigins = {}
    try:
        raw = safe_write.read_regular_bytes(path, MAX_CARGO_LOCK_BYTES)
        document = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        cache[path] = origins
        return origins
    packages = document.get("package") if isinstance(document, dict) else None
    if not isinstance(packages, list):
        cache[path] = origins
        return origins
    for package in packages:
        if not isinstance(package, dict):
            continue
        name, version = package.get("name"), package.get("version")
        if not (isinstance(name, str) and name
                and isinstance(version, str) and version):
            continue
        if "source" not in package:
            origin = evidence.FIRST_PARTY_PACKAGE_ORIGIN
        elif isinstance(package.get("source"), str) and package["source"]:
            origin = "external"
        else:
            origin = "unknown"
        origins.setdefault((name, version), set()).add(origin)
    cache[path] = origins
    return origins


def _advisory_package(finding):
    """Return the advisory's package/version, including Trivy's SARIF prose."""
    tool_evidence = finding.get("tool_evidence")
    tool_evidence = tool_evidence if isinstance(tool_evidence, dict) else {}
    name = tool_evidence.get("package_name")
    version = tool_evidence.get("vulnerable_versions")
    if isinstance(name, str) and name and isinstance(version, str) and version:
        return name, version
    if evidence.tool_name(finding) != "trivy":
        return None
    title = finding.get("title")
    match = _TRIVY_PACKAGE.search(title) if isinstance(title, str) else None
    return (match.group(1), match.group(2)) if match else None


def mark(findings, target_root, cache: OriginCache):
    """Mark and reframe exact sourceless Cargo package/version advisories.

    An ambiguous identity (the same name/version appearing with both local and
    external sources), a malformed lockfile, or a registry package changes
    nothing: those findings still queue for the ordinary tool advisor.
    """
    try:
        target_root = os.fspath(target_root)
    except TypeError:
        return
    if not target_root:
        return
    for finding in findings:
        tool = evidence.tool_name(finding)
        if tool not in ADVISORY_ADAPTERS and tool != "trivy":
            continue
        tool_evidence = finding.get("tool_evidence")
        if not isinstance(tool_evidence, dict) or tool_evidence.get("kind") == SECRET_KIND:
            continue
        lock_path = _cargo_lock_path(target_root, finding)
        package = _advisory_package(finding)
        if lock_path is None or package is None:
            continue
        origins = _cargo_package_origins(lock_path, cache).get(package, set())
        if origins != {evidence.FIRST_PARTY_PACKAGE_ORIGIN}:
            continue
        name, version = package
        marked = dict(tool_evidence)
        marked.update({
            "package_name": name,
            "vulnerable_versions": version,
            "package_origin": evidence.FIRST_PARTY_PACKAGE_ORIGIN,
        })
        finding["tool_evidence"] = marked
        advisory = evidence.tool_rule_id(finding) or "the reported advisory"
        finding["impact"] = inert_text(
            "%s applies to this project's %s %s package."
            % (advisory, name, version), mode="body")
        finding["remediation"] = inert_text(
            "Fix the affected first-party code and release a patched project "
            "version; this is a workspace/path package, not an external dependency.",
            mode="body")
