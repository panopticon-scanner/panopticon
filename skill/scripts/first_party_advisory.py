"""Classify dependency advisories against the reviewed project's own packages.

Cargo (#3593): workspace and local path packages have no ``source`` in
Cargo.lock. An exact scanner package/version match against only those entries is
first-party only when one confined, bounded Cargo.toml read also proves an
in-tree, publishable package with that identity.

npm (#3623): a package-lock.json / npm-shrinkwrap.json (lockfile v2+) lists the
root project and every workspace / ``file:`` package at a key outside
``node_modules``. An exact match against only those entries is first-party when
the package is the root or one npm linked, its realpath is inside the review
root, and its own package.json proves the same name and version and is
publishable: ``private: true`` is npm's ``publish = false``, except for the
review root itself.

The claim then changes from "a third-party dependency is used" to "this project
version is affected" before the advisor queue is built. Ambiguity and unreadable
input fail closed onto the ordinary advisor path.
"""
import fnmatch
import json
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
MAX_CARGO_MANIFEST_BYTES = 1024 * 1024
MAX_CARGO_MANIFEST_INGEST_BYTES = 48 * 1024 * 1024
MAX_CARGO_MANIFESTS = 1024
# npm (#3623): a lockfile is controller input like Cargo.lock, larger in practice;
# every read still spends the one shared ingest budget above.
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
MAX_NPM_LOCK_BYTES = 16 * 1024 * 1024
MAX_NPM_MANIFEST_BYTES = 1024 * 1024
NPM_PUBLIC_REGISTRY = "https://registry.npmjs.org"
_TRIVY_PACKAGE = re.compile(
    r"(?:^|\s)Package:\s*(\S+)\s+Installed Version:\s*(\S+)(?:\s|$)")
_DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
_MISSING = object()

PackageOrigins = dict[tuple[str, str], set[str]]
OriginCache = dict[str, PackageOrigins]
ManifestDocument = dict[str, object]
ManifestCache = dict[str, ManifestDocument | None]


class IngestCache:
    """Cargo advisory facts and bounded manifest parses for one ingest."""

    def __init__(self) -> None:
        self.package_origins: OriginCache = {}
        self.manifests: ManifestCache = {}
        self.manifest_bytes_remaining = MAX_CARGO_MANIFEST_INGEST_BYTES
        self.manifest_budget_exhausted = False
        self.budget_exhaustion_count = 0


def _cargo_lock_path(target_root, finding):
    """Return a confined Cargo.lock path for *finding*, else None."""
    return _lock_path(target_root, finding, ("Cargo.lock",))


def _lock_path(target_root, finding, names):
    """Return a confined lockfile path named one of *names* for *finding*, else None."""
    location = finding.get("location")
    rel = location.get("file") if isinstance(location, dict) else None
    if not isinstance(rel, str):
        return None
    # Finding paths use `/`; on POSIX a backslash is a literal filename byte
    # (#2988), while on Windows it is the platform separator.
    rel = rel.replace(os.sep, "/")
    while rel.startswith("./"):
        rel = rel[2:]
    if (not rel or rel.startswith("/") or os.path.basename(rel) not in names
            or any(part in ("", ".", "..") for part in rel.split("/"))):
        return None
    root = target_root
    candidate = os.path.realpath(os.path.join(root, *rel.split("/")))
    try:
        if os.path.commonpath((root, candidate)) != root:
            return None
    except ValueError:
        return None
    return candidate


def _inside(root, path):
    try:
        return os.path.commonpath((root, path)) == root
    except ValueError:
        return False


def _manifest_path(target_root, base, package_dir):
    """A Cargo.toml below *target_root*, resolved from one manifest path."""
    if not isinstance(package_dir, str) or not package_dir or os.path.isabs(package_dir):
        return None
    root = target_root
    candidate = os.path.realpath(os.path.join(base, package_dir, "Cargo.toml"))
    return candidate if _inside(root, candidate) else None


def _read_budgeted_bytes(path, file_limit, cache: IngestCache):
    """Read one file while charging the shared advisory-ingest byte budget."""
    if cache.manifest_budget_exhausted or cache.manifest_bytes_remaining <= 0:
        cache.manifest_bytes_remaining = 0
        cache.manifest_budget_exhausted = True
        cache.budget_exhaustion_count += 1
        return None

    limit = min(file_limit, cache.manifest_bytes_remaining)
    try:
        raw = safe_write.read_regular_bytes(path, limit)
    except safe_write.ReadLimitExceeded:
        cache.manifest_bytes_remaining -= limit
        if cache.manifest_bytes_remaining == 0:
            cache.manifest_budget_exhausted = True
            cache.budget_exhaustion_count += 1
        return None
    except OSError:
        return None

    cache.manifest_bytes_remaining -= len(raw)
    if cache.manifest_bytes_remaining == 0:
        cache.manifest_budget_exhausted = True
    return raw


def _read_toml(path, target_root, cache: IngestCache):
    """Return one confined, cached TOML document within the ingest budget."""
    root = target_root
    real_path = os.path.realpath(path)
    if not _inside(root, real_path):
        return None
    if real_path in cache.manifests:
        return cache.manifests[real_path]
    raw = _read_budgeted_bytes(real_path, MAX_CARGO_MANIFEST_BYTES, cache)
    if raw is None:
        cache.manifests[real_path] = None
        return None
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        cache.manifests[real_path] = None
        return None
    cached = document if isinstance(document, dict) else None
    cache.manifests[real_path] = cached
    return cached


def _expand_member_pattern(workspace_dir, pattern, target_root):
    """Expand one bounded Cargo workspace-member pattern without following dir links."""
    if not isinstance(pattern, str) or not pattern or os.path.isabs(pattern):
        raise ValueError("invalid Cargo workspace member")
    native = pattern.replace("/", os.sep)
    if os.altsep:
        native = native.replace(os.altsep, os.sep)
    parts = native.split(os.sep)
    if any(part in ("", "..") or part == "**" for part in parts):
        raise ValueError("unbounded Cargo workspace member")

    candidates = [workspace_dir]
    for part in parts:
        if part == ".":
            continue
        if any(char in part for char in "*?["):
            expanded = []
            for directory in candidates:
                real_dir = os.path.realpath(directory)
                if not _inside(target_root, real_dir):
                    raise ValueError("Cargo workspace member escapes target")
                try:
                    entries = sorted(os.scandir(real_dir), key=lambda entry: entry.name)
                except OSError as exc:
                    raise ValueError("unreadable Cargo workspace member parent") from exc
                for entry in entries:
                    if (fnmatch.fnmatchcase(entry.name, part)
                            and entry.is_dir(follow_symlinks=False)):
                        expanded.append(entry.path)
                        if len(expanded) > MAX_CARGO_MANIFESTS:
                            raise ValueError("too many Cargo workspace members")
            candidates = expanded
        else:
            candidates = [os.path.join(directory, part) for directory in candidates]
        if len(candidates) > MAX_CARGO_MANIFESTS:
            raise ValueError("too many Cargo workspace members")

    manifests = []
    for directory in candidates:
        manifest = _manifest_path(target_root, directory, ".")
        if manifest is None:
            raise ValueError("Cargo workspace member escapes target")
        manifests.append(manifest)
    return manifests


def _workspace_members(document, manifest_path, target_root):
    workspace = document.get("workspace")
    if workspace is None:
        return [], None
    if not isinstance(workspace, dict):
        raise ValueError("malformed Cargo workspace")
    members = workspace.get("members", [])
    excludes = workspace.get("exclude", [])
    if (not isinstance(members, list) or not all(isinstance(row, str) for row in members)
            or not isinstance(excludes, list)
            or not all(isinstance(row, str) for row in excludes)):
        raise ValueError("malformed Cargo workspace members")
    workspace_package = workspace.get("package", {})
    if not isinstance(workspace_package, dict):
        raise ValueError("malformed Cargo workspace package defaults")

    base = os.path.dirname(manifest_path)
    included = {
        path for pattern in members
        for path in _expand_member_pattern(base, pattern, target_root)
    }
    excluded = {
        path for pattern in excludes
        for path in _expand_member_pattern(base, pattern, target_root)
    }
    return sorted(included - excluded), workspace_package


def _dependency_paths(document):
    """Yield local dependency directories declared by one Cargo manifest."""
    paths = []

    def collect(table):
        if table is None:
            return
        if not isinstance(table, dict):
            raise ValueError("malformed Cargo dependency table")
        for spec in table.values():
            if isinstance(spec, str):
                continue
            if not isinstance(spec, dict):
                raise ValueError("malformed Cargo dependency")
            if "path" not in spec:
                continue
            path = spec.get("path")
            if not isinstance(path, str) or not path:
                raise ValueError("malformed Cargo path dependency")
            paths.append(path)

    for key in _DEPENDENCY_TABLES:
        collect(document.get(key))

    workspace = document.get("workspace")
    if isinstance(workspace, dict):
        collect(workspace.get("dependencies"))

    targets = document.get("target")
    if targets is not None:
        if not isinstance(targets, dict):
            raise ValueError("malformed Cargo target table")
        for target in targets.values():
            if not isinstance(target, dict):
                raise ValueError("malformed Cargo target dependencies")
            for key in _DEPENDENCY_TABLES:
                collect(target.get(key))

    patches = document.get("patch")
    if patches is not None:
        if not isinstance(patches, dict):
            raise ValueError("malformed Cargo patch table")
        for table in patches.values():
            collect(table)
    collect(document.get("replace"))
    return paths


def _inherited_value(package, workspace_package, key):
    value = package.get(key, _MISSING)
    if isinstance(value, dict) and value.get("workspace") is True:
        return workspace_package.get(key, _MISSING)
    return value


def _manifest_package(package, workspace_package):
    """Return ``((name, version), publishable)`` or None for invalid metadata."""
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    version = _inherited_value(package, workspace_package, "version")
    if not (isinstance(name, str) and name
            and isinstance(version, str) and version):
        return None
    publish = _inherited_value(package, workspace_package, "publish")
    if publish is _MISSING:
        publishable = True
    elif publish is False:
        publishable = False
    elif publish is True:
        publishable = True
    elif isinstance(publish, list) \
            and all(isinstance(registry, str) and registry for registry in publish):
        publishable = "crates-io" in publish
    else:
        return None
    return (name, version), publishable


def _publishable_manifest_identities(lock_path, target_root, cache: IngestCache):
    """Exact identities proved by one in-tree publishable Cargo.toml."""
    root_manifest = _manifest_path(target_root, os.path.dirname(lock_path), ".")
    if root_manifest is None:
        return set()
    queue: list[tuple[str, dict[str, object]]] = [(root_manifest, {})]
    seen: dict[str, dict[str, object]] = {}
    matches: dict[tuple[str, str], list[bool]] = {}

    while queue:
        if len(seen) >= MAX_CARGO_MANIFESTS:
            return set()
        manifest_path, inherited = queue.pop(0)
        prior = seen.get(manifest_path)
        if prior is not None:
            if prior != inherited:
                return set()
            continue
        document = _read_toml(manifest_path, target_root, cache)
        if document is None:
            return set()
        seen[manifest_path] = inherited

        try:
            members, local_workspace = _workspace_members(
                document, manifest_path, target_root)
            workspace_package = (local_workspace if local_workspace is not None
                                 else inherited)
            package = document.get("package", _MISSING)
            if package is not _MISSING:
                package_fact = _manifest_package(package, workspace_package)
                if package_fact is None:
                    return set()
                identity, publishable = package_fact
                matches.setdefault(identity, []).append(publishable)

            for member in members:
                queue.append((member, workspace_package))
            for package_dir in _dependency_paths(document):
                dependency = _manifest_path(
                    target_root, os.path.dirname(manifest_path), package_dir)
                if dependency is None:
                    return set()
                queue.append((dependency, workspace_package))
        except (OSError, ValueError, RecursionError):
            return set()
        if len(queue) + len(seen) > MAX_CARGO_MANIFESTS:
            return set()

    return {
        identity for identity, declarations in matches.items()
        if declarations == [True]
    }


def _cargo_package_origins(path, target_root, cache: IngestCache):
    """Map Cargo package identities to fail-closed lock/manifest origin classes."""
    if path in cache.package_origins:
        return cache.package_origins[path]
    origins: PackageOrigins = {}
    raw = _read_budgeted_bytes(path, MAX_CARGO_LOCK_BYTES, cache)
    if raw is None:
        cache.package_origins[path] = origins
        return origins
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        cache.package_origins[path] = origins
        return origins
    packages = document.get("package") if isinstance(document, dict) else None
    if not isinstance(packages, list):
        cache.package_origins[path] = origins
        return origins
    publishable = _publishable_manifest_identities(path, target_root, cache)
    for package in packages:
        if not isinstance(package, dict):
            continue
        name, version = package.get("name"), package.get("version")
        if not (isinstance(name, str) and name
                and isinstance(version, str) and version):
            continue
        identity = (name, version)
        if "source" not in package:
            origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN
                      if identity in publishable else "unknown")
        elif isinstance(package.get("source"), str) and package["source"]:
            origin = "external"
        else:
            origin = "unknown"
        origins.setdefault(identity, set()).add(origin)
    cache.package_origins[path] = origins
    return origins


def _unique_object(pairs):
    """A JSON object hook that refuses duplicate keys: a repeated `packages` key could
    hide a registry entry behind a local one (json keeps only the last)."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key %r" % key)
        out[key] = value
    return out


def _read_json(path, file_limit, target_root, cache: IngestCache):
    """One confined, cached, budgeted JSON object, else None."""
    real_path = os.path.realpath(path)
    if not _inside(target_root, real_path):
        return None
    if real_path in cache.manifests:
        return cache.manifests[real_path]
    raw = _read_budgeted_bytes(real_path, file_limit, cache)
    document = None
    if raw is not None:
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, RecursionError):
            document = None
    cached = document if isinstance(document, dict) else None
    cache.manifests[real_path] = cached
    return cached


def _npm_node_modules_name(key):
    """The package name a `node_modules/...` lock key installs, else None."""
    parts = key.split("/")
    if "node_modules" not in parts:
        return None
    rest = parts[len(parts) - 1 - parts[::-1].index("node_modules") + 1:]
    if len(rest) == 1 and rest[0] and not rest[0].startswith("@"):
        return rest[0]
    if len(rest) == 2 and rest[0].startswith("@") and len(rest[0]) > 1 and rest[1]:
        return "/".join(rest)
    return None


def _npm_manifest_fact(package_dir, target_root, cache: IngestCache):
    """``((name, version), publishable)`` from one in-tree package.json, else None.

    ``private: true`` is npm's ``publish = false``: never first-party, except for
    the review root itself (#3623 ruling). A ``publishConfig.registry`` other than
    the public registry is private-only, like a Cargo publish list without
    crates-io. Anything malformed is None."""
    real_dir = os.path.realpath(package_dir)
    if not _inside(target_root, real_dir):
        return None
    document = _read_json(os.path.join(real_dir, "package.json"), MAX_NPM_MANIFEST_BYTES,
                          target_root, cache)
    if document is None:
        return None
    name, version = document.get("name"), document.get("version")
    if not (isinstance(name, str) and name and isinstance(version, str) and version):
        return None
    private = document.get("private", False)
    if not isinstance(private, bool):
        return None
    publishable = not private or real_dir == target_root
    config = document.get("publishConfig", _MISSING)
    if config is not _MISSING:
        if not isinstance(config, dict):
            return None
        registry = config.get("registry", _MISSING)
        if registry is not _MISSING:
            if not isinstance(registry, str):
                return None
            publishable = publishable and registry.rstrip("/") == NPM_PUBLIC_REGISTRY
    return (name, version), publishable


def _npm_package_origins(lock_path, target_root, cache: IngestCache):
    """Map npm lock identities to fail-closed origin classes (#3623).

    A key outside ``node_modules`` is a local package: the root (``""``), a
    workspace member or a ``file:`` target. It is first-party only when it is the
    root or the target of a ``link: true`` entry, and its in-tree package.json
    proves the same identity and is publishable. Every ``node_modules`` package
    that is not a link is external. A malformed lock classifies nothing."""
    if lock_path in cache.package_origins:
        return cache.package_origins[lock_path]
    origins: PackageOrigins = {}
    cache.package_origins[lock_path] = origins
    document = _read_json(lock_path, MAX_NPM_LOCK_BYTES, target_root, cache)
    packages = document.get("packages") if document is not None else None
    if not isinstance(packages, dict) or len(packages) > 64 * MAX_CARGO_MANIFESTS:
        return origins
    lock_dir = os.path.dirname(lock_path)
    linked, local = set(), []
    found: PackageOrigins = {}
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            return origins
        installed = _npm_node_modules_name(key)
        if installed is None and "node_modules" in key.split("/"):
            return origins
        if installed is not None:
            if entry.get("link") is True:
                resolved = entry.get("resolved")
                if not isinstance(resolved, str):
                    return origins
                linked.add(os.path.normpath(resolved))
                continue
            name = entry.get("name", installed)
            version = entry.get("version")
            if isinstance(name, str) and name and isinstance(version, str) and version:
                found.setdefault((name, version), set()).add("external")
            continue
        local.append((key, entry))
    if len(local) > MAX_CARGO_MANIFESTS:
        return origins
    root_name = document.get("name")
    for key, entry in local:
        name = entry.get("name", root_name if key == "" else None)
        version = entry.get("version")
        if not (isinstance(name, str) and name and isinstance(version, str) and version):
            continue
        identity = (name, version)
        fact = None
        if key == "" or os.path.normpath(key) in linked:
            fact = _npm_manifest_fact(os.path.join(lock_dir, key), target_root, cache)
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (identity, True)
                  else "unknown")
        found.setdefault(identity, set()).add(origin)
    origins.update(found)
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


def mark(findings, target_root, cache: IngestCache):
    """Mark and reframe exact in-tree publishable Cargo package advisories.

    An ambiguous identity, a malformed lock/manifest, an unpublishable or
    outside-tree package, and a registry package all change nothing: those
    findings still queue for the ordinary tool advisor. Classification is
    isolated per finding because this runs outside ingest's adapter try block;
    no one malformed finding may abort the rest of tool ingest.
    """
    try:
        target_root = os.fspath(target_root)
    except TypeError:
        return
    if not target_root:
        return
    target_root = os.path.realpath(target_root)
    for finding in findings:
        try:
            _mark_finding(finding, target_root, cache)
        except Exception:  # noqa: BLE001 - trust-boundary classification fails closed
            continue


def _mark_finding(finding, target_root, cache):
    """Classify one finding; the public loop owns fail-closed isolation."""
    tool = evidence.tool_name(finding)
    if tool not in ADVISORY_ADAPTERS and tool != "trivy":
        return
    tool_evidence = finding.get("tool_evidence")
    if not isinstance(tool_evidence, dict) or tool_evidence.get("kind") == SECRET_KIND:
        return
    package = _advisory_package(finding)
    if package is None:
        return
    lock_path = _lock_path(target_root, finding, ("Cargo.lock",) + NPM_LOCKS)
    if lock_path is None:
        return
    if os.path.basename(lock_path) == "Cargo.lock":
        ecosystem, member = "Cargo", "workspace/path member"
        origins = _cargo_package_origins(lock_path, target_root, cache).get(package, set())
    else:
        ecosystem, member = "npm", "workspace/local package"
        origins = _npm_package_origins(lock_path, target_root, cache).get(package, set())
    if origins != {evidence.FIRST_PARTY_PACKAGE_ORIGIN}:
        return
    name, version = package
    marked = dict(tool_evidence)
    marked["package_origin"] = evidence.FIRST_PARTY_PACKAGE_ORIGIN
    if tool == "trivy":
        # Trivy's generic SARIF adapter never owned package_name. Adding it
        # here would change finding_fingerprint/reconcile identity only on
        # classified runs, so keep the parsed pair in non-identity evidence.
        marked["advisory_package"] = {"name": name, "version": version}
    finding["tool_evidence"] = marked
    advisory = evidence.tool_rule_id(finding) or "the reported advisory"
    finding["impact"] = inert_text(
        "%s applies to this project's in-tree publishable %s %s %s package."
        % (advisory, name, version, ecosystem), mode="body")
    finding["remediation"] = inert_text(
        "Fix the affected first-party code and release a patched project "
        "version; the matched publishable %s is not an external dependency." % member,
        mode="body")
