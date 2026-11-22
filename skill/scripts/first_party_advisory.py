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

Python (#3623): a uv.lock, poetry.lock or pdm.lock records local-path packages
(uv ``editable`` / ``directory`` / ``virtual`` sources, a Poetry ``directory``
source, a PDM ``path``). An exact match under PEP 503 names against only those
entries is first-party when the package's realpath is inside the review root and
its own pyproject.toml proves the same name and static version and is
publishable: a ``Private ::`` classifier, Poetry's ``package-mode = false``,
uv's ``package = false``, PDM's ``distribution = false``, dynamic classifiers
and a uv ``virtual`` source are not, except for the review root itself. A dynamic
version fails closed, and so does another PEP 440-equal spelling of the same
release, local or not. Pipfile.lock
and requirements.txt carry no versioned local identity and stay with the advisor.

Go (#3623, owner ruling G1): nothing is classified. A go.mod declares no version
of its own module, so a main module, a go.work ``use`` module and a local
``replace`` target (whose version is the consumer's require line, not the
module's) have no identity a manifest proves; every Go advisory stays with the
advisor.

Maven and Gradle (#3623, owner rulings J1 and J2): nothing is classified. A
gradle.lockfile lists only resolved external modules, never the build's own
projects, and nothing shows the pinned scanners report a sibling Maven reactor
module; every pom.xml and Gradle advisory stays with the advisor.

Every ecosystem (#3760): the parser is chosen by the lock's file name, so a finding
that declares an ecosystem other than that lock's own is never classified. Nor is
an osv-scanner finding that declares none: osv-scanner always sets it, and only
Trivy and the audit adapters, whose findings carry no ecosystem, are judged by the
lock alone.

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
from scripts.tools.base import INERT_CUT, inert_text
from scripts.tools.sarif_utils import VULNERABILITY_KIND


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
NPM_INSTALLED_VERSION_TOOLS = frozenset({"osv-scanner", "trivy"})
# Python (#3623): the same lock budget as npm. pip-audit audits an environment, not
# the lock, so it never classifies -- like npm-audit.
PYTHON_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock")
MAX_PYTHON_LOCK_BYTES = 16 * 1024 * 1024
# PyPI refuses every `Private ::` classifier (#3686 review), not only Do Not Upload.
PYTHON_PRIVATE_CLASSIFIER_PREFIX = "Private ::"
_PEP503_SEPARATORS = re.compile(r"[-_.]+")
# Every lock the marker reads, and (#3760) the OSV ecosystem each belongs to. A
# finding that declares another one is not that lock's advisory, whatever its file
# says. A lock in the tuple with no row here refuses every declared ecosystem, and a
# test holds the two to the same names.
FIRST_PARTY_LOCKS = ("Cargo.lock",) + NPM_LOCKS + PYTHON_LOCKS
LOCK_ECOSYSTEMS = {"Cargo.lock": "crates.io",
                   **{name: "npm" for name in NPM_LOCKS},
                   **{name: "PyPI" for name in PYTHON_LOCKS}}
# #3696 round 2: the adapters whose findings carry no ecosystem at all. Only theirs
# may omit it; osv-scanner always sets one, so its absence is malformed input.
ADAPTERS_WITHOUT_ECOSYSTEM = frozenset({"trivy", "pip-audit", "npm-audit", "bundler-audit",
                                        "cargo-audit", "dependency-check"})
_TRIVY_PACKAGE = re.compile(
    r"(?:^|\s)Package:\s*(\S+)\s+Installed Version:\s*(\S+)(?:\s|$)")
_DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
_MISSING = object()

PackageOrigins = dict[tuple[str, str], set[str]]
OriginCache = dict[str, PackageOrigins]
ManifestDocument = dict[str, object]
# #3639 review: keyed by (format, realpath) -- a Cargo.toml symlinked to a package.json
# must never be answered from the other parser's cache entry.
ManifestCache = dict[tuple[str, str], ManifestDocument | None]


class IngestCache:
    """Cargo advisory facts and bounded manifest parses for one ingest."""

    def __init__(self) -> None:
        self.package_origins: OriginCache = {}
        self.manifests: ManifestCache = {}
        self.manifest_bytes_remaining = MAX_CARGO_MANIFEST_INGEST_BYTES
        self.manifest_budget_exhausted = False
        self.budget_exhaustion_count = 0
        # #3765: every lock or manifest that changed while it was read, in order. Such a
        # read grants nothing; the count is disclosed per tool at ingest.
        self.unstable_reads: list[str] = []
        # How many times a refused file was consulted, the first read and every cached
        # miss after it: a loop reads this before and after proving one identity to
        # learn whether an unstable file decided it.
        self.unstable_touches = 0
        # Advisories left with the advisor whose lock, or a manifest consulted for
        # their identity, was an unstable read. Not a cause: a registry copy of the
        # same identity keeps it with the advisor too. Disclosed per tool as a delta.
        self.unstable_denials = 0


def _cargo_lock_path(target_root, finding):
    """Return a confined Cargo.lock path for *finding*, else None."""
    return _lock_path(target_root, finding, ("Cargo.lock",))


# #3765, the gate ruling: a location is matched against a lock only when it is a plain
# relative path. A scheme, a percent-escape, a query or a fragment is a URI this code
# does not interpret, and reading it as a directory name reads some other directory.
# A backslash or the cut mark means the path may have been rewritten to be shown
# (`inert_text` spells a control character as backslash-x-NN, and that text names a
# different, real directory; a lone surrogate, U+D800 to U+DFFF, is spelled `U+XXXX`
# with no backslash, `inert.spelled`, and only that range is). All of these stay with
# the advisor.
_NOT_PLAIN = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:|[\x00-\x1f\x7f%?#\\]|"
                        r"U\+D[89A-F][0-9A-F]{2}|"
                        + re.escape(INERT_CUT))


def _lock_path(target_root, finding, names):
    """Return a confined lockfile path named one of *names* for *finding*, else None."""
    location = finding.get("location")
    rel = location.get("file") if isinstance(location, dict) else None
    if not isinstance(rel, str):
        return None
    # Finding paths use `/`; on POSIX a backslash is a literal filename byte
    # (#2988), while on Windows it is the platform separator.
    rel = rel.replace(os.sep, "/")
    if _NOT_PLAIN.search(rel):
        return None
    while rel.startswith("./"):
        rel = rel[2:]
    if (not rel or rel.startswith("/") or os.path.basename(rel) not in names
            or any(part in ("", ".", "..") for part in rel.split("/"))):
        return None
    root = target_root
    candidate = os.path.realpath(os.path.join(root, *rel.split("/")))
    # #3686 review: the format, and the origin cache, follow the realpath's name. A
    # `poetry.lock` symlinked to a `pdm.lock` (or a `Cargo.lock`) would be parsed as a
    # format no scanner read it as, so the resolved name must be the reported one.
    if os.path.basename(candidate) != os.path.basename(rel):
        return None
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
    """Read one file while charging the shared advisory-ingest byte budget.

    Through ``safe_write.read_stable_regular_bytes`` (#3765): a file that changes, or
    is swapped, while it is read is a named refusal (``cache.unstable_reads``), and
    its bytes are never parsed. Every lock and manifest reader comes through here."""
    if cache.manifest_budget_exhausted or cache.manifest_bytes_remaining <= 0:
        cache.manifest_bytes_remaining = 0
        cache.manifest_budget_exhausted = True
        cache.budget_exhaustion_count += 1
        return None

    limit = min(file_limit, cache.manifest_bytes_remaining)
    try:
        raw = safe_write.read_stable_regular_bytes(path, limit)
    except safe_write.UnstableFileError as exc:
        cache.unstable_reads.append(path)
        cache.unstable_touches += 1
        # The bytes were read, so they are charged, like any other read.
        cache.manifest_bytes_remaining -= min(exc.bytes_read, limit)
        if cache.manifest_bytes_remaining == 0:
            cache.manifest_budget_exhausted = True
            cache.budget_exhaustion_count += 1
        return None
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
    key = ("toml", real_path)
    if key in cache.manifests:
        cache.unstable_touches += real_path in cache.unstable_reads
        return cache.manifests[key]
    raw = _read_budgeted_bytes(real_path, MAX_CARGO_MANIFEST_BYTES, cache)
    if raw is None:
        cache.manifests[key] = None
        return None
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        cache.manifests[key] = None
        return None
    cached = document if isinstance(document, dict) else None
    cache.manifests[key] = cached
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
    touched = cache.unstable_touches
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
            # Cargo's manifests are read as one set, so an unstable one could have
            # been the manifest of any identity the set does not prove.
            origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if identity in publishable
                      else _UNSTABLE if cache.unstable_touches > touched else "unknown")
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
    key = ("json", real_path)
    if key in cache.manifests:
        cache.unstable_touches += real_path in cache.unstable_reads
        return cache.manifests[key]
    raw = _read_budgeted_bytes(real_path, file_limit, cache)
    document = None
    if raw is not None:
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, RecursionError):
            document = None
    cached = document if isinstance(document, dict) else None
    cache.manifests[key] = cached
    return cached


_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
# An origin that is unknown because the manifest that would have proved it changed
# while it was read (#3765). Never first-party; kept apart only to be counted.
_UNSTABLE = "unstable"


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
    # _read_json confines the realpath to the review root, cache hits included.
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
                # #3639 review: a link resolves to a RELATIVE in-lock path; a URL or an
                # absolute path is not a local package and fails the whole lock.
                # #3653: a real npm link carries no version or integrity of its own.
                resolved = entry.get("resolved")
                if (not isinstance(resolved, str) or not resolved or os.path.isabs(resolved)
                        or _URL_SCHEME.match(resolved)
                        or "version" in entry or "integrity" in entry):
                    return origins
                linked.add(os.path.normpath(resolved))
                continue
            # #3639 review: a scanner names an install from its key path, so a registry
            # entry whose own name or version cannot be read would hide that copy.
            name = entry.get("name", installed)
            version = entry.get("version")
            if not (isinstance(name, str) and name and isinstance(version, str) and version):
                return origins
            found.setdefault((name, version), set()).add("external")
            continue
        if "name" in entry and not (isinstance(entry["name"], str) and entry["name"]):
            return origins
        local.append((key, entry))
    if len(local) > MAX_CARGO_MANIFESTS:
        return origins
    # #3653: every link must name a real local entry of this lock. A disguised
    # registry `resolved` (leading whitespace, percent-encoded or schemeless URL)
    # or a dangling path is not a key outside node_modules, and fails the lock.
    if not linked <= {os.path.normpath(key) for key, _ in local}:
        return origins
    root_name = document.get("name")
    for key, entry in local:
        name = entry.get("name", root_name if key == "" else None)
        version = entry.get("version")
        if not (isinstance(name, str) and name and isinstance(version, str) and version):
            continue
        identity = (name, version)
        fact = None
        touched = cache.unstable_touches
        if key == "" or os.path.normpath(key) in linked:
            fact = _npm_manifest_fact(os.path.join(lock_dir, key), target_root, cache)
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (identity, True)
                  else _UNSTABLE if cache.unstable_touches > touched else "unknown")
        found.setdefault(identity, set()).add(origin)
    origins.update(found)
    return origins


def _pep503(name):
    """A PEP 503 normalised distribution name."""
    return _PEP503_SEPARATORS.sub("-", name).lower()


# PEP 440 suffixes, each matched flat at one position: no nested quantifier, so no
# input can backtrack (#3686 CI: semgrep regex_dos on the one-pattern form).
_PEP440_PRE_RE = re.compile(r"[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]*)")
_PEP440_POST_RE = re.compile(r"-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]*)")
_PEP440_DEV_RE = re.compile(r"[-_.]?dev[-_.]?([0-9]*)")
_PEP440_PRE = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def _pep440_parts(text):
    """(epoch, release, pre, post, dev, local) for a PEP 440 version, else None."""
    epoch = "0"
    if "!" in text:
        epoch, text = text.split("!", 1)
        if not (epoch.isascii() and epoch.isdigit()):
            return None
    local = None
    if "+" in text:
        text, label = text.split("+", 1)
        segments = re.split(r"[-_.]", label)
        if not all(seg.isascii() and seg.isalnum() for seg in segments):
            return None
        local = tuple(int(seg) if seg.isdigit() else seg for seg in segments)
    end = 0
    while end < len(text) and (text[end].isdigit() or text[end] == ".") and text[end].isascii():
        end += 1
    release_text, rest = text[:end], text[end:]
    if release_text.endswith("."):
        # `1.0.post1`: that dot is the suffix's separator, not part of the release.
        release_text, rest = release_text[:-1], "." + rest
    parts = release_text.split(".")
    if not all(part.isdigit() for part in parts):
        return None
    release = [int(part) for part in parts]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = post = dev = None
    match = _PEP440_PRE_RE.match(rest)
    if match:
        pre = (_PEP440_PRE.get(match[1], match[1]), int(match[2] or 0))
        rest = rest[match.end():]
    match = _PEP440_POST_RE.match(rest)
    if match:
        post = int(match[1] or match[3] or 0)
        rest = rest[match.end():]
    match = _PEP440_DEV_RE.match(rest)
    if match:
        dev = int(match[1] or 0)
        rest = rest[match.end():]
    if rest:
        return None
    return (int(epoch), tuple(release), pre, post, dev, local)


def _pep440_key(version):
    """A comparison key under which PEP 440-equal spellings agree (``1.2.0-rc1`` and
    ``1.2rc1``). Only used to find ambiguity, never to confirm: an unparseable version
    keys as its own lower-cased text, as does one with a number past Python's int()
    digit limit, so it fails closed for that identity alone, not the whole lock."""
    text = version.strip().lower()
    try:
        parts = _pep440_parts(text[1:] if text.startswith("v") else text)
    except ValueError:
        return text
    return text if parts is None else parts


def _pep508_name(name):
    """True for a PEP 508 project name: ASCII letters, digits, ``.``, ``_`` and ``-``,
    starting and ending with a letter or digit."""
    return (bool(name) and name.isascii() and name[0].isalnum() and name[-1].isalnum()
            and all(ch.isalnum() or ch in "._-" for ch in name))


def _local_path(value):
    """A lock's relative local path, else None; a non-string or empty path raises."""
    if not isinstance(value, str) or not value:
        raise ValueError("malformed local path")
    if os.path.isabs(value) or _URL_SCHEME.match(value):
        return None
    return os.path.normpath(value)


def _uv_source(entry):
    """``(kind, path)`` for one uv.lock entry: kind is local, virtual, external or
    unknown. A source naming no single known kind fails the whole lock."""
    source = entry.get("source", _MISSING)
    if source is _MISSING:
        return "unknown", None
    if not isinstance(source, dict):
        raise ValueError("malformed uv source")
    kinds = [key for key in ("registry", "git", "url", "path", "directory", "editable",
                             "virtual") if key in source]
    if len(kinds) != 1:
        raise ValueError("ambiguous uv source")
    kind = kinds[0]
    if kind in ("registry", "git", "url"):
        return "external", None
    if kind == "path":
        # A local wheel or sdist, not a project directory.
        return "unknown", None
    path = _local_path(source[kind])
    if path is None:
        return "unknown", None
    return ("virtual" if kind == "virtual" else "local"), path


def _poetry_source(entry):
    """``(kind, path)`` for one poetry.lock entry; no source is PyPI."""
    source = entry.get("source", _MISSING)
    if source is _MISSING:
        return "external", None
    if not isinstance(source, dict) or not isinstance(source.get("type"), str):
        raise ValueError("malformed Poetry source")
    kind = source["type"]
    if kind in ("git", "url", "legacy"):
        return "external", None
    if kind != "directory":
        return "unknown", None
    path = _local_path(source.get("url"))
    return ("unknown", None) if path is None else ("local", path)


def _pdm_source(entry):
    """``(kind, path)`` for one pdm.lock entry; no path, git or url is the index."""
    kinds = [key for key in ("path", "git", "url") if key in entry]
    if len(kinds) > 1:
        raise ValueError("ambiguous PDM source")
    if not kinds:
        return "external", None
    if kinds[0] != "path":
        return "external", None
    path = _local_path(entry["path"])
    return ("unknown", None) if path is None else ("local", path)


_PYTHON_SOURCES = {"uv.lock": _uv_source, "poetry.lock": _poetry_source,
                   "pdm.lock": _pdm_source}


def _python_manifest_fact(package_dir, target_root, cache: IngestCache, *, virtual=False):
    """``((name, version), publishable)`` from one in-tree pyproject.toml, else None.

    ``[project]`` comes first; Poetry's legacy ``[tool.poetry]`` only without it. A
    dynamic or missing version is None (#3623 ruling: fail closed). A ``Private ::``
    classifier, ``package-mode = false``, ``[tool.uv] package = false``,
    ``[tool.pdm] distribution = false``, ``dynamic = ["classifiers"]`` (a private
    classifier could not be seen) and a uv virtual source are unpublishable, except
    for the review root itself (#3623 ruling, as npm's ``private``). Anything malformed
    is None."""
    real_dir = os.path.realpath(package_dir)
    # _read_toml confines the realpath to the review root, cache hits included.
    document = _read_toml(os.path.join(real_dir, "pyproject.toml"), target_root, cache)
    if document is None:
        return None
    tool = document.get("tool", {})
    if not isinstance(tool, dict):
        return None
    poetry, uv = tool.get("poetry", _MISSING), tool.get("uv", _MISSING)
    pdm = tool.get("pdm", _MISSING)
    project = document.get("project", _MISSING)
    if any(table is not _MISSING and not isinstance(table, dict)
           for table in (poetry, uv, pdm, project)):
        return None
    if project is not _MISSING:
        dynamic = project.get("dynamic", [])
        if (not isinstance(dynamic, list) or not all(isinstance(row, str) for row in dynamic)
                or "version" in dynamic):
            return None
        declared = project
    elif poetry is not _MISSING:
        declared = poetry
    else:
        return None
    name, version = declared.get("name"), declared.get("version")
    if not (isinstance(name, str) and name and isinstance(version, str) and version):
        return None
    # #3686 review round 3: dynamic classifiers are filled in at build time, so a
    # `Private ::` one cannot be seen here; unseen is unpublishable.
    publishable = not virtual and not (
        project is not _MISSING and "classifiers" in project.get("dynamic", []))
    for table in (project, poetry):
        if table is _MISSING:
            continue
        classifiers = table.get("classifiers", [])
        if (not isinstance(classifiers, list)
                or not all(isinstance(row, str) for row in classifiers)):
            return None
        if any(row.strip().startswith(PYTHON_PRIVATE_CLASSIFIER_PREFIX)
               for row in classifiers):
            publishable = False
    for table, key in ((poetry, "package-mode"), (uv, "package"), (pdm, "distribution")):
        flag = table.get(key, True) if table is not _MISSING else True
        if not isinstance(flag, bool):
            return None
        publishable = publishable and flag
    return (_pep503(name), version), publishable or real_dir == target_root


def _python_package_origins(lock_path, target_root, cache: IngestCache):
    """Map Python lock identities (PEP 503 names) to fail-closed origin classes (#3623).

    Every ``[[package]]`` entry is classified by its lock's source record. A local
    entry is first-party only when its in-tree pyproject.toml proves the exact
    identity and is publishable; registry, git and url entries are external, and
    anything else is unknown. A malformed lock, or an entry whose name is not a PEP
    508 name or whose (non-local) version cannot be read, classifies nothing. Two
    spellings of one PEP 440 release under one name, local or not, make a local
    identity ambiguous."""
    if lock_path in cache.package_origins:
        return cache.package_origins[lock_path]
    origins: PackageOrigins = {}
    cache.package_origins[lock_path] = origins
    raw = _read_budgeted_bytes(lock_path, MAX_PYTHON_LOCK_BYTES, cache)
    if raw is None:
        return origins
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        return origins
    packages = document.get("package", [])
    if not isinstance(packages, list) or len(packages) > 64 * MAX_CARGO_MANIFESTS:
        return origins
    classify = _PYTHON_SOURCES[os.path.basename(lock_path)]
    lock_dir = os.path.dirname(lock_path)
    found: PackageOrigins = {}
    # #3686 review: a registry `1.2.0-rc1` is the same release as a local `1.2.0rc1`,
    # and so is a second local `1.2.0.rc1`.
    spellings: dict[tuple[str, object], set[str]] = {}
    local = []
    try:
        for entry in packages:
            if not isinstance(entry, dict):
                return origins
            name, version = entry.get("name"), entry.get("version", _MISSING)
            if not (isinstance(name, str) and _pep508_name(name)):
                return origins
            kind, path = classify(entry)
            if version is _MISSING and kind in ("local", "virtual"):
                # A dynamic local version has no identity to match.
                continue
            if not (isinstance(version, str) and version):
                return origins
            identity = (_pep503(name), version)
            spellings.setdefault((identity[0], _pep440_key(version)), set()).add(version)
            if kind in ("local", "virtual"):
                local.append((identity, kind, path))
            else:
                found.setdefault(identity, set()).add(kind)
    except ValueError:
        return origins
    if len(local) > MAX_CARGO_MANIFESTS:
        return origins
    for identity, kind, path in local:
        touched = cache.unstable_touches
        fact = _python_manifest_fact(os.path.join(lock_dir, path), target_root, cache,
                                     virtual=kind == "virtual")
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (identity, True)
                  else _UNSTABLE if cache.unstable_touches > touched else "unknown")
        found.setdefault(identity, set()).add(origin)
        # Confirmation stays an exact match; another spelling of the same release
        # only makes the identity ambiguous.
        if len(spellings[(identity[0], _pep440_key(identity[1]))]) > 1:
            found[identity].add("unknown")
    origins.update(found)
    return origins


def _ecosystem_agrees(tool, tool_evidence, lock_name):
    """False when the finding's ecosystem is not the lock's own (#3760).

    The parser is chosen by the lock's file name, so a record that says ``Maven`` at a
    ``Cargo.lock`` would otherwise be matched against the crates. A declared ecosystem
    must be exactly the lock's OSV ecosystem; anything else -- another ecosystem,
    another case, a non-string (an explicit ``None`` included), or a lock with no row
    in ``LOCK_ECOSYSTEMS`` -- stays on the advisor path, whichever adapter declared it.

    An ABSENT ecosystem is accepted only from ``ADAPTERS_WITHOUT_ECOSYSTEM``, whose
    findings never carry one, so the lock alone decides for them as before. osv-scanner
    always sets it (and its adapter drops a JSON ``null``), so an osv finding without
    one is malformed and is refused (#3696 round 2)."""
    declared = tool_evidence.get("ecosystem", _MISSING)
    if declared is _MISSING:
        return tool in ADAPTERS_WITHOUT_ECOSYSTEM
    return isinstance(declared, str) and declared == LOCK_ECOSYSTEMS.get(lock_name)


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
    if not isinstance(tool_evidence, dict):
        return
    # #3765: the scanner located this finding outside the scan mount (an absolute path
    # off the mount, an authority, or a SARIF base that is not the mount). Its
    # `location.file` is spelled as it always was, which can be the name of a lock in
    # the tree, so the fact is carried here and decides before any lock is read. Any
    # value refuses: only a scanner adapter writes the key, and only to say this.
    if "uri_base" in tool_evidence:
        return
    # #3765: Trivy's identity is parsed from its message, and a misconfiguration,
    # licence or secret record can carry the same text. Only a record Trivy itself
    # tagged a vulnerability may be matched against a lock. (This replaces the earlier
    # `kind == secret` refusal: Trivy is the only adapter that sets a kind, and a
    # secret record's kind is never `vulnerability`.)
    if tool == "trivy" and tool_evidence.get("kind") != VULNERABILITY_KIND:
        return
    package = _advisory_package(finding)
    if package is None:
        return
    lock_path = _lock_path(target_root, finding, FIRST_PARTY_LOCKS)
    if lock_path is None:
        return
    if not _ecosystem_agrees(tool, tool_evidence, os.path.basename(lock_path)):
        return                         # #3760: decided before the lock is read
    if os.path.basename(lock_path) == "Cargo.lock":
        ecosystem, member = "Cargo", "workspace/path member"
        origins = _cargo_package_origins(lock_path, target_root, cache).get(package, set())
    elif os.path.basename(lock_path) in PYTHON_LOCKS:
        # #3623: as for npm, only the review root's own lock and only scanners that
        # report an installed version (pip-audit audits an environment, not the lock).
        if os.path.dirname(lock_path) != target_root or tool not in NPM_INSTALLED_VERSION_TOOLS:
            return
        ecosystem, member = "Python", "workspace/path package"
        origins = _python_package_origins(lock_path, target_root, cache).get(
            (_pep503(package[0]), package[1]), set())
    else:
        # #3639 review: only the review root's own lock is the reviewed project -- a
        # shrinkwrap npm published inside a tarball (`node_modules/x/`) or a vendored
        # project's lock is somebody else's root. Members are proved through the root
        # lock's links. And only scanners that report an INSTALLED version: npm-audit's
        # `vulnerable_versions` is a range, which may happen to equal one version.
        if os.path.dirname(lock_path) != target_root or tool not in NPM_INSTALLED_VERSION_TOOLS:
            return
        ecosystem, member = "npm", "workspace/local package"
        origins = _npm_package_origins(lock_path, target_root, cache).get(package, set())
    if origins != {evidence.FIRST_PARTY_PACKAGE_ORIGIN}:
        # #3765: count it when an unstable read was involved -- the lock's own, or a
        # manifest consulted for this identity.
        cache.unstable_denials += lock_path in cache.unstable_reads or _UNSTABLE in origins
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
