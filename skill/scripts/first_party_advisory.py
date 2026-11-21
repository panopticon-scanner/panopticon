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

Ruby (#3623, owner rulings R1 and R2): a Gemfile.lock lists every gem a ``PATH``
source provides. An exact match against only those entries is first-party when the
source's realpath is inside the review root and its one ``*.gemspec`` proves the
same name and version with plain string literals (``x.name = "lit"``,
``x.version = "lit"``; ``Foo::VERSION`` and every other form fail closed), and the
gem is publishable: a literal ``allowed_push_host`` other than rubygems.org is
private-only, except for the review root itself.

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
NPM_INSTALLED_VERSION_TOOLS = frozenset({"osv-scanner", "trivy"})
# Python (#3623): the same lock budget as npm. pip-audit audits an environment, not
# the lock, so it never classifies -- like npm-audit.
PYTHON_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock")
MAX_PYTHON_LOCK_BYTES = 16 * 1024 * 1024
# PyPI refuses every `Private ::` classifier (#3686 review), not only Do Not Upload.
PYTHON_PRIVATE_CLASSIFIER_PREFIX = "Private ::"
_PEP503_SEPARATORS = re.compile(r"[-_.]+")
# Ruby (#3623): the root's own Gemfile.lock, read under the shared budget. bundler-audit
# and gems.locked stay out (owner ruling R2).
RUBY_LOCKS = ("Gemfile.lock",)
MAX_RUBY_LOCK_BYTES = 16 * 1024 * 1024
MAX_GEMSPEC_BYTES = 1024 * 1024
RUBYGEMS_HOST = "https://rubygems.org"
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
    key = ("toml", real_path)
    if key in cache.manifests:
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
    key = ("json", real_path)
    if key in cache.manifests:
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
        if key == "" or os.path.normpath(key) in linked:
            fact = _npm_manifest_fact(os.path.join(lock_dir, key), target_root, cache)
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (identity, True)
                  else "unknown")
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
        fact = _python_manifest_fact(os.path.join(lock_dir, path), target_root, cache,
                                     virtual=kind == "virtual")
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (identity, True)
                  else "unknown")
        found.setdefault(identity, set()).add(origin)
        # Confirmation stays an exact match; another spelling of the same release
        # only makes the identity ambiguous.
        if len(spellings[(identity[0], _pep440_key(identity[1]))]) > 1:
            found[identity].add("unknown")
    origins.update(found)
    return origins


_GEM_SECTIONS = {"PATH": "local", "GEM": "external", "GIT": "external",
                 "PLUGIN SOURCE": "external"}
# Headers Bundler writes whose contents never name a source (#3692 review H2).
_GEM_SKIPPED = frozenset(("PLATFORMS", "DEPENDENCIES", "CHECKSUMS", "RUBY VERSION",
                          "BUNDLED WITH"))
_GEM_SPEC = re.compile(r"    ([^ ()]+) \(([^ ()]+)\)\Z")
_GEM_DEPENDENCY = re.compile(r"      [^ ()!]+(?: \([^()]+\))?\Z")
_GEM_OPTION = re.compile(r"  ([a-z_]+): (.+)\Z")
_GEM_SPECS_MARKER = "  specs:"


class _GemSection:
    """One Gemfile.lock source section."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.remote: str | None = None
        self.options: set[str] = set()
        self.specs: list[tuple[str, str]] = []


def _odd_whitespace(text):
    """True when the text holds whitespace other than a plain space or a newline, or a
    byte-order mark: Ruby and Python disagree on where such a line starts or ends."""
    return "\ufeff" in text or any(ch.isspace() and ch not in " \n" for ch in text)


def _ascii_alnum(text):
    return bool(text) and text.isascii() and text.isalnum()


def _gem_release(version):
    """``(release, platform)``: Bundler splits a spec's version at its first ``-``, so
    ``1.0-x86_64-linux`` is release 1.0 on that platform (#3692 review H1)."""
    release, _, platform = version.partition("-")
    return release, platform


def _gem_version_ok(version):
    """True for a spec version RubyGems accepts: ``[0-9]+(\\.[0-9a-zA-Z]+)*``, then an
    optional ``-platform`` of letters, digits, ``_``, ``.`` and ``-``."""
    release, dash, platform = version.partition("-")
    segments = release.split(".")
    if not (segments[0].isascii() and segments[0].isdigit()
            and all(_ascii_alnum(segment) for segment in segments)):
        return False
    return not dash or (bool(platform) and platform.isascii()
                        and all(ch.isalnum() or ch in "_.-" for ch in platform))


def _gem_canonical(release):
    """RubyGems' own equality key (``Gem::Version#canonical_segments``): the release
    split into digit and letter runs, with trailing zeros dropped from the numeric
    head and again from the rest, so 1.2, 1.2.0 and 1.2.0.0 are one version (#3692
    review item 3)."""
    runs: list[int | str] = [int(run) if run.isdigit() else run
                             for run in re.findall(r"[0-9]+|[A-Za-z]+", release)]
    head = next((i for i, run in enumerate(runs) if isinstance(run, str)), len(runs))
    parts = []
    for part in (runs[:head], runs[head:]):
        while part and part[-1] == 0:
            part = part[:-1]
        parts.extend(part)
    return tuple(parts)


def _gem_lock_sections(text):
    r"""Each source section of a Gemfile.lock, in order (#3692 reviews).

    An allowlist: a column-0 header must be exactly a ``_GEM_SECTIONS`` source or a
    ``_GEM_SKIPPED`` header, whose contents are skipped. Inside a source a line is
    exactly one of: an option at two spaces (``  name: value``), the marker ``  specs:``
    with nothing after it, a spec at four (``    name (version)``, a RubyGems-valid
    version) or a spec's dependency at six (``      name`` or ``      name (...)``).
    Any other header or indent, any whitespace but plain spaces (a tab, ``\r``,
    U+2028, a BOM, ...), an indented line before the first header, an option after
    ``specs:``, a spec before it, and a dependency with no spec above it fail the
    whole lock (ValueError). Only ``remote:`` is understood; any other option is kept
    as an unknown marker."""
    if _odd_whitespace(text):
        raise ValueError("Gemfile.lock whitespace Bundler reads differently")
    sections: list[_GemSection] = []
    current: _GemSection | None = None
    skipping = False
    in_specs = False
    for line in text.split("\n"):
        if not line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            if line in _GEM_SKIPPED:
                current, skipping = None, True
            elif line in _GEM_SECTIONS:
                current, skipping = _GemSection(_GEM_SECTIONS[line]), False
                sections.append(current)
            else:
                raise ValueError("unknown Gemfile.lock header")
            in_specs = False
            continue
        if skipping:
            continue
        if current is None:
            raise ValueError("Gemfile.lock line outside a section")
        if indent == 6:
            if not (in_specs and current.specs and _GEM_DEPENDENCY.match(line)):
                raise ValueError("malformed Gemfile.lock dependency")
        elif indent == 4:
            match = _GEM_SPEC.match(line)
            if not in_specs or match is None or not _gem_version_ok(match[2]):
                raise ValueError("malformed Gemfile.lock spec")
            current.specs.append((match[1], match[2]))
        elif indent == 2 and not in_specs:
            # Bundler builds the source at `specs:`; a later option is not part of it.
            if line == _GEM_SPECS_MARKER:
                in_specs = True
                continue
            option = _GEM_OPTION.match(line)
            if option is None or option[1] == "specs":
                raise ValueError("malformed Gemfile.lock option")
            if option[1] != "remote":
                current.options.add(option[1])
            elif current.remote is not None:
                raise ValueError("two Gemfile.lock remotes")
            else:
                current.remote = option[2]
        else:
            raise ValueError("malformed Gemfile.lock line")
    return sections


# Ruby's reserved words: none can be a block variable.
_RUBY_KEYWORDS = frozenset(
    "alias and begin break case class def defined do else elsif end ensure false for if "
    "in module next nil not or redo rescue retry return self super then true undef unless "
    "until when while yield __FILE__ __LINE__ __ENCODING__".split())
_GEMSPEC_OPEN = re.compile(r"( *)Gem::Specification\.new(?: +(do) *| *\{ *)"
                           r"\| *([a-z_][A-Za-z0-9_]*) *\| *\Z")
_GEMSPEC_SETTER = re.compile(r"([a-z_][a-z0-9_]*) *= *")
_GEMSPEC_DEPENDENCY = re.compile(r"add_(?:runtime_|development_)?dependency")
_RUBY_CODING = re.compile(r"coding[:=] *([A-Za-z0-9_.-]+)", re.IGNORECASE)
# Bundler's glob is `{,*,*/*}.gemspec`: bound the listing it takes to mirror it.
MAX_GEMSPEC_SCAN_ENTRIES = 65536


def _plain_strings(text):
    """The plain Ruby string literals in a comma-separated run, else None.

    Plain means inert: ``"..."`` with no ``\\`` and no ``#`` (so no escape and no
    interpolation), or ``'...'`` with no ``\\``. Nothing else may appear -- no
    adjacent literal, no trailing comma, no code."""
    strings: list[str] = []
    pos, size = 0, len(text)
    while True:
        while pos < size and text[pos] == " ":
            pos += 1
        if pos == size:
            return strings if not strings else None
        quote = text[pos]
        end = text.find(quote, pos + 1) if quote in "\"'" else -1
        if end < 0:
            return None
        body = text[pos + 1:end]
        if "\\" in body or (quote == '"' and "#" in body):
            return None
        strings.append(body)
        pos = end + 1
        while pos < size and text[pos] == " ":
            pos += 1
        if pos == size:
            return strings
        if text[pos] != ",":
            return None
        pos += 1


def _ruby_literal(text):
    """``(kind, value)`` for an inert right-hand side, else None: one plain string, an
    array of plain strings, ``true`` / ``false`` / ``nil`` or a decimal integer."""
    text = text.strip(" ")
    if text in ("true", "false", "nil") or (text.isascii() and text.isdigit()):
        return "atom", text
    if text.startswith("[") and text.endswith("]"):
        strings = _plain_strings(text[1:-1])
        return None if strings is None else ("array", strings)
    strings = _plain_strings(text)
    return ("string", strings[0]) if strings is not None and len(strings) == 1 else None


def _gemspec_statement(rest):
    """One statement on the block variable, ``rest`` being what follows ``x.``:
    ``("set", field, literal)``, ``("metadata", key, value)`` or ``("dependency",)``,
    else None."""
    if rest.startswith("metadata["):
        close = rest.find("]")
        key = _plain_strings(rest[len("metadata["):close]) if close > 0 else None
        tail = rest[close + 1:].lstrip(" ") if close > 0 else ""
        value = _ruby_literal(tail[1:]) if tail.startswith("=") else None
        if key is None or len(key) != 1 or value is None or value[0] != "string":
            return None
        return "metadata", key[0], value[1]
    dependency = _GEMSPEC_DEPENDENCY.match(rest)
    if dependency:
        args = rest[dependency.end():]
        if args.startswith(" "):
            strings = _plain_strings(args)
        elif args.startswith("(") and args.rstrip(" ").endswith(")"):
            strings = _plain_strings(args.rstrip(" ")[1:-1])
        else:
            strings = None
        return ("dependency",) if strings else None
    setter = _GEMSPEC_SETTER.match(rest)
    literal = _ruby_literal(rest[setter.end():]) if setter else None
    if setter is None or literal is None:
        return None                # (`x.metadata = ...` is refused by the caller)
    return "set", setter[1], literal


def _inert_line(line):
    """True for a blank line, or a ``#`` comment that does not change how Ruby reads
    the file: a magic ``coding:`` comment must say UTF-8, the encoding this reader
    read it in."""
    stripped = line.strip(" ")
    if not stripped:
        return True
    if not stripped.startswith("#"):
        return False
    coding = _RUBY_CODING.search(stripped)
    return coding is None or coding[1].lower() == "utf-8"


def _gemspec_document(text):
    """The literal facts of one gemspec's text, else None (#3623 R1, #3692 reviews).

    An allowlist of EVERY line, so nothing the reader accepts can fail to run and
    nothing it does not understand can run beside it:

    - outside the block: blank lines, ``#`` comments, the opener and its closer;
    - the opener: ``Gem::Specification.new do |x|`` or ``... { |x|``, whitespace before
      ``do``, ``x`` a Ruby local-variable name that is not a keyword;
    - the closer: ``end`` (``}``) at the opener's indentation;
    - inside: blank lines, comments, ``x.<field> = <literal>``,
      ``x.add_(runtime_|development_)?dependency "lit", ...`` (parenthesised or not) and
      ``x.metadata["key"] = "lit"``. A literal is one plain string, an array of plain
      strings, ``true`` / ``false`` / ``nil`` or an integer.

    ``x.name`` and ``x.version`` are each assigned exactly once, a non-empty plain
    string; ``allowed_push_host`` may appear only as that metadata key, at most once.
    Anything else -- a conditional, a ``require``, a second statement, a trailing
    comment, an interpolation, a call on the right-hand side, a non-UTF-8 ``coding:``
    comment, whitespace other than spaces -- refuses the file."""
    text = text.replace("\r\n", "\n")
    if _odd_whitespace(text):
        return None
    lines = text.split("\n")
    first = next((i for i, line in enumerate(lines) if not _inert_line(line)), None)
    if first is None:
        return None
    opener = _GEMSPEC_OPEN.match(lines[first])
    if opener is None or opener[3] in _RUBY_KEYWORDS:
        return None
    closer = opener[1] + ("end" if opener[2] else "}")
    prefix = opener[3] + "."
    document: ManifestDocument = {}
    closed = False
    for line in lines[first + 1:]:
        if closed or _inert_line(line):
            if not _inert_line(line):
                return None                            # code after the block
            continue
        if line == closer:
            closed = True
            continue
        body = line.strip(" ")
        statement = _gemspec_statement(body[len(prefix):]) if body.startswith(prefix) else None
        if statement is None:
            return None
        if statement[0] == "metadata" and statement[1] == "allowed_push_host":
            if "allowed_push_host" in document:
                return None
            document["allowed_push_host"] = statement[2]
        elif "allowed_push_host" in line or (statement[0] != "metadata"
                                             and "metadata" in line):
            return None
        if statement[0] == "set" and statement[1] in ("name", "version"):
            kind, value = statement[2]
            if statement[1] in document or kind != "string" or not value:
                return None
            document[statement[1]] = value
    if not closed or "name" not in document or "version" not in document:
        return None
    return document


def _gemspec_path(real_dir, target_root):
    """The one gemspec Bundler would load for a path source, else None (#3692 review
    item 5). Bundler globs ``{,*,*/*}.gemspec`` without dot-matching: the literal
    ``.gemspec``, ``*.gemspec`` here and ``*/*.gemspec`` one directory down, never a
    dot-prefixed name. More than one match, an unreadable or oversized listing, or a
    subdirectory that resolves outside the review root is None."""
    def matches(name):
        return name == ".gemspec" or (name.endswith(".gemspec") and not name.startswith("."))

    found, seen = [], 0
    try:
        with os.scandir(real_dir) as top:
            entries = sorted(top, key=lambda entry: entry.name)
        for entry in entries:
            seen += 1
            if matches(entry.name):
                found.append(entry.path)
            if entry.name.startswith(".") or not entry.is_dir():
                continue
            if not _inside(target_root, os.path.realpath(entry.path)):
                return None
            with os.scandir(entry.path) as below:
                for child in below:
                    seen += 1
                    if seen > MAX_GEMSPEC_SCAN_ENTRIES:
                        return None
                    if child.name != ".gemspec" and matches(child.name):
                        found.append(child.path)
            if seen > MAX_GEMSPEC_SCAN_ENTRIES:
                return None
    except OSError:
        return None
    return found[0] if len(found) == 1 else None


def _gemspec_fact(package_dir, target_root, cache: IngestCache):
    """``((name, version), publishable)`` from the one gemspec Bundler would load for an
    in-tree path source, else None (#3623 rulings R1 and R2, #3692 reviews).

    R1, literal only: see ``_gemspec_document``. R2: a literal
    ``x.metadata["allowed_push_host"]`` other than rubygems.org (bare, or with exactly
    one trailing ``/``) is private-only. The review root itself is exempt from R2."""
    real_dir = os.path.realpath(package_dir)
    if not _inside(target_root, real_dir):
        return None
    listing = ("gemspec-dir", real_dir)
    if listing not in cache.manifests:
        found = _gemspec_path(real_dir, target_root)
        cache.manifests[listing] = None if found is None else {"path": found}
    listed = cache.manifests[listing]
    if listed is None:
        return None
    path = os.path.realpath(str(listed["path"]))
    if not _inside(target_root, path):
        return None
    key = ("gemspec", path)
    if key not in cache.manifests:
        raw = _read_budgeted_bytes(path, MAX_GEMSPEC_BYTES, cache)
        try:
            text = raw.decode("utf-8") if raw is not None else None
        except UnicodeError:
            text = None
        cache.manifests[key] = None if text is None else _gemspec_document(text)
    document = cache.manifests[key]
    if document is None:
        return None
    host = document.get("allowed_push_host")
    publishable = host is None or host in (RUBYGEMS_HOST, RUBYGEMS_HOST + "/")
    return ((document["name"], document["version"]),
            publishable or real_dir == target_root)


def _bundler_reads_here(remote):
    """True when Bundler's ``expand_path`` of a PATH remote is the plain join this
    reader makes: relative, no URL scheme, no ``~`` (which is ``$HOME``) and no ``..``
    component (which is lexical, so a symlink below it would be read differently)."""
    return (isinstance(remote, str) and not os.path.isabs(remote)
            and not _URL_SCHEME.match(remote) and not remote.startswith("~")
            and ".." not in remote.split("/"))


def _ruby_package_origins(lock_path, target_root, cache: IngestCache):
    """Map Gemfile.lock identities to fail-closed origin classes (#3623).

    A gem under a ``PATH`` source is first-party only when the source's remote is one
    Bundler reads where this reader does, its realpath is inside the review root, the
    source carries no option but ``remote``, the spec has no platform, the one gemspec
    Bundler would load proves the exact identity and is publishable, and no other
    spec in the lock -- under any source, platform or spelling -- is the same name at
    a version RubyGems reads as equal (1.2 and 1.2.0). ``GEM``, ``GIT`` and plugin
    sources are external. A malformed lock classifies nothing."""
    if lock_path in cache.package_origins:
        return cache.package_origins[lock_path]
    origins: PackageOrigins = {}
    cache.package_origins[lock_path] = origins
    raw = _read_budgeted_bytes(lock_path, MAX_RUBY_LOCK_BYTES, cache)
    if raw is None:
        return origins
    try:
        sections = _gem_lock_sections(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return origins
    if sum(len(section.specs) for section in sections) > 64 * MAX_CARGO_MANIFESTS:
        return origins
    local = [(section, spec) for section in sections if section.kind == "local"
             for spec in section.specs]
    if len(local) > MAX_CARGO_MANIFESTS:
        return origins
    found: PackageOrigins = {}
    lock_dir = os.path.dirname(lock_path)
    # How many specs share one name and RubyGems-equal release, whatever the source.
    twins: dict[tuple[str, tuple], int] = {}
    for section in sections:
        for name, version in section.specs:
            key = (name, _gem_canonical(_gem_release(version)[0]))
            twins[key] = twins.get(key, 0) + 1
            if section.kind == "external":
                # Keyed by release too: Bundler reads `foo (1.0-java)` as foo 1.0.
                for identity in {(name, version), (name, _gem_release(version)[0])}:
                    found.setdefault(identity, set()).add("external")
    for section, spec in local:
        release, platform = _gem_release(spec[1])
        fact = None
        if (not section.options and not platform and _bundler_reads_here(section.remote)
                and twins[(spec[0], _gem_canonical(release))] == 1):
            fact = _gemspec_fact(os.path.join(lock_dir, section.remote), target_root, cache)
        origin = (evidence.FIRST_PARTY_PACKAGE_ORIGIN if fact == (spec, True)
                  else "unknown")
        for identity in {spec, (spec[0], release)}:
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
    """Mark and reframe exact in-tree publishable package advisories (Cargo, npm,
    Python and Ruby).

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
    lock_path = _lock_path(target_root, finding, ("Cargo.lock",) + NPM_LOCKS + PYTHON_LOCKS
                           + RUBY_LOCKS)
    if lock_path is None:
        return
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
    elif os.path.basename(lock_path) in RUBY_LOCKS:
        # #3623: as for npm, only the review root's own lock and only scanners that
        # report an installed version (bundler-audit stays out, owner ruling R2).
        if os.path.dirname(lock_path) != target_root or tool not in NPM_INSTALLED_VERSION_TOOLS:
            return
        ecosystem, member = "Ruby", "path gem"
        origins = _ruby_package_origins(lock_path, target_root, cache).get(package, set())
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
