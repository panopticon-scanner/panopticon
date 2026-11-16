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


_GEM_SECTIONS = {"PATH": "local", "GEM": "external", "GIT": "external",
                 "PLUGIN SOURCE": "external"}
# Headers Bundler writes whose contents never name a source (#3692 review H2).
_GEM_SKIPPED = frozenset(("PLATFORMS", "DEPENDENCIES", "CHECKSUMS", "RUBY VERSION",
                          "BUNDLED WITH"))
_GEM_SPEC = re.compile(r"    ([^ ()]+) \(([^ ()]+)\)\Z")
_GEM_OPTION = re.compile(r"  ([a-z_]+):(?: (.*))?\Z")


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


def _gem_lock_sections(text):
    """Each source section of a Gemfile.lock, in order (#3692 review H2 and L2).

    An allowlist: a column-0 header must be exactly a ``_GEM_SECTIONS`` source or a
    ``_GEM_SKIPPED`` header, whose contents are skipped. Any other header, any
    whitespace but plain spaces (a tab, ``\r``, U+2028, a BOM, ...), an indented line
    before the first header, an option after ``specs:``, and a spec line that is not
    ``    name (version)`` fails the whole lock (ValueError). Inside a source, only
    ``remote:`` and ``specs:`` are understood; any other option is kept as an unknown
    marker."""
    if _odd_whitespace(text):
        raise ValueError("Gemfile.lock whitespace Bundler reads differently")
    sections: list[_GemSection] = []
    current: _GemSection | None = None
    skipping = False
    in_specs = False
    for line in text.split("\n"):
        if not line:
            continue
        if not line.startswith(" "):
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
        if current is None or not line.strip():
            raise ValueError("Gemfile.lock line outside a section")
        if line.startswith("      "):
            if not in_specs:
                raise ValueError("indented line outside specs")
            continue                                        # a spec's own dependency
        if line.startswith("    "):
            match = _GEM_SPEC.match(line)
            if not in_specs or match is None:
                raise ValueError("malformed Gemfile.lock spec")
            current.specs.append((match[1], match[2]))
            continue
        option = _GEM_OPTION.match(line)
        if option is None or in_specs:
            # Bundler builds the source at `specs:`; a later option is not part of it.
            raise ValueError("malformed Gemfile.lock option")
        in_specs = option[1] == "specs"
        if option[1] == "remote":
            if current.remote is not None or not option[2]:
                raise ValueError("malformed Gemfile.lock remote")
            current.remote = option[2]
        elif not in_specs:
            current.options.add(option[1])
    return sections


def _gem_release(version):
    """``(release, platform)``: Bundler splits a spec's version at its first ``-``, so
    ``1.0-x86_64-linux`` is release 1.0 on that platform (#3692 review H1)."""
    release, _, platform = version.partition("-")
    return release, platform


_GEMSPEC_OPEN = re.compile(r"( *)Gem::Specification\.new *"
                           r"(?:(do) *\| *(\w+) *\||\{ *\| *(\w+) *\|) *\Z")
_PLAIN_LITERAL = r"""(?:"([^"\\#]*)"|'([^'\\]*)')"""
_GEMSPEC_LITERAL = {
    field: re.compile(r" *(\w+)\.%s *= *%s *\Z" % (field, _PLAIN_LITERAL))
    for field in ("name", "version")}
# Any assignment-looking mention of the field, as code, symbol or text (`:version=`).
_GEMSPEC_ANY = {field: re.compile(r"\b%s\b[^\w=\n]*=(?![=~>])" % field)
                for field in ("name", "version")}
_GEMSPEC_METADATA = re.compile(r" *(\w+)\.metadata\[(?:\"([\w.-]+)\"|'([\w.-]+)')\]"
                               r" *= *%s *\Z" % _PLAIN_LITERAL)
# #3692 review M1: Ruby the reader cannot follow fails the whole gemspec.
_GEMSPEC_REFUSED = re.compile(
    r"__END__|=begin|<<|&:|\\\Z|\.\Z|\A *&?\.|ObjectSpace"
    r"|\b(?:send|public_send|__send__|instance_variable_set|instance_variable_get"
    r"|instance_eval|instance_exec|class_eval|class_exec|module_eval|module_exec"
    r"|define_method|define_singleton_method|eval|def|alias|alias_method|undef|method"
    r"|binding)\b"
    r"|\bGem\b(?!::)")
_GEMSPEC_STRING = re.compile(r"""\"[^"\\#]*\"|'[^'\\]*'""")


def _gemspec_fact(package_dir, target_root, cache: IngestCache):
    """``((name, version), publishable)`` from the one ``*.gemspec`` in an in-tree
    directory, else None (#3623 rulings R1 and R2, #3692 review M1 and M2).

    R1, literal only: see ``_gemspec_document``. R2: a literal
    ``x.metadata["allowed_push_host"]`` other than rubygems.org is private-only. The
    review root itself is exempt from R2."""
    real_dir = os.path.realpath(package_dir)
    if not _inside(target_root, real_dir):
        return None
    try:
        names = sorted(entry.name for entry in os.scandir(real_dir)
                       if entry.name.endswith(".gemspec"))
    except OSError:
        return None
    if len(names) != 1:
        return None
    path = os.path.realpath(os.path.join(real_dir, names[0]))
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
    publishable = host is None or (isinstance(host, str)
                                   and host.rstrip("/") == RUBYGEMS_HOST)
    return ((document["name"], document["version"]),
            publishable or real_dir == target_root)


def _literal(match, group):
    """The plain literal a ``_PLAIN_LITERAL`` pair of groups captured."""
    return match[group] if match[group] is not None else match[group + 1]


def _gemspec_document(text):
    """The literal facts of one gemspec's text, else None (#3623 R1, #3692 M1/M2).

    An allowlist. The gemspec holds one ``Gem::Specification.new do |x|`` (or
    ``{ |x|``) line, once ``Specification`` in all, closed by ``end`` (``}``) at its own
    indentation. Inside that block, ``x.name = "lit"`` and ``x.version = "lit"`` each
    appear exactly once as plain literals, and nothing else anywhere assigns, names
    or symbolizes ``name=``/``version=``. Every other mention of ``x`` is one per line,
    inside the block, and of the form ``x.<ident> = ...``,
    ``x.add_(runtime_|development_)?dependency ...`` or a literal metadata line. Every
    line mentioning ``metadata`` is ``x.metadata["key"] = "lit"``; one mentioning
    ``allowed_push_host`` is that line with that key, at most once. ``_GEMSPEC_REFUSED``
    (dynamic dispatch, reopening, heredocs, ``__END__``, line continuations, an aliased
    ``Gem``) and whitespace other than spaces fail closed."""
    text = text.replace("\r\n", "\n")
    if _odd_whitespace(text) or text.count("Specification") != 1:
        return None
    lines = text.split("\n")
    if any(_GEMSPEC_REFUSED.search(line) for line in lines):
        return None
    opened = [(i, match) for i, match in enumerate(map(_GEMSPEC_OPEN.match, lines)) if match]
    if len(opened) != 1:
        return None
    first, opener = opened[0]
    var = opener[3] or opener[4]
    closer = opener[1] + ("end" if opener[2] else "}")
    try:
        last = lines.index(closer, first + 1, len(lines))
    except ValueError:
        return None
    document: ManifestDocument = {}
    for field, loose in _GEMSPEC_ANY.items():
        # The mention rule below keeps this line inside the block.
        found = [i for i, line in enumerate(lines) if loose.search(line)]
        if len(found) != 1:
            return None
        match = _GEMSPEC_LITERAL[field].fullmatch(lines[found[0]])
        if match is None or match[1] != var or not _literal(match, 2):
            return None
        document[field] = _literal(match, 2)
    mention = re.compile(r"(?<![\w'\"$@:.])%s(?![\w?!])" % re.escape(var))
    hosts = []
    for i, line in enumerate(lines):
        if i == first:
            continue
        metadata = _GEMSPEC_METADATA.fullmatch(line)
        if "metadata" in line and (metadata is None or metadata[1] != var):
            return None
        if "allowed_push_host" in line:
            if metadata is None or _literal(metadata, 2) != "allowed_push_host":
                return None
            hosts.append(_literal(metadata, 4))
        mentions = len(mention.findall(_GEMSPEC_STRING.sub("", line)))
        if not mentions:
            continue
        if mentions != 1 or not first < i < last or not (
                metadata is not None
                or re.match(r" *%s\.\w+ *=(?![=~>])" % re.escape(var), line)
                or re.match(r" *%s\.add_(?:runtime_|development_)?dependency\b"
                            % re.escape(var), line)):
            return None
    if len(hosts) > 1:
        return None
    if hosts:
        document["allowed_push_host"] = hosts[0]
    return document


def _ruby_package_origins(lock_path, target_root, cache: IngestCache):
    """Map Gemfile.lock identities to fail-closed origin classes (#3623).

    A gem under a ``PATH`` source is first-party only when the source's realpath is
    inside the review root, the source carries no option but ``remote``/``specs``,
    and the directory's one gemspec proves the exact identity and is publishable.
    ``GEM``, ``GIT`` and plugin sources are external, under both the spec's version
    and its release, so a platform-suffixed copy makes the release ambiguous (#3692
    review H1); a local spec with a platform is never first-party. A malformed lock
    classifies nothing."""
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
    for section in sections:
        if section.kind == "external":
            for name, version in section.specs:
                # Keyed by release too: Bundler reads `foo (1.0-java)` as foo 1.0.
                for identity in {(name, version), (name, _gem_release(version)[0])}:
                    found.setdefault(identity, set()).add("external")
    for section, spec in local:
        remote = section.remote
        release, platform = _gem_release(spec[1])
        fact = None
        if (isinstance(remote, str) and not section.options and not platform
                and not os.path.isabs(remote) and not _URL_SCHEME.match(remote)):
            fact = _gemspec_fact(os.path.join(lock_dir, remote), target_root, cache)
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
    lock_path = _lock_path(target_root, finding, ("Cargo.lock",) + NPM_LOCKS + RUBY_LOCKS)
    if lock_path is None:
        return
    if os.path.basename(lock_path) == "Cargo.lock":
        ecosystem, member = "Cargo", "workspace/path member"
        origins = _cargo_package_origins(lock_path, target_root, cache).get(package, set())
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
