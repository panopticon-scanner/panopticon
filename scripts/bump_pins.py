#!/usr/bin/env python3
"""Keep this repo's hand-maintained pins current, safely -- one FAMILY per mode.

Dependabot covers this repo's pip and github-actions dependencies. It does NOT
cover the artifacts the Dockerfile fetches by curl and verifies by SHA256 --
rustup, Go, gosec, gitleaks and friends -- nor the wheel digests the privileged
builds install by. Those are pinned by hand, so they drift by hand, and nobody
notices until something forces the issue.

On 2026-09-01 rustup forced it the bad way: the fetch used the MOVING
`rustup/dist/` URL, so shipping 1.29.1 upstream broke `sha256sum -c` and every
from-scratch build with it. Pinning to the immutable archive URL fixed that, and
in doing so changed the failure mode -- the build is now stable indefinitely,
which means drift is SILENT rather than loud. A pin that cannot break is a pin
nobody remembers to bump.

So: check on a schedule, and open a PR when upstream moves. The point is not
urgency (there is none now) but visibility.

Families (`bump_pins.py <family>`), one mode each because they answer to
different upstreams and different verification steps:

  rustup        the Dockerfile's `ARG RUSTUP_VERSION` + its two init checksums,
                read from rust-lang's own manifest.
  trivy         the scanner version + both archive checksums, checked against
                the publisher's release checksum file and archive bytes.
  rust-toolchain  the compiler version from a checksum-verified stable manifest.
  requirements  the `--hash=sha256:` lines in the requirements files the
                privileged builds install from (#1641), read from PyPI's JSON
                API. Versions are NOT chosen here -- the `name==version` pins in
                those files are, and this mode fills in what bytes each one is
                allowed to be.
  gems          the Dockerfile's `ARG <GEM>_VERSION` + `ARG <GEM>_GEM_SHA256`
                pairs, read from rubygems' own API. The tools image installs
                each .gem from a checksum-gated file with
                --ignore-dependencies (#1734), so this also refuses to pin a
                release whose runtime closure has DRIFTED from the reviewed
                one -- a new dependency, or a tightened constraint on one the
                base image's ruby provides. Neither is a change a digest can
                catch, and both break the image rather than the download.
  tinyproxy     read-only check of the egress sidecar's multi-platform digest;
                a stale pin produces a workflow warning for manual review.

RULE, inherited from the #run7 FIXME this automates: never guess a checksum.
Every SHA written here is read from upstream's own metadata AND recomputed from
the downloaded artifact before it reaches a pinned file.

Needs the network, so it is an OPERATOR tool: nothing in the test suite runs it
against a live index (tests/test_bump_pins.py drives it off canned responses).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tomllib
import urllib.parse
import urllib.request

RUSTUP_STABLE = "https://static.rust-lang.org/rustup/release-stable.toml"
RUSTUP_ARCHIVE = "https://static.rust-lang.org/rustup/archive/{v}/{triple}/rustup-init"
RUSTUP_TRIPLES = {"AMD64": "x86_64-unknown-linux-gnu",
                  "ARM64": "aarch64-unknown-linux-gnu"}
RUST_STABLE = "https://static.rust-lang.org/dist/channel-rust-stable.toml"
TRIVY_LATEST = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
TRIVY_TAG = "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v{v}"
TRIVY_RELEASE = "https://github.com/aquasecurity/trivy/releases/download/v{v}/{name}"
TRIVY_ARCHIVES = {"AMD64": "Linux-64bit", "ARM64": "Linux-ARM64"}
PYPI_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"
RUBYGEMS_LATEST = "https://rubygems.org/api/v1/versions/{name}/latest.json"
RUBYGEMS_RELEASE = "https://rubygems.org/api/v2/rubygems/{name}/versions/{version}.json"
RUBYGEMS_DOWNLOAD = "https://rubygems.org/downloads/{name}-{version}.gem"
# The files the `requirements` family maintains when none is named.
REQUIREMENTS_FILES = (".github/requirements-gate.txt", "requirements-fixtures.txt",
                      "requirements-tools.txt")
TIMEOUT = 120
DOWNLOAD_HOSTS = frozenset({
    "api.github.com",
    "auth.docker.io",
    "files.pythonhosted.org",
    "github.com",
    "pypi.org",
    "registry-1.docker.io",
    "release-assets.githubusercontent.com",
    "rubygems.org",
    "static.rust-lang.org",
})


def _download_origin(url: str) -> tuple[str, str, int]:
    """Validate a download URL and return its normalized HTTPS origin."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        raise RuntimeError("download URL is malformed") from None
    if parsed.scheme.lower() != "https":
        raise RuntimeError("download URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError("download URL must not contain credentials")
    if parsed.netloc.endswith(":"):
        raise RuntimeError("download URL has an invalid port")
    try:
        port = parsed.port
    except ValueError:
        raise RuntimeError("download URL has an invalid port") from None
    host = parsed.hostname.lower() if parsed.hostname else None
    if host not in DOWNLOAD_HOSTS:
        raise RuntimeError("download host is not approved: %r" % host)
    if port not in (None, 443):
        raise RuntimeError("download URL must use HTTPS port 443")
    return "https", host, 443


def _has_authorization(request: urllib.request.Request) -> bool:
    return any(name.lower() == "authorization"
               for name, _value in request.header_items())


class _DownloadRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Apply the download policy before urllib sends each redirect."""

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("Location") or headers.get("URI")
        if location is not None:
            # urllib's default handler reports unsupported redirect URLs in an
            # HTTPError, including their userinfo. Validate first so even a
            # rejected Location cannot disclose embedded credentials.
            try:
                redirect_url = urllib.parse.urljoin(req.full_url, location)
            except (TypeError, ValueError):
                raise RuntimeError("download URL is malformed") from None
            _download_origin(redirect_url)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_origin = _download_origin(newurl)
        if (_has_authorization(req)
                and _download_origin(req.full_url) != new_origin):
            raise RuntimeError(
                "refusing authenticated redirect to a different origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str | urllib.request.Request) -> bytes:
    request_url = url.full_url if isinstance(url, urllib.request.Request) else url
    _download_origin(request_url)
    opener = urllib.request.build_opener(_DownloadRedirectHandler())
    with opener.open(url, timeout=TIMEOUT) as fh:
        return fh.read()


# --- family: rustup -----------------------------------------------------------

def current_rustup_pin(text: str) -> tuple[str | None, dict[str, str]]:
    """(version, {ARCH: sha}) as pinned in the Dockerfile today. Pure."""
    m = re.search(r"^ARG RUSTUP_VERSION=(\S+)\s*$", text, re.M)
    version = m.group(1) if m else None
    shas = {}
    for arch in RUSTUP_TRIPLES:
        s = re.search(r"^ARG RUSTUP_INIT_SHA256_%s=([0-9a-f]{64})\s*$" % arch, text, re.M)
        if s:
            shas[arch] = s.group(1)
    return version, shas


def _rustup_version(version: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("invalid rustup version: %r" % version)
    return version


def latest_rustup_version() -> str:
    """The current stable rustup version, from rust-lang's own manifest."""
    body = _get(RUSTUP_STABLE).decode("utf-8", "replace")
    m = re.search(r"^version\s*=\s*['\"]([^'\"]+)['\"]", body, re.M)
    if not m:
        raise RuntimeError("could not parse a version out of %s" % RUSTUP_STABLE)
    return _rustup_version(m.group(1))


def verified_rustup_shas(version: str) -> dict[str, str]:
    """{ARCH: sha} for `version`, each read from upstream AND verified.

    Reading the published .sha256 alone would only prove upstream is
    self-consistent. Hashing the artifact too is what makes the pin mean
    something -- and it is exactly the step the FIXME said not to skip.
    """
    version = _rustup_version(version)
    out = {}
    for arch, triple in RUSTUP_TRIPLES.items():
        url = RUSTUP_ARCHIVE.format(v=version, triple=triple)
        published = _get(url + ".sha256").decode("ascii", "replace").split()[0].strip()
        if not re.fullmatch(r"[0-9a-f]{64}", published):
            raise RuntimeError("%s.sha256 is not a sha256: %r" % (url, published[:80]))
        actual = hashlib.sha256(_get(url)).hexdigest()
        if actual != published:
            raise RuntimeError(
                "rustup %s %s: published sha256 %s != actual %s -- refusing to pin"
                % (version, arch, published, actual))
        out[arch] = actual
    return out


def rewrite_rustup_pin(text: str, version: str, shas: dict[str, str]) -> str:
    """Dockerfile text with the rustup pin updated. Pure, and total: raises
    rather than silently no-op'ing if a line it expects is absent."""
    version = _rustup_version(version)
    new = re.sub(r"^ARG RUSTUP_VERSION=\S+\s*$",
                 "ARG RUSTUP_VERSION=%s" % version, text, count=1, flags=re.M)
    if new == text:
        raise RuntimeError("no ARG RUSTUP_VERSION line to update")
    for arch, sha in shas.items():
        pat = r"^ARG RUSTUP_INIT_SHA256_%s=[0-9a-f]{64}\s*$" % arch
        after = re.sub(pat, "ARG RUSTUP_INIT_SHA256_%s=%s" % (arch, sha),
                       new, count=1, flags=re.M)
        if after == new:
            raise RuntimeError("no ARG RUSTUP_INIT_SHA256_%s line to update" % arch)
        new = after
    return new


def run_rustup(args) -> int:
    with open(args.dockerfile, encoding="utf-8") as fh:
        text = fh.read()
    have, _have_shas = current_rustup_pin(text)
    if not have:
        print("bump-pins: no RUSTUP_VERSION pin found; nothing to do")
        return 0
    want = latest_rustup_version()
    print("bump-pins: rustup pinned=%s latest=%s" % (have, want))
    if have == want:
        print("bump-pins: up to date")
        return 0

    shas = verified_rustup_shas(want)          # raises unless each SHA verifies
    if not args.write:
        print("bump-pins: %s -> %s available (re-run with --write)" % (have, want))
        return 0
    with open(args.dockerfile, "w", encoding="utf-8") as fh:
        fh.write(rewrite_rustup_pin(text, want, shas))
    print("bump-pins: wrote rustup %s" % want)
    for arch, sha in sorted(shas.items()):
        print("  %s %s" % (arch, sha))
    return 0


# --- families: Trivy and Rust compiler ---------------------------------------

def _numeric_version(version: str, family: str) -> str:
    if not isinstance(version, str) or not re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise RuntimeError("invalid %s version: %r" % (family, version))
    return version


def _single_arg(text: str, name: str, value_pattern: str) -> str:
    values = re.findall(r"^ARG " + re.escape(name) + r"=(.*)$", text, re.M)
    if len(values) != 1 or not re.fullmatch(value_pattern + r"[ \t]*", values[0]):
        raise RuntimeError("expected exactly one valid ARG %s line" % name)
    return values[0].rstrip(" \t")


def _replace_arg(text: str, name: str, value: str) -> str:
    old = _single_arg(text, name, r"\S+")
    return re.sub(r"^ARG " + re.escape(name) + r"=" + re.escape(old) + r"[ \t]*$",
                  "ARG %s=%s" % (name, value), text, count=1, flags=re.M)


def current_trivy_pin(text: str) -> tuple[str, dict[str, str]]:
    version = _numeric_version(_single_arg(text, "TRIVY_VERSION", r"\S+"), "Trivy")
    shas = {arch: _single_arg(text, "TRIVY_SHA256_%s" % arch, r"[0-9a-f]{64}")
            for arch in TRIVY_ARCHIVES}
    return version, shas


def _trivy_release(url: str, version: str | None = None) -> tuple[str, dict[str, str]]:
    try:
        release = json.loads(_get(url))
        tag = release["tag_name"]
        if not isinstance(tag, str) or not tag.startswith("v"):
            raise ValueError("invalid tag")
        found = _numeric_version(tag[1:], "Trivy")
        if version is not None and found != version:
            raise ValueError("release tag does not match requested version")
        assets = release["assets"]
        if not isinstance(assets, list):
            raise ValueError("invalid assets")
        urls: dict[str, str] = {}
        for asset in assets:
            name, asset_url = asset["name"], asset["browser_download_url"]
            if not isinstance(name, str) or not isinstance(asset_url, str):
                raise ValueError("invalid asset")
            if name in urls:
                raise ValueError("duplicate asset")
            urls[name] = asset_url
        return found, urls
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeError("invalid Trivy release metadata") from exc


def latest_trivy_version() -> str:
    version, _assets = _trivy_release(TRIVY_LATEST)
    return version


def verified_trivy_shas(version: str) -> dict[str, str]:
    version = _numeric_version(version, "Trivy")
    _found, assets = _trivy_release(TRIVY_TAG.format(v=version), version)
    names = {arch: "trivy_%s_%s.tar.gz" % (version, suffix)
             for arch, suffix in TRIVY_ARCHIVES.items()}
    checksum_name = "trivy_%s_checksums.txt" % version
    for name in (*names.values(), checksum_name):
        expected_url = TRIVY_RELEASE.format(v=version, name=name)
        if assets.get(name) != expected_url:
            raise RuntimeError("Trivy release lacks exact official asset %s" % name)
    try:
        checksum_text = _get(assets[checksum_name]).decode("ascii")
    except UnicodeError as exc:
        raise RuntimeError("Trivy checksums are not ASCII") from exc
    published: dict[str, str] = {}
    for line in checksum_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            raise RuntimeError("malformed Trivy checksum line")
        sha, name = match.groups()
        if name in published:
            raise RuntimeError("duplicate Trivy checksum entry: %s" % name)
        published[name] = sha
    for name in names.values():
        if name not in published:
            raise RuntimeError("missing Trivy checksum entry: %s" % name)
    shas = {}
    for arch, name in names.items():
        actual = hashlib.sha256(_get(assets[name])).hexdigest()
        if actual != published[name]:
            raise RuntimeError("Trivy %s %s: published sha256 differs from archive -- refusing to pin"
                               % (version, arch))
        shas[arch] = actual
    return shas


def rewrite_trivy_pin(text: str, version: str, shas: dict[str, str]) -> str:
    version = _numeric_version(version, "Trivy")
    current_trivy_pin(text)
    if set(shas) != set(TRIVY_ARCHIVES) or any(
            not re.fullmatch(r"[0-9a-f]{64}", sha) for sha in shas.values()):
        raise RuntimeError("Trivy rewrite requires both valid architecture SHA256s")
    new = _replace_arg(text, "TRIVY_VERSION", version)
    for arch in TRIVY_ARCHIVES:
        new = _replace_arg(new, "TRIVY_SHA256_%s" % arch, shas[arch])
    return new


def run_trivy(args) -> int:
    with open(args.dockerfile, encoding="utf-8") as fh:
        text = fh.read()
    have, old_shas = current_trivy_pin(text)
    want = latest_trivy_version()
    shas = verified_trivy_shas(want)
    print("bump-pins: trivy pinned=%s latest=%s" % (have, want))
    if have == want and old_shas == shas:
        print("bump-pins: up to date")
        return 0
    new = rewrite_trivy_pin(text, want, shas)
    if not args.write:
        print("bump-pins: %s -> %s available (re-run with --write)" % (have, want))
        return 0
    with open(args.dockerfile, "w", encoding="utf-8") as fh:
        fh.write(new)
    print("bump-pins: wrote Trivy %s" % want)
    return 0


def current_rust_toolchain_pin(text: str) -> str:
    return _numeric_version(_single_arg(text, "RUST_TOOLCHAIN_VERSION", r"\S+"),
                            "Rust toolchain")


def latest_rust_toolchain_version() -> str:
    manifest = _get(RUST_STABLE)
    try:
        companion = _get(RUST_STABLE + ".sha256").decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("Rust stable manifest checksum is not ASCII") from exc
    match = re.fullmatch(r"([0-9a-f]{64})(?:\s+\*?channel-rust-stable\.toml)?", companion)
    if not match or hashlib.sha256(manifest).hexdigest() != match.group(1):
        raise RuntimeError("Rust stable manifest SHA256 verification failed")
    try:
        doc = tomllib.loads(manifest.decode("utf-8"))
        rust = doc["pkg"]["rust"]
        upstream = rust["version"]
        if not isinstance(upstream, str):
            raise ValueError("invalid version")
        version_match = re.fullmatch(
            r"((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
            r" \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)", upstream)
        if not version_match:
            raise ValueError("invalid Rust version")
        for triple in RUSTUP_TRIPLES.values():
            if rust["target"][triple]["available"] is not True:
                raise ValueError("Rust target unavailable: %s" % triple)
        return _numeric_version(version_match.group(1), "Rust toolchain")
    except (KeyError, TypeError, ValueError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError("invalid or unavailable Rust stable manifest") from exc


def rewrite_rust_toolchain_pin(text: str, version: str) -> str:
    version = _numeric_version(version, "Rust toolchain")
    current_rust_toolchain_pin(text)
    return _replace_arg(text, "RUST_TOOLCHAIN_VERSION", version)


def run_rust_toolchain(args) -> int:
    with open(args.dockerfile, encoding="utf-8") as fh:
        text = fh.read()
    have = current_rust_toolchain_pin(text)
    want = latest_rust_toolchain_version()
    print("bump-pins: rust-toolchain pinned=%s latest=%s" % (have, want))
    if have == want:
        print("bump-pins: up to date")
        return 0
    new = rewrite_rust_toolchain_pin(text, want)
    if not args.write:
        print("bump-pins: %s -> %s available (re-run with --write)" % (have, want))
        return 0
    with open(args.dockerfile, "w", encoding="utf-8") as fh:
        fh.write(new)
    print("bump-pins: wrote Rust toolchain %s" % want)
    return 0


# --- family: gems -------------------------------------------------------------
# The tools image no longer runs RubyGems' resolver: it downloads each .gem,
# gates it on `sha256sum -c`, and installs it with --local
# --ignore-dependencies (#1734). That makes these pins the same shape as the
# release binaries above, drifting the same silent way, so the rustup family's
# answer applies unchanged -- read the digest from upstream's own metadata AND
# recompute it from the artifact before writing it down.

# ARG prefix -> gem name. The Dockerfile spells each pin as a PAIR:
# `ARG <PREFIX>_VERSION` and `ARG <PREFIX>_GEM_SHA256`.
GEMS = (("BRAKEMAN", "brakeman"),
        ("BUNDLER_AUDIT", "bundler-audit"),
        ("THOR", "thor"))
# The runtime closure this repo has REVIEWED, as {gem: {dependency:
# requirement}}, read from rubygems' own API on the day each version was
# pinned. Both halves are load-bearing, and for different reasons:
#
#   a new NAME is a gem nothing installs. The image installs with
#   --ignore-dependencies, so it would simply be absent.
#
#   a changed REQUIREMENT is a constraint this tool cannot evaluate. `racc` and
#   `bundler` come from the base image's ruby, whose version is not knowable
#   from here, and `thor` is installed at whatever THOR_VERSION says -- so
#   "does 1.5.0 satisfy `~> 2.0`?" is a question only the image build answers,
#   at `bundle-audit update` and at smoke_adapters.py. Comparing names alone
#   let a tightened constraint through --write and deferred the failure to
#   that build, with a green pin in the diff to argue it was fine.
#
# Either way the answer is to stop and make a human look. Update this table in
# the same commit as the version bump, once the image build is green.
REVIEWED_GEM_RUNTIME = {
    "brakeman": {"racc": ">= 0"},
    "bundler-audit": {"bundler": ">= 1.2.0", "thor": "~> 1.0"},
    "thor": {},
}


def _gem_version(version: str) -> str:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        raise RuntimeError("invalid gem version: %r" % version)
    return version


def current_gem_pins(text: str) -> dict[str, tuple[str, str]]:
    """{ARG prefix: (version, sha256)} as pinned in the Dockerfile today. Pure.

    A gem is reported only when BOTH halves are present. A version with no
    digest beside it is precisely what a careless bump leaves behind, and
    calling that "pinned" would hide the one state this tool exists to find.
    """
    out: dict[str, tuple[str, str]] = {}
    for prefix, _name in GEMS:
        version = re.search(r"^ARG %s_VERSION=(\S+)\s*$" % prefix, text, re.M)
        sha = re.search(r"^ARG %s_GEM_SHA256=([0-9a-f]{64})\s*$" % prefix,
                        text, re.M)
        if version and sha:
            out[prefix] = (version.group(1), sha.group(1))
    return out


def latest_gem_version(name: str) -> str:
    """The current release of `name`, from rubygems' own API."""
    body = _get(RUBYGEMS_LATEST.format(name=name))
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise RuntimeError("rubygems did not answer with JSON for %s: %s"
                           % (name, exc)) from exc
    version = doc.get("version") if isinstance(doc, dict) else None
    if not isinstance(version, str):
        raise RuntimeError("rubygems named no version for %s" % name)
    return _gem_version(version)


def verified_gem_sha(name: str, version: str) -> tuple[str, dict[str, str | None]]:
    """(sha256, {runtime dependency: requirement string}) for `name-version.gem`.

    The digest is read from rubygems' release document AND recomputed from the
    downloaded .gem, for the reason the rustup family states: the published
    value alone proves only that the index agrees with itself.

    The runtime dependencies come back with it, REQUIREMENTS INCLUDED, because
    the image installs with --ignore-dependencies: the closure is something
    this repo asserts rather than something RubyGems works out. A release that
    requires a new gem -- or that tightens a constraint on one the base image's
    ruby provides -- carries a perfectly good digest and is still wrong to pin.
    See `unreviewed_gem_requirements`.
    """
    version = _gem_version(version)
    body = _get(RUBYGEMS_RELEASE.format(name=name, version=version))
    try:
        release = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise RuntimeError("rubygems did not answer with JSON for %s %s: %s"
                           % (name, version, exc)) from exc
    published = (release.get("sha") or "") if isinstance(release, dict) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", published or ""):
        raise RuntimeError("%s %s: published sha is not a sha256: %r"
                           % (name, version, (published or "")[:80]))
    actual = hashlib.sha256(
        _get(RUBYGEMS_DOWNLOAD.format(name=name, version=version))).hexdigest()
    if actual != published:
        raise RuntimeError(
            "%s %s: published sha256 %s != actual %s -- refusing to pin"
            % (name, version, published, actual))
    runtime = (release.get("dependencies") or {}).get("runtime") or []
    return actual, {d["name"]: d.get("requirements") for d in runtime
                    if isinstance(d, dict) and isinstance(d.get("name"), str)}


def unreviewed_gem_requirements(name: str, runtime: dict[str, str | None]) -> list[str]:
    """How this release's runtime closure differs from the reviewed one, or [].

    Pure. `runtime` is `verified_gem_sha`'s second value: {dependency:
    requirement string}. Every difference is reported, not just the first, so
    one run tells an operator the whole story.
    """
    reviewed = REVIEWED_GEM_RUNTIME.get(name)
    if reviewed is None:
        return [("%s has no reviewed runtime closure; add one to "
                 + "REVIEWED_GEM_RUNTIME") % name]
    out = []
    for dep in sorted(runtime):
        if dep not in reviewed:
            out.append("%s now requires %s (%s), which the image does not "
                       "install" % (name, dep, runtime[dep]))
        elif runtime[dep] != reviewed[dep]:
            out.append("%s changed its requirement on %s from %r to %r"
                       % (name, dep, reviewed[dep], runtime[dep]))
    for dep in sorted(set(reviewed) - set(runtime)):
        out.append("%s no longer requires %s; drop it from "
                   "REVIEWED_GEM_RUNTIME" % (name, dep))
    return out


def rewrite_gem_pin(text: str, prefix: str, version: str, sha: str) -> str:
    """Dockerfile text with one gem's version AND digest updated.

    Pure, and total: raises rather than silently no-op'ing if either line it
    expects is absent. Writing one of the two would leave a digest that cannot
    match the artifact the new version's URL serves, which is a build that
    breaks at `sha256sum -c` with nothing in the diff to explain it.
    """
    version = _gem_version(version)
    new = re.sub(r"^ARG %s_VERSION=\S+\s*$" % prefix,
                 "ARG %s_VERSION=%s" % (prefix, version), text, count=1,
                 flags=re.M)
    if new == text:
        raise RuntimeError("no ARG %s_VERSION line to update" % prefix)
    after = re.sub(r"^ARG %s_GEM_SHA256=[0-9a-f]{64}\s*$" % prefix,
                   "ARG %s_GEM_SHA256=%s" % (prefix, sha), new, count=1,
                   flags=re.M)
    if after == new:
        raise RuntimeError("no ARG %s_GEM_SHA256 line to update" % prefix)
    return after


def run_gems(args) -> int:
    with open(args.dockerfile, encoding="utf-8") as fh:
        text = fh.read()
    pins = current_gem_pins(text)
    if not pins:
        print("bump-pins: no gem pins found; nothing to do")
        return 0
    stale = []
    for prefix, name in GEMS:
        if prefix not in pins:
            continue
        have, _sha = pins[prefix]
        want = latest_gem_version(name)
        print("bump-pins: %s pinned=%s latest=%s" % (name, have, want))
        if have != want:
            stale.append((prefix, name, want))
    if not stale:
        print("bump-pins: up to date")
        return 0
    if not args.write:
        for _prefix, name, want in stale:
            print("bump-pins: %s -> %s available (re-run with --write)"
                  % (name, want))
        return 0

    # Verify EVERY bump before writing ANY of them: a half-applied pass leaves
    # the file describing a build that was never checked.
    verified = []
    for prefix, name, want in stale:
        sha, runtime = verified_gem_sha(name, want)   # raises unless it verifies
        drift = unreviewed_gem_requirements(name, runtime)
        if drift:
            raise RuntimeError(
                "%s %s does not have the runtime closure this repo reviewed, "
                "and the image installs with --ignore-dependencies -- so a "
                "digest says nothing about whether it would WORK:\n  %s\n"
                "Check the Dockerfile still installs what this needs, build "
                "the image, then update REVIEWED_GEM_RUNTIME and re-run."
                % (name, want, "\n  ".join(drift)))
        verified.append((prefix, name, want, sha))
    for prefix, _name, want, sha in verified:
        text = rewrite_gem_pin(text, prefix, want, sha)
    with open(args.dockerfile, "w", encoding="utf-8") as fh:
        fh.write(text)
    for _prefix, name, want, sha in verified:
        print("bump-pins: wrote %s %s\n  %s" % (name, want, sha))
    return 0


# --- family: tinyproxy (read-only) --------------------------------------------

PROXY_SOURCE = "skill/scripts/tools/egress.py"
PROXY_REPOSITORY = "kalaksi/tinyproxy"
PROXY_TOKEN = ("https://auth.docker.io/token?service=registry.docker.io"
               "&scope=repository:kalaksi/tinyproxy:pull")
PROXY_MANIFEST = "https://registry-1.docker.io/v2/kalaksi/tinyproxy/manifests/%s"
PROXY_MEDIA_TYPES = ("application/vnd.oci.image.index.v1+json",
                     "application/vnd.docker.distribution.manifest.list.v2+json")


def current_proxy_digest(text: str) -> str:
    """Read the literal pin without importing or executing the reviewed tree."""
    for node in ast.parse(text).body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "PROXY_IMAGE" for t in node.targets)):
            value = ast.literal_eval(node.value)
            prefix = "docker.io/" + PROXY_REPOSITORY + "@"
            if isinstance(value, str) and value.startswith(prefix):
                digest = value[len(prefix):]
                if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    return digest
    raise RuntimeError("no literal digest-pinned tinyproxy image in " + PROXY_SOURCE)


def latest_proxy_digest(tag: str = "latest") -> str:
    """Hash the registry's multi-platform manifest for `tag`; fetch no image
    layers.

    Registry V2's public pull token and manifest endpoints, not an authenticated
    Docker CLI or a platform-specific image ID. See Docker's registry/auth docs
    and distribution.github.io/distribution/spec/api/#pulling-an-image-manifest.

    `tag` defaults to the floating `latest` Docker Hub resolves at pull time --
    the tag `run_tinyproxy` compares the pinned digest against. This check is
    read-only advice for manual review (the module docstring: "a stale pin
    produces a workflow warning"), never a write -- so a repo that has
    deliberately declined a newer release and stayed on an older one warns
    here too, on every run, until an operator dismisses it or a caller passes
    the declined release's own tag instead.
    """
    auth = json.loads(_get(PROXY_TOKEN))
    token = (auth.get("token") or auth.get("access_token")) if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("Docker registry did not return a public pull token")
    request = urllib.request.Request(PROXY_MANIFEST % tag, headers={
        "Authorization": "Bearer " + token, "Accept": ", ".join(PROXY_MEDIA_TYPES)})
    raw = _get(request)
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") not in PROXY_MEDIA_TYPES):
        raise RuntimeError("tinyproxy %s is not a supported multi-platform manifest" % tag)
    architectures: set[str | None] = set()
    for entry in manifest.get("manifests") or []:
        platform = entry.get("platform") if isinstance(entry, dict) else None
        if isinstance(platform, dict) and platform.get("os") == "linux":
            architectures.add(platform.get("architecture"))
    if not {"amd64", "arm64"} <= architectures:
        raise RuntimeError("tinyproxy %s does not cover linux/amd64 and linux/arm64" % tag)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run_tinyproxy(args) -> int:
    with open(args.source, encoding="utf-8") as fh:
        have = current_proxy_digest(fh.read())
    want = latest_proxy_digest()
    print("bump-pins: tinyproxy pinned=%s latest=%s" % (have, want))
    if have == want:
        print("bump-pins: up to date")
    else:
        print("::warning title=Tinyproxy pin is stale::Review docker.io/%s@%s "
              "and update PROXY_IMAGE after testing the proxy on both architectures. "
              "The pin was not changed." % (PROXY_REPOSITORY, want))
    return 0


# --- family: requirements -----------------------------------------------------
# What `--require-hashes` needs is one `--hash=sha256:` line per artifact pip
# could legitimately choose for the target platform. Writing those by hand is
# how a digest gets invented; this reads each one from PyPI's JSON API and
# recomputes it from the downloaded wheel, exactly as the rustup family does.

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """[(lineno, joined)] with `\\`-continuations folded in. lineno is where the
    logical line STARTS."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = None
    for n, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = n
        stripped = line.strip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1].strip())
            continue
        buf.append(stripped)
        out.append((start, " ".join(p for p in buf if p)))
        buf, start = [], None
    if buf:
        out.append((start or 1, " ".join(p for p in buf if p)))
    return out


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """[(name, version)] for every `name==version` pin in a requirements file."""
    pins = []
    for _n, joined in _logical_lines(text):
        if joined.startswith("#"):
            continue
        m = _PIN.match(joined)
        if m:
            pins.append((m.group("name"), m.group("version")))
    return pins


# The machine architectures the builds these pins protect actually run on.
# ubuntu-latest (the gate) is amd64 only, but docker-publish.yml builds the
# tools image -- and with it the fixtures image FROM it -- for linux/amd64 AND
# linux/arm64, so an x86_64-only hash block fails `--require-hashes` on the
# arm64 leg alone (#1734). Both are kept for every file: pip only needs ONE
# `--hash` on a line to match the artifact it actually fetched, so the digests
# an amd64 build never uses cost it nothing.
LINUX_ARCHES = ("x86_64", "aarch64")


def wheel_is_installable(filename: str) -> bool:
    """Could the linux builds this repo pins for select this wheel?

    The surfaces are ubuntu-latest for the gate and the `python:3.12-slim`
    images for the fixtures and the tools -- so the answer is the pure-Python
    wheels plus the linux binary ones for either architecture in
    `LINUX_ARCHES`. Every CPython ABI is kept rather than just today's: the
    gate's `python-version` is a pin of its own and moving it must not silently
    leave pip with nothing it may install.

    `"linux" in tag` is load-bearing next to the arch suffix, not decoration:
    `macosx_11_0_arm64` also ends in an arm64 spelling, and `aarch64` is the
    one manylinux uses, so the two tests together are what keep a macOS wheel
    out of a linux build's hash block.
    """
    if not filename.endswith(".whl"):
        return False
    platform_tag = filename[:-len(".whl")].rsplit("-", 1)[-1]
    for tag in platform_tag.split("."):
        if tag == "any":
            return True
        if "linux" in tag and tag.endswith(LINUX_ARCHES):
            return True
    return False


def verified_pypi_hashes(name: str, version: str) -> list[str]:
    """Every sha256 `name==version` may install as, read from PyPI AND verified.

    PyPI publishes each file's digest beside it, which alone only proves the
    index is self-consistent. Downloading the wheel and recomputing the digest
    is what makes the pin a control, and it is the same step the rustup family
    refuses to skip.
    """
    body = _get(PYPI_RELEASE.format(name=name, version=version))
    try:
        release = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise RuntimeError("PyPI did not answer with JSON for %s==%s: %s"
                           % (name, version, exc)) from exc
    digests = []
    for entry in release.get("urls") or []:
        filename = entry.get("filename") or ""
        if not wheel_is_installable(filename):
            continue
        published = (entry.get("digests") or {}).get("sha256") or ""
        if not re.fullmatch(r"[0-9a-f]{64}", published):
            raise RuntimeError("%s: published sha256 is not a sha256: %r"
                               % (filename, published[:80]))
        actual = hashlib.sha256(_get(entry["url"])).hexdigest()
        if actual != published:
            raise RuntimeError(
                "%s: published sha256 %s != actual %s -- refusing to pin"
                % (filename, published, actual))
        digests.append(actual)
    if not digests:
        raise RuntimeError(
            "%s==%s publishes no wheel this platform may install; pin a version "
            "that does rather than falling back to an sdist" % (name, version))
    return sorted(set(digests))


def rewrite_requirements(text: str, hashes: dict[tuple[str, str], list[str]]) -> str:
    """Requirements text with every pin's hash block regenerated.

    Pure, and total in both directions: a pin with no hashes raises, and so does
    a set of hashes with no pin to attach them to. Comments and blank lines are
    left exactly where they were -- the prose around a pin is why anyone can
    review it.
    """
    lines = text.splitlines()
    out: list[str] = []
    written = set()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        m = None if stripped.startswith("#") else _PIN.match(stripped)
        if not m:
            out.append(lines[i])
            i += 1
            continue
        while i < len(lines) - 1 and lines[i].rstrip().endswith("\\"):
            i += 1
        i += 1
        key = (m.group("name"), m.group("version"))
        digests = hashes.get(key)
        if not digests:
            raise RuntimeError("no verified hashes for %s==%s" % key)
        out.append("%s==%s \\" % key)
        for n, digest in enumerate(digests):
            out.append("    --hash=sha256:%s%s"
                       % (digest, "" if n == len(digests) - 1 else " \\"))
        written.add(key)
    unused = sorted(set(hashes) - written)
    if unused:
        raise RuntimeError("hashes for pins this file does not carry: %s"
                           % ", ".join("%s==%s" % k for k in unused))
    return "\n".join(out) + "\n"


def run_requirements(args) -> int:
    rc = 0
    for path in args.files or list(REQUIREMENTS_FILES):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        pins = parse_requirements(text)
        if not pins:
            print("bump-pins: %s pins nothing; nothing to do" % path)
            continue
        hashes = {pin: verified_pypi_hashes(*pin) for pin in pins}
        new = rewrite_requirements(text, hashes)
        if new == text:
            print("bump-pins: %s up to date (%d pins)" % (path, len(pins)))
            continue
        if not args.write:
            print("bump-pins: %s hashes available (re-run with --write)" % path)
            rc = 0
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("bump-pins: wrote %s" % path)
        for name, version in pins:
            print("  %s==%s  %d artifact(s)" % (name, version,
                                                len(hashes[(name, version)])))
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    families = ap.add_subparsers(dest="family", required=True,
                                 metavar="<family>")

    rustup = families.add_parser(
        "rustup", help="the Dockerfile's rustup version + init checksums")
    rustup.add_argument("--dockerfile", default="Dockerfile")
    rustup.set_defaults(run=run_rustup)

    trivy = families.add_parser("trivy", help="the Dockerfile's verified Trivy archives")
    trivy.add_argument("--dockerfile", default="Dockerfile")
    trivy.set_defaults(run=run_trivy)

    toolchain = families.add_parser("rust-toolchain", help="the Dockerfile's Rust compiler")
    toolchain.add_argument("--dockerfile", default="Dockerfile")
    toolchain.set_defaults(run=run_rust_toolchain)

    reqs = families.add_parser(
        "requirements",
        help="the --hash lines in the privileged builds' requirements files")
    reqs.add_argument("--file", action="append", dest="files", metavar="PATH",
                      help="a requirements file to refresh (repeatable; "
                           "default: %s)" % ", ".join(REQUIREMENTS_FILES))
    reqs.set_defaults(run=run_requirements)

    gems = families.add_parser(
        "gems", help="the Dockerfile's gem versions + their .gem checksums")
    gems.add_argument("--dockerfile", default="Dockerfile")
    gems.set_defaults(run=run_gems)

    proxy = families.add_parser("tinyproxy", help="check the egress sidecar digest (read-only)")
    proxy.add_argument("--source", default=PROXY_SOURCE)
    proxy.set_defaults(run=run_tinyproxy)

    for parser in (rustup, trivy, toolchain, reqs, gems):
        parser.add_argument("--write", action="store_true",
                            help="apply the bump (default: report only)")
    args = ap.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
