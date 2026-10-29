#!/usr/bin/env python3
"""Maintain the repo's hand-written supply-chain pins, one family per mode.

Dependabot does not cover Dockerfile downloads or the wheel digests privileged
builds install. Immutable URLs made those pins stable but their drift silent,
so scheduled checks keep it visible. Families are:

  rustup          version plus two init checksums from rust-lang's manifest
  trivy           version plus two publisher-verified archive checksums
  rust-toolchain  compiler version from the checksum-verified stable manifest
  requirements    allowed PyPI wheel bytes for committed `name==version` pins
  gems            version/digest pairs whose reviewed runtime closure is fixed
  tinyproxy       read-only check of the sidecar's multi-platform digest

Writing modes never guess: a SHA comes from upstream metadata and is recomputed
from the downloaded artifact. This is a networked operator tool; tests inject
canned responses and never contact a live index.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import time
import tomllib
import urllib.parse
import urllib.request

from pin_requirements import (parse_requirement_hashes, parse_requirements,
                              rewrite_requirements)

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
LINUX_ARCHES = ("x86_64", "aarch64")
# #2877: check policy is per installed file, not "would write mode change it?"
REQUIREMENTS_POLICIES = {
    ".github/requirements-gate.txt": ("x86_64",),
    "requirements-fixtures.txt": LINUX_ARCHES,
    "requirements-tools.txt": LINUX_ARCHES,
}
REQUIREMENTS_FILES = tuple(REQUIREMENTS_POLICIES)
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


def _get(url: str | urllib.request.Request, timeout=TIMEOUT) -> bytes:
    request_url = url.full_url if isinstance(url, urllib.request.Request) else url
    _download_origin(request_url)
    opener = urllib.request.build_opener(_DownloadRedirectHandler())
    with opener.open(url, timeout=timeout) as fh:
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
# Gems are downloaded, checksum-gated, then installed `--ignore-dependencies`
# (#1734), so each Dockerfile pin is a version/SHA pair verified like rustup.
GEMS = (("BRAKEMAN", "brakeman"),
        ("BUNDLER_AUDIT", "bundler-audit"),
        ("THOR", "thor"))
# Reviewed {gem: {dependency: requirement}} closures. A new name is absent
# under `--ignore-dependencies`; a changed constraint can only be judged by the
# image's Ruby. Either drift needs a human and a green image build.
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

    Recomputes the published digest. Requirements are retained because
    `--ignore-dependencies` makes the reviewed closure this repo's assertion.
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
    """All differences from this gem's reviewed runtime closure."""
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
    """Update one gem's version and digest; raise if either line is absent."""
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
# Write mode recomputes every selected wheel; check mode maps committed hashes
# to PyPI filenames and enforces the narrower policy of the file that owns them.


def _requirements_arches(path: str) -> tuple[str, ...]:
    normalized = os.path.normpath(path).replace("\\", "/")
    for filename, arches in REQUIREMENTS_POLICIES.items():
        if normalized == filename or normalized.endswith("/" + filename):
            return arches
    raise RuntimeError("no requirements check policy for %s" % path)


def wheel_is_installable(filename: str, arches=LINUX_ARCHES) -> bool:
    """Is this a pure wheel or a linux wheel for one of `arches`?"""
    if not filename.endswith(".whl"):
        return False
    platform_tag = filename[:-len(".whl")].rsplit("-", 1)[-1]
    for tag in platform_tag.split("."):
        if tag == "any":
            return True
        if "linux" in tag and tag.endswith(arches):
            return True
    return False


def pypi_release_files(name: str, version: str) -> list[dict]:
    """Read one release's file list, with bounded retries for check-mode CI."""
    url = PYPI_RELEASE.format(name=name, version=version)
    reason = "unknown PyPI failure"
    for attempt in range(3):
        try:
            body = _get(url, timeout=5)
            try:
                release = json.loads(body.decode("utf-8", "replace"))
            except ValueError as exc:
                raise RuntimeError("PyPI did not answer with JSON for %s==%s: %s"
                                   % (name, version, exc)) from exc
            files = release.get("urls") if isinstance(release, dict) else None
            if not isinstance(files, list) or not all(isinstance(f, dict) for f in files):
                raise RuntimeError("PyPI JSON has no file list for %s==%s" % (name, version))
            return files
        except (OSError, RuntimeError, ValueError) as exc:
            reason = str(exc)
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))
    raise RuntimeError(reason)


def verified_pypi_hashes(name: str, version: str) -> list[str]:
    """Every installable wheel sha, read from PyPI and recomputed."""
    digests = []
    for entry in pypi_release_files(name, version):
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


def requirement_hash_errors(path: str, text: str,
                            releases: dict[tuple[str, str], list[dict]]) -> list[str]:
    """Policy errors in one file, in block/digest/PyPI filename order."""
    arches = _requirements_arches(path)
    errors = []
    for name, version, digests in parse_requirement_hashes(text):
        pin = (name, version)
        if pin not in releases:  # its fetch failed; run_requirements reports that separately
            continue
        prefix = "%s: %s==%s" % (path, name, version)
        host_installable = False
        files = releases[pin]
        for digest in digests:
            matches = sorted(
                (entry for entry in files
                 if (entry.get("digests") or {}).get("sha256") == digest),
                key=lambda entry: str(entry.get("filename") or ""))
            if not matches:
                errors.append("%s: %s: not published for this release" % (prefix, digest))
                continue
            for entry in matches:
                filename = str(entry.get("filename") or "")
                if not filename.endswith(".whl"):
                    reason = "sdist"
                elif not wheel_is_installable(filename, arches):
                    reason = "off-policy wheel"
                else:
                    host_installable |= wheel_is_installable(filename, ("x86_64",))
                    continue
                errors.append("%s: %s: %s: %s" % (prefix, digest, filename, reason))
        if not host_installable:
            errors.append("%s: no installable x86_64-or-any digest" % prefix)
    return errors


def run_requirements(args) -> int:
    paths = args.files or list(REQUIREMENTS_FILES)
    if args.check:
        documents = []
        pins = set()
        errors = []
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            try:
                _requirements_arches(path)
            except RuntimeError as exc:
                errors.append(str(exc))
                continue
            documents.append((path, text))
            pins.update(parse_requirements(text))
        releases = {}
        unavailable = []
        for pin in sorted(pins):
            try:
                releases[pin] = pypi_release_files(*pin)
            except RuntimeError as exc:
                unavailable.append("could not verify %s==%s: %s" % (*pin, exc))
                break
        for path, text in documents:
            errors.extend(requirement_hash_errors(path, text, releases))
        for error in errors + unavailable:
            print("bump-pins: " + error, file=sys.stderr)
        return 2 if unavailable else (1 if errors else 0)  # outage != bad policy
    for path in paths:
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
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("bump-pins: wrote %s" % path)
        for name, version in pins:
            print("  %s==%s  %d artifact(s)" % (name, version,
                                                len(hashes[(name, version)])))
    return 0


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
    req_mode = reqs.add_mutually_exclusive_group()
    req_mode.add_argument("--write", action="store_true", help="apply the bump")
    req_mode.add_argument("--check", action="store_true", help="validate committed hashes")
    reqs.set_defaults(run=run_requirements)

    gems = families.add_parser(
        "gems", help="the Dockerfile's gem versions + their .gem checksums")
    gems.add_argument("--dockerfile", default="Dockerfile")
    gems.set_defaults(run=run_gems)

    proxy = families.add_parser("tinyproxy", help="check the egress sidecar digest (read-only)")
    proxy.add_argument("--source", default=PROXY_SOURCE)
    proxy.set_defaults(run=run_tinyproxy)

    for parser in (rustup, trivy, toolchain, gems):
        parser.add_argument("--write", action="store_true",
                            help="apply the bump (default: report only)")
    args = ap.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
