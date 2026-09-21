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
  requirements  the `--hash=sha256:` lines in the requirements files the
                privileged builds install from (#1641), read from PyPI's JSON
                API. Versions are NOT chosen here -- the `name==version` pins in
                those files are, and this mode fills in what bytes each one is
                allowed to be.

RULE, inherited from the #run7 FIXME this automates: never guess a checksum.
Every SHA written here is read from upstream's own metadata AND recomputed from
the downloaded artifact before it reaches a pinned file.

Needs the network, so it is an OPERATOR tool: nothing in the test suite runs it
against a live index (tests/test_bump_pins.py drives it off canned responses).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request

RUSTUP_STABLE = "https://static.rust-lang.org/rustup/release-stable.toml"
RUSTUP_ARCHIVE = "https://static.rust-lang.org/rustup/archive/{v}/{triple}/rustup-init"
RUSTUP_TRIPLES = {"AMD64": "x86_64-unknown-linux-gnu",
                  "ARM64": "aarch64-unknown-linux-gnu"}
PYPI_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"
# The files the `requirements` family maintains when none is named.
REQUIREMENTS_FILES = (".github/requirements-gate.txt", "requirements-fixtures.txt")
TIMEOUT = 120


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as fh:  # nosec B310 - https literal
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


def wheel_is_installable(filename: str) -> bool:
    """Could the linux x86_64 builds this repo pins for select this wheel?

    Both surfaces are linux/amd64 -- ubuntu-latest for the gate, the
    `python:3.12-slim` tools image for the fixtures -- so the answer is the
    pure-Python wheels plus the linux x86_64 binary ones. Every CPython ABI is
    kept rather than just today's: the gate's `python-version` is a pin of its
    own and moving it must not silently leave pip with nothing it may install.
    """
    if not filename.endswith(".whl"):
        return False
    platform_tag = filename[:-len(".whl")].rsplit("-", 1)[-1]
    for tag in platform_tag.split("."):
        if tag == "any":
            return True
        if "linux" in tag and tag.endswith("x86_64"):
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

    reqs = families.add_parser(
        "requirements",
        help="the --hash lines in the privileged builds' requirements files")
    reqs.add_argument("--file", action="append", dest="files", metavar="PATH",
                      help="a requirements file to refresh (repeatable; "
                           "default: %s)" % ", ".join(REQUIREMENTS_FILES))
    reqs.set_defaults(run=run_requirements)

    for parser in (rustup, reqs):
        parser.add_argument("--write", action="store_true",
                            help="apply the bump (default: report only)")
    args = ap.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
