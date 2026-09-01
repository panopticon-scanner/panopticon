#!/usr/bin/env python3
"""Keep the Dockerfile's checksum-pinned artifacts current, safely.

Dependabot covers this repo's pip and github-actions dependencies. It does NOT
cover the 14 artifacts the Dockerfile fetches by curl and verifies by SHA256 --
rustup, Go, gosec, gitleaks and friends. Those are pinned by hand, so they drift
by hand, and nobody notices until something forces the issue.

On 2026-09-01 rustup forced it the bad way: the fetch used the MOVING
`rustup/dist/` URL, so shipping 1.29.1 upstream broke `sha256sum -c` and every
from-scratch build with it. Pinning to the immutable archive URL fixed that, and
in doing so changed the failure mode -- the build is now stable indefinitely,
which means drift is SILENT rather than loud. A pin that cannot break is a pin
nobody remembers to bump.

So: check on a schedule, and open a PR when upstream moves. The point is not
urgency (there is none now) but visibility.

RULE, inherited from the #run7 FIXME this automates: never guess a checksum.
Every SHA written here is read from upstream's own `.sha256` file AND verified
against the downloaded artifact before it reaches the Dockerfile.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request

RUSTUP_STABLE = "https://static.rust-lang.org/rustup/release-stable.toml"
RUSTUP_ARCHIVE = "https://static.rust-lang.org/rustup/archive/{v}/{triple}/rustup-init"
RUSTUP_TRIPLES = {"AMD64": "x86_64-unknown-linux-gnu",
                  "ARM64": "aarch64-unknown-linux-gnu"}
TIMEOUT = 120


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as fh:  # nosec B310 - https literal
        return fh.read()


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


def latest_rustup_version() -> str:
    """The current stable rustup version, from rust-lang's own manifest."""
    body = _get(RUSTUP_STABLE).decode("utf-8", "replace")
    m = re.search(r"^version\s*=\s*['\"]([^'\"]+)['\"]", body, re.M)
    if not m:
        raise RuntimeError("could not parse a version out of %s" % RUSTUP_STABLE)
    return m.group(1)


def verified_rustup_shas(version: str) -> dict[str, str]:
    """{ARCH: sha} for `version`, each read from upstream AND verified.

    Reading the published .sha256 alone would only prove upstream is
    self-consistent. Hashing the artifact too is what makes the pin mean
    something -- and it is exactly the step the FIXME said not to skip.
    """
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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dockerfile", default="Dockerfile")
    ap.add_argument("--write", action="store_true",
                    help="apply the bump (default: report only)")
    args = ap.parse_args(argv)

    with open(args.dockerfile, encoding="utf-8") as fh:
        text = fh.read()
    have, have_shas = current_rustup_pin(text)
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


if __name__ == "__main__":
    sys.exit(main())
