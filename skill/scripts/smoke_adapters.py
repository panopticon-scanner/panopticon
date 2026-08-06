#!/usr/bin/env python3
"""Assert every bundled scanner can actually execute as the scanner user.

Run inside the image, as uid 1000, at build time. Building and pushing an
image proves only that the layers assembled — not that a single tool can run
in it. Two real regressions shipped through that gap:

  * semgrep could not create ``~/.semgrep`` because ``$HOME`` was root-owned,
    so it died on startup and wrote a 0-byte SARIF that read as "no findings"
    (#455).
  * dependency-check could not lock ``odc.mv.db`` because ``/opt/odc-data``
    was ``chmod a+rX``; H2 blocks rather than failing, so every scan burned
    its full 900s timeout and returned nothing (#451).

Both were invisible to CI, which never executed the image. Both are caught
here in about a second.

Exit 0 when every check passes; exit 1 with a report naming each failure.
Stdlib only, no third-party imports — this must run before anything else is
proven to work.
"""
import os
import subprocess
import sys

# Directories a tool must be able to WRITE, not merely read. Keep the reason
# attached: a bare path list invites someone to "tidy" it back to a+rX.
REQUIRED_WRITABLE = {
    "/opt/odc-data": (
        "dependency-check opens odc.mv.db read-write even under --noupdate; "
        "when the lock cannot be taken H2 blocks instead of failing (#451)"),
    os.path.expanduser("~"): (
        "tools lazily create dotfiles under $HOME at scan time — semgrep's "
        "~/.semgrep, dotnet's ~/.dotnet first-run sentinel (#455)"),
}

# Cheap liveness probes. Each must exit 0 quickly as the scanner user; a
# non-zero exit or a timeout means the tool cannot run in this image at all.
# semgrep needs --disable-version-check: its version ping is separate from
# --metrics=off and blocks ~96s with no network.
PROBES = {
    "semgrep": ["semgrep", "--version", "--disable-version-check"],
    "bandit": ["bandit", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "trivy": ["trivy", "--version"],
    "osv-scanner": ["osv-scanner", "--version"],
    "cargo-audit": ["cargo-audit", "--version"],
    "gosec": ["gosec", "-version"],
    "brakeman": ["brakeman", "--version"],
    "bundler-audit": ["bundle-audit", "version"],
    "pip-audit": ["pip-audit", "--version"],
    "eslint": ["eslint", "--version"],
    "spotbugs": ["/opt/spotbugs/bin/spotbugs", "-version"],
    "dependency-check": ["/opt/dependency-check/bin/dependency-check.sh", "--version"],
    "dotnet": ["dotnet", "--version"],
}

PROBE_TIMEOUT = 180


def check_writable(path, why):
    """True if the current user can create a file in path."""
    probe = os.path.join(
        path,
        ".panopticon-write-probe-%d-%s" % (os.getpid(), os.urandom(6).hex()),
    )
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(probe)
        return True, ""
    except OSError as e:
        return False, "%s not writable by uid %d (%s) — %s" % (
            path, os.getuid(), e.strerror, why)

def run_probe(name, argv):
    try:
        res = subprocess.run(argv, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=PROBE_TIMEOUT)
    except FileNotFoundError:
        return False, "%s: binary not found (%s)" % (name, argv[0])
    except subprocess.TimeoutExpired:
        return False, "%s: no response in %ds — a blocked call home or a lock wait" % (
            name, PROBE_TIMEOUT)
    if res.returncode != 0:
        tail = (res.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        return False, "%s: exited %d%s" % (
            name, res.returncode, (" — " + tail[-1][:160]) if tail else "")
    return True, ""


def main():
    failures = []

    for path, why in sorted(REQUIRED_WRITABLE.items()):
        if not os.path.isdir(path):
            failures.append("%s is missing — %s" % (path, why))
            continue
        ok, msg = check_writable(path, why)
        if not ok:
            failures.append(msg)

    for name in sorted(PROBES):
        ok, msg = run_probe(name, PROBES[name])
        if not ok:
            failures.append(msg)

    if failures:
        print("smoke-adapters: %d check(s) FAILED as uid %d\n"
              % (len(failures), os.getuid()), file=sys.stderr)
        for f in failures:
            print("  - %s" % f, file=sys.stderr)
        print("\nThe image assembled but cannot run these tools. Publishing it "
              "would ship adapters that silently produce nothing.", file=sys.stderr)
        return 1

    print("smoke-adapters: %d tools + %d writable paths OK as uid %d"
          % (len(PROBES), len(REQUIRED_WRITABLE), os.getuid()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
