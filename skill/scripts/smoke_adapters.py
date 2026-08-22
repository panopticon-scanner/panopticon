#!/usr/bin/env python3
"""Assert every bundled scanner can actually execute as the scanner user.

Run inside the image, as uid 1000, at build time. Building and pushing an
image proves only that the layers assembled — not that a single tool can run
in it. Two real regressions shipped through that gap:

  * semgrep could not create ``~/.semgrep`` because ``$HOME`` was root-owned,
    so it died on startup and wrote a 0-byte SARIF that read as "no findings"
    (#455). Guarded two ways here: ``$HOME`` must be writable (below), AND the
    real ``semgrep scan`` argv must emit valid SARIF (``check_semgrep_scan``) —
    a ``--version`` probe never reaches the ~/.semgrep-creation path.
  * dependency-check could not lock ``odc.mv.db`` because ``/opt/odc-data``
    was ``chmod a+rX``; H2 blocks rather than failing, so every scan burned
    its full 900s timeout and returned nothing (#451).

Both were invisible to CI, which never executed the image. Both are caught
here in about a second.

Exit 0 when every check passes; exit 1 with a report naming each failure.
Stdlib plus project-local imports only — no third-party dependencies. This must
run before anything else is proven to work.
"""
import os
import subprocess
import sys

from scripts.run_tools import recommendable_tools

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


def _validate_probe_registry(probes):
    """Ensure the probe set stays locked to the adapter registry."""
    expected = set(recommendable_tools())
    actual = set(probes)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        raise RuntimeError(
            "smoke_adapters PROBES drift from recommendable_tools(): "
            "missing=%s extra=%s" % (sorted(missing), sorted(extra))
        )


PROBE_TIMEOUT = 180

_ROSLYN_PROBE_SOURCE = """using System.Diagnostics;
class P {
    static void Main(string[] args) {
        Process.Start(args[0]);
    }
}
"""


def check_roslyn_secguard_build(runner=subprocess.run):
    """Run a minimal C# build with the baked SecurityCodeScan analyzer and
    require SARIF output containing an SCS finding. Mirrors the real adapter's
    build path; a plain `dotnet --version` probe cannot catch a missing or
    miswired analyzer (#1110)."""
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        proj_dir = os.path.join(d, "p")
        os.makedirs(proj_dir)
        csproj = os.path.join(proj_dir, "p.csproj")
        with open(csproj, "w", encoding="utf-8") as fh:
            fh.write(
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                '  <PropertyGroup>\n'
                '    <OutputType>Exe</OutputType>\n'
                '    <TargetFramework>net8.0</TargetFramework>\n'
                '  </PropertyGroup>\n'
                '</Project>\n'
            )
        program = os.path.join(proj_dir, "Program.cs")
        with open(program, "w", encoding="utf-8") as fh:
            fh.write(_ROSLYN_PROBE_SOURCE)
        sarif = os.path.join(d, "out.sarif")
        cmd = [
            "dotnet", "build", csproj,
            "-p:TreatWarningsAsErrors=false",
            "-p:ErrorLog=" + sarif + ",version=2.1",
        ]
        try:
            runner(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=PROBE_TIMEOUT)
        except FileNotFoundError:
            return False, "roslyn-secguard build: dotnet not found"
        except subprocess.TimeoutExpired:
            return False, "roslyn-secguard build: no response in %ds" % PROBE_TIMEOUT
        except OSError as e:
            return False, "roslyn-secguard build: failed to exec dotnet (%s)" % (
                e.strerror or repr(e))
        if not os.path.exists(sarif):
            return False, "roslyn-secguard build: no SARIF output produced"
        with open(sarif, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except ValueError as e:
                return False, "roslyn-secguard build: SARIF is not valid JSON (%s)" % e
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                if rule_id.startswith("SCS"):
                    return True, ""
        return False, "roslyn-secguard build: no SecurityCodeScan (SCS) findings in SARIF"


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
    "spotbugs": ["/opt/spotbugs/bin/spotbugs", "-version"],
    "dependency-check": ["/opt/dependency-check/bin/dependency-check.sh", "--version"],
    "npm-audit": ["npm", "--version"],
    "eslint-security": ["eslint", "--version"],
    "roslyn-secguard": check_roslyn_secguard_build,
}

_validate_probe_registry(PROBES)

# The direct end-to-end gate for the #455 regression. A `semgrep --version`
# probe and a writable-$HOME assertion are both PROXIES: version never creates
# ~/.semgrep, and a writable $HOME is necessary but not sufficient (a bad rule
# in /opt/semgrep-rules, or any other startup fault, still yields the 0-byte
# SARIF that reads as "no findings"). Running the REAL adapter argv against a
# fixture exercises the whole path — startup + ~/.semgrep creation + rule load +
# SARIF emission — so the only way it passes is if `semgrep scan` genuinely
# works in this image. Mirrors tools/legacy_sarif.py's TOOL_CMD["semgrep"].
SEMGREP_SCAN = ["semgrep", "scan", "--config", "/opt/semgrep-rules",
                "--metrics=off", "--disable-version-check", "--sarif", "--quiet"]

# A tiny file with an obvious shell-injection sink, so the scan has real code to
# load rules against. We do NOT assert on the finding COUNT (that would couple
# the gate to the vendored ruleset's contents); we assert only that scan emits
# valid, non-empty SARIF — which a startup crash never does.
_SEMGREP_FIXTURE = ("import subprocess\n"
                    "def run(cmd):\n"
                    "    subprocess.call(cmd, shell=True)\n")


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
        res = subprocess.run(  # nosec B603
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=PROBE_TIMEOUT,
        )
    except FileNotFoundError:
        return False, "%s: binary not found (%s)" % (name, argv[0])
    except subprocess.TimeoutExpired:
        return False, "%s: no response in %ds — a blocked call home or a lock wait" % (
            name, PROBE_TIMEOUT)
    except OSError as e:
        return False, "%s: failed to exec %s (%s)" % (
            name, argv[0], e.strerror or repr(e))
    if res.returncode != 0:
        tail = (res.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        return False, "%s: exited %d%s" % (
            name, res.returncode, (" — " + tail[-1][:160]) if tail else "")
    return True, ""


def check_semgrep_scan(runner=subprocess.run):
    """Run the real `semgrep scan` adapter argv against a fixture and require
    valid, non-empty SARIF. This is the direct gate for #455 (a `--version`
    probe cannot reach the ~/.semgrep-creation path). The exit CODE alone can't
    catch the crash — semgrep exits 1 both for 'findings present' (clean) and
    for the startup crash — so the load-bearing assertion is that stdout is
    non-empty, parseable SARIF; the crash writes 0 bytes. `runner` is injectable
    for tests."""
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        fixture = os.path.join(d, "probe.py")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write(_SEMGREP_FIXTURE)
        try:
            res = runner(SEMGREP_SCAN + [fixture], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=PROBE_TIMEOUT)
        except FileNotFoundError:
            return False, "semgrep scan: binary not found (%s)" % SEMGREP_SCAN[0]
        except subprocess.TimeoutExpired:
            return False, "semgrep scan: no response in %ds" % PROBE_TIMEOUT
        except OSError as e:
            return False, "semgrep scan: failed to exec (%s)" % (e.strerror or repr(e))
    stderr_tail = (res.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    hint = (" — " + stderr_tail[-1][:200]) if stderr_tail else ""
    # exit 0 = clean, 1 = findings present; anything else is a real failure.
    if res.returncode not in (0, 1):
        return False, "semgrep scan: exited %d%s" % (res.returncode, hint)
    if not (res.stdout or b"").strip():
        return False, ("semgrep scan: produced EMPTY output — the #455 0-byte "
                       "SARIF crash (root-owned $HOME blocks ~/.semgrep)%s" % hint)
    try:
        sarif = json.loads(res.stdout)
    except ValueError as e:
        return False, "semgrep scan: output is not valid SARIF JSON (%s)" % e
    if not isinstance(sarif, dict) or "runs" not in sarif:
        return False, "semgrep scan: output JSON is not SARIF (no 'runs' key)"
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
        probe = PROBES[name]
        if callable(probe):
            ok, msg = probe()
        else:
            ok, msg = run_probe(name, probe)
        if not ok:
            failures.append(msg)

    # End-to-end gate: the liveness probe above only proves `semgrep --version`
    # runs; this proves `semgrep scan` produces real SARIF (#455).
    ok, msg = check_semgrep_scan()
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

    print("smoke-adapters: %d tools + %d writable paths + semgrep scan OK as uid %d"
          % (len(PROBES), len(REQUIRED_WRITABLE), os.getuid()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
