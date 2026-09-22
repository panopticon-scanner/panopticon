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
import threading

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

# #1576 (run-13 OPS-2542050329): the most combined stdout/stderr one probe may
# retain. A version probe emits a line; a malfunctioning or unexpectedly
# verbose scanner can emit at line rate for the whole PROBE_TIMEOUT, and the
# build worker used to hold every byte of it before even checking the exit
# code. Past this the head is kept and the rest is read-and-discarded (the
# child must never block on a full pipe), and the truncation is announced on
# stderr and named in the probe's failure message.
PROBE_OUTPUT_MAX_BYTES = 1 * 1024 * 1024

_ROSLYN_PROBE_SOURCE = """using System;
using System.Diagnostics;
class P {
    static void Main(string[] args) {
        var input = Console.ReadLine();
        var p = new Process();
        p.StartInfo.FileName = "exportLegacy.exe";
        p.StartInfo.Arguments = " -user " + input + " -role user";
        p.Start();
    }
}
"""


def check_roslyn_secguard_build(runner=subprocess.run):
    """Run a minimal C# project through the baked DotnetariumSCS standalone
    tool and require SARIF output containing an SCS finding. Mirrors the real
    adapter's invocation path; a plain `dotnet --version` probe cannot catch a
    missing or miswired scanner (#1110)."""
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
            "dotnetarium-scs", csproj,
            "--export=" + sarif,
            "--ignore-msbuild-errors",
            "--no-banner",
        ]
        try:
            runner(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=PROBE_TIMEOUT)
        except FileNotFoundError:
            return False, "roslyn-secguard build: dotnetarium-scs not found"
        except subprocess.TimeoutExpired:
            return False, "roslyn-secguard build: no response in %ds" % PROBE_TIMEOUT
        except OSError as e:
            return False, "roslyn-secguard build: failed to exec dotnetarium-scs (%s)" % (
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
        return False, "roslyn-secguard build: no DotnetariumSCS (SCS) findings in SARIF"


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

# Bandit ships its own SARIF formatter. The image used to install a second
# distribution under the same entry-point name, making formatter selection
# depend on metadata enumeration order. Exercise the real adapter format here,
# after checking that its single registered provider is Bandit itself.
BANDIT_SARIF_SCAN = ["bandit", "-q", "-f", "sarif"]

# A tiny file with an obvious shell-injection sink, so the scan has real code to
# load rules against. We do NOT assert on the finding COUNT (that would couple
# the gate to the vendored ruleset's contents); we assert only that scan emits
# valid, non-empty SARIF — which a startup crash never does.
_SEMGREP_FIXTURE = ("import subprocess\n"
                    "def run(cmd):\n"
                    "    subprocess.call(cmd, shell=True)\n")

# Kept as data and written only below into a TemporaryDirectory: no vulnerable
# Python fixture belongs in the source tree. B105 is stable and requires no
# execution, imports, network, or environment access from the control source.
_BANDIT_FIXTURE = 'password = "bandit-positive-control"\n'


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

def _read_capped(stream, cap=PROBE_OUTPUT_MAX_BYTES):
    """Read `stream` to EOF keeping at most `cap` bytes; return (kept, truncated).

    The same bounded-sink shape as `run_tools._stream_and_write` (#1111/#1510):
    stop ACCUMULATING at the cap but keep READING, because a producer left with
    a full pipe blocks on write and the probe then burns its whole timeout for
    nothing. The head is what is kept -- a scanner that cannot start says so
    immediately, and the alternative is buffering the flood to find its tail.
    """
    chunks: list[bytes] = []
    kept = 0
    truncated = False
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            return b"".join(chunks), truncated
        room = cap - kept
        if room <= 0:
            truncated = True
            continue                      # drain, unstored
        if len(chunk) > room:
            chunks.append(chunk[:room])
            kept = cap
            truncated = True
            continue
        chunks.append(chunk)
        kept += len(chunk)


def _run_probe_captured(name, argv, popen=subprocess.Popen,
                        accepted_returncodes=(0,), include_output_hint=True):
    """Run one probe under a byte cap and deadline; return its captured head.

    Popen rather than subprocess.run because run() buffers the ENTIRE output
    before it returns -- there is no point at which a cap could be applied
    (#1576). The deadline Popen lacks is restored by a watchdog, which also
    unblocks the read at EOF by killing the child.
    """
    try:
        proc = popen(argv, stdout=subprocess.PIPE,  # nosec B603
                     stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return False, "%s: binary not found (%s)" % (name, argv[0]), b""
    except OSError as e:
        return (False, "%s: failed to exec %s (%s)" % (
            name, argv[0], e.strerror or repr(e)), b"")

    timed_out = {"hit": False}

    def _watchdog():
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:                 # noqa: BLE001 - already gone is fine
            pass

    timer = threading.Timer(PROBE_TIMEOUT, _watchdog)
    timer.daemon = True
    timer.start()
    try:
        out, truncated = _read_capped(proc.stdout, PROBE_OUTPUT_MAX_BYTES)
        rc = proc.wait()                  # bounded: the watchdog guarantees exit
    finally:
        timer.cancel()
        try:
            proc.stdout.close()
        except Exception:                 # noqa: BLE001
            pass
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:             # noqa: BLE001
                pass
    # A watchdog kill lands rc < 0. Only call it a timeout when the child did
    # not finish cleanly first, so a probe that exits a hair before the deadline
    # is not misreported.
    if timed_out["hit"] and rc != 0:
        return (False,
                "%s: no response in %ds — a blocked call home or a lock wait" % (
                    name, PROBE_TIMEOUT), b"")
    if truncated:
        print("smoke-adapters: %s emitted more than PROBE_OUTPUT_MAX_BYTES (%d) "
              "on a probe; kept the first %d bytes and discarded the rest"
              % (name, PROBE_OUTPUT_MAX_BYTES, PROBE_OUTPUT_MAX_BYTES),
              file=sys.stderr)
    if rc not in accepted_returncodes:
        tail = (out.decode("utf-8", "replace").strip().splitlines()
                if include_output_hint else [])
        note = (" (output truncated at %d bytes)" % PROBE_OUTPUT_MAX_BYTES
                if truncated else "")
        return (False, "%s: exited %d%s%s" % (
            name, rc, (" — " + tail[-1][:160]) if tail else "", note), out)
    return True, "", out


def run_probe(name, argv, popen=subprocess.Popen):
    """Run one liveness probe under a byte cap and a wall-clock deadline."""
    ok, msg, _out = _run_probe_captured(name, argv, popen=popen)
    return ok, msg


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


def _entry_point_distribution_name(entry_point):
    """Return the normalized distribution name owning an entry point."""
    distribution = getattr(entry_point, "dist", None)
    name = getattr(distribution, "name", None)
    if not name and distribution is not None:
        try:
            name = distribution.metadata["Name"]
        except (KeyError, TypeError):
            name = None
    return str(name or "").lower().replace("_", "-")


def check_bandit_sarif(entry_points=None, runtime_version=None, capture=None):
    """Require Bandit's sole native SARIF formatter and real runtime metadata."""
    import json
    import tempfile

    if entry_points is None:
        from importlib import metadata
        entry_points = metadata.entry_points(group="bandit.formatters")
    sarif_entries = [entry for entry in entry_points
                     if getattr(entry, "name", None) == "sarif"]
    if len(sarif_entries) != 1:
        return (False,
                "bandit SARIF: expected exactly one 'bandit.formatters' "
                "entry named 'sarif'; found %d" % len(sarif_entries))

    entry = sarif_entries[0]
    provider = _entry_point_distribution_name(entry)
    target = getattr(entry, "value", None)
    if provider != "bandit" or target != "bandit.formatters.sarif:report":
        return (False,
                "bandit SARIF: formatter must be Bandit's native "
                "bandit.formatters.sarif:report; found provider=%r target=%r"
                % (provider or None, target))

    if runtime_version is None:
        import bandit
        runtime_version = bandit.__version__
    if not isinstance(runtime_version, str) or not runtime_version:
        return False, "bandit SARIF: installed Bandit runtime has no version"

    if capture is None:
        capture = _run_probe_captured
    with tempfile.TemporaryDirectory() as d:
        fixture = os.path.join(d, "probe.py")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write(_BANDIT_FIXTURE)
        ok, msg, output = capture(
            "bandit SARIF scan", BANDIT_SARIF_SCAN + [fixture],
            accepted_returncodes=(0, 1), include_output_hint=False)
    if not ok:
        return False, msg
    if not output.strip():
        return False, "bandit SARIF: scan produced empty output"
    try:
        document = json.loads(output)
    except (TypeError, ValueError):
        return False, "bandit SARIF: scan output is not valid JSON"
    if not isinstance(document, dict):
        return False, "bandit SARIF: scan output is not a SARIF object"
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        return False, "bandit SARIF: scan output has no valid run"
    run = runs[0]
    results = run.get("results")
    if not isinstance(results, list) or not results:
        return False, "bandit SARIF: positive-control scan has no findings"
    if not any(isinstance(result, dict) and result.get("ruleId") == "B105"
               for result in results):
        return False, "bandit SARIF: positive-control B105 finding is missing"
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict) or driver.get("name") != "Bandit":
        return False, "bandit SARIF: run has no Bandit tool driver"
    for field in ("version", "semanticVersion"):
        if driver.get(field) != runtime_version:
            return (False,
                    "bandit SARIF: driver.%s=%r does not match runtime %r"
                    % (field, driver.get(field), runtime_version))
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

    # Formatter ownership and real emission are separate contracts: the first
    # rejects duplicate providers, while the scan proves the selected native
    # formatter reports the installed runtime version in raw SARIF.
    ok, msg = check_bandit_sarif()
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

    print("smoke-adapters: %d tools + %d writable paths + semgrep/Bandit SARIF scans OK as uid %d"
          % (len(PROBES), len(REQUIRED_WRITABLE), os.getuid()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
