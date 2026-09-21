"""Pin against the #1742 (SEC-E3A) class: no scanner adapter may be invoked
with cwd equal to, or inside, the scanned TARGET.

Why this matters, generalized past cargo-audit's own bug: a scanner's cwd is
the directory ITS OWN config/dispatch resolution walks from. cargo is a
dispatcher that reads `.cargo/config.toml` upward from cwd and honours
`[alias]`; bundle-audit resolves its default `.bundler-audit.yml` against the
directory it scans. Either lets a HOSTILE target plant a file that redirects
what the scanner does or reads, purely by virtue of `cwd=target`. The fix for
both (see cargo_audit.py / bundler_audit.py) is the same shape pip-audit
already used (#1646): invoke from an empty scratch directory and name the
target explicitly, by path, in argv.

This test iterates every registered adapter (`scripts.tools.ADAPTERS` --
per-instance, so the five LegacySarifAdapter tools, e.g. gosec vs. semgrep,
are checked independently even though they share one module), drives each
`invoke()` against a fresh fake target directory seeded with just enough of a
fixture to get past whatever `invoke()` itself expects to find (mirroring
each adapter's own `is_applicable` marker -- `invoke()` does not re-check
applicability, but several adapters branch or early-return without invoking
the scanner at all when their target has nothing to work with, which would
make the pin vacuously pass for them), and records every `cwd` the adapter's
scanner subprocess was launched with.

No adapter here bypasses `run_tool` for its scanner subprocess (verified by
inspection: the only other `subprocess.*` use under skill/scripts/tools/ is
egress.py's proxy sidecar, which is not part of any adapter's `invoke`), so
patching `scripts.tools.base.subprocess.Popen` -- `run_tool`'s one call site
-- is sufficient to observe every adapter's launch.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from _test_helpers import FakePopen
from scripts.tools import ADAPTERS


# Adapters that legitimately need cwd equal to (or inside) the target. An
# allowlist is a DOCUMENTED decision -- one line of reasoning per entry, not
# silence. Checked by test_allowlisted_adapters_actually_need_target_cwd
# below, so a stale entry (one that no longer uses the target as cwd) fails
# loudly instead of quietly becoming an unused exception.
ALLOWED_TARGET_CWD = {
    # gosec resolves the Go package(s) it analyses via `go list`-style,
    # CWD-RELATIVE package patterns (`./...`) through go/packages, which
    # shells out to the `go` binary and needs the target's go.mod on its
    # module search path from the working directory (see the Dockerfile's
    # own gosec comment: "gosec loads packages through go/packages, which
    # shells out to `go`"). gosec is a STATIC ANALYSER, not a dispatcher with
    # an alias table: unlike `cargo`, it has no external-subcommand/alias
    # mechanism a target could hijack merely by being the cwd. Nor does `go
    # list` read any PER-DIRECTORY config a target could plant: Go's own
    # environment overrides come only from the fixed $GOENV file (a path
    # outside any repository, not settable via `go env -w` from inside one)
    # or the process environment -- there is no "go.env" the target's tree
    # can carry. The one documented case of the Go toolchain executing
    # something merely by being invoked inside a module is CVE-2023-39320 (a
    # crafted `toolchain` directive in go.mod could run a script/binary
    # relative to the module root, on any `go` subcommand that reads go.mod,
    # `go list` included); the image pins Go 1.25.14 (Dockerfile `ARG
    # GO_VERSION`), released long after that September 2023 fix, so the one
    # known GOFLAGS/toolchain-adjacent execution vector is not live here.
    "gosec": (
        "static analyser (go/packages -> `go list`, cwd-relative package "
        "pattern via go.mod on the module search path); no alias/dispatcher "
        "surface like cargo's; no per-directory go.env exists for a target "
        "to plant; the one documented toolchain-execution vector on a bare "
        "`go` invocation inside a module (CVE-2023-39320, the go.mod "
        "`toolchain` directive) was fixed well before the pinned Go 1.25.14"
    ),
}


def _seed_fixture(name, root):
    """Write just enough of a fake tree that *name*'s invoke() takes its real
    code path (the one that launches a scanner subprocess) instead of an
    early return for "nothing to scan here" -- mirroring each adapter's own
    is_applicable marker. Adapters that always invoke regardless (no gate
    inside invoke() itself) get nothing; harmless either way.
    """
    if name == "cargo-audit":
        open(os.path.join(root, "Cargo.lock"), "w").close()
    elif name == "bundler-audit":
        open(os.path.join(root, "Gemfile.lock"), "w").close()
    elif name == "pip-audit":
        with open(os.path.join(root, "requirements.txt"), "w") as fh:
            fh.write("flask==1.0.0\n")
    elif name == "eslint-security":
        with open(os.path.join(root, "index.js"), "w") as fh:
            fh.write("console.log(1);\n")
    elif name == "npm-audit":
        with open(os.path.join(root, "package-lock.json"), "w") as fh:
            fh.write("{}\n")
    elif name == "brakeman":
        os.makedirs(os.path.join(root, "config"), exist_ok=True)
        open(os.path.join(root, "config", "routes.rb"), "w").close()
    elif name == "spotbugs":
        open(os.path.join(root, "pom.xml"), "w").close()
        os.makedirs(os.path.join(root, "target", "classes"), exist_ok=True)
    elif name == "dependency-check":
        open(os.path.join(root, "pom.xml"), "w").close()
        with open(os.path.join(root, "app.jar"), "w") as fh:
            fh.write("not a real jar\n")
    elif name == "roslyn-secguard":
        open(os.path.join(root, "app.csproj"), "w").close()
        os.makedirs(os.path.join(root, "obj"), exist_ok=True)
        open(os.path.join(root, "obj", "project.assets.json"), "w").close()
    # osv-scanner, semgrep/bandit/trivy/gitleaks/gosec: invoke() launches the
    # scanner unconditionally (applicability is enforced by the DRIVER, not
    # inside invoke() itself), so no fixture is needed to exercise them.


def _record_popen_calls(adapter, target):
    """Run *adapter*.invoke(target) with its scanner subprocess faked, and
    return every (argv, cwd) the fake Popen was launched with."""
    calls = []

    def _record(cmd, **kwargs):
        calls.append((list(cmd), kwargs.get("cwd")))
        return FakePopen(stdout=b"", stderr=b"", returncode=0)

    with mock.patch("scripts.tools.base.subprocess.Popen", side_effect=_record):
        adapter.invoke(target)
    return calls


def _is_inside(cwd, root):
    if cwd is None:
        return False
    cwd_real = os.path.realpath(cwd)
    root_real = os.path.realpath(root)
    return cwd_real == root_real or cwd_real.startswith(root_real + os.sep)


class TestAdapterCwdConfinement(unittest.TestCase):
    def _invoke_in_fresh_target(self, name, adapter):
        root = tempfile.mkdtemp(prefix="cwd-confine-%s-" % name.replace("/", "_"))
        try:
            _seed_fixture(name, root)
            return root, _record_popen_calls(adapter, root)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_no_undocumented_adapter_invokes_with_cwd_inside_target(self):
        offenders = []
        for name, adapter in sorted(ADAPTERS.items()):
            with self.subTest(adapter=name):
                root, calls = self._invoke_in_fresh_target(name, adapter)
                self.assertTrue(
                    calls,
                    "%s: invoke() launched nothing -- the pin cannot verify "
                    "this adapter's cwd; give it a fixture in _seed_fixture "
                    "or confirm it never scans" % name)
                for cmd, cwd in calls:
                    if _is_inside(cwd, root) and name not in ALLOWED_TARGET_CWD:
                        offenders.append(
                            "%s: cwd=%r is the target (or inside it); argv=%r"
                            % (name, cwd, cmd))
        self.assertEqual(
            offenders, [],
            "adapter(s) invoked their scanner with cwd inside the scanned "
            "target -- a target can plant scanner-native dispatch/config "
            "there (#1742 class). Add to ALLOWED_TARGET_CWD with a reason if "
            "this is legitimate, or fix the adapter:\n" + "\n".join(offenders))

    def test_allowlisted_adapters_actually_need_target_cwd(self):
        # A stale allowlist entry -- one whose adapter no longer uses
        # cwd=target -- is an undocumented pass, not a documented one.
        for name, reason in ALLOWED_TARGET_CWD.items():
            with self.subTest(adapter=name):
                self.assertIn(name, ADAPTERS, "unknown adapter in allowlist")
                self.assertTrue(reason.strip(), "empty allowlist reason")
                root, calls = self._invoke_in_fresh_target(name, ADAPTERS[name])
                self.assertTrue(
                    any(_is_inside(cwd, root) for _cmd, cwd in calls),
                    "%s is allowlisted for cwd=target but no recorded call "
                    "actually used it -- the allowlist entry is stale" % name)

    def test_cargo_audit_and_bundler_audit_are_not_allowlisted(self):
        # The two adapters #1742 fixed must stay off the allowlist: they are
        # supposed to be CLEAN now, not documented exceptions.
        self.assertNotIn("cargo-audit", ALLOWED_TARGET_CWD)
        self.assertNotIn("bundler-audit", ALLOWED_TARGET_CWD)


if __name__ == "__main__":
    unittest.main()
