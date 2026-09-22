"""Pin against the #1742 (SEC-E3A) / #1877 class: no scanner adapter may be
invoked with cwd equal to, or inside, the scanned TARGET -- and every adapter
must NAME the directory it runs from.

Why this matters, generalized past cargo-audit's own bug: a scanner's cwd is
the directory ITS OWN config/dispatch resolution walks from. cargo is a
dispatcher that reads `.cargo/config.toml` upward from cwd and honours
`[alias]`; bundle-audit resolves its default `.bundler-audit.yml` against the
directory it scans; npm reads `.npmrc`, semgrep `.semgrepignore`, gitleaks
`.gitleaksignore`. Either lets a HOSTILE target plant a file that redirects
what the scanner does or reads, purely by virtue of `cwd=target`. The fix is
the shape pip-audit already used (#1646) and `base.scratch_cwd` now carries:
invoke from an empty scratch directory and name the target explicitly, by
path, in argv.

Three things are asserted, because a cwd can be wrong in three ways:
1. it is not the target, or inside it (#1742);
2. it is NAMED -- `cwd=None` is not "somewhere neutral" but "whatever the
   caller's cwd happens to be", and in the real deployment the caller is
   `_run_adapter.py` inside a container whose image ends `WORKDIR /src`, the
   target mount itself (#1877). A missing cwd is therefore counted as
   unproven, never as safe;
3. it is EMPTY at launch and gone afterwards -- a scratch that already holds
   files is a smaller version of the same problem, and one that outlives the
   run is a leak. The only entries permitted are the files the ADAPTER ITSELF
   generates there, named one by one in `_GENERATED_IN_CWD`.

This test iterates every registered adapter (`scripts.tools.ADAPTERS` --
per-instance, so the five LegacySarifAdapter tools, e.g. gosec vs. semgrep,
are checked independently even though they share one module), drives each
`invoke()` against a fresh fake target directory seeded with just enough of a
fixture to get past whatever `invoke()` itself expects to find (mirroring
each adapter's own `is_applicable` marker -- `invoke()` does not re-check
applicability, but several adapters branch or early-return without invoking
the scanner at all when their target has nothing to work with, which would
make the pin vacuously pass for them), and records every `cwd` the adapter's
scanner subprocess was launched with, plus what that directory held at the
moment of launch.

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

# Files an adapter GENERATES into its own scratch cwd before launching, named
# exactly, so "the scratch was empty" stays a real assertion rather than a
# blanket tolerance for whatever happens to be there.
_GENERATED_IN_CWD = {
    # The generated eslint flat config; the cwd IS the config dir (see
    # eslint_security.invoke), and nothing the target controls reaches it.
    "eslint-security": ["eslint.config.mjs"],
    # The empty `--config` bundle-audit is pinned to, which must live inside
    # the scratch so the target's own .bundler-audit.yml is never the default
    # (#1742 finding 3).
    "bundler-audit": ["empty-bundler-audit.yml"],
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
    return one record per launch.

    Each record is `{argv, cwd, existed, entries}`: `existed` and `entries`
    are read INSIDE the fake Popen -- i.e. at the instant the scanner would
    have started -- because that, not what the directory looks like after the
    adapter's `finally` has run, is what the scanner would have resolved its
    config against.
    """
    calls = []

    def _record(cmd, **kwargs):
        cwd = kwargs.get("cwd")
        existed = cwd is not None and os.path.isdir(cwd)
        calls.append({
            "argv": list(cmd),
            "cwd": cwd,
            "existed": existed,
            "entries": sorted(os.listdir(cwd)) if existed else None,
        })
        return FakePopen(stdout=b"", stderr=b"", returncode=0)

    with mock.patch("scripts.tools.base.subprocess.Popen", side_effect=_record):
        adapter.invoke(target)
    return calls


def _is_inside(name, cwd, root):
    """True when *cwd* -- the argument an adapter passed `run_tool`, for the
    adapter named *name* -- is the target, inside it, or UNPROVEN.

    #1877: `cwd=None` counts as the target for EVERY adapter, with no
    exception. `run_tool` -> `subprocess.Popen` with no `cwd` kwarg inherits
    the CALLING PROCESS's cwd, and in the real deployment that calling
    process is `_run_adapter.py` running inside the tools container, whose
    image ends `WORKDIR /src` (Dockerfile) -- and `/src` IS the target mount
    (`run_tools.py`'s `docker run ... -v target:/src:ro`). run_tools now
    passes `-w` on every dispatch, but that is the container-level BELT: an
    `invoke()` run anywhere else (a host-side test, a future runner) has no
    such dispatcher in front of it, so the adapter itself must still name its
    own cwd. A missing cwd is unproven, never neutral.
    """
    if cwd is None:
        return True
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
                for call in calls:
                    if (_is_inside(name, call["cwd"], root)
                            and name not in ALLOWED_TARGET_CWD):
                        offenders.append(
                            "%s: cwd=%r is the target (or inside it, or "
                            "unnamed); argv=%r"
                            % (name, call["cwd"], call["argv"]))
        self.assertEqual(
            offenders, [],
            "adapter(s) invoked their scanner with cwd inside the scanned "
            "target, or with no cwd at all (which is the container's "
            "`WORKDIR /src`, i.e. the target) -- a target can plant "
            "scanner-native dispatch/config there (#1742/#1877 class). Use "
            "`base.scratch_cwd`, or add to ALLOWED_TARGET_CWD with a "
            "reason:\n" + "\n".join(offenders))

    def test_every_scratch_cwd_is_empty_at_launch_and_gone_afterwards(self):
        # The cwd being "not the target" is not enough: a scratch that
        # already holds files is the same exposure at a smaller scale, and a
        # scratch that outlives invoke() is a leak that accumulates one
        # directory per tool per scan.
        for name, adapter in sorted(ADAPTERS.items()):
            if name in ALLOWED_TARGET_CWD:
                continue          # documented target cwd; not a scratch
            with self.subTest(adapter=name):
                _root, calls = self._invoke_in_fresh_target(name, adapter)
                permitted = _GENERATED_IN_CWD.get(name, [])
                for call in calls:
                    cwd = call["cwd"]
                    self.assertTrue(
                        call["existed"],
                        "%s: cwd %r did not exist when the scanner launched"
                        % (name, cwd))
                    self.assertEqual(
                        call["entries"], permitted,
                        "%s: the scratch cwd held %r at launch; only the "
                        "adapter's own generated files may be there, and "
                        "each must be named in _GENERATED_IN_CWD"
                        % (name, call["entries"]))
                    self.assertFalse(
                        os.path.exists(cwd),
                        "%s: the scratch cwd %r outlived invoke()"
                        % (name, cwd))

    def test_allowlisted_adapters_actually_need_target_cwd(self):
        # A stale allowlist entry -- one whose adapter no longer uses
        # cwd=target -- is an undocumented pass, not a documented one.
        for name, reason in ALLOWED_TARGET_CWD.items():
            with self.subTest(adapter=name):
                self.assertIn(name, ADAPTERS, "unknown adapter in allowlist")
                self.assertTrue(reason.strip(), "empty allowlist reason")
                root, calls = self._invoke_in_fresh_target(name, ADAPTERS[name])
                self.assertTrue(
                    any(_is_inside(name, c["cwd"], root) for c in calls),
                    "%s is allowlisted for cwd=target but no recorded call "
                    "actually used it -- the allowlist entry is stale" % name)

    def test_gosec_is_the_only_allowlisted_adapter(self):
        # #1877 closed the eleven inherited-WORKDIR entries this allowlist
        # used to carry. It is back to exactly one documented exception, and
        # a new entry must be argued for, not appended to a crowd.
        self.assertEqual(sorted(ALLOWED_TARGET_CWD), ["gosec"])

    def test_cargo_audit_and_bundler_audit_are_not_allowlisted(self):
        # The two adapters #1742 fixed must stay off the allowlist: they are
        # supposed to be CLEAN now, not documented exceptions.
        self.assertNotIn("cargo-audit", ALLOWED_TARGET_CWD)
        self.assertNotIn("bundler-audit", ALLOWED_TARGET_CWD)


if __name__ == "__main__":
    unittest.main()
