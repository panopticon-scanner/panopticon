import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


def _read_dockerfile() -> str:
    with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
        return fh.read()


def _read_dockerfile_fixtures() -> str:
    with open(os.path.join(ROOT, "Dockerfile.fixtures"), encoding="utf-8") as fh:
        return fh.read()


class TestDockerfile(unittest.TestCase):
    def test_bundles_core_tools(self):
        text = _read_dockerfile().lower()
        for tool in ["semgrep", "gitleaks", "trivy", "bandit", "brakeman", "gosec", "eslint"]:
            self.assertIn(tool, text, tool)
        self.assertIn("useradd", text)  # non-root user created


class TestDockerfilePhase1(unittest.TestCase):
    def test_phase1_adapters_mentioned(self):
        text = _read_dockerfile()
        self.assertIn("pip-audit", text)
        self.assertIn("osv-scanner", text)
        self.assertIn("eslint-plugin-security", text)


class TestFindSecBugsIntegrity(unittest.TestCase):
    """#539: the FindSecBugs plugin jar is loaded as unsandboxed analyzer
    bytecode in the SpotBugs JVM and the image is published + rebuilt daily, so
    its download must be integrity-verified, not piped straight to disk."""

    def setUp(self):
        self.text = _read_dockerfile()

    def test_findsecbugs_digest_is_pinned_and_verified(self):
        self.assertRegex(self.text, r"FINDSECBUGS_SHA256=[0-9a-f]{64}")
        self.assertRegex(
            self.text,
            r'echo "\$\{FINDSECBUGS_SHA256\}\s+/opt/spotbugs/plugin/'
            r'findsecbugs-plugin\.jar"\s*\|\s*sha256sum -c'
        )

    def test_findsecbugs_uses_canonical_maven_path_not_scrape_endpoint(self):
        # The legacy remotecontent?filepath= scrape endpoint ships no checksum
        # sidecar; the canonical /maven2/ GAV path does.
        self.assertIn("repo1.maven.org/maven2/com/h3xstream/findsecbugs",
                      self.text)
        self.assertNotIn("remotecontent?filepath=", self.text)

    def test_all_fetched_binaries_are_checksum_verified(self):
        # #run7 TST-A2A: the checksum regression previously covered only
        # FindSecBugs; osv-scanner/gitleaks/gosec/dependency-check verify their
        # downloads too but had ZERO test, so dropping any `sha256sum -c` or SHA
        # pin passed the suite untouched. Lock all of them in (arch-split and
        # single-SHA shapes both), plus the rustup/dotnet installers and the
        # SpotBugs tarball added in Task 5.
        for artifact, sha_re in (
                ("/tmp/osv-scanner", r"OSV_SCANNER_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gitleaks.tar.gz", r"GITLEAKS_SHA256_(X64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gosec.tar.gz", r"GOSEC_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/dc.zip", r"DEPENDENCY_CHECK_SHA256=[0-9a-f]{64}"),
                ("/tmp/spotbugs.tgz", r"SPOTBUGS_SHA256=[0-9a-f]{64}"),
                ("/tmp/rustup-init", r"RUSTUP_INIT_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/dotnet-install.sh", r"DOTNET_INSTALL_SHA256=[0-9a-f]{64}")):
            self.assertRegex(self.text, sha_re, "no pinned SHA256 for %s" % artifact)
            self.assertRegex(
                self.text, artifact.replace(".", r"\.") + r'"\s*\|\s*sha256sum -c',
                "%s is not sha256sum-verified" % artifact)

    def test_dotnet_network_steps_are_timeout_bounded(self):
        # run-8 OPS-A1A: every network step in this file is `timeout`-wrapped so a
        # hung feed can't stall the build to the 120-min job cap. The two dotnet
        # steps (SDK download + `dotnet tool install`) were the exceptions.
        self.assertRegex(self.text, r"timeout \d+ /tmp/dotnet-install\.sh",
                         "dotnet SDK install has no timeout wrapper")
        self.assertRegex(self.text, r"timeout \d+ dotnet tool install",
                         "dotnet tool install has no timeout wrapper")


class TestOfflineAssets(unittest.TestCase):
    def setUp(self):
        self.text = _read_dockerfile()

    def test_offline_assets_baked(self):
        for marker in ["--download-db-only",          # trivy DB
                       "/opt/semgrep-rules",           # vendored rules
                       "advisory-db",                  # rustsec clone
                       "--download-offline-databases", # osv
                       "/opt/odc-data",                # dependency-check
                       "dotnetarium-scs"]:             # C# security scanner
            self.assertIn(marker, self.text)

    def test_nvd_db_from_pinned_cache_image_not_synced_at_build(self):
        # The NVD database is COPY'd from the cron-published cache image (the
        # "Refresh NVD data cache" workflow), not synced at build — so no build
        # hits the NVD API or needs a secret.
        self.assertIn("ARG NVD_DATA_REF", self.text)
        self.assertIn("AS nvd-data", self.text)
        self.assertIn("COPY --from=nvd-data /opt/odc-data /opt/odc-data", self.text)
        # the old build-time sync and its secret mount are gone
        self.assertNotIn("--mount=type=secret,id=nvd_api_key", self.text)
        self.assertNotIn("--updateonly", self.text)
        self.assertNotIn("ENV NVD_API_KEY", self.text)

    def test_nvd_data_ref_default_is_digest(self):
        # OPS-E1A: the default NVD cache ref must be content-pinned so PR and
        # local builds do not follow a mutable tag.
        self.assertRegex(
            self.text,
            r"ARG NVD_DATA_REF=.*@sha256:[0-9a-f]{64}"
        )

    def test_osv_warm_failures_are_visible(self):
        # SEC-E3B: OSV DB warm previously swallowed failures with `>/dev/null`.
        # The build must fail loud if a declared offline database was not
        # actually produced, and the scanner log must be surfaced.
        self.assertIn(
            '::error::OSV offline DB warm did not produce the $eco database', self.text
        )
        self.assertIn("cat /tmp/osv-warm.log >&2", self.text)

    def test_osv_warm_covers_every_applicable_ecosystem(self):
        # #calibration-1: the warm produced npm + PyPI only -- "the ecosystems
        # covered by the fixture corpus" -- so osv-scanner could not load a DB
        # for any other ecosystem, exited 127, produced no output, and SANK
        # CERTIFICATION on the first real (Go + RubyGems) target. Every
        # ecosystem OsvScannerAdapter.is_applicable accepts must be warmed, and
        # each must be verified, or the gap reappears silently on a new target.
        for manifest in ("package-lock.json", "requirements.txt", "go.mod",
                         "Gemfile.lock", "Cargo.lock", "pom.xml"):
            self.assertIn("/tmp/osv-warm/%s" % manifest, self.text, manifest)
        # ecosystem directory names are osv-scanner's own spelling, verified
        # against the pinned release -- not guessed
        for eco in ("npm", "PyPI", "Go", "RubyGems", "crates.io", "Maven"):
            self.assertIn(eco, self.text, eco)
        # #run7 review: scope the "no swallowed failures" check to the OSV warm
        # block. The old global assertNotIn(">/dev/null 2>&1") tripped on any
        # unrelated future use of that common idiom anywhere in the Dockerfile.
        # #run8 TST-B3A: assert both scoping markers exist FIRST, so renaming or
        # removing one fails as a diagnosable message naming the missing marker
        # rather than a bare IndexError from split(...)[1] on a one-element list.
        start_marker, end_marker = "mkdir -p /opt/osv-db", "rm -rf /tmp/osv-warm"
        self.assertIn(start_marker, self.text,
                      "OSV-warm block start marker missing from Dockerfile")
        self.assertIn(end_marker, self.text,
                      "OSV-warm block end marker missing from Dockerfile")
        osv_block = self.text.split(start_marker)[1].split(end_marker)[0]
        self.assertNotIn("/dev/null", osv_block)

    def test_gosec_has_the_go_toolchain_it_requires(self):
        # #calibration-4 (gotify): the image shipped the gosec BINARY but no Go
        # toolchain. gosec loads packages through go/packages, which shells out
        # to `go`; without it every package fails to load and gosec STILL EXITS
        # CLEANLY, writing a well-formed SARIF with zero results. That lands in
        # tool_manifest.produced, satisfies `missing: []`, and certifies the run
        # -- so a Go target got a scanner that reported success having read
        # nothing. Both Go targets scanned to date (fzf, gotify) had zero gosec
        # coverage: 185 real findings between them, silently absent. Worse than
        # the osv-scanner gap, which at least exited 127 and gated.
        self.assertIn("ARG GO_VERSION=", self.text, "no pinned Go toolchain")
        self.assertRegex(self.text, r"go\$\{GO_VERSION\}\.linux-",
                         "Go toolchain is not fetched from the pinned version")
        self.assertIn("ENV PATH=/usr/local/go/bin:$PATH", self.text,
                      "Go toolchain installed but not on PATH")
        # No network at scan time, so a target's go.mod must never be able to
        # send Go looking for a different toolchain to download.
        self.assertIn("ENV GOTOOLCHAIN=local", self.text)

    def test_gosec_is_proven_to_read_go_source_at_build(self):
        # A binary that runs is not a scanner that scans. The `Files: 0` failure
        # above is invisible in every signal the run records, so the only place
        # to catch it is the build: compile a module with one obvious finding
        # and fail unless gosec both LOADS it and REPORTS the issue. Mirrors the
        # per-ecosystem OSV warm verification, for the same reason.
        self.assertIn("/tmp/gosec-verify", self.text,
                      "no build-time proof that gosec can read Go source")
        self.assertIn("gosec read %d files / %d issues", self.text,
                      "gosec verification does not assert on files AND issues")
        start, end = "mkdir -p /tmp/gosec-verify", "rm -rf /tmp/gosec-verify"
        self.assertIn(start, self.text, "gosec-verify block start marker missing")
        self.assertIn(end, self.text, "gosec-verify block end marker missing")
        block = self.text.split(start)[1].split(end)[0]
        # The gosec invocation itself may not be silenced -- swallowing its
        # output is how the original defect stayed invisible for two runs.
        self.assertNotIn("/dev/null", block)

    def test_gosec_and_go_versions_are_compatible(self):
        # These two are a PAIR, not independent pins. gosec type-checks through
        # go/packages and cannot read export data from a toolchain newer than
        # the one it was built against: Go 1.27 + gosec 2.20.0 failed with
        # `internal error: package "errors" without types was imported`, which
        # is the same zero-coverage outcome by another route. Whoever bumps one
        # must bump the other, so assert both pins are present and explicit.
        go = re.search(r"ARG GO_VERSION=(\S+)", self.text)
        gosec = re.search(r"ARG GOSEC_VERSION=(\S+)", self.text)
        self.assertIsNotNone(go, "GO_VERSION pin missing")
        self.assertIsNotNone(gosec, "GOSEC_VERSION pin missing")
        self.assertRegex(go.group(1), r"^\d+\.\d+(\.\d+)?$")
        self.assertRegex(gosec.group(1), r"^\d+\.\d+(\.\d+)?$")
        self.assertIn("Bump these two together.", self.text,
                      "the Go/gosec version coupling is not documented at the pin")

    def test_publish_cadence_and_tags(self):
        with open(os.path.join(ROOT, ".github", "workflows",
                               "docker-publish.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        on = wf.get(True, {})
        sched = on.get("schedule") or []           # run-9 TST-B3A: guard the [0] index
        self.assertTrue(sched, "workflow has no schedule trigger")
        self.assertEqual(sched[0]["cron"], "0 6 * * *")
        self.assertIn("workflow_dispatch", on)
        promote = on["workflow_dispatch"]["inputs"]["promote_weekly"]
        self.assertEqual(promote.get("type"), "boolean")
        self.assertIn("default", promote)
        self.assertEqual(promote.get("default"), False)
        self.assertIn(
            "(github.event_name == 'schedule' && steps.cadence.outputs.weekly == 'true') || inputs.promote_weekly == true",
            str(wf["jobs"]["merge"]["steps"]),
        )

        # Negative regression: the weekly tag expression must live in the
        # metadata-action tags input, not just anywhere in the file.
        meta_step = next(
            (s for s in wf["jobs"]["merge"]["steps"]
             if s.get("id") == "meta"), None
        )
        self.assertIsNotNone(meta_step, "no 'meta' step in the merge job")  # TST-B3A
        self.assertIn(
            "(github.event_name == 'schedule' && steps.cadence.outputs.weekly == 'true') || inputs.promote_weekly == true",
            meta_step["with"]["tags"],
        )
        self.assertIn(
            "type=raw,value=daily,enable={{is_default_branch}}",
            meta_step["with"]["tags"],
        )

        # The workflow must pass the computed asset-refresh date into the
        # build-args so daily rebuilds bust the layers that embed $ASSET_REFRESH.
        build_step = next(
            (s for s in wf["jobs"]["build"]["steps"]
             if s.get("id") == "build"), None
        )
        self.assertIsNotNone(build_step, "no 'build' step in the build job")  # TST-B3A
        self.assertIn(
            "ASSET_REFRESH=${{ steps.cadence.outputs.date }}",
            build_step["with"]["build-args"],
        )

    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)


class TestDockerBuildPrWorkflow(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, ".github", "workflows",
                               "docker-build-pr.yml"), encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)

    def test_expanded_trigger_paths_present(self):
        on = self.wf.get(True, {})
        paths = on.get("pull_request", {}).get("paths", [])
        self.assertIn(".github/workflows/docker-build-pr.yml", paths)
        self.assertIn("skill/scripts/**", paths)

    def test_dockerfile_fixtures_is_trigger_and_built(self):
        on = self.wf.get(True, {})
        paths = on.get("pull_request", {}).get("paths", [])
        self.assertIn("Dockerfile.fixtures", paths)
        step_names = " ".join(
            s.get("name", "") for s in self.wf["jobs"]["build"]["steps"])
        self.assertIn("Build Dockerfile.fixtures", step_names)


class TestDockerfileFixtures(unittest.TestCase):
    def test_bundles_fixture_clone_refs_and_rust_build(self):
        text = _read_dockerfile_fixtures()
        for marker in [
            "ARG RAILS_GOAT_SHA",
            "ARG WEB_GOAT_SHA",
            "ARG ASP_GOAT_SHA",
            "COPY tests/fixtures/vulnerable-rust",
            "cargo build",
        ]:
            self.assertIn(marker, text, marker)

    def test_fixture_refs_are_pinned_shas_not_mutable_branches(self):
        # #1252 (SEC-E2C): the goat fixtures must be pinned to immutable commit
        # SHAs, never a mutable branch like `main` — a moving ref could swap the
        # vendored vulnerable corpus under us. Guards against re-introducing a
        # `--branch <name>` clone.
        text = _read_dockerfile_fixtures()
        self.assertNotIn("clone --branch", text)    # no `git clone --branch <ref>` mutable clone
        for arg in ("RAILS_GOAT_SHA", "WEB_GOAT_SHA", "ASP_GOAT_SHA"):
            m = re.search(r"ARG %s=([0-9a-f]+)" % arg, text)
            self.assertIsNotNone(m, "%s not found" % arg)
            self.assertRegex(m.group(1), r"^[0-9a-f]{40}$",
                             "%s must be a full 40-hex commit SHA, not a ref" % arg)


class TestDockerPublishWorkflow(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, ".github", "workflows",
                               "docker-publish.yml"), encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)

    def test_build_job_does_not_request_unused_id_token(self):
        perms = self.wf["jobs"]["build"]["permissions"]
        self.assertNotIn("id-token", perms)

    def test_merge_job_retains_id_token_for_attestation(self):
        perms = self.wf["jobs"]["merge"]["permissions"]
        self.assertEqual(perms.get("id-token"), "write")

    def test_concurrency_guard_is_configured(self):
        self.assertIn("concurrency", self.wf)
        self.assertTrue(self.wf["concurrency"]["group"])
