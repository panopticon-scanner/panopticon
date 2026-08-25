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
        # single-SHA shapes both).
        for artifact, sha_re in (
                ("/tmp/osv-scanner", r"OSV_SCANNER_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gitleaks.tar.gz", r"GITLEAKS_SHA256_(X64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gosec.tar.gz", r"GOSEC_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/dc.zip", r"DEPENDENCY_CHECK_SHA256=[0-9a-f]{64}")):
            self.assertRegex(self.text, sha_re, "no pinned SHA256 for %s" % artifact)
            self.assertRegex(
                self.text, artifact.replace(".", r"\.") + r'"\s*\|\s*sha256sum -c',
                "%s is not sha256sum-verified" % artifact)


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

    def test_publish_cadence_and_tags(self):
        with open(os.path.join(ROOT, ".github", "workflows",
                               "docker-publish.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        on = wf.get(True, {})
        self.assertEqual(on["schedule"][0]["cron"], "0 6 * * *")
        self.assertIn("workflow_dispatch", on)
        promote = on["workflow_dispatch"]["inputs"]["promote_weekly"]
        self.assertEqual(promote.get("type"), "boolean")
        self.assertFalse(promote.get("default", False))
        self.assertIn(
            "(github.event_name == 'schedule' && steps.cadence.outputs.weekly == 'true') || inputs.promote_weekly == true",
            str(wf["jobs"]["merge"]["steps"]),
        )

        # Negative regression: the weekly tag expression must live in the
        # metadata-action tags input, not just anywhere in the file.
        meta_step = next(
            s for s in wf["jobs"]["merge"]["steps"]
            if s.get("id") == "meta"
        )
        self.assertIn(
            "(github.event_name == 'schedule' && steps.cadence.outputs.weekly == 'true') || inputs.promote_weekly == true",
            meta_step["with"]["tags"],
        )

    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)


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
