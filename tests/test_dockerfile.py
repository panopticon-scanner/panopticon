import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


def _read_dockerfile() -> str:
    with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
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
        self.assertRegex(self.text, r'echo "\$\{FINDSECBUGS_SHA256\}\s+/opt/spotbugs/plugin/findsecbugs-plugin\.jar"\s*\|\s*sha256sum -c')

    def test_findsecbugs_uses_canonical_maven_path_not_scrape_endpoint(self):
        # The legacy remotecontent?filepath= scrape endpoint ships no checksum
        # sidecar; the canonical /maven2/ GAV path does.
        self.assertIn("repo1.maven.org/maven2/com/h3xstream/findsecbugs",
                      self.text)
        self.assertNotIn("remotecontent?filepath=", self.text)


class TestOfflineAssets(unittest.TestCase):
    def setUp(self):
        self.text = _read_dockerfile()

    def test_offline_assets_baked(self):
        for marker in ["--download-db-only",          # trivy DB
                       "/opt/semgrep-rules",           # vendored rules
                       "advisory-db",                  # rustsec clone
                       "--download-offline-databases", # osv
                       "/opt/odc-data",                # dependency-check
                       "/opt/nuget-packages",          # SCS offline feed
                       "fallbackPackageFolders"]:      # nuget.config wiring
            self.assertIn(marker, self.text)

    def test_nvd_key_is_buildkit_secret_not_env(self):
        self.assertIn("--mount=type=secret,id=nvd_api_key", self.text)
        self.assertNotIn("ENV NVD_API_KEY", self.text)

    def test_publish_cadence_and_tags(self):
        with open(os.path.join(ROOT, ".github", "workflows",
                               "docker-publish.yml"), encoding="utf-8") as fh:
            wf = fh.read()
        self.assertIn('cron: "0 6 * * *"', wf)      # daily asset refresh
        self.assertIn("workflow_dispatch", wf)
        self.assertIn("promote_weekly", wf)          # emergency weekly bump
        self.assertIn("value=daily", wf)
        self.assertIn("value=weekly", wf)
        self.assertIn("ASSET_REFRESH", wf)           # cache-bust build-arg

    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)
