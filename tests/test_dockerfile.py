import os
import unittest
from pathlib import Path

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


class TestDockerfile(unittest.TestCase):
    def test_bundles_core_tools(self):
        with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
            text = fh.read().lower()
        for tool in ["semgrep", "gitleaks", "trivy", "bandit", "brakeman", "gosec", "eslint"]:
            self.assertIn(tool, text, tool)
        self.assertIn("useradd", text)  # non-root user created


class TestDockerfilePhase1(unittest.TestCase):
    def test_phase1_adapters_mentioned(self):
        text = (Path(ROOT) / "Dockerfile").read_text()
        self.assertIn("pip-audit", text)
        self.assertIn("osv-scanner", text)
        self.assertIn("eslint-plugin-security", text)


class TestOfflineAssets(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), os.pardir,
                               "Dockerfile")) as fh:
            self.text = fh.read()

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
        with open(os.path.join(os.path.dirname(__file__), os.pardir,
                               ".github", "workflows",
                               "docker-publish.yml")) as fh:
            wf = fh.read()
        self.assertIn('cron: "0 6 * * *"', wf)      # daily asset refresh
        self.assertIn("workflow_dispatch", wf)
        self.assertIn("promote_weekly", wf)          # emergency weekly bump
        self.assertIn("value=daily", wf)
        self.assertIn("value=weekly", wf)
        self.assertIn("ASSET_REFRESH", wf)           # cache-bust build-arg

    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)
