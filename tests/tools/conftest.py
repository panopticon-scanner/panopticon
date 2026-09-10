"""Shared constants for the tools integration test sub-package."""
import os

# Define FIXTURE_ROOT for the tools sub-package so existing imports of the
# form ``from conftest import FIXTURE_ROOT`` resolve against this file.
FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures"),
)

OK_SCAN_EXIT_CODES = (0, 1)  # 0 = clean exit, 1 = findings detected

# #1528: a binary on PATH is NOT the precondition these adapters actually have.
# Every one of them depends on an asset baked into panopticon-tools -- semgrep's
# vendored rules at /opt/semgrep-rules, bandit's SARIF formatter, trivy's and
# osv-scanner's offline databases, the Go toolchain gosec shells out to, the
# eslint plugin loaded by absolute path. Measured: on a dev host with semgrep
# and bandit installed the adapters exit 7 and 2 respectively, because the
# ASSETS are missing. So gate on the image, and say so.
TOOLS_IMAGE_MARKER = "/opt/panopticon/scripts"


def in_tools_image():
    return os.path.isdir(TOOLS_IMAGE_MARKER)
