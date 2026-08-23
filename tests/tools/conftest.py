"""Shared constants for the tools integration test sub-package."""
import os

# Define FIXTURE_ROOT for the tools sub-package so existing imports of the
# form ``from conftest import FIXTURE_ROOT`` resolve against this file.
FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures"),
)

OK_SCAN_EXIT_CODES = (0, 1)  # 0 = clean exit, 1 = findings detected
