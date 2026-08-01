"""Pluggable static-analysis tool adapters for panopticon."""
from scripts.tools.pip_audit import PipAuditAdapter
from scripts.tools.npm_audit import NpmAuditAdapter
from scripts.tools.osv_scanner import OsvScannerAdapter
from scripts.tools.eslint_security import EslintSecurityAdapter
from scripts.tools.legacy_sarif import LegacySarifAdapter
from scripts.tools.brakeman import BrakemanAdapter
from scripts.tools.bundler_audit import BundlerAuditAdapter
from scripts.tools.spotbugs import SpotBugsAdapter
from scripts.tools.dependency_check import DependencyCheckAdapter

ADAPTERS = {
    "pip-audit": PipAuditAdapter(),
    "npm-audit": NpmAuditAdapter(),
    "osv-scanner": OsvScannerAdapter(),
    "eslint-security": EslintSecurityAdapter(),
    "semgrep": LegacySarifAdapter("semgrep"),
    "bandit": LegacySarifAdapter("bandit"),
    "trivy": LegacySarifAdapter("trivy"),
    "gitleaks": LegacySarifAdapter("gitleaks"),
    "gosec": LegacySarifAdapter("gosec"),
    "eslint": LegacySarifAdapter("eslint"),
    "brakeman": BrakemanAdapter(),
    "bundler-audit": BundlerAuditAdapter(),
    "spotbugs": SpotBugsAdapter(),
    "dependency-check": DependencyCheckAdapter(),
}
