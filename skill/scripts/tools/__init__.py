"""Pluggable static-analysis tool adapters for panopticon."""
from .pip_audit import PipAuditAdapter
from .npm_audit import NpmAuditAdapter
from .osv_scanner import OsvScannerAdapter
from .eslint_security import EslintSecurityAdapter
from .legacy_sarif import LegacySarifAdapter
from .brakeman import BrakemanAdapter
from .bundler_audit import BundlerAuditAdapter
from .spotbugs import SpotBugsAdapter
from .dependency_check import DependencyCheckAdapter
from .cargo_audit import CargoAuditAdapter
from .roslyn_secguard import RoslynSecGuardAdapter

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
    "brakeman": BrakemanAdapter(),
    "bundler-audit": BundlerAuditAdapter(),
    "spotbugs": SpotBugsAdapter(),
    "dependency-check": DependencyCheckAdapter(),
    "cargo-audit": CargoAuditAdapter(),
    "roslyn-secguard": RoslynSecGuardAdapter(),
}

# Adapters that execute target build logic (contained: no network, no
# secrets, read-only mounts). Recorded in report meta by synthesize.
EXECUTES_TARGET_BUILD = frozenset({"roslyn-secguard"})

# Adapters with no offline mode (live advisory-API clients); dispatched only
# under run_tools --online. Offline substitute: osv-scanner's baked DBs.
ONLINE_ONLY = frozenset({"pip-audit", "npm-audit"})
