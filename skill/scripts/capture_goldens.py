"""Capture one authentic raw payload per tool adapter, trimmed to a few findings.

Runs INSIDE the fixtures image, where every adapter has a target that actually
produces findings. The output seeds a normalization-contract test, so the
payloads must be real tool output rather than hand-written approximations --
the whole point is to prove parse() handles what the tools really emit.
"""
import argparse
import json
import os
import sys

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.run_tools import _redact_capture  # noqa: E402
from scripts.tools import ADAPTERS  # noqa: E402

# The image layout as configuration (#1654): a hardcoded /opt/panopticon
# import root above and a fixed TARGETS table below meant that moving a mount
# or a fixture root required editing this file in lockstep with the
# Dockerfiles. Each root is an environment variable, today's value as the
# default, overridable per-run by a CLI flag (see _build_parser/main).
DEFAULT_FIXTURES_ROOT = "/opt/panopticon-fixtures"
DEFAULT_SRC_ROOT = "/src"
DEFAULT_PROBES_ROOT = "/mnt"
ENV_FIXTURES_ROOT = "PANOPTICON_FIXTURES_ROOT"
ENV_SRC_ROOT = "PANOPTICON_SRC_ROOT"
ENV_PROBES_ROOT = "PANOPTICON_PROBES_ROOT"


def targets(fixtures_root=DEFAULT_FIXTURES_ROOT, src_root=DEFAULT_SRC_ROOT,
            probes_root=DEFAULT_PROBES_ROOT) -> dict[str, str]:
    """The tool -> scan-target mapping for one image layout.

    Three roots make up the whole layout. `fixtures_root` holds the real
    vulnerable corpora baked into the fixtures image (railsgoat, WebGoat,
    AspGoat, vulnerable-rust). `probes_root` holds the /mnt-style
    single-purpose probe mounts (gosec's Go module, the npm/pip lockfile
    probes). `src_root` is the fourth kind of mount, explained below.
    """
    return {
        "brakeman": f"{fixtures_root}/railsgoat",
        "bundler-audit": f"{fixtures_root}/railsgoat",
        "semgrep": f"{fixtures_root}/railsgoat",
        "spotbugs": f"{fixtures_root}/WebGoat",
        "dependency-check": f"{fixtures_root}/WebGoat",
        "roslyn-secguard": f"{fixtures_root}/AspGoat",
        "cargo-audit": f"{fixtures_root}/vulnerable-rust",
        # /src, never the operator's own checkout: these three used to point at
        # /mnt/panopticon, so gitleaks scanned the real working tree -- .env and all
        # -- and #run12 committed the live key it found into a public golden. The
        # goldens README already documented them as /src-mounted (pass 2); only this
        # table disagreed. Refreshing gitleaks now needs a target that carries
        # SYNTHETIC secrets, which is the point.
        "bandit": src_root,
        "gitleaks": src_root,
        "trivy": src_root,
        "osv-scanner": src_root,
        "gosec": f"{probes_root}/gotify",
        "eslint-security": src_root,       # mounted at /src: eslint's flat config
                                           # ignores files outside its base path
        "npm-audit": f"{probes_root}/npmprobe",
        "pip-audit": f"{probes_root}/pipprobe",
    }


# The resolved default table, kept as a module attribute (not only the
# `targets()` builder) so a test can substitute the whole mapping with
# `mock.patch.object(cg, "TARGETS", {...})`: main() reads the bare name
# `TARGETS`, looked up at call time, so the patch is visible for the call.
TARGETS = targets()

# Where each format keeps its finding list, so a trim keeps the envelope intact.
LIST_KEYS = ("warnings", "results", "dependencies", "vulnerabilities", "advisories")
KEEP = 3


def _trim_xml(raw: bytes) -> bytes:
    """Keep the first KEEP finding elements of an XML report, still well-formed."""
    try:
        root = ET.fromstring(raw.decode("utf-8", "replace"), forbid_dtd=True)
    except (ET.ParseError, DefusedXmlException):
        return raw
    kept = 0
    for child in list(root):
        if child.tag in ("BugInstance", "result", "finding"):
            kept += 1
            if kept > KEEP:
                root.remove(child)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _has_vulns_osv(pkg) -> bool:
    return bool(isinstance(pkg, dict) and pkg.get("vulnerabilities"))


def _has_vulns(entry) -> bool:
    """dependency-check lists every dependency it saw, and most are clean.
    Keeping the first N kept 3 clean ones and produced a golden that parsed to
    ZERO findings -- a golden that proves nothing. Prefer the entries that
    actually carry vulnerabilities."""
    return bool(isinstance(entry, dict) and entry.get("vulnerabilities"))


def trim(raw: bytes) -> bytes:
    """Shrink a payload to a few findings without changing its shape.

    XML is trimmed structurally, never sliced: spotbugs emits a BugCollection
    document, and cutting it at a byte offset produced an unclosed element that
    no longer parsed. A golden that cannot be parsed is worse than a large one,
    but 579 KB of it is not worth committing either -- so drop whole
    BugInstance elements and keep the document well-formed.
    """
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return _trim_xml(raw)
    if isinstance(data, list):
        return json.dumps(data[:KEEP], indent=1).encode()
    if isinstance(data, dict):
        if "runs" in data and isinstance(data["runs"], list):      # SARIF
            data["runs"] = data["runs"][:1]
            for run in data["runs"]:
                if isinstance(run.get("results"), list):
                    run["results"] = run["results"][:KEEP]
                # rules can be enormous; keep enough to resolve the results
                drv = (run.get("tool") or {}).get("driver") or {}
                if isinstance(drv.get("rules"), list):
                    drv["rules"] = drv["rules"][:10]
        else:
            # osv-scanner nests two levels deep (results[].packages[]), so a
            # trim of `results` alone leaves every package behind it -- 243 KB.
            if isinstance(data.get("results"), list) and any(
                    isinstance(r, dict) and "packages" in r for r in data["results"]):
                results = []
                for r in data["results"][:1]:
                    pkgs = r.get("packages") or []
                    vuln_pkgs = [pk for pk in pkgs if _has_vulns_osv(pk)]
                    r = dict(r)
                    r["packages"] = (vuln_pkgs or pkgs)[:KEEP]
                    results.append(r)
                data["results"] = results
            for k in LIST_KEYS:
                v = data.get(k)
                if isinstance(v, list):
                    # Findings-bearing entries first, so the trim cannot leave a
                    # golden that parses to nothing.
                    interesting = [e for e in v if _has_vulns(e)]
                    data[k] = (interesting[:KEEP] if interesting else v[:KEEP])
                elif isinstance(v, dict):
                    data[k] = dict(list(v.items())[:KEEP])
        return json.dumps(data, indent=1).encode()
    return raw


def redact_bytes(raw: bytes):
    """Mask secrets in a payload that is about to be COMMITTED. -> (bytes, fired)

    Three adapters below scan /mnt/panopticon -- the operator's own checkout --
    so a real .env sits in gitleaks' path, and #run12 committed a live API key
    into a public golden because nothing here looked. Capture is the last point
    where a secret can be stopped before it enters git history, where removing
    it costs a rewrite rather than an edit.

    Delegates to `run_tools._redact_capture` -- the PRODUCTION capture pass
    (#1639 P11) -- rather than running a second flat sweep of its own. These
    files are the goldens a real capture is tested against, so they have to be
    masked with the same semantics a real capture gets: parse a JSON payload and
    walk its string leaves (a flat sweep cannot tell a key from a value, and
    silently renamed a bandit metrics key that held a UUID-shaped path), flat
    pass for XML, original bytes back when nothing fired.

    `fired` is a byte comparison for the same reason the pass short-circuits:
    a clean payload is never round-tripped through a lossy decode/encode, so a
    golden stays byte-identical to what the tool really emitted.
    """
    masked = _redact_capture("golden", raw)
    return masked, masked != raw


def _target_override(value):
    """argparse `type=` for `--target NAME=PATH`.

    NAME must be a registered adapter and the value must contain '=';
    raising ArgumentTypeError for either turns the mistake into an ordinary
    argparse usage error (exit 2) rather than a KeyError deep in main().
    """
    name, sep, path = value.partition("=")
    if not sep:
        raise argparse.ArgumentTypeError(
            "--target must be NAME=PATH (no '=' in %r)" % value)
    if name not in ADAPTERS:
        raise argparse.ArgumentTypeError(
            "--target: %r is not a registered adapter" % name)
    return name, path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture one authentic raw payload per tool adapter.")
    parser.add_argument("out_dir")
    parser.add_argument("names", nargs="*",
                        help="adapter names to capture (default: all registered)")
    parser.add_argument("--fixtures-root", default=None,
                        help="default: $%s or %r" %
                        (ENV_FIXTURES_ROOT, DEFAULT_FIXTURES_ROOT))
    parser.add_argument("--src-root", default=None,
                        help="default: $%s or %r" % (ENV_SRC_ROOT, DEFAULT_SRC_ROOT))
    parser.add_argument("--probes-root", default=None,
                        help="default: $%s or %r" %
                        (ENV_PROBES_ROOT, DEFAULT_PROBES_ROOT))
    parser.add_argument("--target", action="append", default=[],
                        type=_target_override, metavar="NAME=PATH",
                        help="override one adapter's target (repeatable)")
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    only = args.names or sorted(ADAPTERS)

    fixtures_root = args.fixtures_root or os.environ.get(
        ENV_FIXTURES_ROOT, DEFAULT_FIXTURES_ROOT)
    src_root = args.src_root or os.environ.get(ENV_SRC_ROOT, DEFAULT_SRC_ROOT)
    probes_root = args.probes_root or os.environ.get(
        ENV_PROBES_ROOT, DEFAULT_PROBES_ROOT)
    if (fixtures_root, src_root, probes_root) == (
            DEFAULT_FIXTURES_ROOT, DEFAULT_SRC_ROOT, DEFAULT_PROBES_ROOT):
        # No root was customized by flag or environment: read the (possibly
        # test-substituted) module-level table rather than rebuilding it.
        target_map = dict(TARGETS)
    else:
        target_map = targets(fixtures_root, src_root, probes_root)
    target_map.update(args.target)   # --target NAME=PATH wins outright

    report: dict[str, dict[str, str | int | None]] = {}
    for name in only:
        adapter = ADAPTERS.get(name)
        target = target_map.get(name)
        if adapter is None or target is None or not os.path.isdir(target):
            report[name] = {"status": "no-target", "target": target}
            continue
        try:
            applicable = adapter.is_applicable(target)
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "is_applicable-error", "error": str(exc)[:120]}
            continue
        if not applicable:
            report[name] = {"status": "not-applicable", "target": target}
            continue
        try:
            raw, rc = adapter.invoke(target)
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "invoke-error", "error": str(exc)[:160]}
            continue
        try:
            parsed = adapter.parse(raw, "Probe")
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "parse-error", "rc": rc,
                            "error": str(exc)[:160], "bytes": len(raw)}
            continue
        small = trim(raw)
        # Redact BEFORE the check below, so what is verified is what is written.
        small, redacted = redact_bytes(small)
        # A trimmed payload must still parse, or the golden is useless.
        try:
            reparsed = adapter.parse(small, "Probe")
        except Exception as exc:                      # noqa: BLE001
            report[name] = {"status": "trim-broke-parse", "error": str(exc)[:160]}
            continue
        with open(os.path.join(out_dir, "%s.raw" % name), "wb") as fh:
            fh.write(small)
        report[name] = {"status": "ok", "rc": rc, "raw_bytes": len(raw),
                        "findings": len(parsed), "golden_bytes": len(small),
                        "golden_findings": len(reparsed),
                        # Loud on purpose: a secret in a scan target means the
                        # TARGET is wrong, and that outlives this one masking.
                        "redacted": redacted}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
