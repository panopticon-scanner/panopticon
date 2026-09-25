import json
import os
import re
import shlex
import unittest

import yaml

import shell_reader
import workflow_guard
from workflow_forms import names_file, regions

from _test_helpers import fake_aws_key

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


def _read_dockerfile() -> str:
    with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
        return fh.read()


def _read_dockerfile_fixtures() -> str:
    with open(os.path.join(ROOT, "Dockerfile.fixtures"), encoding="utf-8") as fh:
        return fh.read()


# Longest first so the alternation cannot settle for a prefix. `sh` last is what
# keeps `sha256sum` out: `sh` matches, then `\b` fails against the `a`.
_INTERPRETERS = ("python3", "python", "bash", "dash", "perl", "ruby", "node",
                 "zsh", "ksh", "sh")

# `... | sh`, `... | sudo bash -s --`, `... | /usr/bin/env python3 -`
_PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/usr/bin/env\s+)?(?:[\w.-]*/)*"
    r"(?:%s)\b" % "|".join(_INTERPRETERS))
# `bash <(curl ...)` -- no pipe, same event
_PROCESS_SUB_FETCH = re.compile(r"<\(\s*(?:curl|wget)\b")
_FETCH = re.compile(r"\b(?:curl|wget)\b")


def _logical_lines(text):
    """[(lineno, joined)] with Dockerfile `\\`-continuations folded in, so a
    fetch and the pipe it feeds read as one string even when they are written as
    two lines. lineno is where the logical line STARTS."""
    out, start, buf = [], None, []
    for n, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = n
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        out.append((start, " ".join(p.strip() for p in buf if p.strip())))
        start, buf = None, []
    if buf:
        out.append((start, " ".join(p.strip() for p in buf if p.strip())))
    return out


def fetch_piped_into_a_shell(text):
    """[(lineno, logical line)] for every fetch executed as it arrives.

    Two shapes, both of which leave no artifact to check a digest against:
    a fetch piped into an interpreter, and an interpreter reading a fetch
    through process substitution. A fetch piped into something that is not an
    interpreter (`| gpg --dearmor`, `| sha256sum -c -`, `| tar -x`) is a
    different act and is left alone.
    """
    hits = []
    for lineno, joined in _logical_lines(text):
        if not _FETCH.search(joined):
            continue
        if _PIPE_TO_SHELL.search(joined) or _PROCESS_SUB_FETCH.search(joined):
            hits.append((lineno, joined))
    return hits


def _download_checksum_defects(text):
    """Require checks for every explicit RUN download, even unused files.

    Reuse the workflow guard's bounded shell reader, transfer discovery,
    checksum binding and use ordering. Docker ARG digest pins stay covered
    independently below; no shell expansion or execution happens here.
    Checks must occur in the same RUN as the download. For executable uses,
    support only an uninterrupted && chain from the check to every use: a
    Docker shell need not enable errexit. Leave other control-flow shapes
    unproven rather than interpret shell failure/exit behavior here.
    """
    defects = []
    for lineno, line in _logical_lines(shell_reader.without_comments(text)):
        if not line.upper().startswith("RUN "):
            continue
        statements = workflow_guard.read(line[4:])
        checks = workflow_guard._checks(statements)
        conditions = {i: (None, branch) for i, branch in regions(statements).items()}
        for index, fetch in workflow_guard._fetch_records(statements):
            if fetch.dest is None:
                continue  # streamed execution has its own guard below
            _names, uses = workflow_guard._uses(statements, fetch.dest, after=index)
            deadline = uses[0][0] if uses else len(statements)
            # Without a use, bind to the real download's branch rather than a
            # synthetic unconditional endpoint outside any enclosing `if`.
            binding = uses[0][0] if uses else index
            if not any(index < check < deadline and why is None
                       and names_file(checked, fetch.dest)
                       and workflow_guard._binds(conditions, check, binding)
                       and _checksum_blocks_uses(statements, check, uses)
                       for check, checked, why in checks):
                defects.append((lineno, str(fetch.dest)))
    return defects


def _checksum_blocks_uses(statements, check, uses):
    # Without pipefail, only the final pipeline command controls &&. Do not
    # credit a checksum piped into a successful `cat`/`tee`, even if ordered.
    last = shell_reader.command(statements[check].stages[-1].argv)
    if not last or os.path.basename(last[0]) not in workflow_guard.CHECKSUM_TOOLS:
        return False
    return all(all(statement.separator == "&&" for statement in statements[check:use])
               for use, _description in uses)


class TestDownloadChecksumGuard(unittest.TestCase):
    def test_discovers_new_downloads_including_unused_files(self):
        for fetch in ("curl -fL https://example.invalid/new -o /tmp/new",
                      "curl --output=/tmp/new https://example.invalid/new",
                      "curl https://example.invalid/new > /tmp/new",
                      "wget -O /tmp/new https://example.invalid/new",
                      "wget --output-document=/tmp/new https://example.invalid/new"):
            with self.subTest(fetch=fetch):
                self.assertEqual(_download_checksum_defects("RUN " + fetch),
                                 [(1, "/tmp/new")])
                verified = ("RUN " + fetch
                            + ' && echo "${NEW_SHA256}  /tmp/new" | sha256sum -c -')
                self.assertEqual(_download_checksum_defects(verified), [])
                self.assertEqual(_download_checksum_defects(verified + " && /tmp/new"), [])

    def test_wrong_missing_late_and_decoy_checks_fail(self):
        fetch = "RUN curl https://example.invalid/new -o /tmp/new"
        check = 'echo "${NEW_SHA256}  /tmp/new" | sha256sum -c -'
        for tail in ("", " && " + check.replace("/tmp/new", "/tmp/other"),
                     " && " + check.replace("/tmp/new", "/tmp/new-old"),
                     " && /tmp/new && " + check,
                     " && tar -xf /tmp/new && " + check,
                     " # " + check,
                     " && echo '" + check + "'",
                     " && " + check + " || true",
                     ' && echo "/tmp/new" | sha256sum -c -'):
            with self.subTest(tail=tail):
                self.assertEqual(_download_checksum_defects(fetch + tail), [(1, "/tmp/new")])
        self.assertEqual(_download_checksum_defects("RUN " + check + " && " + fetch[4:]),
                         [(1, "/tmp/new")])

    def test_failed_check_cannot_fall_through_to_execution(self):
        prefix = ('RUN curl https://example.invalid/new -o /tmp/new'
                  ' && echo "${NEW_SHA256}  /tmp/new" | sha256sum -c -')
        for tail in (" ; /tmp/new", " && true ; /tmp/new",
                     " && chmod +x /tmp/new ; /tmp/new",
                     " | cat && /tmp/new"):
            with self.subTest(tail=tail):
                self.assertEqual(_download_checksum_defects(prefix + tail), [(1, "/tmp/new")])
        for tail in (" && /tmp/new", " && true && /tmp/new",
                     " && chmod +x /tmp/new && /tmp/new"):
            with self.subTest(tail=tail):
                self.assertEqual(_download_checksum_defects(prefix + tail), [])

    def test_unused_conditional_download_binds_to_its_own_branch(self):
        fetch = 'curl https://example.invalid/new -o /tmp/new'
        check = 'echo "${NEW_SHA256}  /tmp/new" | sha256sum -c -'
        self.assertEqual(_download_checksum_defects(
            'RUN if test -n "$arch"; then ' + fetch + ' && ' + check + '; fi'), [])
        self.assertEqual(_download_checksum_defects(
            'RUN ' + fetch + '; if test -n "$arch"; then ' + check + '; fi'),
            [(1, "/tmp/new")])

    def test_continuations_arch_selected_sha_and_prose(self):
        text = ('ARG NEW_SHA256_AMD64=' + 'a' * 64 + '\n'
                'ARG NEW_SHA256_ARM64=' + 'b' * 64 + '\n'
                'RUN case "$arch" in amd64) sha256="${NEW_SHA256_AMD64}" ;; '
                'arm64) sha256="${NEW_SHA256_ARM64}" ;; esac \\\n'
                ' && curl https://example.invalid/new \\\n'
                ' -o /tmp/new \\\n'
                ' && echo "${sha256}  /tmp/new" | sha256sum -c - \\\n'
                ' && chmod +x /tmp/new && /tmp/new\n')
        self.assertEqual(_download_checksum_defects(text), [])
        self.assertTrue(_download_checksum_defects(text.replace("| sha256sum -c -", "")))
        self.assertEqual(_download_checksum_defects(
            '# RUN curl https://example.invalid/decoy -o /tmp/decoy\n'
            'RUN echo "curl https://example.invalid/decoy -o /tmp/decoy"\n'), [])


class TestDockerfile(unittest.TestCase):
    def test_bundles_core_tools(self):
        text = _read_dockerfile().lower()
        for tool in ["semgrep", "gitleaks", "trivy", "bandit", "brakeman", "gosec", "eslint"]:
            self.assertIn(tool, text, tool)
        self.assertIn("useradd", text)  # non-root user created


class TestDockerfilePhase1(unittest.TestCase):
    def test_phase1_adapters_mentioned(self):
        # Each tool is asserted where the image actually gets it from, which
        # after #1734 is no longer all one file: two of the three moved into a
        # pinned closure, and a Dockerfile grep would pass on the PROSE that
        # explains the move -- naming the tool in a comment is not shipping it.
        text = _read_dockerfile()
        self.assertIn("osv-scanner", text)
        with open(os.path.join(ROOT, "requirements-tools.txt"),
                  encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^pip-audit==")
        with open(os.path.join(ROOT, "tools-image", "node", "package.json"),
                  encoding="utf-8") as fh:
            self.assertIn("eslint-plugin-security",
                          json.load(fh)["dependencies"])

    def test_node_closure_pins_typescript_parser_and_compiler(self):
        node_root = os.path.join(ROOT, "tools-image", "node")
        with open(os.path.join(node_root, "package.json"), encoding="utf-8") as fh:
            declared = json.load(fh)["dependencies"]
        with open(os.path.join(node_root, "package-lock.json"), encoding="utf-8") as fh:
            locked = json.load(fh)["packages"]
        self.assertEqual(declared["@typescript-eslint/parser"], "8.70.1")
        self.assertEqual(declared["typescript"], "6.0.3")
        self.assertEqual(locked[""]["dependencies"], declared)
        for package, version in (("@typescript-eslint/parser", "8.70.1"),
                                 ("typescript", "6.0.3")):
            item = locked["node_modules/" + package]
            self.assertEqual(item["version"], version)
            self.assertTrue(item["integrity"].startswith("sha512-"))
        self.assertEqual(len(locked), 153)


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
        self.assertEqual(_download_checksum_defects(self.text), [],
                         "every explicit download needs a checksum before use")
        # Retain the existing digest-pin checks independently of discovery.
        for artifact, sha_re in (
                ("/tmp/osv-scanner", r"OSV_SCANNER_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gitleaks.tar.gz", r"GITLEAKS_SHA256_(X64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/gosec.tar.gz", r"GOSEC_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/dc.zip", r"DEPENDENCY_CHECK_SHA256=[0-9a-f]{64}"),
                ("/tmp/spotbugs.tgz", r"SPOTBUGS_SHA256=[0-9a-f]{64}"),
                ("/tmp/rustup-init", r"RUSTUP_INIT_SHA256_(AMD64|ARM64)=[0-9a-f]{64}"),
                ("/tmp/dotnet-install.sh", r"DOTNET_INSTALL_SHA256=[0-9a-f]{64}")):
            self.assertRegex(self.text, sha_re, "no pinned SHA256 for %s" % artifact)

    def test_dotnet_network_steps_are_timeout_bounded(self):
        # run-8 OPS-A1A: every network step in this file is `timeout`-wrapped so a
        # hung feed can't stall the build to the 120-min job cap. The two dotnet
        # steps (SDK download + `dotnet tool install`) were the exceptions.
        self.assertRegex(self.text, r"timeout \d+ /tmp/dotnet-install\.sh",
                         "dotnet SDK install has no timeout wrapper")
        self.assertRegex(self.text, r"timeout \d+ dotnet tool install",
                         "dotnet tool install has no timeout wrapper")


class TestPinnedRustAndTrivy(unittest.TestCase):
    def setUp(self):
        self.text = _read_dockerfile()

    def _run_for(self, marker):
        runs = [line for _n, line in _logical_lines(self.text)
                if line.startswith("RUN ") and marker in line]
        self.assertEqual(len(runs), 1, "expected one RUN command for %s" % marker)
        return runs[0]

    def test_rust_compiler_and_cargo_audit_are_pinned(self):
        self.assertRegex(self.text, r"(?m)^ARG RUST_TOOLCHAIN_VERSION=(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
        self.assertRegex(self.text, r"(?m)^ARG CARGO_AUDIT_VERSION=0\.22\.2$")
        rustup = self._run_for("/tmp/rustup-init -y")
        self.assertIn("--default-toolchain ${RUST_TOOLCHAIN_VERSION}", rustup)
        self.assertNotIn("--default-toolchain stable", rustup)
        cargo = self._run_for("cargo install cargo-audit")
        self.assertIn("--version ${CARGO_AUDIT_VERSION}", cargo)
        self.assertIn("--locked", cargo)

    def test_trivy_release_is_pinned_for_both_supported_architectures(self):
        self.assertRegex(self.text, r"(?m)^ARG TRIVY_VERSION=(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
        for arch in ("AMD64", "ARM64"):
            self.assertRegex(self.text, r"(?m)^ARG TRIVY_SHA256_" + arch + r"=[0-9a-f]{64}$")
        install = self._run_for("/tmp/trivy.tar.gz")
        self.assertIn('arch="$(dpkg --print-architecture)"', install)
        self.assertIn('amd64) trivy_arch="64bit"; sha256="${TRIVY_SHA256_AMD64}"', install)
        self.assertIn('arm64) trivy_arch="ARM64"; sha256="${TRIVY_SHA256_ARM64}"', install)
        self.assertIn('*) echo "unsupported arch: $arch" >&2; exit 1', install)
        self.assertIn('trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz', install)

    def test_trivy_archive_is_verified_before_extracting_only_the_binary(self):
        install = self._run_for("/tmp/trivy.tar.gz")
        fetch = install.index(' -o /tmp/trivy.tar.gz')
        verify = install.index('echo "${sha256}  /tmp/trivy.tar.gz" | sha256sum -c -')
        extract = install.index('tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy')
        self.assertLess(fetch, verify)
        self.assertLess(verify, extract)
        self.assertIn('&& echo "${sha256}  /tmp/trivy.tar.gz" | sha256sum -c - && tar', install)
        self.assertIn('&& rm /tmp/trivy.tar.gz', install)

    def test_unverified_trivy_apt_feed_is_absent(self):
        self.assertNotIn("aquasecurity.github.io/trivy-repo", self.text)
        self.assertNotIn("/etc/apt/sources.list.d/trivy.list", self.text)
        self.assertNotIn("apt-get install -y --no-install-recommends trivy", self.text)


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

    def test_fetched_artifacts_use_immutable_urls(self):
        # 2026-09-01: rustup-init was fetched from `rustup/dist/<triple>/`,
        # which always serves the LATEST rustup. When rust-lang shipped 1.29.1
        # the pinned SHA stopped matching and every from-scratch build died on
        # `sha256sum -c` -- red CI on PRs whose diff touched nothing related.
        # A checksum pin is only meaningful against an immutable artifact: on a
        # moving URL it is a time bomb, not a guarantee. The #run7 FIXME called
        # this exact failure a release in advance.
        # Assert on the FETCH lines, not the whole file: the comment above the
        # pin names `rustup/dist/` to explain what went wrong, and a blanket
        # assertNotIn cannot tell prose from a download.
        fetches = [ln for ln in self.text.splitlines()
                   if "curl" in ln and "rustup-init" in ln]
        self.assertTrue(fetches, "no rustup-init fetch found in the Dockerfile")
        for ln in fetches:
            self.assertNotIn(
                "rustup/dist/", ln,
                "rustup-init must come from the immutable "
                "rustup/archive/<version>/ URL; rustup/dist/ serves the latest "
                "build, so the checksum pin breaks on every rustup release")
            self.assertIn("rustup/archive/${RUSTUP_VERSION}/", ln,
                          "the rustup fetch should be version-pinned")
        self.assertRegex(self.text, r"ARG RUSTUP_VERSION=\d+\.\d+\.\d+")

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

    def test_the_pinned_closures_are_trigger_paths(self):
        # #1734: a lockfile edit changes what the image installs and is the
        # ONE edit that can break `--require-hashes` or `npm ci` while leaving
        # the Dockerfile byte-identical. Without these the build that would
        # catch it never runs on the PR that caused it.
        on = self.wf.get(True, {})
        paths = on.get("pull_request", {}).get("paths", [])
        for path in ("requirements-tools.txt", "tools-image/**"):
            self.assertIn(path, paths)

    def test_tools_build_reads_the_main_branch_layer_cache(self):
        # #1421: this workflow fires on skill/scripts/**, so most PRs pay for it,
        # and a plain `docker build` has no layer cache -- each qualifying PR was
        # a cold full build compiling cargo-audit from source. It now reads the
        # gha cache docker-publish.yml writes on main.
        build = next((s for s in self.wf["jobs"]["build"]["steps"]
                      if s.get("name") == "Build Dockerfile"), None)
        self.assertIsNotNone(build, "no 'Build Dockerfile' step")
        self.assertIn("docker/build-push-action", build.get("uses", ""),
                      "the tools build is not a cache-aware buildx build")
        self.assertIn("type=gha", build["with"]["cache-from"])
        # The scope must be the one docker-publish.yml writes for THIS runner's
        # architecture, or the cache is real but always empty.
        self.assertIn("scope=linux-amd64", build["with"]["cache-from"])

    def test_buildx_is_set_up_before_the_cached_build(self):
        names = [s.get("name") for s in self.wf["jobs"]["build"]["steps"]]
        self.assertIn("Set up Buildx", names)
        self.assertLess(names.index("Set up Buildx"),
                        names.index("Build Dockerfile"))

    def test_the_tools_image_is_loaded_for_the_fixtures_build(self):
        # Dockerfile.fixtures is `FROM panopticon-tools:latest`. buildx does NOT
        # export to the docker daemon by default, so dropping `load` would leave
        # the tools build green and the fixtures build failing on a base image
        # that is only in the build cache.
        build = next(s for s in self.wf["jobs"]["build"]["steps"]
                     if s.get("name") == "Build Dockerfile")
        self.assertTrue(build["with"].get("load"), "tools image is not loaded")
        self.assertIn("panopticon-tools:latest", str(build["with"]["tags"]))

    def test_the_pr_build_writes_no_layer_cache(self):
        # Deliberate, and worth a test because "add cache-to as well" is the
        # obvious-looking follow-up: a mode=max export of this image is several
        # GB against a 10GB repo-wide quota, so writing one per PR would evict
        # the main-branch caches these builds read.
        for step in self.wf["jobs"]["build"]["steps"]:
            self.assertNotIn("cache-to", step.get("with") or {},
                             "a PR build exporting a layer cache will evict the "
                             "main-branch cache it depends on")

    def test_dockerfile_fixtures_is_trigger_and_built(self):
        on = self.wf.get(True, {})
        paths = on.get("pull_request", {}).get("paths", [])
        self.assertIn("Dockerfile.fixtures", paths)
        step_names = " ".join(
            s.get("name", "") for s in self.wf["jobs"]["build"]["steps"])
        self.assertIn("Build Dockerfile.fixtures", step_names)
        # #1641: the image's pinned digests are part of what it builds.
        self.assertIn("requirements-fixtures.txt", paths)


class TestDockerfileFixtures(unittest.TestCase):
    def test_bundles_fixture_clone_refs_and_rust_build(self):
        text = _read_dockerfile_fixtures()
        for marker in [
            "ARG RAILS_GOAT_SHA",
            "ARG WEB_GOAT_SHA",
            "ARG ASP_GOAT_SHA",
            "COPY tests/fixtures/vulnerable-rust",
            "cargo build",
            # #1655: roslyn-secguard refuses a C# target with no restore
            # output, and the containment lane scans read-only with
            # `--network none`, so the restore can only have happened here.
            "COPY tests/fixtures/hostile-csproj",
            "dotnet restore /opt/panopticon-fixtures/hostile-csproj",
        ]:
            self.assertIn(marker, text, marker)

    def test_the_hostile_fixture_is_restored_but_never_built(self):
        # #1655. evil.csproj's `Hostile` target is hooked BeforeTargets="Build":
        # it fires when the project is BUILT, which is the act the containment
        # probe performs inside a no-egress container on a throwaway copy.
        # `dotnet build` HERE would run its `curl` on the image builder, which
        # has a network -- the one place the fixture must not execute.
        lines = [line for _n, line in
                 _logical_lines(_read_dockerfile_fixtures())
                 if line.startswith("RUN") and "hostile-csproj" in line]
        self.assertTrue(lines, "nothing in Dockerfile.fixtures prepares the "
                               "hostile fixture; the containment lane's "
                               "adapter would find it inapplicable")
        for line in lines:
            self.assertIn("dotnet restore", line)
            self.assertNotIn("dotnet build", line)
            # Re-review I2: the restore is INTOLERANT on purpose. AspGoat's
            # `|| echo "... skipped"` three lines up is the in-file model for
            # making a flaky step tolerant; copied here it ships an unrestored
            # fixture, the lane fails on applicability, and the message blames
            # the probe -- the exact defect the bake exists to prevent.
            self.assertNotIn("||", line, "the hostile restore must fail the image build, not fall through")
            self.assertNotRegex(line, r";\s*(true|echo)\b", "the hostile restore must not be made tolerant")

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


class TestNoFetchIsPipedIntoAShell(unittest.TestCase):
    """SEC-E3C (#1251): a remote installer piped straight into an interpreter
    executes whatever the server returns, and there is no artifact left to
    check a digest against -- the fetch and the execution are the same event.

    Both instances named in the issue (rustup, dotnet-install) were fixed by
    #1467 and its dotnet sibling: each now downloads to a file, verifies it with
    `sha256sum -c`, and only then runs it. What was missing is the guard --
    `test_all_fetched_binaries_are_checksum_verified` pins the digests of the
    artifacts we already fetch that way, but nothing stopped a NEW dependency
    from arriving as `curl ... | sh`, which has no artifact to pin and so would
    never appear on that list.
    """

    def test_the_rule_flags_a_piped_installer(self):
        # The positive control. A guard run only over a clean tree can pass
        # while matching nothing at all, so prove it says no before believing
        # it when it says yes.
        hostile = (
            "RUN curl -sfL https://example.test/install.sh | sh\n"
            "RUN wget -qO- https://example.test/get | sudo bash -s -- --yes\n"
            "RUN curl -sfL https://example.test/i.py \\\n"
            "    | python3 -\n"
            "RUN bash <(curl -sfL https://example.test/install.sh)\n"
        )
        hits = fetch_piped_into_a_shell(hostile)
        self.assertEqual([1, 2, 3, 5], [n for n, _ in hits], hits)

    def test_the_rule_leaves_a_verified_download_alone(self):
        benign = (
            "RUN curl -sfL https://example.test/rustup-init -o /tmp/r \\\n"
            "    && echo \"$SHA  /tmp/r\" | sha256sum -c - \\\n"
            "    && chmod +x /tmp/r && /tmp/r -y\n"
            # a fetch piped into a NON-interpreter is a different thing: this
            # one dearmors an apt signing key, it does not execute the bytes.
            "RUN curl -sfL https://example.test/key | gpg --dearmor -o /k.gpg\n"
        )
        self.assertEqual([], fetch_piped_into_a_shell(benign))

    def test_no_dockerfile_pipes_a_fetch_into_a_shell(self):
        for name, text in (("Dockerfile", _read_dockerfile()),
                           ("Dockerfile.fixtures", _read_dockerfile_fixtures())):
            hits = fetch_piped_into_a_shell(text)
            self.assertEqual(
                [], hits,
                "%s pipes a network fetch straight into an interpreter; "
                "download to a file and `sha256sum -c` it first:\n%s"
                % (name, "\n".join("  line %d: %s" % h for h in hits)))


class TestTheGosecProbeWritesAHardcodedCredential(unittest.TestCase):
    """#1578 fix round 2: the probe's AWS key is split, and must stay exact.

    gitleaks scans this repository's own tree in CI, and since #1578 a secret
    adapter's findings are HIGH -- so the `AKIA`+16 literal in the gosec verify
    probe was reporting panopticon's own image recipe as a committed
    credential. The literal is now two adjacent single-quoted shell words,
    which the shell concatenates with nothing between them.

    That is only safe if the Go file comes out byte-identical: the probe exists
    to prove gosec can READ Go source, and it proves it by requiring a G101
    hit. A split that inserted so much as a quote would leave the build green
    on a file gosec no longer flags -- or red for the wrong reason. So this
    parses the RUN line the way a shell would and pins the produced source.
    """

    PROBE_GO = 'package verify\\n\\nvar token = "%s_hardcoded_secret_value"\\n'

    def setUp(self):
        self.text = _read_dockerfile()

    def _printf_argv(self):
        """The probe's `printf` line, split the way `/bin/sh` would."""
        lines = [ln for ln in self.text.splitlines()
                 if "printf 'package verify" in ln]
        self.assertEqual(len(lines), 1,
                         "expected exactly one gosec-probe printf: %s" % lines)
        command = lines[0].strip().removeprefix("&& ").removesuffix(" \\").strip()
        return shlex.split(command)

    def test_the_produced_go_source_is_byte_identical(self):
        self.assertEqual(self._printf_argv(),
                         ["printf", self.PROBE_GO % fake_aws_key()])

    def test_the_key_literal_is_not_spelled_out_anywhere_in_the_file(self):
        # The half that would have failed before the split. Whole-file, not
        # just that line: the same literal must not creep back into a comment.
        self.assertNotIn(fake_aws_key(), self.text)

    def test_the_probe_still_asserts_gosec_found_something(self):
        # Non-vacuity for the two above: a byte-identical Go file proves
        # nothing if the build stopped checking that gosec reported an issue.
        self.assertIn("issues = len(d.get('Issues') or [])", self.text)
        self.assertIn("files > 0 and issues > 0", self.text)
