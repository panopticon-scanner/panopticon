import json
import os
import re
import shlex
import unittest

from tests._test_helpers import fake_aws_key

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
    return _fold_numbered(enumerate(text.splitlines(), 1))


def _fold_numbered(numbered):
    """The fold behind `_logical_lines`, over (lineno, line) pairs -- so a caller
    that has already dropped comment lines keeps the file's own numbers while
    a `\\`-continuation still folds THROUGH the dropped line, as docker does."""
    out, start, buf = [], None, []
    for n, line in numbered:
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
    """Require each Dockerfile download to be checked before use.

    This is deliberately bounded to the Dockerfile's command shape. It does
    not interpret shell values, functions, or workflow ``run:`` programs.
    """
    defects = []
    numbered = ((n, line) for n, line in enumerate(text.splitlines(), 1)
                if not line.lstrip().startswith("#"))
    for lineno, line in _fold_numbered(numbered):
        if not line.upper().startswith("RUN "):
            continue
        tokens = _shell_tokens(line[4:])
        commands = list(_commands(tokens))
        for start, end, tool, url, dest in _downloads(commands):
            # #2829 owner-approved accepted gap: this exact clone is fresh-required
            # security-advisory DATA for cargo-audit, not a binary, and is intentionally
            # unpinned: pinning it would stale the advisories; no other clone is exempt.
            if (tool, url, dest) == (
                    "git clone", "https://github.com/rustsec/advisory-db",
                    "/home/scanner/.cargo/advisory-db") and not any(
                        _uses_dest(token, dest) and token != dest + "/.git"
                        for token in tokens[end:]
                    ):
                continue
            if not _checked_before_use(tokens, commands, start, end, dest):
                defects.append((lineno, dest))
    return defects


_CONTROL = {"&&", "||", ";", ";;", "|", "&"}
_HASH_VALUE = r"(?:\$\{[^}]+\}|[0-9a-f]{64})"


def _shell_tokens(script):
    lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def _commands(tokens):
    start = 0
    for index, token in enumerate(tokens + [";"]):
        if token in _CONTROL:
            if start < index:
                yield start, index, tokens[start:index]
            start = index + 1


def _downloads(commands):
    for start, end, words in commands:
        offset = 1 if words and words[0] in {"then", "do", "else"} else 0
        if words[offset:offset + 1] == ["timeout"] and len(words) > offset + 2:
            offset += 2
        command = os.path.basename(words[offset]) if offset < len(words) else ""
        args = words[offset + 1:]
        if command in {"curl", "wget"}:
            dest = None
            for index, arg in enumerate(args):
                if arg in {"-o", "-O"} and index + 1 < len(args):
                    dest = args[index + 1]
                elif arg.startswith(("--output=", "--output-document=")):
                    dest = arg.split("=", 1)[1]
                elif arg == ">" and index + 1 < len(args):
                    dest = args[index + 1]
            url = next((arg for arg in args if arg.startswith(("http://", "https://"))), "")
            if dest:
                yield start + offset, end, command, url, dest
        elif command == "git" and args[:1] == ["clone"]:
            url_index = next((i for i, arg in enumerate(args)
                              if arg.startswith(("http://", "https://"))), None)
            if url_index is not None and url_index + 1 < len(args):
                yield start + offset, end, "git clone", args[url_index], args[url_index + 1]


def _uses_dest(token, dest):
    return token == dest or token.startswith(dest.rstrip("/") + "/")


def _checked_before_use(tokens, commands, fetch_start, fetch_end, dest):
    for check_start, check_end, words in commands:
        if check_start <= fetch_start or not words:
            continue
        if os.path.basename(words[0]) != "sha256sum" or words[1:] != ["-c", "-"]:
            continue
        previous = next((row for row in commands if row[1] == check_start - 1), None)
        if tokens[check_start - 1:check_start] != ["|"] or previous is None:
            continue
        hashed = any(re.search(_HASH_VALUE + r"\s{2}" + re.escape(dest) + r"(?:\s|$)", word)
                     for word in previous[2])
        controls = [token for token in tokens[fetch_end:check_start]
                    if token in _CONTROL]
        used_early = any(_uses_dest(token, dest)
                         for token in tokens[fetch_end:previous[0]])
        next_control = tokens[check_end] if check_end < len(tokens) else None
        if (not hashed or used_early or not controls or controls[0] != "&&"
                or any(token not in {"&&", "|"} for token in controls)
                or next_control in {"||", "|"}):
            continue
        uses = [index for index, token in enumerate(tokens[check_end:], check_end)
                if _uses_dest(token, dest)]
        if all(all(token in {"&&", "|"} for token in tokens[check_end:index]
                   if token in _CONTROL) for index in uses):
            return True
    return False


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

    def test_only_fresh_rustsec_advisory_data_clone_is_accepted(self):
        url = "https://github.com/rustsec/advisory-db"
        dest = "/home/scanner/.cargo/advisory-db"
        clone = "RUN timeout 60 git clone --depth 1 %s %s" % (url, dest)
        self.assertEqual([], _download_checksum_defects(clone))
        for command, fetched in (
                ("git clone %s /tmp/advisory-db" % url, "/tmp/advisory-db"),
                ("git clone %s.git %s" % (url, dest), dest),
                ("git clone https://example.invalid/advisory-db %s" % dest, dest),
                ("curl %s -o %s" % (url, dest), dest),
        ):
            with self.subTest(command=command):
                self.assertEqual([(1, fetched)], _download_checksum_defects("RUN " + command))
        self.assertEqual([(1, dest)], _download_checksum_defects(
            clone + " && sh %s/tool" % dest))


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
        self.assertEqual(len(locked), 141)

    def test_node_closure_overrides_every_minimatch_to_the_fixed_release(self):
        """#3419: neither vulnerable dependency range admits fixed 11.0.1."""
        node_root = os.path.join(ROOT, "tools-image", "node")
        with open(os.path.join(node_root, "package.json"), encoding="utf-8") as fh:
            declared = json.load(fh)
        with open(os.path.join(node_root, "package-lock.json"), encoding="utf-8") as fh:
            locked = json.load(fh)["packages"]
        self.assertEqual(declared.get("overrides"), {"minimatch": "11.0.1"})
        minimatches = {path: item.get("version") for path, item in locked.items()
                       if path.endswith("/minimatch")}
        self.assertTrue(minimatches)
        self.assertEqual({"11.0.1"}, set(minimatches.values()), minimatches)

    def test_minimatch_11_glob_7_limit_stays_in_the_formatter_cache_path(self):
        """#3419: glob 7 magic patterns are incompatible with minimatch 11."""
        lock_path = os.path.join(ROOT, "tools-image", "node", "package-lock.json")
        with open(lock_path, encoding="utf-8") as fh:
            locked = json.load(fh)["packages"]

        def dependents(package):
            return {path for path, item in locked.items()
                    if package in item.get("dependencies", {})}

        self.assertEqual({"node_modules/rimraf"}, dependents("glob"))
        self.assertEqual({
            "node_modules/@microsoft/eslint-formatter-sarif/node_modules/flat-cache",
        }, dependents("rimraf"))


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


def _osv_warm_contracts(text):
    """Read warm invocations, manifest writes and the adjacent ecosystem check.
    Bounded to the Dockerfile's explicit RUN/for/if shape; never executes shell.
    """
    contracts = []
    numbered = ((n, line) for n, line in enumerate(text.splitlines(), 1)
                if not line.lstrip().startswith("#"))
    for _line, run in _fold_numbered(numbered):
        if not run.startswith("RUN "):
            continue
        required = ("osv-scanner", "--experimental-download-offline-databases",
                    "--experimental-offline", "--recursive /tmp/osv-warm")
        if not all(marker in run for marker in required):
            continue
        loop = re.search(r"\bfor eco in ([^;]+); do\s+if\s+"
                         r"\[ ! -s [\"']?/opt/osv-db/osv-scanner/\$eco/"
                         r"all\.zip[\"']? \]", run)
        if loop:
            writes = set(re.findall(r">\s*(/tmp/osv-warm/[^\s;&]+)", run))
            contracts.append((set(shlex.split(loop.group(1))), writes))
    return contracts


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
        self.assertIn("COPY --chown=scanner:scanner --from=nvd-data /opt/odc-data /opt/odc-data",
                      self.text)
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
        self.assertEqual(_osv_warm_contracts(self.text), [(
            {"npm", "PyPI", "Go", "RubyGems", "crates.io", "Maven"},
            {"/tmp/osv-warm/" + name for name in (
                "package-lock.json", "requirements.txt", "go.mod",
                "Gemfile.lock", "Cargo.lock", "pom.xml")})])
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


    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)



# --- ARC-2930403871 (#1771): the .NET package cache a non-root scan can read --
# The fix for that finding is an ORDERING property of this file, and nothing
# pinned it. `ENV NUGET_PACKAGES=/opt/nuget-packages` has to precede every
# `dotnet restore`, because a restore bakes the ABSOLUTE path of the global
# packages folder into the project's `obj/project.assets.json`; and the line that
# opens that folder to the scan user has to follow the last restore, because the
# restore is what fills it. Move the ENV three lines down and the image still
# builds: the path baked in is /root/.nuget/packages again, /root is mode 0700,
# and the C# probes go back to reporting an empty SCS result -- which
# `roslyn_secguard` cannot tell from a clean one. That is the #1655 failure shape
# the bake exists to prevent, reached through the uid instead of through a
# skipped restore, and the suite would not have said a word.
NUGET_CACHE = "/opt/nuget-packages"


def nuget_cache_defects(text):
    """Why a scan running as `scanner` could not read this image's .NET packages.

    Comment lines are dropped before continuations are folded, the way
    `test_dockerfile_closures.dockerfile_commands` does it and for the same
    reason: this file's prose quotes the very commands the rule reads, so a
    reader that kept it would grade the explanation instead of the build. They
    are dropped WITH their numbers carried (`_fold_numbered`), not blanked in
    place: a blank line would end a `\\`-continuation that docker folds through
    a comment, hiding the instruction after it -- and every `lineno` below must
    stay the line a reader of a red CI job will open, in a file whose whole
    point is that position matters.
    """
    numbered = [(n, ln) for n, ln in enumerate(text.splitlines(), 1)
                if not ln.lstrip().startswith("#")]
    env, restores, opens = [], [], []
    for order, (lineno, joined) in enumerate(_fold_numbered(numbered)):
        if joined.startswith("ENV") and "NUGET_PACKAGES=" in joined:
            env.append((order, lineno, joined))
        elif joined.startswith("RUN") and "dotnet restore" in joined:
            restores.append((order, lineno, joined))
        elif (joined.startswith("RUN") and NUGET_CACHE in joined
                and ("chmod" in joined or "chown" in joined)):
            opens.append((order, lineno, joined))
    defects = []
    if not env:
        defects.append(
            "no `ENV NUGET_PACKAGES=...`: the .NET restores below bake "
            "/root/.nuget/packages into project.assets.json, and /root is not "
            "readable by the uid the scans run as (ARC-2930403871, #1771)")
    for order, lineno, joined in env:
        value = joined.split("NUGET_PACKAGES=", 1)[1].split()[0].strip('"')
        if value.startswith("/root"):
            defects.append("line %d points NUGET_PACKAGES at %s, inside root's "
                           "home" % (lineno, value))
        later = [n for n, _l, _j in restores if n < order]
        if later:
            defects.append(
                "the `ENV NUGET_PACKAGES` on line %d comes AFTER %d `dotnet "
                "restore` line(s); a restore that ran before it baked the old "
                "absolute path into project.assets.json and the scan user "
                "cannot read it (ARC-2930403871, #1771)" % (lineno, len(later)))
    if not restores:
        defects.append("no `dotnet restore` left in this file; #1655's bake is "
                       "gone and the C# fixtures are inapplicable, not unreadable")
    if not opens:
        defects.append(
            "nothing opens %s to the scan user: the restores run as root, so "
            "without a `chmod`/`chown` naming it the packages are root-only "
            "(ARC-2930403871, #1771)" % NUGET_CACHE)
    for order, lineno, _joined in opens:
        after = [n for n, _l, _j in restores if n > order]
        if after:
            defects.append(
                "the line that opens %s (line %d) comes BEFORE %d `dotnet "
                "restore` line(s), so what they cache afterwards keeps the "
                "root-only mode it was written with" % (NUGET_CACHE, lineno,
                                                        len(after)))
    return defects


SCRIPTS_COPY = "COPY skill/scripts /opt/panopticon/scripts"
SMOKE_RUN = "RUN python3 /opt/panopticon/scripts/smoke_adapters.py"
# Instructions that only set metadata: they add no files, so they cost nothing
# when the layers around them are rebuilt.
_METADATA = ("ENV", "USER", "WORKDIR", "ARG", "LABEL")


def layer_order_defects(text):
    """Why this image would store more than it has to on an ordinary merge (#2106).

    Two rules, read from the final stage with comments dropped the way
    `nuget_cache_defects` drops them:

    * `skill/scripts` changes on most merges, and every layer below a COPY is
      rebuilt when the copied files change. So its COPY sits right above the
      smoke test that runs it, with only metadata between them, and its
      `ENV PYTHONPATH` moves down with it.
    * The NVD database is copied with `--chown`, after the user it names
      exists. A later `chown`/`chmod` of /opt/odc-data stores the whole
      database again in a new layer, and the H2 database still needs
      scanner to own it (#451).
    """
    numbered = [(n, ln) for n, ln in enumerate(text.splitlines(), 1)
                if not ln.lstrip().startswith("#")]
    lines = [(n, j) for n, j in _fold_numbered(numbered) if j]
    starts = [i for i, (_n, j) in enumerate(lines) if j.split()[0].upper() == "FROM"]
    final = lines[starts[-1] + 1:] if starts else lines

    def first(pred):
        return next((i for i, (_n, j) in enumerate(final) if pred(j)), None)

    defects = []
    copy_at = first(lambda j: j == SCRIPTS_COPY)
    smoke_at = first(lambda j: j == SMOKE_RUN)
    env_at = first(lambda j: j.startswith("ENV PYTHONPATH="))
    if copy_at is None or smoke_at is None:
        defects.append("the final stage needs both `%s` and `%s`" % (SCRIPTS_COPY, SMOKE_RUN))
    elif copy_at > smoke_at:
        defects.append("line %d copies skill/scripts AFTER the smoke test that runs it"
                       % final[copy_at][0])
    else:
        for n, j in final[copy_at + 1:smoke_at]:
            if j.split()[0].upper() not in _METADATA:
                defects.append(
                    "line %d (`%s`) sits between the skill/scripts COPY and the smoke "
                    "test, so it is rebuilt on every change to skill/scripts" % (n, j.split()[0]))
        if env_at is None or env_at < copy_at:
            defects.append("`ENV PYTHONPATH=` must come after the skill/scripts COPY it "
                           "points at")

    nvd_at = first(lambda j: j.startswith("COPY") and "--from=nvd-data" in j.split())
    user_at = first(lambda j: j.startswith("RUN") and re.search(r"\buseradd\b.*\bscanner\b", j))
    if nvd_at is None:
        defects.append("no `COPY --from=nvd-data` in the final stage")
    else:
        if "--chown=scanner:scanner" not in final[nvd_at][1].split():
            defects.append("line %d copies the NVD database without "
                           "`--chown=scanner:scanner`" % final[nvd_at][0])
        if user_at is None or user_at > nvd_at:
            defects.append("the scanner user must be created before line %d's "
                           "`--chown` names it" % final[nvd_at][0])
        for n, j in final[nvd_at + 1:]:
            if (j.startswith("RUN") and "/opt/odc-data" in j
                    and re.search(r"\bch(?:own|mod)\b", j)):
                defects.append("line %d re-owns /opt/odc-data in a later layer, which "
                               "stores the whole database a second time" % n)
    return defects


_ORDERED = """FROM base AS nvd-data
FROM python:3.12-slim
RUN useradd -m -u 1000 scanner
COPY --chown=scanner:scanner --from=nvd-data /opt/odc-data /opt/odc-data
USER scanner
# a comment between them is not an instruction
%s
ENV PYTHONPATH=/opt/panopticon
%s
RUN semgrep --version
""" % (SCRIPTS_COPY, SMOKE_RUN)


class TestLayerOrder(unittest.TestCase):
    def test_the_dockerfile_keeps_merges_cheap(self):
        self.assertEqual(layer_order_defects(_read_dockerfile()), [])

    def test_the_ordered_control_is_clean(self):
        self.assertEqual(layer_order_defects(_ORDERED), [])

    def assert_one_defect(self, text, words):
        defects = layer_order_defects(text)
        self.assertEqual(len(defects), 1, defects)
        self.assertIn(words, defects[0])

    def test_a_run_between_the_copy_and_the_smoke_test(self):
        text = _ORDERED.replace(SMOKE_RUN, "RUN apt-get update\n" + SMOKE_RUN)
        self.assert_one_defect(text, "line 9 (`RUN`) sits between")

    def test_a_copy_between_the_copy_and_the_smoke_test(self):
        text = _ORDERED.replace(SMOKE_RUN, "COPY a /b\n" + SMOKE_RUN)
        self.assert_one_defect(text, "(`COPY`) sits between")

    def test_the_scripts_copied_high_up_as_before_2106(self):
        text = _ORDERED.replace(SCRIPTS_COPY + "\nENV PYTHONPATH=/opt/panopticon\n", "")
        text = text.replace("RUN useradd", SCRIPTS_COPY
                            + "\nENV PYTHONPATH=/opt/panopticon\nRUN useradd")
        defects = layer_order_defects(text)
        self.assertEqual([d.split(" sits")[0] for d in defects],
                         ["line 5 (`RUN`)", "line 6 (`COPY`)"])

    def test_pythonpath_left_behind(self):
        text = _ORDERED.replace("ENV PYTHONPATH=/opt/panopticon\n", "")
        text = text.replace("USER scanner", "ENV PYTHONPATH=/opt/panopticon\nUSER scanner")
        self.assert_one_defect(text, "`ENV PYTHONPATH=` must come after")

    def test_pythonpath_missing(self):
        self.assert_one_defect(_ORDERED.replace("ENV PYTHONPATH=/opt/panopticon\n", ""),
                               "`ENV PYTHONPATH=` must come after")

    def test_the_scripts_copied_after_the_smoke_test(self):
        text = _ORDERED.replace(SCRIPTS_COPY + "\n", "")
        text = text.replace("RUN semgrep", SCRIPTS_COPY + "\nRUN semgrep")
        self.assert_one_defect(text, "AFTER the smoke test")

    def test_no_smoke_test(self):
        self.assert_one_defect(_ORDERED.replace(SMOKE_RUN + "\n", ""), "needs both")

    def test_an_earlier_stage_does_not_count(self):
        text = SCRIPTS_COPY + "\n" + _ORDERED.replace(SCRIPTS_COPY + "\n", "")
        self.assert_one_defect(text, "needs both")

    def test_the_nvd_copy_without_chown(self):
        self.assert_one_defect(_ORDERED.replace("--chown=scanner:scanner ", ""),
                               "without `--chown=scanner:scanner`")

    def test_the_user_created_after_the_nvd_copy(self):
        text = _ORDERED.replace("RUN useradd -m -u 1000 scanner\n", "")
        text = text.replace("USER scanner", "RUN useradd -m -u 1000 scanner\nUSER scanner")
        self.assert_one_defect(text, "must be created before line 3")

    def test_no_user_at_all(self):
        self.assert_one_defect(_ORDERED.replace("RUN useradd -m -u 1000 scanner\n", ""),
                               "must be created before")

    def test_a_later_chown_of_the_database(self):
        text = _ORDERED.replace(
            "USER scanner",
            "RUN mkdir -p /x \\\n    && chown -R scanner:scanner /opt/odc-data\nUSER scanner")
        self.assert_one_defect(text, "line 5 re-owns /opt/odc-data")

    def test_a_later_chmod_of_the_database(self):
        text = _ORDERED.replace("USER scanner",
                                "RUN chmod -R a+rwX /opt/odc-data\nUSER scanner")
        self.assert_one_defect(text, "re-owns /opt/odc-data")

    def test_no_nvd_copy(self):
        text = _ORDERED.replace(
            "COPY --chown=scanner:scanner --from=nvd-data /opt/odc-data /opt/odc-data\n", "")
        self.assert_one_defect(text, "no `COPY --from=nvd-data`")


class TestDockerfileFixtures(unittest.TestCase):
    def test_runtime_defaults_to_the_scan_user(self):
        text = _read_dockerfile_fixtures()
        users = [line.strip() for line in text.splitlines()
                 if line.strip().startswith("USER ")]
        self.assertTrue(users, "Dockerfile.fixtures declares no runtime user")
        self.assertEqual(users[-1], "USER scanner")
        self.assertNotIn("hadolint ignore=DL3002", text)

    def test_build_steps_use_workdir_instead_of_shell_cd(self):
        offenders = [(line, instruction) for line, instruction in
                     _logical_lines(_read_dockerfile_fixtures())
                     if re.match(r"RUN\s+cd(?:\s|$)", instruction)]
        self.assertEqual(offenders, [])

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
        # #1838 (run-14 SEC-2589722723): the fixture side of the same pin. Every
        # sentence above holds only while `Hostile` hooks BUILD -- re-hooked to
        # `Restore`, or reached by a `<Project InitialTargets=...>`, it would fire
        # its `curl` in the one step this file does run, on the networked image
        # builder. Nothing else reads the file: the corpus is pruned from every
        # review cell before grouping, by decision (`panopticon.yml`'s `Fixtures:`
        # header comment, and its top-level `exclude_paths:`), so this is the whole
        # of the fixture-side guard. Read as XML, not as source text: a
        # single-quoted attribute and an `InitialTargets` on the root are both
        # valid MSBuild that a regex over the file misses (fix round 1).
        from defusedxml import ElementTree as DefusedET   # declared dependency
        root = DefusedET.parse(
            os.path.join(ROOT, "tests", "fixtures", "hostile-csproj",
                         "evil.csproj")).getroot()
        self.assertEqual(
            [(t.get("Name"), t.get("BeforeTargets"), t.get("AfterTargets"),
              t.get("DependsOnTargets")) for t in root.iter("Target")],
            [("Hostile", "Build", None, None)],
            "evil.csproj must hold one Target, hooked to Build and nothing else")
        self.assertEqual(
            (root.get("InitialTargets"), root.get("DefaultTargets")), (None, None),
            "a Project-level InitialTargets/DefaultTargets fires on restore too")

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

    # --- ARC-2930403871 (#1771) -------------------------------------------
    def test_the_nuget_cache_is_out_of_roots_home_and_opened_after_the_restores(self):
        defects = nuget_cache_defects(_read_dockerfile_fixtures())
        self.assertEqual([], defects, "\n".join(defects))


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
