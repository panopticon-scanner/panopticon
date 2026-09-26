import email.message
import hashlib
import io
import json
import os
import re
import traceback
import unittest
import urllib.request
import urllib.response
from unittest import mock

import bump_pins as bp


class _CannedTransport:
    """In-memory HTTP(S) transport that still uses urllib's redirect plumbing."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def open(self, request):
        self.requests.append(request)
        try:
            code, location, body = self.responses[request.full_url]
        except KeyError as exc:
            raise AssertionError("unexpected transport I/O") from exc
        headers = email.message.Message()
        if location is not None:
            headers["Location"] = location
        response = urllib.response.addinfourl(
            io.BytesIO(body), headers, request.full_url, code)
        response.msg = "Found" if code in (301, 302, 303, 307, 308) else "OK"
        return response


class _CannedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, transport):
        super().__init__()
        self.transport = transport

    def https_open(self, request):
        return self.transport.open(request)


class _CannedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, transport):
        super().__init__()
        self.transport = transport

    def http_open(self, request):
        return self.transport.open(request)


class TestDownloadPolicy(unittest.TestCase):
    def _assert_refused_before_transport(self, url, message):
        opener = mock.Mock()
        with mock.patch.object(bp.urllib.request, "urlopen") as old_transport, \
                mock.patch.object(bp.urllib.request, "build_opener",
                                  return_value=opener):
            with self.assertRaisesRegex(RuntimeError, message):
                bp._get(url)
        old_transport.assert_not_called()
        opener.open.assert_not_called()

    def test_non_https_and_unapproved_destinations_are_refused_before_io(self):
        for url, message in (
                ("file:///tmp/harmless-bump-pins-marker", "HTTPS"),
                ("http://pypi.org/project/release", "HTTPS"),
                ("ftp://static.rust-lang.org/release", "HTTPS"),
                ("https://example.com/artifact", "not approved")):
            with self.subTest(url=url):
                self._assert_refused_before_transport(url, message)

    def test_userinfo_and_nonstandard_or_invalid_ports_are_refused_before_io(self):
        for url, message in (
                ("https://operator:do-not-print@pypi.org/project", "credentials"),
                ("https://pypi.org:444/project", "port 443"),
                ("https://pypi.org:/project", "invalid port"),
                ("https://pypi.org:not-a-port/project", "invalid port")):
            with self.subTest(url=url):
                opener = mock.Mock()
                with mock.patch.object(bp.urllib.request, "urlopen") as old_transport, \
                        mock.patch.object(bp.urllib.request, "build_opener",
                                          return_value=opener):
                    with self.assertRaisesRegex(RuntimeError, message) as raised:
                        bp._get(url)
                old_transport.assert_not_called()
                opener.open.assert_not_called()
                self.assertNotIn("do-not-print", str(raised.exception))

    def test_malformed_initial_url_traceback_does_not_disclose_userinfo(self):
        secret = "FAKE_INITIAL_SECRET"
        url = "https://operator:%s@pypi.org\uff0f.example/artifact" % secret
        opener = mock.Mock()
        with mock.patch.object(bp.urllib.request, "build_opener",
                               return_value=opener):
            try:
                bp._get(url)
            except Exception as exc:
                caught = exc
                rendered = "".join(traceback.format_exception(exc))
            else:
                self.fail("malformed credential-bearing URL was accepted")
        self.assertNotIn(secret, rendered)
        self.assertIsInstance(caught, RuntimeError)
        self.assertIn("download URL is malformed", rendered)
        opener.assert_not_called()

    def test_each_canonical_upstream_host_is_allowed(self):
        hosts = ("static.rust-lang.org", "pypi.org", "files.pythonhosted.org",
                 "rubygems.org", "auth.docker.io", "registry-1.docker.io")
        for host in hosts:
            with self.subTest(host=host):
                opener = mock.Mock()
                opener.open.return_value = io.BytesIO(b"upstream bytes")
                with mock.patch.object(bp.urllib.request, "urlopen") as old_transport, \
                        mock.patch.object(bp.urllib.request, "build_opener",
                                          return_value=opener):
                    self.assertEqual(b"upstream bytes",
                                     bp._get("https://%s/artifact" % host))
                old_transport.assert_not_called()
                opener.open.assert_called_once()

    def test_request_headers_object_and_timeout_reach_the_transport(self):
        request = urllib.request.Request(
            "https://registry-1.docker.io/v2/image/manifests/latest",
            headers={"Authorization": "Bearer fixture", "Accept": "application/json"})
        opener = mock.Mock()
        opener.open.return_value = io.BytesIO(b"manifest")
        with mock.patch.object(bp.urllib.request, "urlopen") as old_transport, \
                mock.patch.object(bp.urllib.request, "build_opener",
                                  return_value=opener):
            self.assertEqual(b"manifest", bp._get(request))
        old_transport.assert_not_called()
        sent = opener.open.call_args
        self.assertIs(request, sent.args[0])
        self.assertEqual(bp.TIMEOUT, sent.kwargs["timeout"])
        self.assertEqual("Bearer fixture", sent.args[0].get_header("Authorization"))

    def _get_through_canned_redirects(self, first, responses, headers=None,
                                      transport=None):
        transport = transport or _CannedTransport(responses)
        https = _CannedHTTPSHandler(transport)
        http = _CannedHTTPHandler(transport)
        real_build_opener = urllib.request.build_opener
        legacy_opener = real_build_opener(https, http)

        def build_policy_opener(*handlers):
            return real_build_opener(*handlers, https, http)

        request = urllib.request.Request(first, headers=headers or {})
        with mock.patch.object(
                bp.urllib.request, "urlopen",
                side_effect=lambda req, timeout: legacy_opener.open(req, timeout=timeout)), \
                mock.patch.object(bp.urllib.request, "build_opener",
                                  side_effect=build_policy_opener):
            body = bp._get(request)
        return body, transport.requests

    def test_public_redirect_between_approved_origins_is_allowed(self):
        first = "https://pypi.org/packages/example"
        final = "https://files.pythonhosted.org/packages/example.whl"
        body, requests = self._get_through_canned_redirects(
            first, {first: (302, final, b""), final: (200, None, b"wheel")})
        self.assertEqual(b"wheel", body)
        self.assertEqual([first, final], [request.full_url for request in requests])

    def test_same_origin_authenticated_redirect_preserves_authorization(self):
        first = "https://registry-1.docker.io/v2/image/manifests/latest"
        final = "https://registry-1.docker.io/v2/image/manifests/current"
        body, requests = self._get_through_canned_redirects(
            first, {first: (307, final, b""), final: (200, None, b"manifest")},
            {"Authorization": "Bearer fixture"})
        self.assertEqual(b"manifest", body)
        self.assertEqual("Bearer fixture", requests[1].get_header("Authorization"))

    def test_redirect_downgrade_is_refused_before_target_io(self):
        first = "https://pypi.org/packages/example"
        target = "http://pypi.org/packages/example.whl"
        transport = _CannedTransport(
            {first: (302, target, b""), target: (200, None, b"wheel")})
        with self.assertRaisesRegex(RuntimeError, "HTTPS"):
            self._get_through_canned_redirects(
                first, transport.responses, transport=transport)
        self.assertEqual([first], [request.full_url for request in transport.requests])

    def test_redirect_error_does_not_disclose_destination_userinfo(self):
        first = "https://pypi.org/packages/example"
        target = "file://operator:do-not-print@localhost/tmp/example.whl"
        transport = _CannedTransport({first: (302, target, b"")})
        with self.assertRaisesRegex(RuntimeError, "HTTPS") as raised:
            self._get_through_canned_redirects(
                first, transport.responses, transport=transport)
        self.assertNotIn("do-not-print", str(raised.exception))
        self.assertEqual([first], [request.full_url for request in transport.requests])

    def test_malformed_redirect_traceback_does_not_disclose_userinfo(self):
        first = "https://pypi.org/packages/example"
        secret = "FAKE_REDIRECT_SECRET"
        target = "//operator:%s@pypi.org\uff0f.example/artifact" % secret
        transport = _CannedTransport({first: (302, target, b"")})
        try:
            self._get_through_canned_redirects(
                first, transport.responses, transport=transport)
        except Exception as exc:
            caught = exc
            rendered = "".join(traceback.format_exception(exc))
        else:
            self.fail("malformed credential-bearing redirect was accepted")
        self.assertNotIn(secret, rendered)
        self.assertIsInstance(caught, RuntimeError)
        self.assertIn("download URL is malformed", rendered)
        self.assertEqual([first], [request.full_url for request in transport.requests])

    def test_authenticated_cross_origin_redirect_is_refused_before_target_io(self):
        first = "https://registry-1.docker.io/v2/image/manifests/latest"
        target = "https://auth.docker.io/credential-target"
        transport = _CannedTransport(
            {first: (302, target, b""), target: (200, None, b"should not arrive")})
        with self.assertRaisesRegex(RuntimeError, "authenticated redirect"):
            self._get_through_canned_redirects(
                first, transport.responses, {"Authorization": "Bearer fixture"},
                transport=transport)
        self.assertEqual([first], [request.full_url for request in transport.requests])

    def test_trivy_release_asset_redirect_is_allowed_only_without_credentials(self):
        first = "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/archive"
        target = "https://release-assets.githubusercontent.com/fixture/archive"
        responses = {first: (302, target, b""), target: (200, None, b"archive")}
        body, requests = self._get_through_canned_redirects(first, responses)
        self.assertEqual(body, b"archive")
        self.assertEqual([first, target], [request.full_url for request in requests])
        transport = _CannedTransport(responses)
        with self.assertRaisesRegex(RuntimeError, "authenticated redirect"):
            self._get_through_canned_redirects(
                first, responses, {"Authorization": "Bearer fixture"},
                transport=transport)
        self.assertEqual([first], [request.full_url for request in transport.requests])

    def test_trivy_asset_redirect_to_unapproved_host_is_rejected(self):
        first = "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/archive"
        target = "https://example.com/archive"
        transport = _CannedTransport({first: (302, target, b"")})
        with self.assertRaisesRegex(RuntimeError, "not approved"):
            self._get_through_canned_redirects(first, transport.responses,
                                               transport=transport)
        self.assertEqual([first], [request.full_url for request in transport.requests])

DOCKERFILE = """\
ENV PATH="/usr/local/cargo/bin:${PATH}"
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256_AMD64=%s
ARG RUSTUP_INIT_SHA256_ARM64=%s
RUN curl -sfL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${ru}/rustup-init"
""" % ("a" * 64, "b" * 64)

RUSTUP_ARTIFACTS = {
    "AMD64": b"rustup-init x86_64 fixture bytes",
    "ARM64": b"rustup-init aarch64 fixture bytes",
}
RUSTUP_SHAS = {arch: hashlib.sha256(body).hexdigest()
               for arch, body in RUSTUP_ARTIFACTS.items()}
# Independent upstream oracle: neither the fake server nor expected requests
# may follow bump_pins.RUSTUP_TRIPLES/RUSTUP_ARCHIVE. A production mapping swap
# must put the wrong digest into both the direct result and rewritten Dockerfile.
EXPECTED_RUSTUP_TRIPLES = {
    "AMD64": "x86_64-unknown-linux-gnu",
    "ARM64": "aarch64-unknown-linux-gnu",
}
EXPECTED_RUSTUP_ARCHIVE = (
    "https://static.rust-lang.org/rustup/archive/{version}/{triple}/rustup-init"
)


def _rustup_url(version, triple):
    return EXPECTED_RUSTUP_ARCHIVE.format(version=version, triple=triple)


def _rustup_responses(version, *, swapped=False, mismatched=False):
    responses = {}
    for arch, triple in EXPECTED_RUSTUP_TRIPLES.items():
        url = _rustup_url(version, triple)
        artifact_arch = {"AMD64": "ARM64", "ARM64": "AMD64"}[arch] if swapped else arch
        responses[url] = RUSTUP_ARTIFACTS[artifact_arch]
        responses[url + ".sha256"] = ("f" * 64 if mismatched and arch == "ARM64"
                                       else RUSTUP_SHAS[arch]).encode()
    return responses


def _rustup_fetch(responses, requested):
    def get(url):
        requested.append(url)
        if url not in responses:
            raise AssertionError("unexpected rustup URL: " + url)
        return responses[url]
    return get


def _rustup_urls(version):
    return [_rustup_url(version, triple) + suffix
            for triple in EXPECTED_RUSTUP_TRIPLES.values()
            for suffix in (".sha256", "")]


class TestParse(unittest.TestCase):
    def test_reads_the_current_pin(self):
        v, shas = bp.current_rustup_pin(DOCKERFILE)
        self.assertEqual(v, "1.29.1")
        self.assertEqual(shas, {"AMD64": "a" * 64, "ARM64": "b" * 64})

    def test_absent_pin_is_none_not_a_crash(self):
        v, shas = bp.current_rustup_pin("FROM scratch\n")
        self.assertIsNone(v)
        self.assertEqual(shas, {})


class TestTinyproxyFreshness(unittest.TestCase):
    def _manifest(self, arches=("amd64", "arm64")):
        return json.dumps({"schemaVersion": 2,
                           "mediaType": "application/vnd.oci.image.index.v1+json",
                           "manifests": [{"platform": {"os": "linux", "architecture": a}}
                                         for a in arches]}).encode()

    def test_public_registry_index_is_hashed_without_fetching_layers(self):
        raw = self._manifest()
        with mock.patch.object(bp, "_get", side_effect=[b'{"token":"fixture"}', raw]) as get:
            digest = bp.latest_proxy_digest()
        self.assertEqual(digest, "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertEqual(get.call_count, 2)
        request = get.call_args.args[0]
        self.assertEqual(request.full_url,
                         "https://registry-1.docker.io/v2/kalaksi/tinyproxy/manifests/latest")
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture")
        self.assertIn("application/vnd.oci.image.index.v1+json", request.get_header("Accept"))

    def test_tag_parameter_selects_the_manifest_compared_against(self):
        # #1899: the tag compared against is a parameter, not baked into
        # `PROXY_MANIFEST` -- a repo that has deliberately declined a release
        # and pinned to a specific tag instead of the floating `latest` can
        # still be checked against ITS chosen tag.
        raw = self._manifest()
        with mock.patch.object(bp, "_get", side_effect=[b'{"token":"fixture"}', raw]) as get:
            bp.latest_proxy_digest(tag="1.11.1")
        request = get.call_args.args[0]
        self.assertEqual(request.full_url,
                         "https://registry-1.docker.io/v2/kalaksi/tinyproxy/manifests/1.11.1")

    def test_a_platform_specific_or_malformed_response_is_not_a_freshness_result(self):
        for raw in (b'{}', b'[]', self._manifest(("amd64",))):
            with self.subTest(raw=raw), mock.patch.object(
                    bp, "_get", side_effect=[b'{"token":"fixture"}', raw]):
                with self.assertRaises(RuntimeError):
                    bp.latest_proxy_digest()

    def test_check_reports_drift_without_changing_or_executing_the_source(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "egress.py")
            source = ('raise RuntimeError("never execute the source")\n'
                      'PROXY_IMAGE = "docker.io/kalaksi/tinyproxy@sha256:' + 'a' * 64 + '"\n')
            with open(path, "w") as fh:
                fh.write(source)
            for latest, warning in (("a" * 64, False), ("b" * 64, True)):
                out = io.StringIO()
                with mock.patch.object(bp, "latest_proxy_digest", return_value="sha256:" + latest), \
                        mock.patch("sys.stdout", out):
                    self.assertEqual(bp.main(["tinyproxy", "--source", path]), 0)
                self.assertEqual("::warning" in out.getvalue(), warning)
                with open(path) as fh:
                    self.assertEqual(fh.read(), source)


class TestRewrite(unittest.TestCase):
    def test_rewrites_version_and_both_shas(self):
        out = bp.rewrite_rustup_pin(DOCKERFILE, "1.30.0",
                                    {"AMD64": "c" * 64, "ARM64": "d" * 64})
        v, shas = bp.current_rustup_pin(out)
        self.assertEqual(v, "1.30.0")
        self.assertEqual(shas, {"AMD64": "c" * 64, "ARM64": "d" * 64})
        # the fetch line is templated on ${RUSTUP_VERSION}: it must NOT be edited,
        # or a future bump would have two places to keep in sync.
        self.assertIn("archive/${RUSTUP_VERSION}/", out)

    def test_missing_line_raises_rather_than_silently_no_op(self):
        # A rewrite that quietly changes nothing is the worst outcome: the
        # workflow would open a PR whose diff is empty, or worse, bump the
        # version and leave the old SHAs pinned.
        with self.assertRaises(RuntimeError):
            bp.rewrite_rustup_pin("FROM scratch\n", "1.30.0", {})
        half = "ARG RUSTUP_VERSION=1.29.1\n"
        with self.assertRaises(RuntimeError):
            bp.rewrite_rustup_pin(half, "1.30.0", {"AMD64": "c" * 64})


class TestVerification(unittest.TestCase):
    """The #run7 FIXME's rule -- never guess a checksum -- as executable code."""

    def test_latest_rustup_version_reads_multiline_upstream_manifest(self):
        manifest = b'date = "2026-09-25"\nchannel = "stable"\nversion = "1.28.2"\n'
        with mock.patch.object(bp, "_get", return_value=manifest) as get:
            self.assertEqual(bp.latest_rustup_version(), "1.28.2")
        get.assert_called_once_with(bp.RUSTUP_STABLE)

    def test_latest_rustup_version_refuses_missing_version(self):
        with mock.patch.object(bp, "_get", return_value=b'date = "2026-09-25"\n') as get:
            with self.assertRaisesRegex(RuntimeError, "could not parse a version"):
                bp.latest_rustup_version()
        get.assert_called_once_with(bp.RUSTUP_STABLE)

    def test_malformed_versions_are_refused_before_fetch_or_rewrite(self):
        for version in ("1.2.3/evil", "1.2.3 extra", "1.2.3\n", "1.2", "1.2.3-rc1"):
            with self.subTest(version=version):
                with mock.patch.object(bp, "_get", return_value=('version = "%s"' % version).encode()):
                    with self.assertRaisesRegex(RuntimeError, "invalid rustup version"):
                        bp.latest_rustup_version()
                with mock.patch.object(bp, "_get") as fetch:
                    with self.assertRaisesRegex(RuntimeError, "invalid rustup version"):
                        bp.verified_rustup_shas(version)
                    fetch.assert_not_called()
                with self.assertRaisesRegex(RuntimeError, "invalid rustup version"):
                    bp.rewrite_rustup_pin(DOCKERFILE, version, {})

    def test_sha_is_verified_against_the_artifact(self):
        requested = []
        with mock.patch.object(bp, "_get", _rustup_fetch(
                _rustup_responses("1.30.0"), requested)):
            shas = bp.verified_rustup_shas("1.30.0")
        self.assertEqual(requested, _rustup_urls("1.30.0"))
        self.assertEqual(shas, RUSTUP_SHAS)
        self.assertNotEqual(shas["AMD64"], shas["ARM64"])

    def test_a_published_sha_that_does_not_match_is_refused(self):
        # Reading upstream's .sha256 alone only proves upstream is
        # self-consistent. If the served artifact disagrees with the served
        # digest, that is exactly when a pin must NOT be written.
        requested = []
        with mock.patch.object(bp, "_get", _rustup_fetch(
                _rustup_responses("1.30.0", mismatched=True), requested)):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_rustup_shas("1.30.0")
        self.assertIn("refusing to pin", str(cm.exception))
        self.assertEqual(requested, _rustup_urls("1.30.0"))

    def test_swapped_architecture_artifacts_are_refused(self):
        requested = []
        with mock.patch.object(bp, "_get", _rustup_fetch(
                _rustup_responses("1.30.0", swapped=True), requested)):
            with self.assertRaisesRegex(RuntimeError, "refusing to pin"):
                bp.verified_rustup_shas("1.30.0")
        self.assertEqual(requested, _rustup_urls("1.30.0")[:2])

    def test_a_non_sha_response_is_refused(self):
        # A 404 page or an HTML error body must not be pinned as a checksum.
        requested = []
        responses = _rustup_responses("1.30.0")
        responses[_rustup_urls("1.30.0")[0]] = b"<html>404</html>"
        with mock.patch.object(bp, "_get", _rustup_fetch(responses, requested)):
            with self.assertRaises(RuntimeError):
                bp.verified_rustup_shas("1.30.0")
        self.assertEqual(requested, _rustup_urls("1.30.0")[:1])


class TestMain(unittest.TestCase):
    """The rustup family, end to end through its subcommand."""

    def _run(self, tmp, latest, write=False):
        p = os.path.join(tmp, "Dockerfile")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(DOCKERFILE)
        requested = []
        get = _rustup_fetch(_rustup_responses(latest), requested)
        buf = io.StringIO()
        with mock.patch.object(bp, "latest_rustup_version", return_value=latest), \
             mock.patch.object(bp, "_get", get), \
             mock.patch("sys.stdout", buf):
            rc = bp.main(["rustup", "--dockerfile", p] + (["--write"] if write else []))
        with open(p, encoding="utf-8") as fh:
            return rc, buf.getvalue(), fh.read(), requested

    def test_up_to_date_is_a_no_op(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text, requested = self._run(d, "1.29.1", write=True)
        self.assertEqual(rc, 0)
        self.assertIn("up to date", out)
        self.assertEqual(text, DOCKERFILE, "an up-to-date pin must not be rewritten")
        self.assertEqual(requested, [])

    def test_report_only_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text, requested = self._run(d, "1.30.0")
        self.assertEqual(rc, 0)
        self.assertIn("re-run with --write", out)
        self.assertEqual(text, DOCKERFILE, "no --write must mean no edit")
        self.assertEqual(requested, _rustup_urls("1.30.0"))

    def test_write_applies_the_bump(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, _out, text, requested = self._run(d, "1.30.0", write=True)
        self.assertEqual(rc, 0)
        self.assertEqual(requested, _rustup_urls("1.30.0"))
        v, shas = bp.current_rustup_pin(text)
        self.assertEqual(v, "1.30.0")
        self.assertEqual(shas, RUSTUP_SHAS)


# --- Trivy and compiler freshness: independent publisher fixtures ------------

FRESH_DOCKERFILE = (DOCKERFILE +
                    "ARG TRIVY_VERSION=0.74.0\n"
                    "ARG TRIVY_SHA256_AMD64=" + "1" * 64 + "\n"
                    "ARG TRIVY_SHA256_ARM64=" + "2" * 64 + "\n"
                    "ARG RUST_TOOLCHAIN_VERSION=1.98.1\n"
                    "ARG CARGO_AUDIT_VERSION=0.22.2\n")
TRIVY_NAMES = {
    "AMD64": "trivy_0.75.0_Linux-64bit.tar.gz",
    "ARM64": "trivy_0.75.0_Linux-ARM64.tar.gz",
}
TRIVY_BYTES = {"AMD64": b"independent amd64 tar fixture",
               "ARM64": b"independent arm64 tar fixture"}
TRIVY_DIGESTS = {arch: hashlib.sha256(body).hexdigest()
                 for arch, body in TRIVY_BYTES.items()}
TRIVY_BASE = "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/"
TRIVY_TAG_API = "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v0.75.0"
TRIVY_CHECKSUMS = "trivy_0.75.0_checksums.txt"


def _trivy_fixture(*, checksum_lines=None, swapped=False):
    names = [*TRIVY_NAMES.values(), TRIVY_CHECKSUMS]
    metadata = {"tag_name": "v0.75.0", "assets": [
        {"name": name, "browser_download_url": TRIVY_BASE + name} for name in names]}
    lines = checksum_lines if checksum_lines is not None else [
        "%s  %s" % (TRIVY_DIGESTS[arch], name)
        for arch, name in TRIVY_NAMES.items()]
    responses = {
        bp.TRIVY_LATEST: json.dumps(metadata).encode(),
        TRIVY_TAG_API: json.dumps(metadata).encode(),
        TRIVY_BASE + TRIVY_CHECKSUMS: ("\n".join(lines) + "\n").encode(),
    }
    for arch, name in TRIVY_NAMES.items():
        source = {"AMD64": "ARM64", "ARM64": "AMD64"}[arch] if swapped else arch
        responses[TRIVY_BASE + name] = TRIVY_BYTES[source]
    return responses


def _fixture_get(responses, requests):
    def get(url):
        requests.append(url)
        if url not in responses:
            raise AssertionError("unexpected URL: %s" % url)
        return responses[url]
    return get


RUST_MANIFEST = (b'[pkg.rust]\nversion = "1.99.0 (abcdef123 2026-09-24)"\n'
                 b'[pkg.rust.target.x86_64-unknown-linux-gnu]\navailable = true\n'
                 b'[pkg.rust.target.aarch64-unknown-linux-gnu]\navailable = true\n')


class TestTrivyFreshness(unittest.TestCase):
    def test_literal_architecture_names_and_verified_bytes(self):
        expected_names = {
            "amd64": "trivy_0.74.0_Linux-64bit.tar.gz",
            "arm64": "trivy_0.74.0_Linux-ARM64.tar.gz",
        }
        self.assertEqual(expected_names, {
            arch.lower(): "trivy_0.74.0_%s.tar.gz" % suffix
            for arch, suffix in bp.TRIVY_ARCHIVES.items()})
        self.assertEqual(TRIVY_NAMES, {
            "AMD64": "trivy_0.75.0_Linux-64bit.tar.gz",
            "ARM64": "trivy_0.75.0_Linux-ARM64.tar.gz"})
        requests = []
        with mock.patch.object(bp, "_get", _fixture_get(_trivy_fixture(), requests)):
            self.assertEqual(bp.latest_trivy_version(), "0.75.0")
            self.assertEqual(bp.verified_trivy_shas("0.75.0"), TRIVY_DIGESTS)
        self.assertEqual(requests, [bp.TRIVY_LATEST, TRIVY_TAG_API,
                                    TRIVY_BASE + TRIVY_CHECKSUMS,
                                    TRIVY_BASE + TRIVY_NAMES["AMD64"],
                                    TRIVY_BASE + TRIVY_NAMES["ARM64"]])

    def test_bad_checksums_and_wrong_archives_fail_closed(self):
        good = ["%s  %s" % (TRIVY_DIGESTS[a], n) for a, n in TRIVY_NAMES.items()]
        cases = (good + [good[0]], good[:1],
                 [good[0].replace("  ", " "), good[1]],
                 [good[0].replace("Linux-64bit", "Linux-64bit.tar.gz.extra"), good[1]],
                 ["f" * 64 + "  " + TRIVY_NAMES["AMD64"], good[1]])
        for lines in cases:
            with self.subTest(lines=lines), mock.patch.object(
                    bp, "_get", _fixture_get(_trivy_fixture(checksum_lines=lines), [])):
                with self.assertRaises(RuntimeError):
                    bp.verified_trivy_shas("0.75.0")
        with mock.patch.object(bp, "_get", _fixture_get(_trivy_fixture(swapped=True), [])):
            with self.assertRaisesRegex(RuntimeError, "refusing to pin"):
                bp.verified_trivy_shas("0.75.0")

    def test_invalid_release_and_asset_metadata_fail_closed(self):
        for tag in ("v0.75.0/evil", "0.75.0", "v0.75", "v01.75.0"):
            response = json.dumps({"tag_name": tag, "assets": []}).encode()
            with self.subTest(tag=tag), mock.patch.object(bp, "_get", return_value=response):
                with self.assertRaises(RuntimeError):
                    bp.latest_trivy_version()
        fixture = _trivy_fixture()
        metadata = json.loads(fixture[TRIVY_TAG_API])
        metadata["assets"][0]["browser_download_url"] = "https://example.com/fake"
        fixture[TRIVY_TAG_API] = json.dumps(metadata).encode()
        with mock.patch.object(bp, "_get", _fixture_get(fixture, [])):
            with self.assertRaisesRegex(RuntimeError, "official asset"):
                bp.verified_trivy_shas("0.75.0")

    def test_rewrite_requires_complete_valid_pin_and_sha_map(self):
        updated = bp.rewrite_trivy_pin(FRESH_DOCKERFILE, "0.75.0", TRIVY_DIGESTS)
        self.assertEqual(bp.current_trivy_pin(updated), ("0.75.0", TRIVY_DIGESTS))
        self.assertIn("ARG RUST_TOOLCHAIN_VERSION=1.98.1", updated)
        for text, shas in ((FRESH_DOCKERFILE, {"AMD64": TRIVY_DIGESTS["AMD64"]}),
                           (FRESH_DOCKERFILE.replace("ARG TRIVY_SHA256_ARM64=", "# ARG TRIVY_SHA256_ARM64="), TRIVY_DIGESTS),
                           (FRESH_DOCKERFILE + "ARG TRIVY_VERSION=0.74.0\n", TRIVY_DIGESTS)):
            with self.subTest(text=text, shas=shas), self.assertRaises(RuntimeError):
                bp.rewrite_trivy_pin(text, "0.75.0", shas)

    def test_check_write_and_failed_verification_leave_file_safe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "Dockerfile")
            for args, responses, changed in (
                    ([], _trivy_fixture(), False),
                    (["--write"], _trivy_fixture(), True),
                    (["--write"], _trivy_fixture(swapped=True), False)):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(FRESH_DOCKERFILE)
                with mock.patch.object(bp, "_get", _fixture_get(responses, [])):
                    if changed or not args:
                        self.assertEqual(bp.main(["trivy", "--dockerfile", path] + args), 0)
                    else:
                        with self.assertRaises(RuntimeError):
                            bp.main(["trivy", "--dockerfile", path] + args)
                with open(path, encoding="utf-8") as fh:
                    result = fh.read()
                self.assertEqual(result != FRESH_DOCKERFILE, changed)

    def test_current_release_is_still_verified_before_no_op(self):
        import tempfile
        text = bp.rewrite_trivy_pin(FRESH_DOCKERFILE, "0.75.0", TRIVY_DIGESTS)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "Dockerfile")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            requests = []
            with mock.patch.object(bp, "_get", _fixture_get(_trivy_fixture(), requests)):
                self.assertEqual(bp.main(["trivy", "--dockerfile", path, "--write"]), 0)
            self.assertIn(TRIVY_BASE + TRIVY_NAMES["ARM64"], requests)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), text)


class TestRustToolchainFreshness(unittest.TestCase):
    def _responses(self, manifest=RUST_MANIFEST, sha=None):
        digest = hashlib.sha256(manifest).hexdigest() if sha is None else sha
        return {bp.RUST_STABLE: manifest,
                bp.RUST_STABLE + ".sha256": (digest + "  channel-rust-stable.toml\n").encode()}

    def test_checksum_verified_manifest_and_available_targets(self):
        requests = []
        with mock.patch.object(bp, "_get", _fixture_get(self._responses(), requests)):
            self.assertEqual(bp.latest_rust_toolchain_version(), "1.99.0")
        self.assertEqual(requests, [bp.RUST_STABLE, bp.RUST_STABLE + ".sha256"])

    def test_bad_checksum_version_or_target_fails_closed(self):
        cases = (self._responses(sha="f" * 64),
                 self._responses(RUST_MANIFEST.replace(b"1.99.0", b"1.99.0-rc1")),
                 self._responses(RUST_MANIFEST.replace(b"available = true", b"available = false", 1)),
                 self._responses(RUST_MANIFEST.replace(b"aarch64-unknown-linux-gnu", b"aarch64-unknown-linux-musl")))
        for responses in cases:
            with self.subTest(responses=responses), mock.patch.object(
                    bp, "_get", _fixture_get(responses, [])):
                with self.assertRaises(RuntimeError):
                    bp.latest_rust_toolchain_version()

    def test_rewrite_only_compiler_and_check_write_behavior(self):
        import tempfile
        rewritten = bp.rewrite_rust_toolchain_pin(FRESH_DOCKERFILE, "1.99.0")
        self.assertEqual(rewritten.replace("ARG RUST_TOOLCHAIN_VERSION=1.99.0",
                                           "ARG RUST_TOOLCHAIN_VERSION=1.98.1"), FRESH_DOCKERFILE)
        with self.assertRaises(RuntimeError):
            bp.rewrite_rust_toolchain_pin(FRESH_DOCKERFILE, "1.99.0-rc1")
        with self.assertRaises(RuntimeError):
            bp.rewrite_rust_toolchain_pin(FRESH_DOCKERFILE.replace("ARG RUST_TOOLCHAIN_VERSION=", "# ARG RUST_TOOLCHAIN_VERSION="), "1.99.0")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "Dockerfile")
            for write in (False, True):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(FRESH_DOCKERFILE)
                with mock.patch.object(bp, "_get", _fixture_get(self._responses(), [])):
                    self.assertEqual(bp.main(["rust-toolchain", "--dockerfile", path] +
                                             (["--write"] if write else [])), 0)
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), rewritten if write else FRESH_DOCKERFILE)
            with mock.patch.object(bp, "_get", _fixture_get(self._responses(sha="f" * 64), [])):
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    bp.main(["rust-toolchain", "--dockerfile", path, "--write"])
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), rewritten)


# --- family: requirements (#1641) --------------------------------------------
# Canned PyPI, never the live index: the rule these tests exist to hold is that
# a digest is read from upstream AND recomputed from the artifact, and a test
# that fetched the real wheel would prove that about PyPI's uptime rather than
# about this code.

REQUIREMENTS = """\
# The gate installs exactly this, with --require-hashes.
pytest==9.1.1

pluggy==1.6.0 \\
    --hash=sha256:%s
""" % ("9" * 64)

WHEEL = b"wheel bytes"
OTHER = b"other wheel bytes"
WHEEL_SHA = hashlib.sha256(WHEEL).hexdigest()
OTHER_SHA = hashlib.sha256(OTHER).hexdigest()


def _release(files):
    """A PyPI release document: [(filename, bytes, published_sha)]."""
    return {"urls": [{"filename": name,
                      "url": "https://files.pythonhosted.test/" + name,
                      "packagetype": "bdist_wheel",
                      "digests": {"sha256": sha}}
                     for name, _body, sha in files]}


def _canned(files):
    """A `_get` answering the release JSON and each artifact it names."""
    bodies = {"https://files.pythonhosted.test/" + n: b for n, b, _s in files}

    def get(url):
        if url.endswith("/json"):
            return json.dumps(_release(files)).encode()
        return bodies[url]
    return get


PURE = [("pytest-9.1.1-py3-none-any.whl", WHEEL, WHEEL_SHA)]


class TestWheelSelection(unittest.TestCase):
    """Which artifacts the linux builds this repo pins for could be served."""

    def test_pure_python_and_linux_wheels_are_selected(self):
        for name in ("pytest-9.1.1-py3-none-any.whl",
                     "six-1.17.0-py2.py3-none-any.whl",
                     "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64."
                     "manylinux_2_17_x86_64.whl",
                     "pyyaml-6.0.3-cp312-cp312-musllinux_1_2_x86_64.whl"):
            self.assertTrue(bp.wheel_is_installable(name), name)

    def test_linux_aarch64_wheels_are_selected_too(self):
        # #1734: the tools image publishes linux/amd64 AND linux/arm64
        # (docker-publish.yml), so a hash block holding only the x86_64 wheel
        # makes `--require-hashes` fail the arm64 leg of the build -- the one
        # architecture nobody develops on, on a matrix build where the other leg
        # goes green. The gate and fixture files gain the extra digests
        # harmlessly: pip needs ONE hash on the line to match what it fetched.
        for name in ("pyyaml-6.0.3-cp312-cp312-manylinux2014_aarch64."
                     "manylinux_2_17_aarch64.whl",
                     "pyyaml-6.0.3-cp312-cp312-musllinux_1_2_aarch64.whl"):
            self.assertTrue(bp.wheel_is_installable(name), name)

    def test_other_platforms_and_sdists_are_not(self):
        # macosx_*_arm64 is the trap the aarch64 widening must not spring: it
        # ends in `arm64`, and a substring rule that forgot to require `linux`
        # would pin a wheel no build here can install.
        for name in ("pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl",
                     "pyyaml-6.0.3-cp312-cp312-macosx_10_13_x86_64.whl",
                     "pyyaml-6.0.3-cp312-cp312-win_amd64.whl",
                     "pywin32-311-cp312-cp312-win_arm64.whl",
                     "pytest-9.1.1.tar.gz"):
            self.assertFalse(bp.wheel_is_installable(name), name)


class TestPypiVerification(unittest.TestCase):
    def test_every_installable_wheel_is_hashed_and_verified(self):
        files = PURE + [("pyyaml-6.0.3-cp312-cp312-manylinux_2_17_x86_64.whl",
                         OTHER, OTHER_SHA),
                        ("pyyaml-6.0.3-cp312-cp312-win_amd64.whl", b"win", "f" * 64)]
        with mock.patch.object(bp, "_get", _canned(files)):
            digests = bp.verified_pypi_hashes("pyyaml", "6.0.3")
        # The win32 wheel is not selected, so its (bogus) digest is never
        # reached: selection happens before verification, not after.
        self.assertEqual(sorted({WHEEL_SHA, OTHER_SHA}), digests)

    def test_a_published_digest_that_does_not_match_is_refused(self):
        with mock.patch.object(bp, "_get", _canned(
                [("pytest-9.1.1-py3-none-any.whl", WHEEL, "e" * 64)])):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_pypi_hashes("pytest", "9.1.1")
        self.assertIn("refusing to pin", str(cm.exception))

    def test_a_non_sha_digest_is_refused(self):
        with mock.patch.object(bp, "_get", _canned(
                [("pytest-9.1.1-py3-none-any.whl", WHEEL, "not-a-digest")])):
            with self.assertRaises(RuntimeError):
                bp.verified_pypi_hashes("pytest", "9.1.1")

    def test_a_release_with_nothing_installable_is_refused(self):
        # Falling back to an sdist would build arbitrary code at install time in
        # the two contexts this pin exists to protect.
        with mock.patch.object(bp, "_get", _canned(
                [("pytest-9.1.1-cp312-cp312-win_amd64.whl", WHEEL, WHEEL_SHA)])):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_pypi_hashes("pytest", "9.1.1")
        self.assertIn("no wheel this platform may install", str(cm.exception))

    def test_a_non_json_answer_is_refused(self):
        with mock.patch.object(bp, "_get", lambda url: b"<html>404</html>"):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_pypi_hashes("pytest", "9.1.1")
        self.assertIn("did not answer with JSON", str(cm.exception))


class TestRequirementsRewrite(unittest.TestCase):
    def test_reads_every_pin_including_hashed_ones(self):
        self.assertEqual([("pytest", "9.1.1"), ("pluggy", "1.6.0")],
                         bp.parse_requirements(REQUIREMENTS))

    def test_a_comment_that_looks_like_a_pin_is_not_one(self):
        self.assertEqual([], bp.parse_requirements("# pytest==9.1.1\n"))

    def test_writes_a_hash_block_and_keeps_the_prose(self):
        out = bp.rewrite_requirements(
            REQUIREMENTS, {("pytest", "9.1.1"): [WHEEL_SHA, OTHER_SHA],
                           ("pluggy", "1.6.0"): ["1" * 64]})
        self.assertIn("# The gate installs exactly this", out)
        self.assertIn("pytest==9.1.1 \\\n    --hash=sha256:%s \\\n"
                      "    --hash=sha256:%s\n" % (WHEEL_SHA, OTHER_SHA), out)
        # the old digest is replaced, not appended to
        self.assertNotIn("9" * 64, out)
        self.assertEqual([("pytest", "9.1.1"), ("pluggy", "1.6.0")],
                         bp.parse_requirements(out))

    def test_rewriting_twice_changes_nothing(self):
        hashes = {("pytest", "9.1.1"): [WHEEL_SHA], ("pluggy", "1.6.0"): ["1" * 64]}
        once = bp.rewrite_requirements(REQUIREMENTS, hashes)
        self.assertEqual(once, bp.rewrite_requirements(once, hashes))

    def test_a_pin_with_no_verified_hashes_raises(self):
        # Silently leaving a pin unhashed is the one outcome that matters: pip
        # would refuse the whole file at install time, in the privileged build.
        with self.assertRaises(RuntimeError) as cm:
            bp.rewrite_requirements(REQUIREMENTS, {("pytest", "9.1.1"): [WHEEL_SHA]})
        self.assertIn("pluggy==1.6.0", str(cm.exception))

    def test_hashes_for_a_pin_the_file_does_not_carry_raise(self):
        with self.assertRaises(RuntimeError) as cm:
            bp.rewrite_requirements(
                "pytest==9.1.1\n", {("pytest", "9.1.1"): [WHEEL_SHA],
                                    ("ruff", "0.16.6"): [OTHER_SHA]})
        self.assertIn("ruff==0.16.6", str(cm.exception))


class TestRequirementsMain(unittest.TestCase):
    def _run(self, tmp, write=False, seed="pytest==9.1.1\n"):
        p = os.path.join(tmp, "requirements-gate.txt")
        if seed is not None:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(seed)
        buf = io.StringIO()
        with mock.patch.object(bp, "_get", _canned(PURE)), \
             mock.patch("sys.stdout", buf):
            rc = bp.main(["requirements", "--file", p] + (["--write"] if write else []))
        with open(p, encoding="utf-8") as fh:
            return rc, buf.getvalue(), fh.read()

    def test_report_only_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d)
        self.assertEqual(rc, 0)
        self.assertIn("re-run with --write", out)
        self.assertEqual(text, "pytest==9.1.1\n", "no --write must mean no edit")

    def test_write_fills_the_hashes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d, write=True)
        self.assertEqual(rc, 0)
        self.assertIn("--hash=sha256:%s" % WHEEL_SHA, text)
        self.assertIn("1 artifact(s)", out)

    def test_an_already_hashed_file_is_a_no_op(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self._run(d, write=True)
            rc, out, _text = self._run(d, write=True, seed=None)
        self.assertEqual(rc, 0)
        self.assertIn("up to date", out)

    def test_naming_no_family_is_an_error_not_a_default(self):
        # Two families now write pins; guessing which one the operator meant is
        # how the wrong file gets rewritten.
        with self.assertRaises(SystemExit):
            bp.main([])

    def test_every_privileged_requirements_file_is_on_the_default_list(self):
        # The default list is what `bump_pins requirements` refreshes when no
        # --file is named, which is how an operator refreshes them all beside a
        # version bump. A hashed file missing from it is one nobody re-reads:
        # its digests go stale silently and the next build fails on a pin
        # nothing was watching. #1734 added the tools image's closure.
        self.assertEqual(
            (".github/requirements-gate.txt", "requirements-fixtures.txt",
             "requirements-tools.txt"),
            bp.REQUIREMENTS_FILES)


# --- family: gems (#1734) ----------------------------------------------------
# Canned rubygems, never the live index: what these hold is that a digest is
# read from upstream AND recomputed from the .gem, and a test that fetched the
# real gem would be testing rubygems' uptime instead.

GEM_DOCKERFILE = """\
ARG BRAKEMAN_VERSION=8.0.6
ARG BUNDLER_AUDIT_VERSION=0.9.3
ARG THOR_VERSION=1.5.0
ARG THOR_GEM_SHA256=%s
ARG BRAKEMAN_GEM_SHA256=%s
ARG BUNDLER_AUDIT_GEM_SHA256=%s
RUN curl -sfL "https://rubygems.org/downloads/thor-${THOR_VERSION}.gem" -o /tmp/thor.gem
""" % ("a" * 64, "b" * 64, "c" * 64)

GEM = b"gem bytes"
GEM_SHA = hashlib.sha256(GEM).hexdigest()


def _gem_of(url):
    """The gem name in a rubygems API url, or None for a download url."""
    for pattern in (r"/api/v1/versions/([^/]+)/latest\.json",
                    r"/api/v2/rubygems/([^/]+)/versions/"):
        m = re.search(pattern, url)
        if m:
            return m.group(1)
    return None


def _canned_gems(runtime=None, sha=GEM_SHA, latest="1.5.0", artifact=GEM):
    """A `_get` answering rubygems' three endpoints, per gem name.

    `runtime` is {gem: {dependency: requirement}}; a gem it does not name
    answers with the closure this repo has REVIEWED, so a test states only
    what it changes and cannot accidentally assert the table's contents.
    """
    runtime = dict(runtime or {})

    def get(url):
        name = _gem_of(url)
        if "/api/v1/versions/" in url:
            return json.dumps({"version": latest}).encode()
        if "/api/v2/rubygems/" in url:
            deps = runtime.get(name, bp.REVIEWED_GEM_RUNTIME.get(name, {}))
            return json.dumps({
                "sha": sha, "platform": "ruby",
                "dependencies": {
                    "runtime": [{"name": n, "requirements": r}
                                for n, r in sorted(deps.items())],
                    "development": []}}).encode()
        return artifact
    return get


class TestGemPins(unittest.TestCase):
    def test_reads_every_current_pin(self):
        self.assertEqual(
            {"BRAKEMAN": ("8.0.6", "b" * 64),
             "BUNDLER_AUDIT": ("0.9.3", "c" * 64),
             "THOR": ("1.5.0", "a" * 64)},
            bp.current_gem_pins(GEM_DOCKERFILE))

    def test_a_half_written_pin_is_not_a_pin(self):
        # A version with no digest beside it is the shape a careless bump
        # leaves behind; reporting it as pinned would hide exactly that.
        self.assertEqual({}, bp.current_gem_pins("ARG THOR_VERSION=1.5.0\n"))
        self.assertEqual({}, bp.current_gem_pins("FROM scratch\n"))

    def test_malformed_versions_are_refused_before_fetch_or_rewrite(self):
        for version in ("1.5.0/evil", "1.5.0 extra", "1.5.0\n", "v1.5.0",
                        "1.5.0.pre1"):
            with self.subTest(version=version):
                with mock.patch.object(bp, "_get") as fetch:
                    with self.assertRaisesRegex(RuntimeError, "invalid gem version"):
                        bp.verified_gem_sha("thor", version)
                    fetch.assert_not_called()
                with self.assertRaisesRegex(RuntimeError, "invalid gem version"):
                    bp.rewrite_gem_pin(GEM_DOCKERFILE, "THOR", version, "d" * 64)


class TestGemVerification(unittest.TestCase):
    def test_sha_and_requirements_are_read_from_upstream(self):
        with mock.patch.object(bp, "_get", _canned_gems()):
            sha, runtime = bp.verified_gem_sha("bundler-audit", "0.9.3")
        self.assertEqual(GEM_SHA, sha)
        # the REQUIREMENT comes back with the name: a constraint this tool
        # cannot evaluate is still a constraint it has to notice changing.
        self.assertEqual({"bundler": ">= 1.2.0", "thor": "~> 1.0"}, runtime)

    def test_a_published_sha_that_does_not_match_is_refused(self):
        with mock.patch.object(bp, "_get", _canned_gems(sha="f" * 64)):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_gem_sha("thor", "1.5.0")
        self.assertIn("refusing to pin", str(cm.exception))

    def test_a_non_sha_response_is_refused(self):
        for body in ("<html>404</html>", "", None):
            with self.subTest(body=body), mock.patch.object(
                    bp, "_get", _canned_gems(sha=body)):
                with self.assertRaises(RuntimeError):
                    bp.verified_gem_sha("thor", "1.5.0")


class TestReviewedGemClosure(unittest.TestCase):
    """The rule on both answers, on canned release documents."""

    def test_the_reviewed_closure_itself_is_no_drift(self):
        for gem, reviewed in bp.REVIEWED_GEM_RUNTIME.items():
            with self.subTest(gem=gem):
                self.assertEqual([], bp.unreviewed_gem_requirements(gem, dict(reviewed)))

    def test_every_gem_the_image_installs_has_a_reviewed_closure(self):
        # A gem added to GEMS with no entry here would be bumped against a
        # table that does not describe it, which is the one state the rule
        # cannot reason about.
        self.assertEqual({name for _prefix, name in bp.GEMS},
                         set(bp.REVIEWED_GEM_RUNTIME))

    def test_a_new_dependency_is_drift(self):
        drift = bp.unreviewed_gem_requirements("thor", {"rainbow": ">= 0"})
        self.assertEqual(1, len(drift), drift)
        self.assertIn("rainbow", drift[0])
        self.assertIn("does not install", drift[0])

    def test_a_tightened_constraint_on_a_base_ruby_gem_is_drift(self):
        # The hole the name-only comparison left: racc comes from the base
        # image's ruby, so `>= 0` -> `>= 1.8` is a question only the image
        # build can answer -- and it used to be pinned green here first.
        drift = bp.unreviewed_gem_requirements("brakeman", {"racc": ">= 1.8"})
        self.assertEqual(1, len(drift), drift)
        self.assertIn("racc", drift[0])
        self.assertIn("'>= 0'", drift[0])
        self.assertIn("'>= 1.8'", drift[0])

    def test_a_dropped_dependency_is_drift(self):
        drift = bp.unreviewed_gem_requirements("bundler-audit",
                                               {"bundler": ">= 1.2.0"})
        self.assertEqual(1, len(drift), drift)
        self.assertIn("no longer requires thor", drift[0])

    def test_an_unknown_gem_is_drift_rather_than_a_pass(self):
        self.assertTrue(bp.unreviewed_gem_requirements("rainbow", {}))


class TestGemRewrite(unittest.TestCase):
    def test_rewrites_version_and_digest_together(self):
        out = bp.rewrite_gem_pin(GEM_DOCKERFILE, "THOR", "1.6.0", "d" * 64)
        self.assertEqual(("1.6.0", "d" * 64), bp.current_gem_pins(out)["THOR"])
        # the fetch is templated on ${THOR_VERSION} and must not be edited, or
        # a bump would have two places to keep in sync.
        self.assertIn("thor-${THOR_VERSION}.gem", out)
        # the other two gems are untouched
        self.assertEqual(("8.0.6", "b" * 64), bp.current_gem_pins(out)["BRAKEMAN"])

    def test_missing_line_raises_rather_than_silently_no_op(self):
        for text in ("FROM scratch\n", "ARG THOR_VERSION=1.5.0\n"):
            with self.assertRaises(RuntimeError):
                bp.rewrite_gem_pin(text, "THOR", "1.6.0", "d" * 64)


class TestGemsMain(unittest.TestCase):
    """The gems family end to end through its subcommand."""

    def _run(self, tmp, get, write=False, text=GEM_DOCKERFILE):
        path = os.path.join(tmp, "Dockerfile")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        buf = io.StringIO()
        with mock.patch.object(bp, "_get", get), mock.patch("sys.stdout", buf):
            rc = bp.main(["gems", "--dockerfile", path]
                         + (["--write"] if write else []))
        with open(path, encoding="utf-8") as fh:
            return rc, buf.getvalue(), fh.read()

    def test_up_to_date_is_a_no_op(self):
        import tempfile
        # every gem already at the latest version rubygems reports
        def get(url):
            for name, version in (("thor", "1.5.0"), ("brakeman", "8.0.6"),
                                  ("bundler-audit", "0.9.3")):
                if "/%s/" % name in url or "/%s.json" % name in url:
                    return json.dumps({"version": version}).encode()
            raise AssertionError("unexpected url " + url)
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d, get, write=True)
        self.assertEqual(0, rc)
        self.assertIn("up to date", out)
        self.assertEqual(GEM_DOCKERFILE, text, "an up-to-date pin was rewritten")

    def test_report_only_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d, _canned_gems(latest="9.9.9"))
        self.assertEqual(0, rc)
        self.assertIn("re-run with --write", out)
        self.assertEqual(GEM_DOCKERFILE, text, "no --write must mean no edit")

    def test_write_applies_the_bump(self):
        # The reviewed closure, unchanged, is what a routine bump looks like.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, _out, text = self._run(d, _canned_gems(latest="9.9.9"),
                                       write=True)
        self.assertEqual(0, rc)
        for prefix in ("THOR", "BRAKEMAN", "BUNDLER_AUDIT"):
            self.assertEqual(("9.9.9", GEM_SHA), bp.current_gem_pins(text)[prefix])

    def _refuses(self, runtime):
        """--write against a drifted closure: raises, and writes nothing."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "Dockerfile")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(GEM_DOCKERFILE)
            with mock.patch.object(bp, "_get",
                                   _canned_gems(runtime, latest="9.9.9")), \
                    mock.patch("sys.stdout", io.StringIO()):
                with self.assertRaises(RuntimeError) as cm:
                    bp.main(["gems", "--dockerfile", path, "--write"])
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(GEM_DOCKERFILE, fh.read(),
                                 "a refused bump still wrote to the Dockerfile")
        return str(cm.exception)

    def test_a_grown_runtime_closure_refuses_to_pin(self):
        # The whole point of the Dockerfile's `--ignore-dependencies` install is
        # that the closure is written down. A new release that requires
        # something nobody installs would be pinned green here and then fail --
        # or worse, half-work -- inside the image, so it must stop the bump and
        # say the name.
        self.assertIn("rainbow", self._refuses({"thor": {"rainbow": ">= 0"}}))

    def test_a_tightened_constraint_refuses_to_pin(self):
        message = self._refuses({"brakeman": {"racc": ">= 1.8"}})
        self.assertIn("racc", message)
        self.assertIn("--ignore-dependencies", message)


if __name__ == "__main__":
    unittest.main()
