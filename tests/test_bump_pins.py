import hashlib
import io
import json
import os
import unittest
from unittest import mock

import bump_pins as bp

DOCKERFILE = """\
ENV PATH="/usr/local/cargo/bin:${PATH}"
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256_AMD64=%s
ARG RUSTUP_INIT_SHA256_ARM64=%s
RUN curl -sfL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${ru}/rustup-init"
""" % ("a" * 64, "b" * 64)


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

    def _fake_get(self, artifact, published):
        def get(url):
            return published.encode() if url.endswith(".sha256") else artifact
        return get

    def test_sha_is_verified_against_the_artifact(self):
        art = b"rustup-init bytes"
        good = hashlib.sha256(art).hexdigest()
        with mock.patch.object(bp, "_get", self._fake_get(art, good)):
            shas = bp.verified_rustup_shas("1.30.0")
        self.assertEqual(set(shas), {"AMD64", "ARM64"})
        self.assertEqual(shas["AMD64"], good)

    def test_a_published_sha_that_does_not_match_is_refused(self):
        # Reading upstream's .sha256 alone only proves upstream is
        # self-consistent. If the served artifact disagrees with the served
        # digest, that is exactly when a pin must NOT be written.
        art = b"rustup-init bytes"
        with mock.patch.object(bp, "_get", self._fake_get(art, "f" * 64)):
            with self.assertRaises(RuntimeError) as cm:
                bp.verified_rustup_shas("1.30.0")
        self.assertIn("refusing to pin", str(cm.exception))

    def test_a_non_sha_response_is_refused(self):
        # A 404 page or an HTML error body must not be pinned as a checksum.
        with mock.patch.object(bp, "_get", self._fake_get(b"x", "<html>404</html>")):
            with self.assertRaises(RuntimeError):
                bp.verified_rustup_shas("1.30.0")


class TestMain(unittest.TestCase):
    """The rustup family, end to end through its subcommand."""

    def _run(self, tmp, latest, write=False):
        p = os.path.join(tmp, "Dockerfile")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(DOCKERFILE)
        art = b"bytes"
        sha = hashlib.sha256(art).hexdigest()
        def get(url):
            return sha.encode() if url.endswith(".sha256") else art
        buf = io.StringIO()
        with mock.patch.object(bp, "latest_rustup_version", return_value=latest), \
             mock.patch.object(bp, "_get", get), \
             mock.patch("sys.stdout", buf):
            rc = bp.main(["rustup", "--dockerfile", p] + (["--write"] if write else []))
        with open(p, encoding="utf-8") as fh:
            return rc, buf.getvalue(), fh.read()

    def test_up_to_date_is_a_no_op(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d, "1.29.1", write=True)
        self.assertEqual(rc, 0)
        self.assertIn("up to date", out)
        self.assertEqual(text, DOCKERFILE, "an up-to-date pin must not be rewritten")

    def test_report_only_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, out, text = self._run(d, "1.30.0")
        self.assertEqual(rc, 0)
        self.assertIn("re-run with --write", out)
        self.assertEqual(text, DOCKERFILE, "no --write must mean no edit")

    def test_write_applies_the_bump(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc, _out, text = self._run(d, "1.30.0", write=True)
        self.assertEqual(rc, 0)
        v, _ = bp.current_rustup_pin(text)
        self.assertEqual(v, "1.30.0")


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
    """Which artifacts a linux x86_64 build could actually be served."""

    def test_pure_python_and_linux_x86_64_wheels_are_selected(self):
        for name in ("pytest-9.1.1-py3-none-any.whl",
                     "six-1.17.0-py2.py3-none-any.whl",
                     "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64."
                     "manylinux_2_17_x86_64.whl",
                     "pyyaml-6.0.3-cp312-cp312-musllinux_1_2_x86_64.whl"):
            self.assertTrue(bp.wheel_is_installable(name), name)

    def test_other_platforms_and_sdists_are_not(self):
        for name in ("pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl",
                     "pyyaml-6.0.3-cp312-cp312-macosx_10_13_x86_64.whl",
                     "pyyaml-6.0.3-cp312-cp312-win_amd64.whl",
                     "pyyaml-6.0.3-cp312-cp312-manylinux_2_17_aarch64.whl",
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


if __name__ == "__main__":
    unittest.main()
