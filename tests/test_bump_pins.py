import hashlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scripts import bump_pins as bp  # noqa: E402

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
            rc = bp.main(["--dockerfile", p] + (["--write"] if write else []))
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


if __name__ == "__main__":
    unittest.main()
