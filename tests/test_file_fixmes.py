"""Parameterization + parse guards for file_fixmes (#606).

The DOC path, DOC_URL, and 'run-2 self-scan (2026-08-04)' body text were
hardcoded, so filing a later run's FIXMEs required editing the script. They are
now flags; defaults preserve run-2 behavior. Also pins the section parser.
"""
import os
import shutil
import tempfile
import unittest

import file_fixmes


FIXME_DOC = """# Run FIXMEs

## FIXME-1 — Scout omits a schema field
`bug`, `panel:code`

The scout returned a ScopeProfile missing `depth`.

Second paragraph.

## FIXME-2 — Group names are ._N
`enhancement`

Chunk names reshuffle across runs.

---

## Already fixed
Commentary that must not be filed.
"""


class TestParse(unittest.TestCase):
    def _doc(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "fixmes.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(FIXME_DOC)
        return path

    def test_parses_sections_and_stops_at_trailing_rule(self):
        fixmes = file_fixmes.parse(self._doc())
        self.assertEqual([f["id"] for f in fixmes], ["FIXME-1", "FIXME-2"])
        self.assertEqual(fixmes[0]["title"], "Scout omits a schema field")
        self.assertEqual(fixmes[0]["labels"], ["bug", "panel:code"])
        # label line dropped from body; body content retained
        self.assertNotIn("`bug`", fixmes[0]["body"])
        self.assertIn("missing `depth`", fixmes[0]["body"])
        self.assertNotIn("Already fixed", " ".join(f["body"] for f in fixmes))


class TestBodyProvenance(unittest.TestCase):
    F = {"id": "FIXME-1", "title": "t", "labels": [], "body": "what happened"}

    def test_defaults_describe_run2(self):
        body = file_fixmes.body_for(self.F)
        self.assertIn("run-2 self-scan (2026-08-04", body)
        self.assertIn(file_fixmes.DOC, body)
        self.assertIn("panopticon-scanner/panopticon", body)  # not stale psyberone

    def test_overrides_thread_through(self):
        body = file_fixmes.body_for(
            self.F, doc="docs/superpowers/2026-08-08-run3-fixmes.md",
            doc_url="https://example.test/run3-fixmes.md",
            run_label="run-3", run_date="2026-08-08")
        self.assertIn("run-3 self-scan (2026-08-08", body)
        self.assertIn("https://example.test/run3-fixmes.md", body)
        self.assertIn("2026-08-08-run3-fixmes.md", body)
        self.assertNotIn("run-2 self-scan (2026-08-04", body)


class TestScrubbing(unittest.TestCase):
    def test_title_and_body_scrub_repo_root(self):
        """SEC-B2C: absolute local paths in FIXME text must not reach public issues."""
        root = file_fixmes.file_issues.repo_root()
        f = {
            "id": "FIXME-99",
            "title": "Broken on %ssrc/main.py" % root,
            "labels": ["bug"],
            "body": "Crash happens under %ssrc/main.py when loaded." % root,
        }
        body = file_fixmes.body_for(f)
        self.assertNotIn(root, body)
        self.assertIn("src/main.py", body)
        title = file_fixmes.file_issues.scrub(
            file_fixmes.file_issues.defang("%s — %s" % (f["id"], f["title"])))
        self.assertNotIn(root, title)


if __name__ == "__main__":
    unittest.main()
