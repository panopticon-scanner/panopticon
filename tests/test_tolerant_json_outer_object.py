"""A large reply wrapped in prose must still read as its OUTER document.

A setup-scan proposal for a 4,000-file monorepo carries hundreds of nested
objects (one per group, layer and profile). `tolerant_json.first_balanced_object`
remembers at most `_SCAN_CANDIDATES` closed spans, in CLOSING order, and the
outer object closes last -- so once a document nested more than the cap, any
prose or trailing text around it (which defeats the strict parse first) made
the reader hand back the first INNER object instead. On langfuse, ingest then
refused the proposal ("'groups' must be a non-empty list") after a paid
25-minute dispatch, twice: the replies were a single group object and a single
profile object, each valid JSON on its own.
"""
import json
import unittest

import scripts.tolerant_json as tolerant_json


def proposal(n_groups, n_layers):
    groups = []
    for i in range(n_groups):
        groups.append({
            "capability": "custom:Group%03d" % i,
            "layers": [{"layer": "API", "match": ["web/src/g%03d/l%d/**" % (i, j)]}
                       for j in range(n_layers)],
            "match": ["web/src/g%03d/**" % i],
            "profile": {"entry_points": ["web/src/g%03d/router.ts" % i],
                        "purpose": "Group %d." % i,
                        "surfaces": ["http_web"],
                        "trust_boundaries": ["body parsed in router.ts"]},
            "tests": ["web/src/g%03d/**/*.test.ts" % i]})
    return {"groups": groups}


class OuterObjectSurvivesTheCandidateCap(unittest.TestCase):
    def setUp(self):
        # 120 groups x (group + 3 layers + profile) = 600 nested objects,
        # comfortably past the 256-span cap.
        self.doc = proposal(120, 3)
        self.encoded = json.dumps(self.doc, sort_keys=True, indent=1)
        objects = self.encoded.count("{")
        self.assertGreater(objects, tolerant_json._SCAN_CANDIDATES)

    def test_pure_document_reads_whole(self):
        self.assertEqual(tolerant_json.loads(self.encoded), self.doc)

    def test_prose_prefixed_fenced_document_reads_whole(self):
        text = "Here is the proposal:\n\n```json\n" + self.encoded + "\n```"
        self.assertEqual(tolerant_json.loads(text), self.doc)

    def test_fenced_document_with_trailing_prose_reads_whole(self):
        text = "```json\n" + self.encoded + "\n```\n\nNotes: three layers merged."
        self.assertEqual(tolerant_json.loads(text), self.doc)

    def test_first_balanced_object_prefers_the_enclosing_span(self):
        text = "prefix {not json} " + self.encoded + " suffix"
        self.assertEqual(tolerant_json.first_balanced_object(text), self.doc)

    def test_prose_braces_before_a_bundle_still_reach_it(self):
        # The #1058 shapes the bounded scanner was built for are unchanged.
        bundle = {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}]}
        encoded = json.dumps(bundle)
        for prefix in ('I checked "if (x) { y" in app.py.\n',
                       "".join("{n%d}" % i for i in range(300)),
                       "{a{b{c{d{e}}}}}" * 30):
            with self.subTest(prefix=prefix[:20]):
                self.assertEqual(tolerant_json.loads(prefix + encoded), bundle)


if __name__ == "__main__":
    unittest.main()
