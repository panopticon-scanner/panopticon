import json
import os
import unittest

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "reference", "report-schema.json")


class TestReportSchema(unittest.TestCase):
    def test_schema_is_valid_json(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertEqual(schema["title"], "CodeReviewReport")


if __name__ == "__main__":
    unittest.main()
