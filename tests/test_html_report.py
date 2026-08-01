import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.html_report as hr


class TestHtmlReport(unittest.TestCase):
    def test_escape_escapes_html(self):
        self.assertEqual(hr._escape("<script>alert('x')</script>"),
                         "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;")

    def test_html_doc_is_complete(self):
        doc = hr._html_doc("Test Report", "<p>hello</p>")
        self.assertTrue(doc.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>Test Report</title>", doc)
        self.assertIn("<p>hello</p>", doc)
        self.assertIn(hr._CSS, doc)
        self.assertIn(hr._JS, doc)
