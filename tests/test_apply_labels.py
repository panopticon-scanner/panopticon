import os
import subprocess
import unittest

from conftest import REPO_ROOT

SCRIPT = os.path.join(REPO_ROOT, ".github", "apply-labels.sh")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "labels.yml")


def _run_script():
    proc = subprocess.run(
        ["bash", SCRIPT, "--dry-run"],
        cwd=REPO_ROOT,
        env={**os.environ, "CATALOG": FIXTURE},
        capture_output=True, text=True, timeout=60)   # #run7 TST-G3B: bound the shell-out
    if proc.returncode != 0:
        raise AssertionError("apply-labels.sh failed: %s" % proc.stderr)
    labels = {}
    for line in proc.stdout.splitlines():
        if not line.startswith("would apply:"):
            continue
        # line format: would apply: name (color) — description
        prefix = "would apply: "
        suffix = line[len(prefix):]
        name_color, _, description = suffix.partition(" — ")
        name, _, color = name_color.rpartition(" (")
        color = color.rstrip(")")
        labels[name] = {"color": color, "description": description}
    return labels


class TestApplyLabels(unittest.TestCase):
    def test_normal_entry_extracted(self):
        labels = _run_script()
        self.assertIn("normal-label", labels)
        self.assertEqual(labels["normal-label"]["color"], "000000")
        self.assertEqual(labels["normal-label"]["description"], "Normal entry")

    def test_multiline_description_extracted(self):
        labels = _run_script()
        self.assertIn("multi-line-label", labels)
        self.assertEqual(labels["multi-line-label"]["color"], "111111")
        self.assertEqual(
            labels["multi-line-label"]["description"],
            "Multi-line description")

    def test_reversed_field_order_extracted(self):
        labels = _run_script()
        self.assertIn("reversed-order-label", labels)
        self.assertEqual(labels["reversed-order-label"]["color"], "222222")
        self.assertEqual(
            labels["reversed-order-label"]["description"],
            "Reversed field order")

    def test_embedded_quote_extracted_intact(self):
        labels = _run_script()
        self.assertIn('label-with-"quote', labels)
        self.assertEqual(labels['label-with-"quote']["color"], "333333")
        self.assertEqual(
            labels['label-with-"quote']["description"],
            'Description with "embedded" quote')

    def test_nested_catalog_categories_are_flattened(self):
        labels = _run_script()
        self.assertIn("severity:critical", labels)
        self.assertEqual(labels["severity:critical"]["color"], "b60205")
