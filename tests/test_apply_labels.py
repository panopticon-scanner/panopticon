import os
import subprocess
import sys
import tempfile
import unittest

import yaml

from conftest import REPO_ROOT

SCRIPT = os.path.join(REPO_ROOT, ".github", "apply-labels.sh")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "labels.yml")
CATALOG = os.path.join(REPO_ROOT, ".github", "labels.yml")


def _dry_run(catalog):
    # A private gh executable makes an accidental non-dry run harmless.
    with tempfile.TemporaryDirectory(prefix="panopticon-labels-") as root:
        bin_dir = os.path.join(root, "bin")
        os.mkdir(bin_dir)
        test_home = os.path.join(root, "test-home")
        os.mkdir(test_home)
        temp_dir = os.path.join(root, "tmp")
        os.mkdir(temp_dir)
        calls = os.path.join(root, "gh-calls")
        gh = os.path.join(bin_dir, "gh")
        with open(gh, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nprintf "%s\\n" "$@" >> "$GH_STUB_CALLS"\nexit 97\n')
        os.chmod(gh, 0o700)
        env = {
            **os.environ,
            "CATALOG": catalog,
            "GH_STUB_CALLS": calls,
            "PANOPTICON_TEST_HOME": test_home,
            "TMPDIR": temp_dir,
            "PATH": os.pathsep.join((bin_dir, os.path.dirname(sys.executable),
                                     os.environ.get("PATH", ""))),
        }
        proc = subprocess.run(
            ["bash", SCRIPT, "--dry-run"], cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise AssertionError("apply-labels.sh failed: %s" % proc.stderr)
        if proc.stderr:
            raise AssertionError("apply-labels.sh emitted stderr: %s" % proc.stderr)
        if os.path.exists(calls):
            with open(calls, encoding="utf-8") as fh:
                raise AssertionError("dry-run invoked gh: %s" % fh.read())
        return proc.stdout.splitlines()


def _run_script():
    labels = {}
    for line in _dry_run(FIXTURE):
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
    def test_committed_catalog_dry_run_emits_every_entry_in_order(self):
        with open(CATALOG, encoding="utf-8") as fh:
            catalog = yaml.safe_load(fh)
        entries = (catalog if isinstance(catalog, list) else
                   [entry for axis in catalog.values() for entry in axis])
        expected = [
            "would apply: %s (%s) — %s" % (
                entry["name"], entry.get("color", "ededed"),
                entry.get("description", "").replace("\n", " ").strip())
            for entry in entries
        ]
        self.assertTrue(expected)
        self.assertEqual(_dry_run(CATALOG), expected)

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
