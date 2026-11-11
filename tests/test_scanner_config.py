"""Behavior tests for the scanner-owned configuration policy."""
import unittest

import scripts.scanner_config as sc


class TestTheStagedConfigIsTheScannersOwn(unittest.TestCase):
    """The scanner-authored ini and ignore file contain no target policy."""

    def test_the_ini_holds_exactly_one_key_and_no_target_text(self):
        lines = [ln for ln in sc.BANDIT_INI_TEXT.splitlines() if ln.strip()]
        self.assertEqual(lines[0], "[bandit]")
        self.assertEqual(len([ln for ln in lines if "=" in ln]), 1)
        self.assertEqual(len(lines), 2)
        value = lines[1].split("=", 1)[1]
        for owned in sc.BANDIT_SCANNER_EXCLUDES:
            self.assertIn(owned, [e.strip() for e in value.split(",")])

    def test_no_scanner_owned_exclude_entry_can_split_or_inject(self):
        # A comma would inject another exclusion; a newline or equals sign
        # would inject another ini key.
        for entry in tuple(sc.BANDIT_DEFAULT_EXCLUDES) + tuple(sc.BANDIT_SCANNER_EXCLUDES):
            for char in (",", "\n", "\r", "="):
                self.assertNotIn(char, entry, entry)

    def test_the_ignorefile_declares_nothing(self):
        # Every active line would be a vulnerability id trivy stops reporting.
        active = [ln for ln in sc.TRIVY_IGNOREFILE_TEXT.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(active, [])


if __name__ == "__main__":
    unittest.main()
