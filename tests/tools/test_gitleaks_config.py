"""Gitleaks must select scanner-owned rules at launch."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.tools.legacy_sarif import LegacySarifAdapter, TOOL_CMD, TOOL_TIMEOUT


class TestGitleaksOwnedConfig(unittest.TestCase):
    def test_config_is_live_during_scan_then_removed(self):
        with tempfile.TemporaryDirectory() as target:
            for fail in (False, True):
                observed = {}

                def run(cmd, *, timeout, cwd):
                    self.assertEqual(timeout, TOOL_TIMEOUT)
                    self.assertEqual(cmd[:len(TOOL_CMD["gitleaks"])],
                                     [target if arg == "/src" else arg
                                      for arg in TOOL_CMD["gitleaks"]])
                    self.assertEqual(cmd.count("--config"), 1)
                    config = Path(cmd[cmd.index("--config") + 1])
                    scratch = Path(cwd)
                    self.assertTrue(config.is_absolute())
                    self.assertEqual(config.parent, scratch)
                    self.assertNotEqual(
                        os.path.commonpath((os.path.realpath(target),
                                            os.path.realpath(config))),
                        os.path.realpath(target))
                    self.assertEqual(config.read_bytes(), b"[extend]\nuseDefault = true\n")
                    observed.update(scratch=scratch, config=config)
                    if fail:
                        raise RuntimeError("scanner failed")
                    return b"{}", 0

                with mock.patch("scripts.tools.legacy_sarif.run_tool", side_effect=run):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "scanner failed"):
                            LegacySarifAdapter("gitleaks").invoke(target)
                    else:
                        self.assertEqual(LegacySarifAdapter("gitleaks").invoke(target),
                                         (b"{}", 0))
                self.assertFalse(observed["scratch"].exists())
                self.assertFalse(observed["config"].exists())
