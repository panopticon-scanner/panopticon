"""Report configuration metadata contracts."""

import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP


class TestMetaConfig(unittest.TestCase):
    """#1681 Plan 2: what the target's committed `settings:` asked for."""

    def _report(self, config=None):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None,
                                     timestamp=DEFAULT_TIMESTAMP, config=config),
            findings=findings_mod.FindingSet(findings=[])))

    def test_meta_config_is_emitted_on_every_report(self):
        self.assertEqual(self._report()["meta"]["config"],
                         {"requested": {}, "effective": {}, "refused": [],
                          "clamped": [], "disclosures": []})

    def test_meta_config_carries_the_resolution_verbatim(self):
        cfg = {"requested": {"max_per_group": 5000, "allow_unenforced": True},
               "effective": {"max_per_group": 48},
               "refused": [{"key": "allow_unenforced", "value": True,
                            "reason": "operator-only key"}],
               "clamped": [{"key": "max_per_group", "requested": 5000, "effective": 48}],
               "disclosures": ["target config asked for `max_per_group: 5000`; "
                               "clamped to 48 (the band is 8-48)"]}
        self.assertEqual(self._report(cfg)["meta"]["config"], cfg)

    def test_meta_config_fails_closed_on_a_junk_resolution(self):
        self.assertEqual(self._report("not a dict")["meta"]["config"]["refused"], [])
