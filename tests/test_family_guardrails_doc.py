"""docs/FAMILY-PR-GUARDRAILS.md is the contract handed to each host family
for its first-class-host PR. These guards keep it naming the real seam."""
import os
import unittest

import scripts.hosts as hosts

_HERE = os.path.dirname(os.path.abspath(__file__))
_DOC = os.path.join(os.path.dirname(_HERE), "docs", "FAMILY-PR-GUARDRAILS.md")


def _read_doc():
    with open(_DOC, encoding="utf-8") as fh:
        return fh.read()


class TestFamilyGuardrailsDoc(unittest.TestCase):
    def test_names_every_capability_and_the_three_states(self):
        doc = _read_doc()
        for cap in hosts.CAPABILITIES:
            self.assertIn("`%s`" % cap, doc)
        for state in (hosts.PROVEN, hosts.REFUTED, hosts.UNKNOWN):
            self.assertIn("`%s`" % state, doc)

    def test_names_the_seam_and_the_bar(self):
        doc = _read_doc()
        for token in ("skill/scripts/runners/<host>.py", "HostRunner", "RunResult",
                      "PROBE_IDS", "PROBE_CAPABILITY", "emit_host_agents",
                      "test_todays_shortfall_is_pinned_so_it_moves_consciously",
                      "PANOPTICON_ENTRY_ID", "PANOPTICON_WRITE_ALLOWLIST",
                      "PANOPTICON_READ_SCOPE", "driver loop", "--allow-unenforced"):
            self.assertIn(token, doc, token)

    def test_names_every_known_host_and_the_launch_prompt(self):
        doc = _read_doc()
        for host in hosts.known_hosts():
            if host != "generic":
                self.assertIn(host, doc.lower(), host)
        self.assertIn("docs/FAMILY-PR-GUARDRAILS.md", doc)
        self.assertIn("feat/1344-<host>-first-class-host", doc)

    def test_states_the_verification_commands_contributing_uses(self):
        doc = _read_doc()
        self.assertIn("python -m pytest tests/ -q", doc)
        self.assertIn("python -m ruff check skill/scripts/ tests/", doc)


if __name__ == "__main__":
    unittest.main()
