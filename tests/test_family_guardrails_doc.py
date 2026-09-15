"""docs/FAMILY-PR-GUARDRAILS.md is the contract handed to each host family
for its first-class-host PR. These guards keep it naming the real seam.

#1628 rewrote section 2 from "what your family will run into" into the record
of what each landed host proves, and section 6's launch prompt from one
addressed to codex/kimi into one for the next host. The guards below moved with
those sentences: the token pins cover the seam vocabulary the new prose leans
on, and the three per-host guards are derived from `hosts.py` rather than
pinned to wording, so a sixth row cannot be added without the document saying
what it proves."""
import os
import re
import unittest

import scripts.hosts as hosts
import scripts.runners.base as runners_base

_HERE = os.path.dirname(os.path.abspath(__file__))
_DOC = os.path.join(os.path.dirname(_HERE), "docs", "FAMILY-PR-GUARDRAILS.md")


def _read_doc():
    with open(_DOC, encoding="utf-8") as fh:
        return fh.read()


def _section(doc, number):
    """The text of one top-level section, heading excluded -- so a guard on
    section 6 cannot be satisfied by a sentence somewhere else in the file."""
    match = re.search(r"^## %d\. .*$" % number, doc, re.M)
    assert match, "no section %d in the guardrails document" % number
    rest = doc[match.end():]
    nxt = re.search(r"^## \d+\. ", rest, re.M)
    return rest[:nxt.start()] if nxt else rest


class TestFamilyGuardrailsDoc(unittest.TestCase):
    def test_names_every_capability_and_the_three_states(self):
        doc = _read_doc()
        for cap in hosts.CAPABILITIES:
            self.assertIn("`%s`" % cap, doc)
        for state in (hosts.PROVEN, hosts.REFUTED, hosts.UNKNOWN):
            self.assertIn("`%s`" % state, doc)

    def test_names_the_seam_and_the_bar(self):
        doc = _read_doc()
        # The last six arrived with the seam itself: the probes package and its
        # registry (#1627), the launcher declaration the usage probe reads and
        # the one place a child environment is built (#1626), and the refusal
        # plus the seam list that keep the suite off a real host CLI (#1620).
        # Section 2's as-built record is written on top of all of them.
        for token in ("skill/scripts/runners/<host>.py", "HostRunner", "RunResult",
                      "PROBE_IDS", "PROBE_CAPABILITY", "emit_host_agents",
                      "test_todays_shortfall_is_pinned_so_it_moves_consciously",
                      "PANOPTICON_ENTRY_ID", "PANOPTICON_WRITE_ALLOWLIST",
                      "PANOPTICON_READ_SCOPE", "driver loop", "--allow-unenforced",
                      "skill/scripts/probes/<host>.py", "host_probes.py",
                      "ENVELOPE_FLAGS", "launch_env", "LaunchRefused",
                      "LAUNCH_SEAMS",
                      # #1636: the batch seam has two shapes now, and headless
                      # calls `iter_batch` -- a family that overrode only
                      # `run_batch` would have its override silently ignored.
                      "iter_batch", "run_batch"):
            self.assertIn(token, doc, token)

    def test_names_every_known_host_and_the_launch_prompt(self):
        doc = _read_doc()
        for host in hosts.known_hosts():
            if host != "generic":
                self.assertIn(host, doc.lower(), host)
        self.assertIn("docs/FAMILY-PR-GUARDRAILS.md", doc)
        self.assertIn("feat/1344-<host>-first-class-host", doc)

    def test_section_2_records_what_every_probed_host_proves(self):
        # The replacement for the "findings already recorded for your family"
        # bullets, which told Codex and Kimi what they would run into and
        # outlived both PRs (#1618/#1619/#1620). What replaced them is a
        # per-host record, so this guard is read off the registry instead of a
        # sentence: a driver-selectable row that maps probes must be named in
        # section 2 with its runner module and EVERY probe id it maps. A new
        # family that flips a row and leaves this document alone fails here.
        #
        # Section 3 lets you move an expectation only when its own comment says
        # your PR is the one that moves it, so: THE PR THAT FLIPS A ROW MOVES
        # THIS ONE, by adding its host's paragraph to section 2 in the same
        # commit as the probes. Nothing here is to be relaxed instead.
        section = _section(_read_doc(), 2)
        probed = [h for h in hosts.driver_hosts() if hosts.spec(h).probes]
        self.assertTrue(probed, "a guard over zero hosts proves nothing")
        for host in probed:
            with self.subTest(host=host):
                self.assertIn("skill/scripts/runners/%s.py" % host, section, host)
                for probe_id in sorted(set(hosts.spec(host).probes.values())):
                    self.assertIn("`%s`" % probe_id, section, probe_id)

    def test_section_2_records_gemini_as_retired_not_as_a_family_still_owed_a_pr(self):
        # #1625 took gemini out of the selectable set; its findings bullet used
        # to tell a Gemini agent what to build. While the row is registered but
        # not selectable, section 2 has to say exactly that and point its
        # operators at the fallback. If a future Gemini PR flips the row back,
        # this guard fails until section 2 is rewritten to match -- which is
        # the same PR that re-pins the retirement bar, and which is therefore
        # the one authorised to move this assertion (section 3).
        section = _section(_read_doc(), 2)
        self.assertIn("gemini", hosts.known_hosts())
        self.assertFalse(hosts.spec("gemini").driver_selectable)
        self.assertIn("**Gemini**", section)
        self.assertIn("not** driver-selectable", section)
        self.assertIn("--host generic", section)

    def test_section_6_addresses_the_next_host_not_one_that_has_landed(self):
        # "`<host>` is `codex` or `kimi`" survived both of their PRs, so an
        # operator pasting the prompt would have launched an agent to redo
        # merged work. The prompt is now for a re-attempt or a new host, and
        # this guard is what keeps it that way: no host that already ships a
        # runner module may be named in section 6 at all. The PR that ships a
        # runner is the one that moves this (section 3): its own host leaves
        # section 6 in the same commit, the way codex and kimi should have.
        section = _section(_read_doc(), 6)
        self.assertIn("feat/1344-<host>-first-class-host", section)
        landed = [h for h in hosts.driver_hosts() if runners_base.headless_available(h)]
        self.assertTrue(landed, "a guard over zero landed hosts proves nothing")
        for host in landed:
            with self.subTest(host=host):
                self.assertNotIn(host, section.lower(), host)

    def test_section_7_records_the_open_owner_decision_on_generic(self):
        # #1625 left F5 met but not due: the bar reads {} while `--host
        # generic` is still the only path for a host with no family runner, so
        # deleting it is an owner policy call. Section 7 says so and points at
        # the spec section that carries the write-up (panopticon-docs #55).
        # When someone deletes the row, this guard goes with the section: F5 is
        # the PR that moves it, and it is an OWNER decision, never a family
        # PR's to take (section 3).
        section = _section(_read_doc(), 7)
        self.assertTrue(hosts.spec("generic").driver_selectable)
        self.assertTrue(hosts.is_deprecated("generic"))
        self.assertIn("--host generic", section)
        self.assertIn("owner", section.lower())
        self.assertIn("8.3", section)

    def test_states_the_verification_commands_contributing_uses(self):
        doc = _read_doc()
        self.assertIn("python -m pytest tests/ -q", doc)
        self.assertIn("python -m ruff check skill/scripts/ tests/", doc)


if __name__ == "__main__":
    unittest.main()
