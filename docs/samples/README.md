# Sample output

A real run, not a mock-up: Panopticon reviewing its own repository on 2026-09-20 (run 14), `--security redteam --tools`, Claude Code host.

- [`run14-readout.md`](run14-readout.md): the operator's readout of the run, written the same day. Verdict, populations, the thirteen HIGH findings with their catalog codes, what the run cost to keep alive, and what was filed.
- [`run14-dashboard.png`](run14-dashboard.png): the top of the HTML report. Grade, risk, gate, health index, the certification line, the host-capabilities line, and the severity and panel breakdowns.
- [`run14-findings.png`](run14-findings.png): further down the same report. The "top issues" list, the severity filter, and the first finding cards of one group, each with its catalog code, location, evidence status and effort.

The full artifact set for the run (the JSON report in eight parts, the discarded-claims sibling, the catalog-gap report, the 4 MB HTML page and the host-capabilities record) is about 10 MB and is not checked in.

Two things visible in the screenshots that are accurate rather than pretty: the heading reads `unknown` because the driver does not pass a target name to the synthesizer, so the report's target field falls back to its default (a live cosmetic defect, not a quirk of that run), and the grade is an F. The grade is a bounded health index over verified findings per line of code; this repository is a security scanner that treats its own tree as hostile, and it files everything it finds against itself.
