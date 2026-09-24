# Getting started with Panopticon

Two pages for a person deciding whether to run this on a real codebase: what it does, what it costs, how to run it, and what it will not do. The complete contract is in [`PANOPTICON.md`](PANOPTICON.md); this page is the map. `driver` in the prose means `python3 skill/scripts/driver.py`, run from the root of the repository under review.

## What it does

Panopticon is a code-review skill for an AI coding agent. It does not replace the agent; it drives it. You install it into Claude Code (or Kimi, or Codex), point it at a repository, and it runs a fixed pipeline:

1. **Discovery.** It lists the reviewable files and reads the committed `panopticon.yml` at the repo root, which says how the code is grouped (by business capability, not by directory). `driver setup` proposes that file once; you edit and commit it.
2. **Scout.** One cheap agent per group profiles the files and picks the review domains that apply, on top of a floor the group's own files decide: correctness wherever there is code, and data, testing or architecture wherever that surface actually exists; security wherever there is a security surface, and there it cannot be switched off.
3. **Fan-out.** One reviewer agent per (domain, group) cell, run in parallel, each inside a registered shell that limits its tools to reading its own files and writing one output file, which a guard confines to that file. On a host that cannot mediate writes, the reviewer returns its JSON to the driver instead. Reviewers cite the OCRDb catalog, a fixed taxonomy of review findings, so two runs on two codebases speak the same language.
4. **Tools.** If the `panopticon-tools` Docker image is present, real scanners run against the same tree (Bandit, Semgrep, gitleaks, osv-scanner, Trivy, ESLint security, and language-specific SAST and dependency auditors; pip-audit and npm-audit only under `--online`). Their findings enter the same queue as the agents' findings.
5. **Verify.** Every finding, agent or tool, that clears the verification floor goes to an independent advisor confined to the reviewed group's files, which returns confirmed, rejected, or needs-more-info; an adversarial second opinion is confined more tightly still, to the claim's own files and their immediate evidence neighbourhood. Findings below the floor (a cell of nothing but LOW and INFO) are published as `unverified`. Grades and the gate count confirmed findings only.
6. **Synthesis.** Deduplication, cross-panel corroboration, secret redaction, a health index, a grade, and a CI gate, written as one validated JSON report plus a self-contained HTML file.

The whole thing is a resumable state machine (`driver loop`). If the host hits a session limit at 3 a.m., you rerun the same command in the morning and it continues from its checkpoint.

## What it costs

It is a multi-agent fan-out, so it is not cheap, and the price scales with the matrix (groups × domains) and with the verification queue, not with lines of code directly.

One real measurement, Panopticon reviewing its own repository on 2026-09-20 in its most expensive configuration (adversarial security mode, all tools, and the default Claude profile, whose adjudicating domain-advisors are the Opus seat):

| | |
|---|---|
| Code | 135 K lines |
| Matrix | 8 groups, 85 reviewer cells |
| Agent launches | 916 |
| Tokens | 481 M, of which 430 M were cache reads |
| Cost reported by the host | about $633 |
| Wall clock | 24.5 h, roughly 9 h of it waiting on session quota |

What moves the number, in order:

- **Scope.** `-c` (this branch against its base), `--pr N`, `-d dir` and `-f file` review a slice. A 25-file PR still queues every finding for verification, so pair a delta review with `--max-verify N`; our own delta runs use about twice the changed-file count as a rule of thumb.
- **Security posture.** `--security standard` (the default) is markedly cheaper than `redteam`.
- **Model tier.** Advisors are the expensive seat. The host's model profile decides the tier per role.
- **Hard stops.** `driver loop --max-budget-usd X` stops the run at a dollar figure on hosts that report cost (Claude does; Codex reports tokens only, so use `--max-iterations` and `--entry-timeout` there).

Every report carries its own ledger under `meta.cost` (launches, tokens, dollars where the host reports them), so the second run on a codebase can be budgeted from the first.

## How to run it

Prerequisites: Python 3.11+, `pyyaml` and `jsonschema`, an agent host on `PATH`, and optionally Docker with the `panopticon-tools` image (`docker pull ghcr.io/panopticon-scanner/panopticon-tools:latest`, a public package, then tag it `panopticon-tools`; or `docker build -t panopticon-tools .` from the checkout, which takes over an hour).

Install once (Claude Code shown; Kimi and Codex are in the README):

```bash
git clone https://github.com/panopticon-scanner/panopticon.git
ln -s "$(pwd)/panopticon/skill" ~/.claude/skills/panopticon
python3 panopticon/skill/scripts/dispatch.py --emit-host-agents claude   # then start a fresh session
```

Then, from the root of the repository you want reviewed, with `skill/` meaning the skill's install path:

```bash
python3 skill/scripts/driver.py readiness .
```

Readiness writes nothing and launches nothing. It prints one table: the three Python dependencies, the guide's path, the sub-skills it found, the committed matrix, any run waiting to resume, which host CLIs are on `PATH`, the Docker daemon and image, and the last measured host posture. Every failing row carries its remedy, and a gating row that fails makes `driver loop` refuse to start. Fix what gates, then:

```bash
python3 skill/scripts/driver.py setup .
```

Setup dispatches one classifier over the whole tree and writes `panopticon.yml.draft` at the repo root plus `.panopticon/setup-report.md`. Read the report, adjust the groups if they are wrong, rename the draft to `panopticon.yml`, and commit it. It is the durable, reviewable definition of how your code is grouped.

```bash
python3 skill/scripts/driver.py loop .                          # everything
python3 skill/scripts/driver.py loop . -c --base main            # this branch vs main
python3 skill/scripts/driver.py loop . --pr 217 --fail-on high   # a PR, gate on HIGH+
```

The loop prints progress per phase and per cell, and ends with the terminal summary. The artifacts land under `.panopticon/`:

- `.panopticon/<run-tag>-report.json` (and `_part2.json` onwards when large): the validated report. `summary.gate` is the CI key: `PASS`, `FAIL`, `OFF` when no `--fail-on` was given, `INCONCLUSIVE` when gate-relevant coverage did not complete.
- `.panopticon/<run-tag>-report.json.html`: the same report as one file for humans (it fetches only its web font when opened, and renders without it). Attach it, mail it, drop it in a shared folder.
- `.panopticon/runs/<run-tag>/`: the working set (findings, verdicts, coverage, tool output, dispatch ledger, the measured host posture). The reports above survive if you delete it; you lose the resume state and the recorded host posture with it.

`driver loop` exits 0 when it reaches a checkpoint or completes, and non-zero when it ends in `error` or `paused`. The gate verdict is `summary.gate` in the report; a failing gate is a valid outcome, not a driver error. The synthesizer's own exit codes (`0` clean, `1` gate failed, `2` inconclusive, `3` unreadable catalog bundle, `4` an artifact failed its own schema) are what a CI step keys on when it calls `skill/scripts/synthesize.py` directly.

## What to trust in the report

Read these lines before the findings:

- **Coverage certified** or **NOT CERTIFIED** with the reason. Certified means every planned cell returned, every tool the scout requested produced output, every queued verdict loaded, and no integrity or verify-coverage check fired.
- **Host capabilities**: which of the five run-time controls (tool policy enforced, read scope confined, artifact write guard, model binding, usage ledger) were proven on this host, refuted, or not applicable. The absence of a warning means measured and proven, not assumed.
- **Evidence status** per finding: `tool_confirmed`, `advisor_confirmed`, `corroborated`, `backup_scope_limited` (the primary advisor confirmed it and the adversarial backup could not reach the evidence; it still gates), `needs_more_info`, `unverified`, `tool_reported` (a scanner hit no advisor has adjudicated; it does not gate), `rejected`. Severity is what the reviewer claimed; evidence is what the pipeline could verify. They are independent axes, and only confirmed evidence grades or gates.
- **Discarded claims** are kept, in the report or in a `-discarded.json` sibling when the report is large, never deleted. A high rejection rate on the tool axis is normal (most scanner hits on a mature codebase are noise); a high rejection rate on the agent axis is a signal about the reviewer tier.

## What it does not do

- It reviews one repository per run. There is no cross-repository roll-up.
- It files issues to GitHub only, from a finished report, when you ask it to. No other tracker is supported or planned.
- It does not run as a service and does not collect telemetry. Outbound calls are only the ones you ask for: your agent host; `--online` for the dependency auditors, through an allowlisting proxy; `synthesize --epss` for EPSS scores; GitHub when you file issues; and the image pulls. The scanner containers run with `--network none`.
- It does not certify your code as secure. It certifies that the review it planned was the review it ran, and it says what it could not do.
- On hosts that cannot mediate a reviewer's writes (Codex, generic), write-capable roles need your explicit `--allow-unenforced`. Read the disclosure before accepting it.

## Where to go next

- [`PANOPTICON.md`](PANOPTICON.md): every flag, the driver protocol, the output schema, the host-capability probes, and the security notes on how the target tree is treated as hostile.
- [`samples/`](samples/README.md): a real run's readout and screenshots.
- [`../DEVELOPMENT.md`](../DEVELOPMENT.md): architecture and the design decisions that are not up for casual relitigation.
- [`../SECURITY.md`](../SECURITY.md): how to report a vulnerability in the tool itself.
