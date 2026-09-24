# Security policy

This policy covers vulnerabilities in Panopticon itself: the skill, its scripts, the driver, the scanner image and the workflows in this repository. Findings that Panopticon produces about *your* code are not security reports against this project; file those against your own project.

## Supported versions

| Version | Supported |
|---|---|
| `main` (5.x) | yes |
| tagged releases before 5.0 | no |

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in the tool.

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**. If that button is not offered, email the maintainer at psyberone@gmail.com with `[panopticon security]` in the subject.

Include what you can of: the affected file or workflow, the host you ran on (Claude Code, Kimi, Codex, generic), the command line, and a minimal reproduction. A hostile target repository that makes the reviewer, the driver or a scanner do something it should not is squarely in scope; so is anything that lets a reviewed tree influence what the scanner image runs.

You will get an acknowledgement within seven days. Fixes ship as pull requests on `main`; when a report is confirmed you will be credited in the advisory unless you ask not to be.

## What the tool assumes about its input

The reviewed tree is treated as attacker-controlled. Reviewers read it under confinement on every host that proves a read guard (and the report says when one does not), scanners run in a container with the tree mounted read-only, git is invoked with hooks, filters and external drivers disabled, and a PR under review cannot replace the operator's review configuration. [`docs/PANOPTICON.md`](docs/PANOPTICON.md) describes these controls and their known limits: the reviewer confinement and its refusals under "Notes", the PR-worktree rule under "Modes", the host controls under "Host capabilities". A gap between what those sections claim and what the code does is a vulnerability under this policy.
