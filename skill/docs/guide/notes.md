## Notes
On a host with a proven write guard, self-writing fan-out reviewers and advisors hold scoped `Write`
for their own `out_file` only, guarded by the write-guard hook — never anywhere else in the repo,
and never a sibling cell's findings file (#1571: the guard binds each writer to its own dispatch
entry, so the fan-out's other out_files are as unwritable as the source tree). Codex exposes no
write tool and returns JSON for every role instead. The scout never writes at all: fully read-only,
its returned JSON persisted by the driver (see Driver run-loop above). Every role is otherwise
constrained the same way: no other repo/GitHub writes, no claiming unperformed actions, no
materializing discovered secrets (redact discovered passwords, API keys, PII, and credentials as
`[REDACTED]` in descriptions, exploit scenarios, and evidence citations).

Hostile-content review (redteam mode, deliberately vulnerable corpora, repos that may contain
planted injection payloads) should run with enforcement registered via `--emit-host-agents`. Two
refusals make part of that mechanical rather than advisory, and each keys on a different capability:
`driver run` refuses to dispatch the write-capable reviewers unless `artifact_write_guard` is proven
on this machine, and `driver setup` refuses a shell-less `setup-scan` unless `tool_policy_enforced`
is (#1737). `--allow-unenforced` accepts either explicitly and is recorded. Registration itself is
**disclosed, not refused**, on the review path — a machine with a proven write guard and no emitted
shells runs, with `meta.coverage.tool_policy_mode` reading `advisory` rather than `enforced` — which
is exactly why the unenforced claude launch now carries its own tool deny-list (#1753, see Host
capabilities).

That write-guard is a Claude Code `PreToolUse` hook, so it **structurally cannot run on another
host**; Kimi ships its own equivalent (`kimi_guard_hook.py`, registered through the generated
per-run `config.toml`, which is why the `kimi` row claims `artifact_write_guard`), Codex claims no
write guard (its write-capable roles are bridged by `delivery: return_json`), and
`dispatch.emit_host_agents` can only build a scoped agent shell for `claude`/`kimi`/`codex`. The
refusal that follows is keyed on **measured posture, not on the host's name** (#1344 F3a):
`driver run` refuses to dispatch the write-capable roles (`domain-panel`, `domain-advisor`) unless
this invocation's probe found `artifact_write_guard` `proven`. On `--host generic` it never is — a
reviewer's `Write` is mediated by nothing but the prompt's tool-policy prose, and a write landing
outside the reviewed tree is invisible even to the clean-tree check, which is scoped to
`review_root` — but a `claude` run refuses on identical terms when the probe refutes on *that
machine* (no `.claude/settings.local.json` at the path the host would arm, say), which the old
host-name test could not express. `--allow-unenforced` accepts the risk explicitly; the acceptance
is recorded in the run's `unenforced-ack.json`, bound to the dispatch plan's hash so it cannot be
reused by a later, different fan-out, and surfaces as `meta.integrity.unenforced_acknowledged`.
What that hook mediates is `Write`, `Edit` and `NotebookEdit` and nothing else: `Bash` and `Agent`
are kept out of a reviewer's hands by the enforced shell's `tools:` grant, or — on an unenforced
claude dispatch — by the tool deny-list on its argv (#1753, see Host capabilities), never by the
write guard, which is registered session-wide and so cannot tell the orchestrator's own legitimate
shell from a reviewer's.

A **second, separate refusal** covers the reviewed tree shadowing the enforcement shells (spec
§7.3). A target that ships `panopticon-*` agent files in a project-scoped agent directory — or any
file there whose frontmatter declares one of those names, so `mv` does not evade it — would be
reviewing itself with reviewers it supplied, and the run refuses. A scope directory that cannot be
read refuses the same way: not being able to look is not the same as looking and finding nothing.
`--allow-unenforced` downgrades rather than silences it — the run proceeds with
`tool_policy_enforced` REFUTED and every disclosure surface says so. Neither refusal is the
capability disclosure itself, which gates nothing (see Host capabilities above). Native per-host
write mediation beyond Claude's hook remains open under #1344.
