# P1 — Adapter-Execution Containment and Offline Scan Posture

**Date:** 2026-08-04
**Status:** Approved (pending spec review)
**Scope:** Remediation 1 package P1: #229 (roslyn-secguard `dotnet build`
execution, CRITICAL), #86 (copytree symlink dereference), #218 (pip-audit
PEP 517 fallback), #62 (scan-time egress). NOT in scope: tool-version pinning
and checksum verification (#268/#303 — package P5; this spec touches the
Dockerfile only to add assets, not to pin), and the custom no-MSBuild Roslyn
host (horizon; noted in Section 8).

## Context

roslyn-secguard is the only adapter that executes scanned code: `invoke()`
copies the target and runs a full `dotnet build` (implicit NuGet restore,
repo-controlled MSBuild targets) inside a container that today has unrestricted
egress and receives `NVD_API_KEY` (`run_tools.py:156-158`). This breaks the
documented no-execution invariant that justified dropping `--network none`
(`DEVELOPMENT.md:55-56`). Satellite defects: the pre-build `shutil.copytree`
dereferences attacker-controlled symlinks (#86), pip-audit's positional-project
fallback raises an unsettled build-backend-execution question (#218), and the
egress posture itself is #62.

Decisions locked during brainstorming:

1. **roslyn-secguard stays ON by default, sandboxed.** MSBuild execution
   cannot be neutralized (inline `<Target><Exec>` always runs), so the posture
   is *contained execution*: no network, no secrets, offline analyzer feed.
2. **Zero scan-time egress, no allowlist.** Every adapter runs
   `--network none`. Advisory/rules data is baked into the image at build
   time. The two adapters with no offline mode (pip-audit, npm-audit) demote
   to an explicit `--online` opt-in instead of an always-on network hole.
3. **Image cadence over scan-time freshness.** The published tools image is
   rebuilt on a weekly schedule (plus manual `workflow_dispatch` for emergency
   pushes); consumers pull a static image whose DBs are ≤1 week old.
4. **`NVD_API_KEY` becomes build-time only**, supplied via a BuildKit secret
   mount so it never persists in an image layer or a scan-time environment.

## Section 1: Container policy (`run_tools.py`)

- Both dispatch paths (legacy `TOOL_CMD` and adapter path) add
  `--network none` to every `docker run`, unconditionally.
- Delete the `-e NVD_API_KEY` forwarding entirely.
- New CLI flag `--online`: pip-audit and npm-audit are dispatched only when it
  is present, and only those runs replace `--network none` with the default
  network. Without `--online`, both are skipped with a one-line stderr notice
  (not silently — the notice names the offline substitute, osv-scanner).
- `skill/scripts/tools/__init__.py` gains two constants consumed by dispatch
  and synthesis: `EXECUTES_TARGET_BUILD = {"roslyn-secguard"}` and
  `ONLINE_ONLY = {"pip-audit", "npm-audit"}`.
- `synthesize.build_report` records `meta.build_executing_tools`: the
  intersection of ingested tool names with `EXECUTES_TARGET_BUILD` — the
  artifact states when contained execution happened, in the same honesty
  register as `tool_policy_mode`.

## Section 2: Baked assets and offline flags

| Adapter | Image-build step | Scan-time change |
|---|---|---|
| trivy | `trivy --download-db-only` (cache under scanner home) | add `--skip-db-update --offline-scan` |
| semgrep | vendor chosen registry packs into `/opt/semgrep-rules` | `--config /opt/semgrep-rules --metrics=off` (replaces `--config auto`) |
| cargo-audit | clone RustSec advisory-db into `CARGO_HOME` | add `--no-fetch` |
| osv-scanner | `--download-offline-databases` for supported ecosystems | add `--offline` |
| dependency-check | pre-warm NVD data dir via BuildKit secret `NVD_API_KEY` | add `--noupdate --data <baked dir>` |
| bundler-audit | already baked (`bundle-audit update` at build) | add `--no-update` |
| roslyn-secguard | offline NuGet folder feed (Section 3) | none (restore resolves offline) |

Exact flag spellings and cache paths are verified against each tool's installed
version during implementation; the contract is: **after image build, each
listed adapter must produce findings with `--network none`**, proven by the
fixture suite. If an ecosystem's osv offline DB is impractically large, the
implementation may restrict `--download-offline-databases` to the ecosystems
the fixture corpus exercises and document the subset in the Dockerfile.

`docker-publish.yml` adds `schedule` (`cron: "0 6 * * 1"`, Mondays 06:00 UTC)
and `workflow_dispatch` (emergency manual pushes) triggers; the NVD BuildKit
secret comes from the repo's Actions secrets. Semgrep's vendored packs start
from `p/default` (the closest offline equivalent of today's `--config auto`);
any additional packs are an implementation-time choice recorded as a comment
in the Dockerfile. A
build without the secret still succeeds (dependency-check warms unkeyed,
slower) so local `docker build` keeps working.

## Section 3: roslyn-secguard containment (#229)

- **Offline analyzer feed:** image build downloads the
  `AdaskoTheBeAsT.SecurityCodeScan.VS2022` package closure into a local folder
  feed (e.g. `/opt/nuget-feed`) and writes a root `nuget.config` whose only
  `packageSources` entry is that feed, plus `-p:RestorePackagesPath` under a
  scanner-writable dir. The existing `/Directory.Build.props` analyzer
  injection is unchanged. Implicit restore keeps working for the analyzer;
  everything else is unreachable (`--network none` is the hard guarantee, the
  feed is what keeps the analyzer alive inside it).
- **Execution remains, contained:** hostile `<Target><Exec>` runs as uid-1000
  `scanner` in an ephemeral no-egress container holding zero secrets, with
  both mounts read-only. This is stated, not hidden: `meta` records it
  (Section 1) and the invariant text is rewritten (Section 7).
- **Parse-level rule filter:** `parse()` emits only results whose `ruleId`
  starts with `SCS`. This (a) closes the residual #86 exfiltration channel —
  compiler-error diagnostics quoting dereferenced file content never reach
  findings — and (b) stops restore/compile errors from surfacing as HIGH
  findings when an offline build fails partway. (#210's severity mapping for
  the SCS results themselves stays in P6 — the filter here changes which
  results are eligible, not how they are scored.)

**Accepted residual risks, recorded here deliberately:** (1) a hostile repo
can ship its own `Directory.Build.props` that disables the analyzer — tool
output is a claim, and the tool-axis trust work (#446, P2) is the systemic
answer; (2) dependency-heavy C# repos cannot restore their own packages
offline, so analysis degrades toward syntax-level or empty on those targets —
the SCS-only parse filter makes that failure honest (empty findings + nonzero
rc on stderr) rather than noisy. roslyn-secguard never joins `--online`.

## Section 4: Symlink guard (#86)

Before the copy, walk the target with `os.walk(followlinks=False)`; for every
symlink (file or directory), resolve it; links whose resolved path escapes the
target root are excluded from the copy and counted, with one stderr summary
line (`skipped N out-of-tree symlink(s)`). In-tree links are copied as links
(`symlinks=True` semantics via a copytree `ignore` callback plus
`symlinks=True`). Consequences: out-of-tree content can no longer enter the
build tree (and the parse filter closes the diagnostic leak channel
regardless); dangling links no longer abort the scan via `shutil.Error`;
symlink loops no longer recurse (walk does not follow).

## Section 5: pip-audit static parse (#218)

Delete the positional-project fallback. When no `requirements*.txt` exists:
parse `[project.dependencies]` (and `[project.optional-dependencies]`) from
`pyproject.toml` with stdlib `tomllib`, write the PEP 508 strings to a temp
requirements file, and pass `--requirement <tmp>`. If the table is absent or
declared `dynamic`, the adapter reports not-applicable with a stderr note. No
pip-audit code path can reach a PEP 517 build backend on any version — the
empirical probe #218 asked for becomes unnecessary. This applies in `--online`
mode too (the flag controls dispatch, not adapter internals). The temp file is
removed in a `finally`.

## Section 6: Verification

- **Unit (plain CI):** argv-contract tests in `tests/test_run_tools.py` —
  every dispatch carries `--network none`; no `-e NVD_API_KEY` anywhere;
  `--online` gates exactly `ONLINE_ONLY`; per-adapter offline flags present.
  Adapter unit tests: symlink-guard behavior on a crafted temp tree
  (out-of-tree file/dir links, dangling link, loop), SCS-only parse filter,
  pip-audit tomllib path (static deps → requirements content; dynamic → not
  applicable).
- **Fixture suite (dev-local):** new `hostile-csproj` fixture — a `.csproj`
  with a `BeforeBuild` `<Exec>` that attempts egress (`curl`) and writes a
  marker file, plus one genuine SCS-detectable flaw. Assertions: marker absent
  under the containment run, egress fails, the SCS finding still parses.
  Fixture registered in `tests/fixtures/manifest.json`; the agent-side
  exclusion story stays FIXME-4/#434 (P4).
- **Offline-image check:** a fixture-suite pass runs every baked adapter with
  `--network none` and asserts non-empty findings for its fixture — the
  Section 2 contract, executed.

## Section 7: Invariant rewrite

`run_tools.py` docstring and `DEVELOPMENT.md:55-56` change from "network is
allowed because tools only parse" to the tiered truth: *scan-time network is
disabled for all tools; parse-only adapters never execute target code;
roslyn-secguard executes target build logic inside a no-egress, no-secret,
read-only-mount container and the artifact records it; pip-audit/npm-audit
run only under `--online`.* `.github/workflows/security.yml` keeps working
unchanged (it inherits the offline default; adding `--online` there is a
separate decision left to the operator).

## Section 8: Horizon (explicitly out of scope)

The custom Roslyn analysis host (no MSBuild evaluation, true no-execution
C# coverage) remains the eventual escape hatch if contained execution ever
becomes untenable; #449's PR-first mode consumes this package's posture
unchanged.

## Error handling

- Offline restore failure (dependency-heavy C# repo): build rc≠0 is already
  tolerated (`ok_codes=(0,1)` semantics unchanged); SCS-only filter yields
  honest empty findings; stderr carries the tool's failure excerpt.
- Missing baked asset (e.g. DB dir absent in a stale local image): the
  adapter's own failure surfaces through the existing skip-with-stderr path;
  the fixture-suite offline check is the pre-publish guard.
- `--online` given but network unavailable: pip/npm audit fail into the same
  tolerant skip path as today.
