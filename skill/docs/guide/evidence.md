## Evidence

Findings carry two independent axes: **severity** (impact if true — rewritten only by the two
disclosed caps below) and **evidence.status** (how hard the claim was verified):
- `tool_reported` — a static-analysis tool emitted it (or a tool+agent same-locus merge did); no
  advisor has checked it. NOT gate-eligible.
- `tool_confirmed` — a tool reported it and the claim was independently confirmed. Normally that
  is an advisor verdict. A first-party advisory is the bounded exception (Cargo, #3593; npm,
  Python and Ruby, #3623). For Cargo, ingest
  confirms an exact package/version match against both a sourceless workspace/path entry in
  Cargo.lock and one confined, in-tree member manifest publishable to crates.io (`publish` absent
  or true, or a registry list containing `crates-io`). The claim is therefore that this project's
  own version is affected, not that a third-party dependency is used. npm follows the same rule
  (#3623): an exact match against the review root's own `package-lock.json` /
  `npm-shrinkwrap.json` (lockfile v2+; a nested or vendored lock is somebody else's root) entry
  outside `node_modules` -- the root, or a workspace / `file:` package npm linked (#3653: every
  link must name such an entry and carry no `version` or `integrity`, or the lock fails) -- whose in-tree
  `package.json` has the same name and version and is publishable. `private: true` is npm's
  `publish = false` (only the review root itself is exempt), and a `publishConfig.registry` other
  than the public one is private-only. Only osv-scanner and Trivy are classified, because they
  report the installed version; npm-audit's `vulnerable_versions` is a range, even when it
  happens to name a single version, so its advisories stay with the advisor. Python follows it
  too (#3623): an exact match, under PEP 503 names, against the review root's own `uv.lock`,
  `poetry.lock` or `pdm.lock` where every entry with that identity is a local-path package (a uv
  `editable` / `directory` / `virtual` source, a Poetry `directory` source, a PDM `path`) whose
  realpath is inside the review root and whose own `pyproject.toml` (`[project]`, else Poetry's
  `[tool.poetry]`) has the same name and a static version and is publishable. A `Private ::`
  classifier, `package-mode = false`, `[tool.uv] package = false`, `[tool.pdm] distribution = false`,
  dynamic classifiers and a uv `virtual` source are unpublishable, except for the review root
  itself. A dynamic version, another PEP 440-equal spelling of the same release (local or not) and
  a lock entry whose name is not a PEP 508 name fail closed. A lock (any ecosystem) must resolve to
  a file of the name the scanner reported. `Pipfile.lock` and `requirements.txt` carry no versioned
  local identity and stay with the advisor, and so does pip-audit, which audits an environment, not
  the lock. Go classifies nothing (#3623): a go.mod declares no version of its own module, so a
  main module, a go.work `use` module and a local `replace` target (whose version is the consumer's
  `require`, not the module's) stay with the advisor under every scanner. Ruby follows it too
  (#3623): an exact match against a `PATH` source gem in the review root's own `Gemfile.lock`, where
  no other spec in the lock is the same name at a version RubyGems reads as equal (any source, any
  platform), the source carries no option but `remote`, Bundler would read the remote where it is
  written (no `~`, no `..`, not absolute, not a URL) and its realpath is inside the review root, and
  the one gemspec Bundler's `{,*,*/*}.gemspec` glob finds proves the name and version with plain
  string literals. Every line of that gemspec must be on an allowlist: blank lines and comments, the
  `Gem::Specification.new do |x|` opener and its closer, and inside it `x.<field> = <literal>`,
  `x.add_*dependency "lit", ...` and `x.metadata["key"] = "lit"`; `Foo::VERSION`, a `require`, a
  conditional and every other line refuse the file. The lock is read the same way: known headers,
  exact indents, the bare `specs:` marker and RubyGems-valid versions, with whitespace other than
  spaces failing the whole lock. A literal `allowed_push_host` other than rubygems.org is
  private-only, and that key may appear only as that metadata line; only the review root is exempt.
  bundler-audit and `gems.locked` stay with the advisor. Maven and Gradle classify nothing (#3623):
  a gradle.lockfile lists only external modules, never the build's own projects, and nothing shows
  the pinned scanners report a sibling Maven reactor module, so every pom.xml and Gradle advisory
  stays with the advisor under every scanner. In every ecosystem, a finding that declares an
  ecosystem other than its lock's own (`Maven` at a `Cargo.lock`) stays with the advisor (#3760),
  and so does an osv-scanner finding that declares none: osv-scanner always sets it, and only Trivy
  and the audit adapters, which carry no ecosystem, are judged by the lock alone. Gate-eligible.
- `advisor_confirmed` / `rejected` / `needs_more_info` — advisor verdicts from the verify phase.
  Rejected claims keep their severity and move to `discarded_claims`. A REJECTED verdict is settled
  by one advisor: the adversarial backup round is summoned only for primary-CONFIRMED findings in
  categories whose score reaches `score_gate.BACKUP_FLOOR`, so scepticism is spent on what would
  reach the gate, and the asymmetry is deliberate. The rejection is auditable rather than silent —
  every rejected claim's full advisor prose lands in `discarded_claims`. Tool-sourced findings
  follow the same rule with no backup round at all: one advisor per finding, the first parseable
  verdict is terminal, and it lands as a single-verdict file under `verdicts/<queue_id>.json`. A
  verdict that lands unloadable (a parse/schema failure surfaced at
  `meta.coverage.verdicts.unloadable`, never silently dropped) and forces `INCONCLUSIVE` — lost
  verify coverage never certifies a clean gate (#979). That count includes a bad entry inside a
  loadable bundle (not an object, no known verdict, or no `finding_id` echo; #2990), counted per
  entry.
- `corroborated` — multi-panel agreement (correlated witnesses: prioritized for verification, not
  gate-eligible by default). An agent finding's panel is its review cell's (#3254), never the
  reviewer's own `panel` field, so one cell's findings cannot corroborate each other.
- `unverified` — no verification attempted.
- `backup_scope_limited` — the primary advisor confirmed the claim and the adversarial backup could
  not check it, because the files it needed lay outside the bounded evidence closure it was granted
  (#1638 P16). A confirmed finding wearing a disclosure, not a contested one: gate-eligible, and NOT
  counted as "verified" in the report's coverage line.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings, plus
`backup_scope_limited` (a primary CONFIRMED stands, #1638) — i.e. only claims an advisor verified,
plus the exact first-party advisory match (#3593, #3623: Cargo, npm, Python and Ruby). Run a verify
phase (or pass
`--gate-unverified`) or, absent that deterministic exception, the gate has nothing to fail on.

**Two severity caps (#3231).** The active report caps two kinds of claim at MEDIUM, because nothing
confirms the HIGH they arrived with. Each capped finding says so in `severity_cap`
(`{from, reason, ...}`), and `meta.severity_capped` lists the capped ids per reason; the summary
prints a `**Capped at MEDIUM:**` line.
- `unverified_tool` — a tool-sourced CRITICAL/HIGH whose status is `tool_reported` or
  `needs_more_info`: a scanner pattern hit no advisor confirmed (on a blind advisor, that was 30–40
  semgrep audit HIGHs per run). An advisor `CONFIRMED` (`tool_confirmed`) keeps the scanner's
  severity. Never capped: a secret (a secret adapter, or a credential CWE — 798, 259, 321, 522), a
  dependency advisory (pip-audit, npm-audit, osv-scanner, bundler-audit, cargo-audit,
  dependency-check, or any finding citing a CVE). **Not under `--gate-unverified`:** that flag asks
  for the stricter policy, so there the active severity stays the scanner's and gates as such.
- `unconfirmed_coverage_absence` — an OCRDb TST-A1* ("untested-units") claim that a module has no
  test, made from a cell that cannot see the rest of the repository. It keeps HIGH only when the
  driver confirms no assigned test file anywhere is named after the module (`test_<stem>`) or
  imports it; otherwise it is capped and names up to five of those tests (`referenced_by`). The
  import witness is Python-only, so a module in any other language cannot be confirmed and is capped
  with `measured: false`. This cap applies under every gate policy: it is about the claim's premise,
  not its verification.

Under the default policy the `unverified_tool` cap changes no health, grade or risk number — every
claim it caps is already outside the gate-eligible set those read. A capped coverage-absence finding
an advisor confirmed is gate-eligible, so that cap can move health.

`skill/scripts/evidence_sections.py` owns what the HTML report does with these statuses: the
header's "N verified" counts those same two, the collapsed "Unverified findings" section holds
`tool_reported`/`needs_more_info`/`unverified` plus any status it does not know, and the rest
(`corroborated`, `backup_scope_limited`; `rejected` never reaches the report's findings) are listed
with the findings.

Every finding that needs an advisor queues for verification, tool claims included, so
`--max-verify N` caps that combined set: each ordinary tool finding costs one advisor dispatch, and
an unverified tool HIGH competes with an agent HIGH for the same capped budget. The exception is an
ingest-confirmed first-party advisory (#3593, #3623: Cargo, npm, Python or Ruby), which is already
`tool_confirmed` and spends no
advisor slot. Size N with that in mind — anything cut stays `unverified` or `tool_reported` and
cannot gate. Citations (CWE/OWASP/CVE/EPSS) are audit metadata — they annotate findings but never
decide truth.
