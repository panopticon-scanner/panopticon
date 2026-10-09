## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate` (`PASS` / `FAIL` /
`OFF` / `INCONCLUSIVE`). `INCONCLUSIVE` means gate-relevant coverage did not complete (a high-value
panel ran partial, a scout-requested tool produced no output, or an integrity check fired — an
undeclared or content-substituted findings file, which on the driver path is caught by the driver's
own `dispatch-plan-driver.json` (declares every review cell → `reconcile_findings_files`) and its
`out-file-hashes.json` fan-out snapshot (per-cell sha256 → `verify_out_file_hashes`)) — treat it as
NOT certified, distinct from a real `FAIL`. Another cause (#2178, narrowed by #2222): under the
default `--gate-scope on-diff`, an ACTIVE delta review whose hunk map has no ranges while
gate-eligible findings exist (active, admitted by the evidence policy and by `--fail-on` when one
is set) reads `INCONCLUSIVE`, and `coverage_note` names the map and the remedy; an empty change
with no such finding passes, and the gate never falls back to the wider scope. A further cause
(#2405, widened by #2517): under that same scope, an ACTIVE delta whose map is PROVABLY damaged — a
non-zero `paths_emptied_by_drops`, `ranges_dropped` or `paths_dropped` — reads `INCONCLUSIVE` too,
even when the map still carries ranges, and `coverage_note` names the counter that tripped and the
same remedy. The two drop directions are opposite and both count: an emptied path still admits every
finding in its file to the gate, while a DROPPED path (its value was not a list of ranges at all)
leaves the map, so every finding in it classifies off-diff and leaves the gate's source set — the
fail-open loss a PASS used to hide. A rangeless path that arrived `[]` deliberately does not fire
it: a deletion-only, binary, mode-only or same-content rename change looks exactly like a truncated
map from there.
`summary.coverage_certified` and `meta.coverage.divergence` carry the detail; `main` exits `1` on
FAIL, `2` on INCONCLUSIVE, `4` when an artifact it wrote fails its own published schema (next
paragraph), `3` on an unreadable OCRDb bundle, `0` otherwise. Exit `2` is also argparse's
usage-error code and `main`'s own precondition refusals, which never reach the gate: a `--compare`
report it cannot read (either of the two), a `--compare` with neither `--html-out` nor `--out`, and
an artifact-root refusal. A genuine INCONCLUSIVE run still writes a full report artifact and every
one of those returns before the report is built, so disambiguate them by checking whether the report
exists. Consumers should key certification on `summary.gate` and `summary.coverage_certified`, not
on `overall_grade` alone — a tool-only coverage gap yields `INCONCLUSIVE` with a real grade still
attached. When `meta.coverage.resume` shows pending work in either phase, the terminal summary also
prints a `**Resume:**` line (fan-out/verify done vs. total) directly under the Grade/Gate line; a
fully-complete or resume-absent run prints no such line, so a resumed run never reads as a fresh
full scan. Every `meta.integrity` key that sinks certification is also NAMED on that summary, as an
`**Integrity:**` line saying what the key measured and that the run is not certified (#1761):
`synth/integrity.INTEGRITY_KEYS` is the one table both the gate and the renderer read, so no sinking
key reaches that summary as the bare word `incomplete`. The keys that report without gating — a
cross-domain filing, the planned-file and hash counters, the unenforced-ack disclosure, and the two
discovery disclosures (`discovery_git_failure`, `discovery_files_truncated`, #2271) — print as a
`**Note:**` or not at all. Those two name a DEGRADED surface: a raw walk that did not honour the
target's `.gitignore` because its own Git listing failed, so the reviewed surface may be far larger
than the target's own, and files past the discovery cap that were never reviewed. Discovery printed
both on a stderr the driver buffers and discards on a successful run, so the report is the only
place they reach a person; neither gates certification, because a superset or a prefix of the
intended surface is not an artifact on disk that is other than what it claims to be.

**Terminal completion, artifact validity and coverage certification are three different things
(#1639 P15),** and the exit status names which one failed. *Terminal completion* is whether the run
finished at all — the driver's `complete`/`error` status. *Artifact validity* is whether the files
it wrote are what they claim to be: in the normal completion path — not in a separate
controller-side check — `synthesize` validates the report against
`skill/reference/report-schema.json`, the **hydrated union** of its `_partN.json` splits and
`-discarded.json` sibling against the same schema, `-x0x.json` against
`x0x-report-schema.json`, and a present `-x0x-failures.json` against
`x0x-failure-log-schema.json`;
any failure prints `SCHEMA:` lines naming the artifact and the JSON path, then
`artifact invalid: N schema errors (see …)`, exits `4`, and ends a `driver` run in `error`.
A legitimate catalog-gap finding without `location.file` cannot satisfy X0X's required occurrence
shape. It remains in the main JSON and HTML, while `synthesize` excludes it from the X0X candidate
set and writes `<report-stem>-x0x-failures.json` beside the X0X, where `<report-stem>` means the
report filename without `.json`. That deterministic JSON object has one
`discarded_findings` array; each row carries the bounded, redacted `finding_id`, the reason
`no file locus`, and a bounded, redacted, inert diagnostic whose truncation is marked. The array
keeps duplicate ids because distinct content-derived findings can share one. `synthesize` validates
the log as written, warns
with the exact discard count and log path, then returns the report's ordinary gate status because
the X0X was written. The driver
forwards the disclosure and includes `x0x_discarded`, `x0x_failure_log`, and the same text in its
terminal status. An unchanged resume reproduces the same bytes; a run with no discards removes an
older failure log, so stale failures cannot follow a clean X0X.
The complete `synthesize` status list is: `0` for a valid PASS (and for a pass-1 verify-queue
emission), `1` for a valid FAIL, `2` for a valid INCONCLUSIVE or a pre-report CLI/compare usage
error, `3` for invalid input such as an unreadable OCRDb bundle or tools manifest, and `4` when a
written report, X0X, or X0X failure log fails its published schema. Discarding a locus-free X0X
finding never changes the status selected by the report's gate.
Validation is **fail-closed**: an uninstallable `jsonschema` (a declared runtime dependency) or an
unreadable schema file is an error, never a silent pass, because "we could not check" and "we
checked and it passed" must not look the same. **The schema pins the *controller's* output:** every
input that comes from a review agent or from a target-writable file is normalized to the pinned
types before it reaches the report, at every boundary and for both schemas —
`synth/validate_schema.repair_finding` (findings), `repair_verdict` (an advisor's verdict, through
the one sanitizer `evidence._agent_verdict`), `synth/repair.repair_groups_json`
(`.panopticon/groups.json`) and its two `tools-manifest.json` siblings there,
`integrity.cross_domain_findings`, `synth/coverage_io` (`.panopticon/coverage-*.json`) and the
OCRDb-domain clamp `codes`/`x0x_report` share — so a schema error can only ever mean a bug in
panopticon itself — never a lever a reviewed repository or a reviewer can pull. That is what makes
it safe for this failure to be terminal; it is also why `meta.host_capabilities`, which is copied
verbatim out of an untrusted artifact, is described in the schema without being constrained by it.
The two passes are labelled `SCHEMA pre-write:` (the in-memory document) and `SCHEMA artifact:`
(what was written), an error both find is printed once, and **every artifact is still written** — a
report that failed validation is on disk with `meta.schema_errors` in it, so it can be inspected
(that count is the report's own; an X0X-sibling-only failure leaves it `0`, and the `error` status
carries the total), and the `.panopticon/report.json` compat symlink still points at **this** run's
report rather than the previous run's. *Coverage certification* is whether enough of the review
actually happened for the verdict to mean anything — `summary.gate` and
`summary.coverage_certified`, exits `1` and `2`, both of them VALID reports about a coverage
question. **An unreadable tools manifest is an integrity failure** (#1644): a `tools-manifest.json`
that EXISTS and cannot be read (unreadable, not JSON, not an object) leaves the runner's selected
set unknown, so `tools_absent` is not computed from the scout's advisory list — that fallback
silently drops every scanner the runner selected and the scout never asked for — and the run reports
`meta.integrity.tools_manifest_invalid` with the reason, which fails `integrity_ok` like every other
SINKING entry in that section (`synth/integrity.INTEGRITY_KEYS` says which do), so the gate goes
INCONCLUSIVE, and sets `summary.coverage_certified: false`
with a `coverage_note` saying *tools manifest unreadable*. It is deliberately NOT softer than that:
exempting it from the gate would have made corrupting one byte of a target-writable file the
cheapest way to turn an INCONCLUSIVE run into a PASS on identical findings. An ABSENT manifest (a
pre-#1031 run, `--no-tools`) is a different fact and keeps the scout-derived gate, and a manifest
that parses with malformed FIELDS is a third, repaired at the read (`meta.tools.sanitized` /
`network`) where a bad row costs a warning and the row, never the run. The three are independent: a
run can complete, write a valid artifact and still be `INCONCLUSIVE`; it can pass its gate and still
have written an artifact no consumer can validate. So `4` is never a gate verdict and `1`/`2` never
mean the artifact is unreadable. The domain rules the schema cannot express — an agent-sourced
security HIGH with no CVSS score or no exploit scenario, two findings sharing an id, an unknown
`evidence.status` — are checked alongside it and stay advisory: they print as `SCHEMA:` lines and
are counted in `meta.schema_errors`, and they do not change the exit status.

**Malformed OSV and Roslyn captures (#2105).** Invalid top-level containers fail ingestion.
Malformed child containers or records retain usable sibling findings and disclose partial coverage
in the adapter's `file_coverage` facts and `meta.coverage.tools_file_partial`. The report sets
`summary.coverage_certified: false`; the finding-based security gate and usable delta baseline
remain available, with a partial-coverage diagnostic. Valid empty arrays stay complete. Roslyn's
intentional compiler and location-less diagnostic drops retain their existing policy.

These adapters count distinct identifiable paths in the capture, not every file the scanner read.
A path with any malformed record counts as `unparsed_files` even when other findings from that path
survive. `malformed_records` counts malformed entries or fields; `unlocated_records` counts those
without an identifiable source path, including malformed Roslyn runs. No filename is invented for
them. `files` and structural `records` examples are capped at 100 each, with omitted counts; file
display text is bounded and escaped. One stderr summary reports the malformed and unlocated counts
without quoting scanner values or exceptions. Optional OSV severity metadata keeps its fallback
behavior; these facts describe malformed finding containers and required identifiers or paths.

**Per-run folders (5.1).** Each run's working artifacts — findings, verdicts, coverage, scout
profiles, tool output, dispatch plans, hashes — live under `.panopticon/runs/<tag>/`, where `<tag>`
= `<host>-<mode>-<scope>-<yyyymmdd>-<run-id8>`, derived from the write-once run-manifest so it is
byte-stable across every resume (`runs/latest` symlinks the active run). The **final reports are
durable and top-level**: `.panopticon/<tag>-report.json` (+ `_part2.json` when split, +
`.json.html`), with `.panopticon/report.json` a backward-compat symlink to the latest — so
`rm -rf .panopticon/runs/` reclaims the findings/verdicts bulk without losing any report, and
successive runs' reports coexist for A/B. The review matrix is committed at the repo root as
`panopticon.yml` (the draft, `panopticon.yml.draft`, is a root-level ignored file); everything else
— the setup artifacts and the manifests — stays top-level under `.panopticon/`; `--reset` clears the
current run's folder but keeps its report.

**Secret redaction (#run7 SEC-B2C, #1634).** Reviewers are told to write `[REDACTED]`, and
`skill/scripts/redact.py` is the backstop for when one doesn't. It is applied twice, at both ends of
synthesis. First **at the inputs**: the findings go through `redact.redact_tree` immediately after
they are loaded — *before* `--emit-verify-queue` and *before* `build_report` — so every field
derived from them is computed from already-masked text, whatever derives it. Two derivations make
that placement load-bearing. `summary.top_issues` and `groups[].key_findings` are copies of finding
titles (and `discarded_claims` is a partition of the same list), so redacting only afterwards left
the copies unmasked. And a finding's queue id *is* a hash of its title, so both passes of a run have
to redact on the same side of the verify-queue branch — otherwise pass 1 queues one id, pass 2
recomputes another, the advisor's verdict stops binding, and `coverage_certified` flips to false
with no error. Masking the inputs also masks `verify-queue.json`, which is handed verbatim to the
advisor. Then **over the whole report tree** before any shareable artifact:
`render.redact_report_secrets` walks every string at any depth (`meta`, `summary`, `groups`,
`cross_panel`, `delta` and anything a future producer adds), not a named list of keys, so a producer
that copies text after it cannot reintroduce a secret. One dict feeds report.json, the `_partN.json`
splits, the `-discarded.json` sibling, `.json.html`, `-x0x.json`, `-x0x-failures.json` and the
terminal summary, so all of them inherit it; the failure log also redacts its bounded diagnostic
explicitly. What the whole-tree walk does **not** change is structured data: the patterns are
anchored to well-formed secret formats, so ids, codes, grades, hashes, file paths and the verbatim
`meta.host_capabilities` posture come back identical. Prose is a different matter — a sentence that
happens to contain a token-shaped substring is masked, exactly as it already was inside
`findings[]`; widening or tightening *which* shapes count is #1572's question, not this one's.
