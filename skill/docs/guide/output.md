## Output
Terminal markdown summary + JSON artifact at `--out`.
**What a person reads leads with the health score, and shows no letter grade (#3672, owner's
ruling 2026-11-23).** The terminal summary's headline is
`**Health:** 63.2 / 100  **Risk:** HIGH  **Gate:** FAIL`, and the HTML report's first badge is the
same score. A result that is held back says so beside the score, with each reason:
`**Health:** 63.2 / 100 (provisional; 145 tool findings unanswered by their advisors)`. A report
with no score reads `**Health:** n/a`, and the health line below says why. The Groups section
shows, per panel, the worst gate-eligible severity (`security CRITICAL / code none`), where it
showed an A to F rollup letter. A certified run that carries a `coverage_note` prints it as
`**Coverage note:**`. The letter fields stay in the JSON for one release, with the values they
had (`summary.overall_grade`, `provisional_grade`, `grade_cap`, and each group's
`panel_grades`), and are removed in 5.6. The paragraphs below that speak of "the letter" describe
those JSON fields. CI gate key: `summary.gate` (`PASS` / `FAIL` /
`OFF` / `INCONCLUSIVE`). `INCONCLUSIVE` means gate-relevant coverage did not complete (a high-value
panel ran partial, a scout-requested tool produced no output, or an integrity check fired — an
undeclared or content-substituted findings file, which on the driver path is caught by the driver's
own `dispatch-plan-driver.json` (declares every review cell → `reconcile_findings_files`) and its
`out-file-hashes.json` fan-out snapshot (per-cell sha256 → `verify_out_file_hashes`)) — treat it as
NOT certified, distinct from a real `FAIL`.
`summary.coverage_certified` and `meta.coverage.divergence` carry the detail; `main` exits `1` on
FAIL, `2` on INCONCLUSIVE, `4` when an artifact cannot be published or fails its own published
schema (next paragraph), `3` on an unreadable OCRDb bundle, `0` otherwise. Exit `2` is also argparse's
usage-error code and `main`'s own precondition refusals, which never reach the gate: a `--compare`
report it cannot read (either of the two), a `--compare` with neither `--html-out` nor `--out`, and
an artifact-root refusal. A genuine INCONCLUSIVE run still writes a full report artifact and every
one of those returns before the report is built, so disambiguate them by checking whether the report
exists. Consumers should key certification on `summary.gate` and `summary.coverage_certified`, not
on `overall_grade` alone — a tool-only coverage gap yields `INCONCLUSIVE` with a real grade still
attached. The letter is the health band with a severity cap on top (#3652): a confirmed CRITICAL
caps it at D and a confirmed HIGH at B, so an A never sits beside an open confirmed CRITICAL. The
cap only lowers; `summary.grade_cap` carries the band letter and the cap that lowered it. The
terminal and the HTML no longer print the letter or its cap (#3672); Risk names the worst
confirmed severity. Confirmed means the
default gate's population (`tool_confirmed`, `advisor_confirmed` or `backup_scope_limited`) under
every gate policy, so an unconfirmed finding never caps, even under `--gate-unverified`.
Per-group panel grades are already the max-severity rollup of the group's own gate-eligible
findings, so they need no cap.
When `meta.coverage.resume` shows pending work in either phase, the terminal summary also
prints a `**Resume:**` line (fan-out/verify done vs. total) directly under the Health/Risk/Gate line; a
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
any schema failure prints `SCHEMA:` lines naming the artifact and the JSON path, then
`artifact invalid: N schema errors (see …)`. An artifact path that cannot be written,
published, or removed prints `synthesize: artifact path refused:` with the path and cause.
Either case exits `4` and ends a `driver` run in `error`; artifacts completed before a refusal
remain on disk, later artifacts are not written, and the refused directory or other leaf is left
untouched.
**A split report explains itself, and undone verify work holds the letter back (#3667).** Past
the writer's byte budget `findings[]` is split into `_partN.json` files named in `meta.parts`; the
main file then also carries `meta.parts_findings`, `{part: {origin: count}}` (origin is
`tool:<name>` or `agent`), and the terminal prints a `**Report parts:**` line, the HTML a `JSON
report split:` one, saying how many findings the main file holds and what each part holds.
`findings[]` is published worst first
-- gate-eligible, then severity, then evidence status, then pipeline order -- split or not, so the
main file carries what matters most. `meta.coverage.tool_axis.by_tool` reconciles each scanner:
`ingested == in_report + merged_into_agent + dropped`, every drop with its reason. A tool finding
whose advisor never answered stays in the report as `tool_reported` (not gate-eligible), and the
letter is held back, as it is for an owed agent claim no verify advisor answered (when every verify
launch fails, nothing is confirmed and health alone would read S): `overall_grade` is null,
`provisional_grade` carries it, and `summary.grade_shortfalls` names why (the terminal and the
HTML read "63.2 / 100 (provisional; 145 tool findings unanswered by their advisors)"). That
list is one shared rule: any reason in it
holds the letter back, sinks `coverage_certified`, moves a PASS gate to INCONCLUSIVE and is named
in `coverage_note`. The shortfall's "N tool findings" counts the queued tool-sourced findings owed a
verdict that got none; `tool_axis.unanswered` counts every `tool_reported` finding, which also
takes in agent survivors reinforced by a tool, so it can read higher (24 beside 23, say).
Summoned backup advisors are its third reason (#3676): `meta.coverage.backups` counts, in cells,
the backups the verify phase dispatched (`verify-attempts.json`) as `answered` (EVERY part the
cell was dispatched in -- verify records the count beside the charge, since a scope over 25 claims
is split -- has a bundle the controller stamped a backup, bound to this run by the verify queue
or the driver's `--run-id`, holding a verdict), `unanswered` (a missing or gapped part, an empty
bundle, another run's, no part count, no run to bind to) or `unloadable`, and "5 backup advisors
unanswered" holds the letter back the same way. An unreadable attempts record is a reason of its
own; a run whose backups all answered is unchanged. A finding whose primary answered is not owed
again, so its unanswered backup is a backup reason only, never also a verify-advisor one.
Backup coverage is also counted per claim (#3695). Verify records the ids of the claims it hands
each backup, and a backup is `answered` only when every one of them has a verdict in its own
bundles: one that answers 1 of its 20 claims is `unanswered`, and is asked again on the verify
budget (three dispatches) like a short primary advisor. `claims_scoped` counts the claims handed
out and `claims_unanswered` the ones with no backup verdict, named beside the cells: "1 backup
advisor unanswered" and "19 findings unanswered by their backup advisors". A verdict counts only
for a claim the backup was handed. A record that holds no claim list (written before this) is
never `answered`: its cell is `unanswered`, or `unloadable` when one of its bundle files failed to
load. It is counted in `scope_not_recorded` (`scope_not_recorded_unloadable` says how many of those
are unloadable) and left out of both claim counts, and the reason for the state it landed in says
so: "1 backup advisor unanswered (1 scope not recorded)".
An advisor's verdict counts only for a claim that advisor was handed (#3702). Verdicts are matched
to findings by id across the run, so verify records, for each cell and stage it dispatches, the
claim ids it hands out, the number of parts and the part size (`<group>/<domain>/<stage>/claims`,
`/parts` and `/part_size` in `verify-attempts.json`, in the same write as the charge). A verdict in
a bundle is counted only when that record shows its own part was handed the claim it names. Any
other is dropped: `meta.coverage.verdicts.out_of_scope` counts them, and "2 advisor verdicts
outside their handed scope" is a `grade_shortfalls` reason, so a run with one is NOT CERTIFIED even
when every advisor answered all it was asked. The verify phase refuses such a reply, or asks for
the bundle again, on the usual budget of three dispatches. A bundle whose cell and stage have no
recorded scope counts for nothing, and `scope_not_recorded` counts its verdicts: "verify scope not
recorded: 12 advisor verdicts not counted". That is what a run whose verify phase ran before this
version reads as, and a hand `synthesize.py --verdicts-dir` call over bundles with no
`verify-attempts.json` in the run folder. A run in flight at the upgrade and resumed after it is
affected too: the verify cells it had already finished are never dispatched again, so their scope
is never recorded and their verdicts are not counted. The remedy is a full re-run, not a re-verify:
`--reset` discards the whole run folder, the review included, and the run starts from discovery.
A verdict speaks only for its own cell's instance of a claim (#3707). A claim id is derived from the
claim's domain, category, file, title and line, and no group, so two cells can hold one id: two
reviewers reporting the same thing, or one copying the other's claim. A bundle verdict counts for a
finding only when the bundle is stamped for the cell that finding was loaded from. Where several
cells hold one id, each cell's advisors answer for their own instance (a backup stands over its own
cell's primary and no other), and the claim is decided across them: any CONFIRMED keeps it reported;
otherwise a holding cell that gave no verdict leaves it unverified; and only every holding cell
rejecting it discards it. A cell that was never asked about the claim is not one of the cells that
decide it: the dispatch record shows the id in none of its scopes, as for a cell below the verify
gate, or one whose findings file was refused. It dismisses nothing, and no other cell dismisses its
instance, which stays in the report as it would with no other cell holding the id (a CONFIRMED from
a cell that was asked still reports the claim as confirmed). A cell that was asked and did not
answer is one of the cells that decide. `meta.coverage.verdicts.ids_in_several_cells` counts such
ids. It is a disclosure, not a shortfall: an honest duplicate that both cells confirm, or both
reject, is decided as it always was.
Merging findings at one line changes what the report shows and never what the run owes (#3716).
Findings of one category at one line are merged into the most severe before any verdict is read.
"Most severe" is the severity a finding will be published at, as far as its own content says, and
not the one its reviewer claimed (#3727): a `severity_override` with no reason counts as its code's
default, and a `TST-A1*` claim at CRITICAL or HIGH counts as MEDIUM, its cap. And no finding that
is not REJECTED stays merged under a row whose final severity is below its own; it comes back as
its own finding. One row is not held to that: a scanner finding nobody has confirmed, capped at
MEDIUM, keeps the claim merged into it (a lone claim and a lone scanner finding at one line are
merged whatever their categories). A claim written above its code's default with an empty
override ranks at the default, so beside a scanner finding that outranks the default it is under
the scanner's row, as a claim written at the default is. An uncapped `TST-A1*` claim is the
exception to the exception:
it ranked below where it ends, so it comes back beside the scanner's row. So one id can be in the
report at two severities: one claim filed twice under different codes, by two cells or by one,
where the instance that is not capped comes back over the other; the two rows can differ in
evidence status too.
What is owed is counted first, over every loaded finding. A claim is owed an advisor's answer when
its review cell reaches the verify gate, or the dispatch record says the cell was asked about it;
the cell is the findings file the claim was loaded from, whatever domain its reviewer declared. A
claim that was owed an answer and has none is one unanswered finding whatever it is merged under,
and so is a claim that
another cell confirmed when its own cell was asked and said nothing (the claim is reported
confirmed, and the run is not certified). One claim held by several cells counts once. A tool
finding merged into an agent claim is the exception: no advisor is asked about it while it is
merged, so it owes nothing until it is reported by itself.
What comes back out of a merge as its own finding: a CONFIRMED finding, unless the one it is
merged under is CONFIRMED too; under a REJECTED finding, which goes to `discarded_claims`,
everything not itself REJECTED; a finding that is owed an answer and has none, unless the one it
is merged under is CONFIRMED or is itself owed and unanswered; and any finding not itself REJECTED
whose row ends at a lower severity than its own (#3727, above). Anything else stays merged under a
finding that is in the report.
**What a merge weighs (#3731).** `summary.health.weighted_defect` adds each counted finding's
severity weight times the lines it spans. The findings merged at one line are one merge group, and
a group is counted once, at the heaviest of its findings that count for the gate on their own:
confirmed by its own cell's verdict (any finding not REJECTED under `--gate-unverified`), or a
scanner finding that a CONFIRMED claim absorbed, which no advisor is asked about and which is
confirmed with the pair. The weight is one finding's own, the severity it is published at times
its own lines; nothing is mixed, and no row's range or severity changes. A row carries
`weight_from` (the finding's id and weight) when the group's weight is not its own, and the
group's other counted rows carry `weight_with`, the id of the row that does. So a one-line claim
that wins the merge over a confirmed finding spanning 50 lines does not lighten it, and two counted
rows that came out of one merge are not added.
**A scanner rule's hits (#3732).** A rule that fires several times in one file is one finding. It
is shown at its lowest line, whatever a reviewer flagged (a claim on a later hit is its own row),
with the other hits in `additional_loci`. It carries the highest severity among its hits, and
`severity_from` names the hit and the shown hit's own severity when they differ. In 5.4 every
scanner finding is one line, because no scanner adapter reports a span: no hit carries a
`line_end`, and a scanner finding weighs as one line. The widest-hit rule (a scanner finding
weighs as its widest hit, and a hit in `additional_loci` keeps its `line_end`) would apply only
if an adapter reported a span. The ranges that weigh in 5.4 are agent findings' own. A range that
ends before it starts is read as one line at load.
**A verdict on a scanner rule's hits (#3756).** The advisor is given every hit: the shown line and
each entry of `additional_loci` are one claim. CONFIRMED needs one real hit. REJECTED means every
hit is safe, and it takes effect only when the advisor's `judged_loci` (line numbers) names every
one of the finding's lines. A REJECTED that leaves a line out is not a rejection: the finding
stays in the report with `evidence.status: needs_more_info`, `evidence.unjudged_loci` lists the
lines nobody judged, and `evidence.reasoning` opens with how many were. It is answered, not
verified and not discarded; like any unverified pattern hit it is capped at MEDIUM unless
`--gate-unverified` is set. A number in `judged_loci` that is not one of the finding's lines is
ignored, and anything but a list of integers is read as no list. So an advisor verdict written
before 5.5, or by a host that omits the field, rejects only a finding with one line. Two limits:
a rule that fires on many lines of one file can be confirmed but will rarely be rejected, because
the advisor must name every line; and a hit that carries no line number can never be named, so a
finding holding one can never be rejected. A finding with one hit, and an agent's claim, are
rejected as before.
`meta.coverage.dependency_audit` is the dependency-audit receipt: the ecosystems the tree has a
dependency manifest for (`applicable`), and the dedicated auditors that were `selected` and
`produced` output. Its `unaudited` map (#3648) names each applicable ecosystem that no selected
auditor reads, and why: `no_auditable_file` (none of the files an auditor reads for it is in the
tree, such as a `package.json` with no lockfile), `needs_online` (every auditor that reads the
file there runs only under `--online`, as pip-audit does for a `pyproject.toml`), or `not_run`.
`coverage_note` says it in a fixed sentence, for example
"javascript not audited: no npm-shrinkwrap.json, package-lock.json, yarn.lock or pnpm-lock.yaml;
npm-audit and osv-scanner need one". When no auditor produced anything, that sentence follows "no
SCA tool produced output on an applicable tree".
An ecosystem that is `needs_online` or `not_run` stops certification (#3700), even when another
ecosystem's auditor answered: an auditor reads its file and did not run, so part of the tree's
dependencies went unaudited. Coverage is NOT CERTIFIED, a PASS gate becomes INCONCLUSIVE (exit 2)
and the result is not held back (in the JSON the letter stands), as for a missing scanner or the
whole-tree gap; a FAIL stays FAIL.
`tools_manifest.UNAUDITED_UNCERTIFIED` is the one list of those reasons. The visible change: an
offline run of a tree with a JavaScript lockfile and a `pyproject.toml` is now INCONCLUSIVE until
it runs with `--online`, where it used to PASS with a note only the JSON showed.
`no_auditable_file` is still disclosure only and moves neither the gate nor `coverage_certified`:
the target gives no auditor anything to read. When the tree otherwise certifies, that sentence is
the only sign, and since #3672 a person sees it: a certified run prints its `coverage_note` as a
`**Coverage note:**` line in the terminal summary and a `Coverage note:` line in the HTML.
`security_gate.py`, the CI gate over raw scanner output, does not read this receipt: neither this
rule nor the whole-tree one applies there (#3791).
`meta.coverage.scanner_config_excluded` (#3708) names the scanner's own root config file, which a
full scan does not hand to any review group: the one file it loaded as its config
(`panopticon.yml`, or `.panopticon.yml` when that is the only one). It is disclosure only too,
and `coverage_note` does not mention it: that field is for what needs attention. The key is absent
when no config was left out (a scoped run, or a tree with none).
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
error, `3` for invalid input such as an unreadable OCRDb bundle or tools manifest, or a run folder
that could not be listed (#3701), and `4` when a
report, split part, discarded-claims sibling, X0X, X0X failure log, or HTML page cannot be
published or when a written JSON artifact fails its published schema. Discarding a locus-free X0X
finding never changes the status selected by the report's gate.
A status of `3`, or any status not in this list, publishes no report. The driver ends the run in
`error` with the step's last line, keeps its retry marker, and does not take a report that an
earlier attempt of the run left on disk for this attempt's. When the step printed nothing, the
reason reads `it said nothing`.
The same holds for a step that dies under a status that is in the list (#3769): an uncaught
exception exits `1`, and several refusals exit `2` or `4` before a report is built. Before the step
runs, the driver clears the names a report is read from, in this order:
- It removes the `.panopticon/report.json` and `report.json.html` links, whatever they point at:
  an earlier attempt's report, or another run's (#3778). Until this attempt publishes, those two
  paths do not exist. They then point at what this attempt published, which under status `4` can be
  a report that failed its schema.
- It moves what an earlier attempt of the run published (the report, its HTML page, the X0X and its
  failure log) into `.panopticon/runs/<tag>/earlier-attempt/`, and a regular file at either flat
  name with them. A report found afterwards is therefore this attempt's, and a step that publishes
  none ends the run in `error`. Another run's tag-named files are not touched.

A name that cannot be looked at, a link that cannot be removed or a file that cannot be moved stops
the attempt before the step runs, with the reason. Only regular files are moved: a link, a
directory or a FIFO at a name the step publishes at is left for the step, which refuses it as
before, and the driver takes no report through a link. Split parts and a discarded-claims file of
the earlier attempt are left in place, since only a report names them; a split report that was set
aside therefore cannot be read whole or compared from where it is.
Validation is **fail-closed**: an uninstallable `jsonschema` (a declared runtime dependency) or an
unreadable schema file is an error, never a silent pass, because "we could not check" and "we
checked and it passed" must not look the same. **The schema pins the *controller's* output:** every
input that comes from a review agent or from a target-writable file is normalized to the pinned
types before it reaches the report, at every boundary and for both schemas —
`synth/validate_schema.repair_finding` (findings), `repair_verdict` (an advisor's verdict, through
the one sanitizer `evidence._agent_verdict`), the target-carried `tools-manifest.json` blocks in
`synth/repair` (exclusions, the SEC carve-out, Git drivers, suppression counts),
`integrity.cross_domain_findings`, `synth/coverage_io` (`.panopticon/runs/<tag>/coverage-*.json`) and the
OCRDb-domain clamp `codes`/`x0x_report` share. `groups.json` and the manifest's run-written blocks
are read as written (#3273): first contact halts on a `.panopticon/` that is not this machine's,
their producers bound them, and a hand-named `--groups` file of the wrong shape is ignored whole
(`plan._groups_shape_fault`) — so a schema error can only ever mean a bug in
panopticon itself — never a lever a reviewed repository or a reviewer can pull. That is what makes
it safe for this failure to be terminal; it is also why `meta.host_capabilities`, which is copied
verbatim out of an untrusted artifact, is described in the schema without being constrained by it.
The published schema is checked once, against what was written: the hydrated report union and its
X0X siblings. Errors are labelled `SCHEMA artifact:`, and **every artifact is still written** — an
invalid report is on disk so it can be inspected. `meta.schema_errors` combines those written-
artifact schema errors with in-memory semantic-policy errors; policy warnings are excluded. The
main report is republished with the combined total when the artifact pass finds schema errors. The
`.panopticon/report.json` compat symlink still points at **this** run's report rather than the
previous run's. *Coverage certification* is whether enough of the review
actually happened for the verdict to mean anything — `summary.gate` and
`summary.coverage_certified`, exits `1` and `2`, both of them VALID reports about a coverage
question. **An unreadable tools manifest is an integrity failure** (#1644): a `tools-manifest.json`
that EXISTS and cannot be read (unreadable, not JSON, not an object) leaves the runner's selected
set unknown, so `tools_absent` is not computed from the scout's advisory list — that fallback
silently drops every scanner the runner selected and the scout never asked for — and the run reports
`meta.integrity.tools_manifest_invalid` with the reason, which fails `integrity_ok` like every other
SINKING entry in that section (`synth/integrity.INTEGRITY_KEYS` says which do), so the gate goes
INCONCLUSIVE, and sets `summary.coverage_certified: false`
with a `coverage_note` saying *tools manifest unreadable or invalid*. A run-bound tool ingest also
requires the manifest's exact output receipt (#2070); a missing, malformed, or foreign receipt takes
this same fail-closed path. It is deliberately NOT softer than that:
exempting it from the gate would have made corrupting one byte of a target-writable file the
cheapest way to turn an INCONCLUSIVE run into a PASS on identical findings. An ABSENT manifest when
no run-bound tool ingest was requested (a pre-#1031 run, `--no-tools`) is a different fact and keeps
the scout-derived gate.
**A scout file that cannot be read is an integrity failure (#3780).** With no tools manifest, the
scanners the scouts asked for are the only required set. A `scout-*.json` whose request cannot be
told (the read or parse fails, the content is not an object, or `tools` is there and is not a
list of names) is listed in `meta.integrity.scout_files_unreadable`, the run is not certified, a
PASS gate is INCONCLUSIVE, and the `**Integrity:**` line names the files. This holds with a
manifest too: the file is a damaged run artifact. A scout that asks for no tools (`tools: []`, or
no `tools` at all) is a decline, as before. The coverage phase's retry counter is
`scout_attempts.json`, outside the scouts' `scout-<group>.json` pattern, so it is never read as
one. A counter an earlier build left as `scout-attempts.json` (also the scout file of a group
named `attempts`) is recognised by its shape, an object of counts with no `tools` or `domains`
key, and passed over.
What a call with no `--run-id` certifies over a tools directory (#3766): nothing. A
`synthesize` call given a tools directory that is there, without `--tools-skipped` and without a run
id (absent, or the empty `--run-id ""` the driver sends for a run manifest that carries no
`run_id`), has nothing that binds the directory's output to it, and a manifest in the run directory
is no more bound than the output is. The call reports `meta.integrity.tools_run_unbound: true` and
`summary.coverage_certified: false`; the gate is then INCONCLUSIVE unless a finding already makes it
FAIL or `--fail-on off` turns it off. A hand `run_tools.py` + `synthesize.py` pair is such a call. A
certified result comes from a driver run, which passes the run id. Findings are still ingested and
reported, and `meta.coverage` still says what was produced, failed or absent: with no manifest, a
capture that could not be used is `produced_unusable` whoever asked for it. "Capture" means a file
ingest reads and has an adapter for: ingest reads the names in the tools directory that do not start
with a dot and end in `.sarif` or `.json`, and matches each by its name without the extension
against the registered adapters. The runner writes one output per adapter, so more than one
capture for an adapter (`bandit.json` beside `bandit.sarif`) is that adapter's failure (#3780):
its record is `failed`, reason "more than one capture for one adapter: …", whatever each file
holds, because which one is this run's scan cannot be told. The findings of each capture that
parsed are still reported.
On a call with no run id, a file with no adapter (a report written
into the directory, a `tools-manifest.json` put there; the manifest is looked for in the run
directory, never in the tools directory) is listed under `meta.coverage.adapters` as `failed`, "no
registered adapter", and is not named as lost coverage. With a run id and its receipt it is not read
at all: any `.json` or `.sarif` name the receipt does not list is unbound output
(`meta.integrity.unbound_tool_outputs`), and that does withhold certification. A tools
directory that is given and cannot be listed is lost coverage on every path
(`meta.integrity.tools_dir_unlistable`, the directory and the error on one line): whatever it holds
was not read. That is any failure to list it except "no such file" at the open; an error part way
through the entries counts, whatever the error. A directory that is not there is no tool axis at
all, as before, with or without a run id. The one listing ingest reads from is the one this is judged by. A manifest
that parses with malformed FIELDS is a third, repaired at the read (`meta.tools.sanitized` /
`network`) where a bad row costs a warning and the row, never the run. The three are independent: a
run can complete, write a valid artifact and still be `INCONCLUSIVE`; it can pass its gate and still
have written an artifact no consumer can validate. So `4` is never a gate verdict and `1`/`2` never
mean the artifact is unreadable. The domain rules the schema cannot express — an agent-sourced
security HIGH with no CVSS score or no exploit scenario, two findings sharing an id, or a missing
file locus — are checked in memory as policy, separately from schema validation. They print as
`WARN:` or `REPORT policy:` lines. Policy errors (duplicate ids, missing exploit scenarios, and id
grammar gaps) count in `meta.schema_errors`; warnings do not. Neither changes the exit status.

**How old the advisory data was (#3798).** `meta.coverage.advisory_data` says, for each advisory
source frozen in the tools image (`nvd`, `osv`, `trivy`, `rustsec`, `ruby`), its `date`, its
`age_days` at scan time (`read_at`, when `run_tools` read the dates out of the image) and a `status`:
`current`, `stale` (older than `stale_after_days`, 7) or `unknown` (no readable date, shown as
`unknown`, never as a date). The `osv` row's date is its oldest ecosystem database; `ecosystems`
holds each one's own. The terminal summary and the HTML page show one line
(`Advisory data: NVD 2026-11-23, OSV 2026-11-23, Trivy 2026-11-22, …`) and, when a source is stale or
unknown, a warning line above it. It is disclosure only: the gate, certification, the grade and
health do not read it. The block is absent on a `--no-tools` run and when the manifest carries none.

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

**Which matrix a report ran under (#3651).** Setup proposes a different matrix nearly every time
it is asked, and a review's results move with the matrix. So every report says which one it used,
in `meta.matrix`, and as one `Matrix:` line among the provenance lines of the terminal summary and
of the HTML header:

- `matrix_fingerprint` — a hash of the matrix **as applied**: each review group's files and floor
  panels on the reviewed tree. Two reports with the same fingerprint reviewed the same cells. It is
  effect-based on purpose: groups claim files first-match-wins, so two configs whose groups are in
  a different order are the same matrix only when they realise the same cells, and this hash is
  equal exactly then. It is `summary.health.basis.layout_fingerprint` plus each group's floor
  panels; panels a scout added are not included.
- `config_sha256` — a hash of the config **as written**: groups and globs in authored order,
  `exclude_paths`, and the settings that shape the cut. Key order, comments and whitespace do not
  count.
- `origin` — `committed` when the config file is part of the reviewed commit, byte for byte (a
  **reused** matrix, pinned with the repository); `working_tree` when it is not (a **fresh** one,
  written after the commit by setup or by hand); `unknown` when that could not be measured, which
  is never reported as reused. The driver measures it once, when the run starts. The bytes on
  disk are compared raw with the commit's blob, so a checkout that rewrites line endings
  (`core.autocrlf`, or `eol=crlf` in `.gitattributes`) reads an untouched config as fresh. That
  fails safe: commit the config with the line endings your checkout produces, or disable the
  conversion for it. A config the commit holds under another spelling of the name
  (`Panopticon.yml`), on a filesystem that reads the two as one file, is `committed` (#3684).
- `setup_draft` — for a `working_tree` config, whether it is the draft this target's last
  `driver setup` wrote (`unchanged`) or not (`differs`); `null` when setup recorded none. That
  record lives in the operator's state directory, never in the target.

Compare two reports only when their `matrix_fingerprint` is equal. A fresh or unknown matrix says
so on its line: `comparable only with runs on the same fingerprint`.

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
`cross_panel` and anything a future producer adds), not a named list of keys, so a producer
that copies text after it cannot reintroduce a secret. One dict feeds report.json, the `_partN.json`
splits, the `-discarded.json` sibling, `.json.html`, `-x0x.json`, `-x0x-failures.json` and the
terminal summary, so all of them inherit it; the failure log also redacts its bounded diagnostic
explicitly. What the whole-tree walk does **not** change is structured data: the patterns are
anchored to well-formed secret formats, so ids, codes, grades, hashes, file paths and the verbatim
`meta.host_capabilities` posture come back identical. Prose is a different matter — a sentence that
happens to contain a token-shaped substring is masked, exactly as it already was inside
`findings[]`; widening or tightening *which* shapes count is #1572's question, not this one's.
