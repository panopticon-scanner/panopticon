# Changelog

## Unreleased — 5.2 Claude first-class host (#1344, family PR)

The Claude family's first-class-host PR under `docs/FAMILY-PR-GUARDRAILS.md`:
Claude already shipped its runner, probes, emit branch, registry row and both
guards, so this PR is the evidence a real `driver loop` gives, plus what that
evidence exposed.

- **The workflow guard closes eight LOW follow-ups from its 5.2 reviews (#1793).**
  `env -- - sh` and `env x-y=1 sh` read through to `sh`, and `xargs -I{} {}` is reported (#2307).
  `sh <<< '…'` is read as its script; an interpreter's here-string bash expands is reported (#2293).
  A brace or glob word where a command starts (`{sh,-c}`, `[s]h`) is reported, not read (#2294).
  Globs in `[[ … ]]`, array literals and extglob groups are not commands; `@(sh) -c …` is reported.
  `"$PWD/tool"` and `"$(pwd)/tool"` are read as running a download called `tool` (#2310).
  A bare `tool` is read as running a download written to `/usr/local/bin/tool` (#2308).
  A checksum must precede each use of a download, not only its first (172 pre-existing fail-opens).
  A checksum in a script given to `sh -c`, `eval` or a shell's stdin must stop the step to count.
  Its own pipefail (`bash -o pipefail -c`, a plain `set -o pipefail`) is read as its `-e` is.
  Such a script sits in its runner's branch, and its own `fi` or `done` ends none of the step's.
  A script given to a shell inside `$(...)` is reported if it fetches or its job downloads anything.
  `env A=$X sh` reads through to `sh`; `env $(x)=1 sh` and `env A=$X -c …` are reported.
  `sh {-c,'…'}` and `sh [-]c` are reported, and `sh ./x_*.run` as running a download `x_1.run`.
- **The workflow guard sees through setsid, ionice, taskset, flock, chrt and unbuffer (#1795).**
  Each was read as the command itself, so `setsid curl … | sh` and `curl … | chrt 10 sh` passed
  clean. `scripts/shell_wrappers.py`, which now holds the reader's wrapper table, reads each by
  its own grammar and reports what it cannot settle, such as a `taskset -p` pid that may be 0.
  Behind `xargs`, which appends words, a wrapper that runs nothing as written is reported too.
  A download run as a wrapper, as in `curl -o flock …; ./flock 9`, counts as running it.
  A `$` word behind a wrapper is reported even if it ends in a wrapper's name (`sudo "$PWD/env"`).
- **Separate Codex event parsing and usage accounting (#2299, #1826).** Completed turns,
  messages and final results keep recovery ordering, partial usage and host-error precedence.
- **Separate confined read-tool operations (#2298, #1826).** Read, list and search handlers
  retain the common argument/refusal boundary, grant checks and bounded result disclosures.
- **Reuse the published report schema location in tests (#2297, #1821).** Split-report,
  parity and verdict-binding checks use the validator's reference directory and schema name.
- **Derive the health explanation from grading weights (#2296, #1821).** The terminal
  summary reads the canonical severity weights in display order, preserving its current wording.
- **The workflow guard names the step it cannot read, and refuses a heredoc delimiter bash
  must parse (#1793).** A `shell_lex.Unreadable` escaped `main` as a traceback that named no
  step and hid every other step's defect (#2252); it is now that step's defect. A delimiter
  bash parses to spell (`<<$(...)`) was read as code, so a quote left open in its body hid the
  payload after the terminator (#2224); the reader now refuses it, naming the word.
  A `\`-newline before the word no longer reads as an empty delimiter, which hid the payload.
  A `<<`, `<<-` or `<<<` split by a `\`-newline reads as the one operator bash makes (#2291).
  The closing count says "N defect(s)" where it said "N unverified fetch-and-exec step(s)".
- **SpotBugs findings cite the CWE SpotBugs or FindSecBugs assigns to the pattern (#1795;
  COD-1501398192).** `_SPOTBUGS_CWE` was a hand-written table of seven bug patterns; one of
  them, HARDCODED_KEY, named a pattern neither vendor has ever emitted, so a suppressed
  hard-coded password never reached policy C's gate. The table is now the union of core
  SpotBugs 4.8.6's and the FindSecBugs 1.13.0 plugin's own `findbugs.xml` mappings -- 145
  patterns across both vendors; what neither maps stays uncited, on purpose.
- **Keep score-gate imports from changing the search path (#2279, #1823).** Package and flat
  imports retain evidence module identity without modifying `sys.path`. Direct file execution
  remains supported, and the bootstrap allowance is removed from the import guard.
- **Reuse the coverage string-list filter (#2278, #1822).** Coverage delegates list filtering
  to the schema helper while still accepting a lone string. Manifest inputs remain list-only.
- **Share bounded manifest name validation (#2277, #1820).** Tool repairers share object,
  row-count and name checks. Overlong tool identities are still dropped; suppression names are
  still cut and colliding counts summed, with the same warnings and value checks.
- **Use current tool-policy test fixtures (#2276, #1820).** One driver-plan fixture and case
  table cover enforced, advisory, mixed and unknown modes, retaining the report metadata check.
- **The scanner-owned config leaves `run_tools.py` (#1762, ARC-2609514778; part 1 of 3).**
  The staged `bandit.ini`/`.trivyignore`, the suppression posture, the ignore overlays and
  two of the four ledgers the manifest reads back move to `skill/scripts/scanner_config.py`
  whole: `run_tools.py` goes from 2215 to 1774 lines and the new module is 518, under the
  700-line ceiling. No argv, flag, path or message changed — `tests/test_scanner_config.py`
  pins the docker argv of both staged tools, in both security modes, with and without the
  target's own `.bandit`, against a golden captured before the move. `ToolAdapters` gains
  an `Image` layer so the matrix can claim the new files without passing the 48-file cap.
- **Discovery surfaces the dot-paths the shipped catalogs and the SEC floor claim, and both
  discovery paths apply one policy (#1784, #1771; ARC-124841687, ARC-1940929242).** The policy was
  `ALLOWED_DOTDIR_SUBTREES = (".github/workflows",)` plus a blanket skip of every other root
  dot-path, so 73 of the 74 dot-leading globs `skill/data/commons_catalog.yml` claims --
  `.circleci/**`, `.buildkite/**`, `.github/actions/**`, `.github/*.yml`, `.env*`, `.npmrc`,
  `.eslintrc`, `.husky/**`, `.mvn/**`, `.goreleaser.yml`, `.panopticon.yml` and the rest -- named
  files no group could ever receive, and so did the deterministic SEC floor's own `.circleci`,
  `.buildkite/`, `.github/actions/`, `.travis.yml`, `.drone.yml`, `.pre-commit-config.yaml`,
  `.devcontainer/`, `.env`, `.npmrc`, `.netrc`, `.pgpass` and `.htaccess` hints. A file discovery
  never returns is never `Ungrouped` either, so nothing reported the gap: #1508 (top-level
  `.github/*.yml`) and #1838 (the CI and secret-file floor) both rest on claims that could not
  fire. Owner ruling 2026-09-27, allowlist widen in 5.2 (pruning the claims was rejected): one
  policy in `skill/scripts/dot_paths.py` naming exactly the root dot-directories and dot-files
  those two enumerations spell out, and nothing else -- `.git`, `.venv`, `.tox`, the tool caches,
  `.panopticon/` and any unclaimed dot-path stay pruned, as does a dot-directory nested below the
  root. Both paths now ask that one rule on the same segment: the git-listing filter tested each
  ancestor DIRECTORY while the walk tested the whole FILE path, so every file directly under
  `.github/` was reviewable surface on a git target and invisible on a non-git one -- against two
  docstrings that said both methods shared one policy. The durable guard derives its samples from
  the shipped catalog and the floor hints themselves and asserts both paths keep each one, so a
  claim discovery cannot surface fails in the PR that adds it. `_git_listed_files` also swallowed a
  bare `Exception` into `None`, and the caller then walked -- which stops honouring the target's
  `.gitignore`, the surface policy #500 exists for; "not a git worktree" and "git failed on a
  worktree" are now told apart, the failure is named on stderr and published as the discovery
  block's `git_failure`, and the scan still runs. **Discovered file sets grow on every target**:
  CI, config and secret-bearing files now reach a group, so group and cell counts move -- land this
  before a run, not during one.
- **Share synthesis test isolation (#2204, #1822, #1823).** Synthesis tests reuse the cwd
  guard and one autouse isolation fixture at the same package and module scopes. Report tests
  import mocks explicitly, preserving assertions and removing reliance on prior test imports.
- **Share OCRDb report record helpers (#2203, #1822).** Gap and strain reports use one
  occurrence builder and the catalog's raw domain-prefix helper. Missing-file handling, optional
  strain run IDs, each caller's domain policy and flat imports retain their existing behavior.
- **Derive SARIF levels from the adapter severity map (#2202, #1821).** SARIF retains its
  four allowed level names while sharing their grades with tool normalization. Missing and
  unknown levels, metadata precedence and secret grading keep their existing behavior.
- **Share token usage vocabulary (#2201, #1821).** The dispatch ledger imports usage fields
  and phases from the usage collector, keeping totals, checkpoint mapping, model attribution
  and corrupt-row accounting unchanged.
- **A refused `CODEX_HOME` is the remedy readiness and the setup acknowledgment show (#1803;
  COD-1638371699).** `host_disclosure.remedy` named `--emit-host-agents codex`, and
  `setup_ack._remedy_clause` named it or `driver loop --setup --host codex --mode headless`,
  even though the row's own `registration_refusal` meant that exact command would refuse with
  the same message one step later. A refused `CODEX_HOME` reaches both surfaces as UNKNOWN,
  never as REFUTED, so the acknowledgment yields to the refusal on every branch; both read it
  off `hosts.HostSpec`, and `host_disclosure.lines` prints it once rather than once per
  capability line. Every other host, and codex with no refusal, is unchanged.
- **A SIGTERM the driver did not arm ends the Kimi runner's children before the home strip
  (#1805).** The stripper's SIG_DFL/C-installed branch restored the default disposition and
  re-raised the signal without ending the runner's registered children first, so a process whose
  SIGTERM was never wired to the driver's own handler could die and leave them running against a
  home whose guard hooks had just been stripped. It now calls `terminate_children` -- the same
  bounded termination the interrupt path uses -- before the strip; the chained-predecessor branch
  is unchanged.
- **The workflow guard reads comments, continuations and heredocs the way bash does (#1793;
  COD-3418139920, COD-3636110933).** `shell_reader.statements()` settled all three in passes
  that ran before any quote tracking, so a `#` line inside a multi-line string, a `<<WORD`
  inside quotes, in a comment or at the tail of a `<<<`, and a backslash ending a comment or a
  quoted heredoc line each hid a statement bash runs, and the guard reported the step clean.
  `scripts/shell_lex.py` now reads them in one quote-aware forward pass: heredocs queue until
  the newline, a body ends at the line bash compares, and a delimiter bash must parse to spell
  (`<<$(...)`) stays text. A command's `((` is arithmetic or two subshells, whose heredocs are
  real, by the character after its first group, as bash decides it; nesting that would take
  over eight re-readings of the script to decide raises `shell_lex.Unreadable` rather than
  guess. An `a[...]` subscript, where `<<` is a shift, opens only where bash reads an
  assignment -- across lines, and inside `a=(...)` -- so among a command's arguments
  (`echo a[1<<X]`) `<<` is a heredoc. The scanners after the lexer now agree on `\"`
  inside "...", `$'...'` and an apostrophe inside "...": misread, each hid what followed it.
  Every heredoc on a line is read and filed under its descriptor, so the guard reads the
  script `bash -s <<'A' 3<<'B'` runs (#2128).
  A heredoc opened inside a `$(...)`, `<(...)` or `>(...)` that closes before the newline its
  body would follow raises `shell_lex.Unreadable` too: bash 5.2 takes that body from the lines
  below and runs what follows its terminator, which the guard does not model. Inside `$((...))`
  a `$(...)` is read as the commands bash runs there.
- **A Ctrl-C during a fresh run's first phase ends with the `interrupted:` status (#1805).**
  `orchestrate.loop` called `_first_run`, and the resume seam's `_run`, before its own `try`, so
  a Ctrl-C there escaped as a traceback and `_finish` never ran. Both calls now live inside the
  same `try`, so the loop's existing handlers cover them; nothing before `_first_run` changed.
- **One owner reads the committed config; errors refuse and disclosures print on both paths (#2229,
  #2189; ARC-1814846877, epic #1761).** Five readers each normalized the legacy `groups:` list form
  themselves -- `groups_schema.parse_groups`, `discovery.load_catalog`, `_committed_matrix`,
  `_declares_groups` (a DIFFERENT predicate: does any entry carry a name?) and
  `setup_flow.migrate_config` -- three re-implemented the leaf-vs-parent rule, and the two
  `_committed_exclude_paths` copies each printed the disclosure channel the other dropped, with
  docstrings citing each other wrongly. `groups_schema` owns all of it now
  (`normalize_groups_mapping`, `is_leaf_body`, `committed_bodies`) and every reader calls it.
  Per the owner ruling (2026-09-27) a document with `doc.errors` -- unreadable, no `version: 1`, a
  legacy-only tree -- RAISES on every reader instead of reading as "nothing committed" on some of
  them, and every reader prints `doc.disclosures`, so a refused symlink at the config path can no
  longer be visible on the setup path and silent on the run path. `_committed_matrix` is
  `_matrix_catalog` un-flattened rather than a second pass over the authored bodies, which is #2189:
  a scalar `match: src/**` used to become six one-character globs, a name the schema had just
  rejected came back anyway, and a non-mapping `groups:` value, a `match: [1]` or a `tests: [[a]]`
  crashed `driver setup` with an AttributeError and no JSON status. **Behaviour change:** a setup
  run over a config the schema rejects now refuses with the named error and writes no draft
  (`config_refusal`), where it used to merge against the authored bodies exactly as written --
  char-split globs, rejected names and all -- and tell the operator to move the result over their
  own file; a `driver run` still degrades per entry, one bad group at a time. `panels:`/`exclude:`
  come back from the validated domain sets, so a draft -- and `migrate-config`'s own output --
  renders them sorted rather than in authored order.
- **Every integrity failure that sinks certification is named on the terminal summary (#1761;
  ARC-3284703909).** The rule lived in three places with three memberships: `synth/integrity`
  published ~20 `meta.integrity` keys, `tool_axis.reconcile` re-spelled fourteen of them in a
  hand-written `or` chain, and `render_summary` named four — one of which deliberately does not
  gate. So ten of the fourteen sinking keys had no summary line of their own: nine were named
  nowhere on it, and one (`delta_scope_suppressed_git_drivers`) only inside `coverage_note`. The
  reasons went to stderr and the summary said the bare word `incomplete` — the hole #1644 closed
  for `tools_manifest_invalid` alone. The ten: `content_mismatched_files` (the #493 R4 tamper
  check — bytes that no longer match the fan-out snapshot), `content_snapshot_missing`,
  `content_snapshot_unreadable`, `malformed_findings_files`, `empty_dispatch_plans`,
  `invalid_dispatch_plans`, `invalid_verify_queue`, `dispatch_plan_missing`,
  `dispatch_plan_mismatched` and `delta_scope_suppressed_git_drivers`. One `INTEGRITY_KEYS` table
  in `synth/integrity` owns both facts: whether a truthy value sinks `integrity_ok`, and the
  operator sentence the summary prints for it. `reconcile` reads it as a comprehension,
  `render_summary` as one loop, so a key renders on exactly the truthiness that sinks the gate and
  the summary cannot drift from it again; a certification failure now outranks the non-gating
  cross-domain note, and the report schema's own property list is pinned to the table. The gate
  itself is unchanged — the sinking set is pinned key-by-key against the chain it replaced.
  `report.json` always carried the whole section; the HTML report is #2265.
- **spotbugs and pip-audit emit a repo-relative `location.file`, and the contract says so (#1768,
  #2188; ARC-284455831, ARC-2852754506).** SpotBugs nests a `SourceLine` inside the enclosing
  `<Class>` and another inside each `<Method>` before emitting the bug's own as a DIRECT child, so
  the `.//SourceLine` the adapter read was always the class's: on the pinned golden all three
  findings landed on line 11 of a class spanning 11-75 instead of 65, 69 and 66. It reads the bug's
  own now, falls back to the class's span only when the bug has none, and never a `<Method>`'s — a
  `role="METHOD_CALLED"` one names the CALLEE's file, a JDK source in no repository. The
  `sourcepath` beside it is relative to the SOURCE root (`org/dummy/App.java`), never the repo, so
  on a Maven or Gradle layout it matched no diff hunk and no read grant while the adapter's own
  comment claimed it stayed matchable; it is resolved against the target root by probing the
  conventional Maven/Gradle source roots — `src/main/java`, `src/test/java`, `src/main/kotlin`,
  `src/test/kotlin`, `src`, then the root itself — refusing an absolute or `..`
  sourcepath outright and refusing to follow a symlink out of the tree
  (`claim_scope.confined_to_root`, not a fourth copy of it). When nothing resolves the package path
  is kept and the finding says why in `tool_evidence.path_resolution`, so an unplaceable location
  has a stated cause. The `SourceLine start` that names the bug's line is read tolerantly with it:
  the report schema gives `location.line_start` `minimum: 1`, and SpotBugs' own unknown-line
  sentinel is `-1`, so one bug at an unknown line used to make a whole real Java report
  schema-invalid — absent, `-1`, `0` and an unparseable value now all clamp to 1, the way an
  unparseable rank already falls to MEDIUM rather than raising out of `parse` (which ingest reads as
  "unparseable" and loses the whole document). pip-audit stored the ABSOLUTE host path of the
  manifest it audited in its
  ContextVar and `_located_at` returns what it holds — unreachable on the production path, where
  invoke and parse run in different processes, and a scanner-host layout leak for any caller that
  shares one; it records the repo-relative path now, which is npm-audit's shape already. The
  normalization contract asserts a normalized relative `location.file` for EVERY adapter, with
  dependency-check's jar basename recorded as a disclosed debt naming #2225 — a debt, not an
  allowlist: the shape rule still holds it, and a self-liquidating test FAILS, saying to drop the
  entry, the day that adapter stops emitting a bare jar name.
- **No module is loaded twice, and the `sys.path` bootstrap gets a ceiling (#1766; ARC-188610019,
  ARC-2452079063, ARC-3214704952, ARC-11100703).** A driver-shaped process built two module
  objects from one file for NINE modules — `config_schema`, `coverage_model`, `diff_map`,
  `discovery`, `grouping_engine`, `groups_schema`, `model_resolver`, `plan_contract` and
  `repo_config` — each copy with its own module state and its own patch targets, so
  `dispatch.registration_model` ran on a `model_resolver` whose profile cache
  `mock.patch.object(scripts.model_resolver, …)` could not reach. `dispatch.py`,
  `setup_flow.py` and `grouping_engine.py` now import those siblings from the package, which
  retires four of the nine; the five that remain are the flat-import mode's own
  (`discovery.py` and `setup_proposal.py` must still import with only `skill/scripts` on the
  path) and are named, with their owner, in the new guard. `setup_flow.py`'s two CALL-time
  `import dispatch` statements went with them: each minted a second `dispatch`, with its own
  cached template loader, the first time a setup path ran. `synth/report.py`'s unreachable
  `except ModuleNotFoundError: from _version import __version__` arm is gone.
  `tests/test_module_identity.py` pins all four halves: the import-time census; a SHRINK-ONLY
  per-module ceiling on the `sys.path` write sites under `skill/scripts/` and `scripts/`, so a
  third insert inside an already-permitted module fails too, with each site reported against the
  root it adds (the flat root mints a second name; the `skill/` root is what grants the package
  one); the two `scripts` portions being name-disjoint; and no import fallback in a package
  module, keyed on a handler that imports and accepting `ImportError` alongside
  `ModuleNotFoundError`. A site that GOES AWAY fails a separate staleness test, not the ceiling —
  removing a bootstrap is the guard working. `tests/test_phases_child.py` pins the child
  PYTHONPATH contract by what a child can import rather than by the list of roots. Consolidation,
  including the call-time class the census cannot see, continues in #1516.
- **An interrupted or terminated driver ends its phase child and its runner children (#1805;
  COD-869076756).** A phase child (discovery, tools, synthesize) leads its own session, so the
  terminal's Ctrl-C never reached it, and `_run_child` ended its group only on a timeout: an
  interrupt waited out the 5 s reader join, then left the child running and writing into the run
  folder. A SIGTERM (a supervisor's stop, a CI cancel) killed the driver outright and left the
  phase child and every registered runner child running. `_run_child` now ends the group on any
  exception while its readers start or while it waits, and by the owner's ruling a SIGTERM takes
  the Ctrl-C path: the CLI runs `main` under `procgroup.sigterm_as_interrupt`, which raises it as
  the same interrupt and absorbs every later one until `main` returns; a SIGTERM that nothing
  handles prints `driver: stopped by SIGTERM` and exits 143 on every supported Python. The Kimi
  runner's SIGTERM secret-stripper now lets that interrupt run first and leaves the strip to
  `teardown`, after the children its `config.toml` guards are gone; it still strips before a
  default-disposition SIGTERM ends the process, and at an ignored one it no longer strips a run
  that carries on with entries still in flight (`teardown` or `atexit` strips it later).
- **A refused ledger recovery names the issue it could not read (#1805; COD-273223337).**
  Recovering the filed-issues ledger from GitHub refused the whole batch, anonymously, when a
  quoted marker block in one issue's own text tripped the check; `refusing:` now prefixes that
  issue's URL, and the exactly-once marker, source-report and location rules stay unchanged.
- **An empty `CODEX_HOME` means `~/.codex`; a relative one is refused (#1803; COD-1638371699).**
  `hosts.py` fell back to `~/.codex` only when `CODEX_HOME` was unset, so an empty value made the
  Codex registration directory `agents` and a relative one stayed relative, and every Codex consumer
  resolved it against the working directory -- in the documented flow, the reviewed tree. Under an
  empty value, a target shipping `agents/panopticon-*.toml` passed the runner's up-front check and
  supplied every role's `developer_instructions`; the codex probes inspected those shells, readiness
  called them registered, and `--emit-host-agents codex` wrote `agents/` into the working directory.
  Owner ruling 2026-09-27: empty means unset, and a relative value is refused with "CODEX_HOME must
  be an absolute path (it is 'rel/home'); unset it to use ~/.codex" -- by the runner and its shell
  loader, both codex probes, emission (exit 1, nothing written) and the readiness row. An explicit
  directory still wins, and importing `hosts` never raises.
- **One parser for the `findings-<group>-<domain>` cell identity (#1765, ARC-3899903550).** Four
  modules read that name independently and disagreed at the edges: `findings_contract.cell_of` did
  not validate the domain, `synth/coverage_io.present_cells` and
  `synth/integrity._expected_from_filename` did, and `synth/findings.GROUP_RE` also accepted the
  4.x panel names and their retired `-panel_review` / `-lens_sweep-<lens>` suffixes. On an
  off-roster or mistyped domain -- `findings-App-XYZ.json` -- ingest stamped no `_group`, the
  mislabel guard said "nothing wrong", the floor audit could not see the cell, and the defect
  diagnostic claimed a cell for it anyway: every branch failed toward invisible, in four different
  directions. `cell_of` now validates the trailing token against `groups_schema.DOMAINS` and owns
  the parse; the other three call it, and so does `synth/plan.out_of_scope_findings`. The 4.x
  alternation is DROPPED rather than moved into it: the roles retired in #1441, `plan_contract`
  pins every reviewer `out_file` to `findings-<group>-<domain>.json`, and nothing in the 5.x
  pipeline can produce the old spelling. A file whose trailing token is no domain code now names no
  cell: one whose PAYLOAD was rejected is still named without a cell
  (`malformed_findings_files`), and one that parses cleanly is surfaced by
  `unexpected_findings_files` wherever a dispatch plan exists.
- **Setup's flat seed drops the group names a run would refuse (#1788; COD-2612640453).**
  The vocabulary-absent fallback kept every name `parse_groups` returned, even one it only flags
  as an error: a case twin, a chunk twin, or the reserved `Ungrouped` sink. `groups_schema` now
  exposes `colliding_ids`, and the seed drops those names too.
- **`defang` neutralises issue references and URLs in every form GitHub links (#1793;
  COD-3436467706).** `GH-N` links in any letter case beside `/`, `-` or `.`, and `#N`
  shares its "before" boundary: no ASCII letter, digit or underscore immediately
  precedes either, and no word character follows `GH-N`'s number. `http(s)://` links
  unless an ASCII letter (not a digit or underscore) sits right before the scheme. Case
  insensitivity no longer folds those ASCII checks, and the `GH-N` substitution keeps the
  matched text's own letters, as the `http(s)://` one already did.
- **The Kimi probes report a hung doctor, a failing home writer and a malformed config (#1788;
  COD-2149752625).** Three posture probes on `--host kimi` let an exception escape where their
  siblings already turn it into a reported state: `_kimi_home_arms_and_validates` caught only
  `OSError` around `kimi doctor`, so a doctor that outlives its timeout or writes output that
  does not decode escaped as a traceback; `_kimi_hooks_are_armed` caught only
  `(OSError, RuntimeError)` around the per-run home writer, so a `ValueError` or `TypeError` from
  it escaped too; and `probe_kimi_model_alias` let a malformed or unreadable operator
  `config.toml` escape the same way. All three now report instead of raising, and the writer's
  exception tuple is defined once (`kimi_snapshot._HOME_WRITER_EXCEPTIONS`) so the two probes
  that drive it cannot drift apart again.
- **A sentence-final file name reaches the backup's evidence closure (#1793; COD-148287761).**
  `evidence_scope._PATH_RE` vetoed a sentence-final `.` like any other path character, so a claim
  naming a file only at a sentence's end never reached the closure. A `.` now ends a name unless
  another path character follows, so `grading.py.bak` and `notafile.python` still yield nothing.
- **The category-to-CWE table holds only overrides the catalog can deliver (#1795;
  COD-4238512708).** `config`, `logging` and `headers` named CWE ids `cwe-catalog.json` never
  carried, so those three entries never derived a citation and dropping them changes no output.
  A new test now pins every remaining entry in `CATEGORY_CWE_OVERRIDES` to the catalog.
- **One owner for the persisted retry budgets (#1767, ARC-655791509).** Five phase modules
  hand-copied the same read-bump-write over a counter file under `.panopticon/` in the reviewed
  tree, and the #1809 round consolidated only the READ -- `runio._load_state_json` refuses a
  present-but-torn document -- so the arithmetic on top of it kept THREE answers to the same
  planted value. `coverage._bump_scout_attempts`, `discovery._bump_discovery_attempts` and
  `verify._bump_verify_attempts` raised a bare `ValueError` out of `int()`, a message an operator
  cannot act on where the read one line away would have named the file and `--reset`;
  `review._record_attempts` RESET the cell's tally to 1, refunding every attempt the run really
  spent, which is the one outcome #1809 says the ledger exists to prevent; and
  `persist._give_back_attempts` silently `continue`d, which made a planted value
  indistinguishable from a key nothing had ever charged. The new `phases/budget.py` owns the
  arithmetic -- `count` / `bump` / `bump_many` / `give_back` -- and answers all three the same
  way: a value that is not a non-negative `int` (`bool` excluded, since `isinstance(True, int)`
  is True) is UNREADABLE exactly like a torn document, and refuses with the same actionable
  shape, naming the file, the offending key and `--reset`. Never a reset, never a skip. Each
  caller keeps its own file name, key scheme and description, because those are the on-disk
  contract a RESUMED run reads back; reads still go through `runio._load_state_json` and writes
  through `runio._write_json`, so the symlink refusal at an artifact path is not re-implemented
  behind the new names. `review._cell_exhausted` was the sixth site and the quietest: an
  unreadable value read as "not exhausted" made a spent cell dispatchable again, silently.
- **`ci.yml` states its token posture instead of inheriting one (#1784, ARC-3955973987).**
  `tests/test_workflow_pins.py`'s `privilege_defect` asserts the posture the three `ci.yml` install
  exemptions are written against -- unprivileged trigger, read-only token -- but it read an ABSENT
  `permissions:` block as unprivileged, because a block that does not exist grants no `write` scope.
  So "the default read-only token" in those exemptions meant the repository's `GITHUB_TOKEN`
  setting: not in this tree, not reviewable in a PR, and one settings change away from a write token
  that would keep four unpinned installs exempt. A job with no `permissions:` of its own and no
  workflow-level block to inherit is now a defect naming that job; a block at either level satisfies
  it, which is how `codeql.yml`, `nvd-cache.yml`, `security.yml` and `docker-publish.yml` already
  stood. `ci.yml` and `docker-build-pr.yml`, the only two files that declared nothing, now carry a
  top-level `permissions: contents: read` -- neither pushes, logs in to a registry, nor publishes.
- **A zero-hunk active delta gate reads INCONCLUSIVE, not PASS (#2178; refs #1783).**
  #1783 disclosed the shape on stderr and left the policy open. A diff-hunks artifact that resolves
  a base but carries no diff ranges keeps the delta ACTIVE while matching nothing, so under the
  default `--gate-scope on-diff` the gate's source set is not a measured diff, and a change
  carrying active findings reported a green `PASS` on findings that were never gated.
  OWNER RULING 2026-09-27: refuse to certify. `summary.gate` now reads `INCONCLUSIVE` and
  `summary.coverage_note` names the zero-hunk map plus the remedy (regenerate the diff-hunks
  artifact; the driver's discovery phase writes it) -- or names the REJECTED payload instead, when
  that is why the map is empty, rather than sending the operator to compare a known-broken artifact
  against itself. Two carve-outs are part of the ruling: an empty legitimate change with NO active
  findings still passes, and falling back to the wider scope was REJECTED, because a benign empty
  `--changes` run would then go red on pre-existing findings it did not introduce. `ranges == 0` is
  the measure, not `files == 0`: a map that names a file and gives it no range scopes the gate by
  `diff_map.classify`'s two FAIL-OPEN arms, which is not a measured diff either.
  `delta.zero_hunk_gate_gap` is the one place that decides whether there is a gap, and `certify`'s
  new `delta_zero_hunks` reason joins `gate_relevant_gap` -- so a real FAIL and an armed-but-OFF
  gate are untouched, and `coverage_certified` is false either way. No new report key: the reason
  rides the existing certification note, placed after the unreadable-manifest note (which names a
  broken file) and before every other caveat, since an empty gate scope invalidates the gate
  wholesale.
- **One tested reader for the Dockerfile's dependency-check pins (#1774, ARC-261650949).**
  `docker-publish.yml`'s "Resolve NVD data image digest (content-pin the cache)" step and
  `nvd-cache.yml`'s "Read dependency-check version from the Dockerfile" step each re-derived
  `DEPENDENCY_CHECK_VERSION` -- and one of them `DEPENDENCY_CHECK_SHA256` -- with its own
  `grep | head -1 | cut -d= -f2` and its own inline shape check. Both now call `python3
  scripts/dockerfile_args.py read-arg <NAME>`. The shape checks MOVED there, they were not
  dropped: the module is a closed map of ARG name to anchored pattern, it refuses a name with
  no registered shape, and it exits 2 so `set -euo pipefail` still fails the step -- the
  control nvd-cache.yml described as "constrain to expected shapes so a tampered ARG can't
  inject downstream". The version shape is STRICTER than the grep it replaces, which also
  accepted `10.0.3.` and `1..2`, and a value carrying a second `=` is now refused rather than
  truncated to the part before it. `tests/test_dockerfile_args.py` covers the reader, both
  callers, and the committed Dockerfile's own two pins.
- **One owner decides which evidence statuses count as verified (#1774; ARC-3073755386).**
  `html_report` derived it twice, differently. `_render_header` counted an INCLUSION of two statuses
  (`tool_confirmed` + `advisor_confirmed`) while `_render_findings` split the tabs on an EXCLUSION
  of three (`tool_reported`, `needs_more_info`, `unverified`), so five of the ten possible inputs
  fell on one side of the word in the header and the other side in the tabs -- and the exclusion
  form failed OPEN: a status added to `evidence.EVIDENCE_STATUSES` later would have joined the main
  list silently. Both vocabularies are now closed sets in the new
  `skill/scripts/evidence_sections.py`, which partitions `EVIDENCE_STATUSES` and raises at import if
  it ever stops doing so, the way `score_gate.EVIDENCE_FACTOR` already did. They answer two
  different questions, so neither is the other's complement: `VERIFIED_STATUSES` is the header's
  WORD -- a second opinion agreed, which is why `backup_scope_limited` is not in it (#1638 P16) and
  keeps its own disclosed segment -- and `UNVERIFIED_STATUSES` is the report's SPLIT, what the
  collapsed "Unverified findings" section holds. `corroborated`, `rejected` and
  `backup_scope_limited` are the named remainder that stays in the main severity tabs; `rejected`
  cannot reach them anyway, because `synth/report.py` publishes `resolve_findings`'s `active` list
  as `findings` and the rejected half goes to `discarded_claims` and its own section. **Nothing
  moves for the eight known statuses**: both rules were run over each of them and agree, the
  header's count is the same sum of the same two keys, and
  `test_the_eight_known_statuses_do_not_move` pins that table. What changes is the tenth input -- a
  finding whose `evidence.status` is unknown or missing now lands in the "Unverified findings"
  section instead of the main list, disclosed rather than read as reviewed. The sets live in their
  own module rather than in `evidence.py` because that module and `html_report.py` are both pinned
  at their exact current size by the shrink-only ratchet in `tests/test_flat_module_ceiling.py`,
  whose stated remedy for a module that needs room is a new module; `html_report.py` came down two
  lines and its pin came down with it.
- **Give the issue-ledger default one owner (#1821).** Reconciliation now obtains its default
  ledger path from `file_issues.LEDGER`, matching the loader it already shares. Recovery writes
  and the plan CLI keep the same default, and explicit ledger paths behave as before.
- **Use one owner for runner and adapter vocabulary (#1821).** The loop, Codex preparation
  and session instructions share the runner's setup namespace. Brakeman applicability uses the
  same Rails markers as staging. The Semgrep smoke scan reads the production adapter command
  when invoked and substitutes only its fixture target, so adapter flag changes reach the smoke
  check automatically. Existing setup behavior, scanner arguments and security modes are retained.
- **Bound synthesis run metadata before JSON parsing (#1820, #1825).** A shared reader
  limits ordinary run artifacts to 16 MiB and keeps coverage records at their existing 1 MiB
  limit. It refuses final-component symlinks and nonregular files without waiting for a FIFO
  writer, and turns JSON recursion/memory failures into the caller's normal unreadable-input
  path. Strict metadata and tolerant agent-envelope parsing keep their existing formats.
  Callers retain their shape checks, fallback values and invalid-artifact disclosures; an
  unreadable manifest or verify queue cannot become an absent one. Parent-directory aliases
  such as macOS `/var` remain supported. This supplies the shared reader requested by #2081
  and #2082; changing the existing coverage-skip certification policy remains #2080.
- **Align implementation documentation with the current contracts (#1819).** Kimi preparation
  always creates a fresh home, including on resume; the recorded pointer is informational.
  Report grades use health when available and display n/a without reviewed lines to grade; the
  gate keeps its own policy. Repair documentation names the boundaries and distinguishes content
  bounds from byte limits at the caller. These changes affect comments and docstrings only.
- **`file_fixmes.parse` refuses a heading or a rule it cannot parse (#1765, ARC-4143722514).**
  `HEAD_RE` requires an em dash, so `## FIXME-3 - title` did not match it, and with a section open
  the line was appended to the PREVIOUS FIXME's body -- one issue silently lost, another silently
  doubled; a `---` inside a body closed the section and dropped the rest of it. Neither case said
  anything, and these sections become GitHub issues out of a hand-written doc, so input the parser
  could not read became wrong issues. A second regex, `HEAD_LIKE_RE` ("looks like a FIXME
  heading"), now makes the disagreement loud: a line it matches while `HEAD_RE` does not raises
  `ValueError` naming the line of the doc, its text, and the required `## FIXME-<n> — <title>`
  form. A rule while a section is open raises only when body text sits between it and the next
  heading-like line, which is what makes that rule INSIDE the body; a rule followed by blank lines
  and the next heading is a separator and closes the section, and the trailing rule that ends the
  list -- the documented behaviour -- still stops the parse there and leaves the 'Already fixed'
  commentary unfiled. `main` parses before it loads the ledger or reads the `gh` environment, so a
  refusal precedes every GitHub call (now pinned by a test), and no doc under `docs/` or
  `skill/docs/` mentions this script.
- **A whole-file finding no longer has to invent a line number (#1784; ARC-2002725967).**
  `skill/reference/findings-envelope-schema.json` required `location.line_start` on BOTH of its
  finding definitions (`legacyPanelFinding`, `domainRoleFinding`), while the published
  `report-schema.json` requires only `file` there and says in that `location`'s own description
  (#1522) that a whole-file finding -- a missing header, a bad config -- is legitimate and must
  not have a line number invented for it. The envelope is the stricter of the two AND the one
  that governs emission: `phases/persist.py`'s `ROLE_SCHEMAS` maps the `review-cell` role to it,
  `role_schema` hands it to the runner as the CLI's output schema, and
  `ENVELOPE_SHAPES`/`RETRY_PROMPT_BLOCK` re-prompt a refused reply. So on a host whose CLI
  enforces that schema (claude, codex) a legitimate whole-file finding was either refused or
  re-emitted with a fabricated line, in a pipeline whose premise is that evidence is not
  invented. Both `required` lists are now `["file"]`, and `line_start` keeps
  `{"type": "integer", "minimum": 1}` so an invented `0` -- or a string -- still fails. Nothing
  downstream needed changing: `synth/findings.py` already DROPS a `line_start` a finding does not
  carry rather than filling one in, and every other consumer reads it through `.get`. Two
  residuals are disclosed, not fixed, here (follow-up #2174): `synth/report.py` still WARNs
  `missing location.file/line_start` on the now-sanctioned whole-file finding until that check
  is split, and the envelope still requires `location` itself while the report schema does not,
  so a locus-free catalog-gap finding is still refused. `skill/agents/domain-panel.md` now tells
  the reviewer to omit `line_start`/`line_end` entirely (not `null`) for a whole-file finding
  rather than invent one, and the new `test_envelope_location_required_matches_report` pins each
  envelope `location` `required` set to the report schema's, extending #1602's parity guard
  (`tests/test_schema_parity.py`, report vs schema) to the emission envelope.
- **`collect_usage` counts the input it drops, and the summary line says so (#1782,
  ARC-2134807886).** Three drops were silent: `_iter_records` returned on an `OSError` (an
  unreadable transcript yielded nothing at all, and `collect`'s `if not n: continue` then did not
  even count it), it skipped a line `json.loads` rejected, and `_add` ignored a usage value that
  was not an `int` -- so `total` read as authoritative while being a floor, the one thing the
  module docstring promises against ("an absent number stays absent rather than becoming a
  fabricated zero"). `sources` already held the channel and the precedent:
  `subagent_transcripts_truncated` (#1576) is the number that keeps the rest of the document honest
  when the cap binds. Three counters join it, always present and 0 on a clean run.
  `unreadable_transcripts` counts the FILE once, controller or subagent, and deliberately does NOT
  fold into `subagent_transcripts`: that count has to keep re-summing to
  `subagent_transcripts_by_phase` and to the transcripts actually summed, and an unreadable file
  contributed no record to either. `undecodable_lines` counts each torn line, once per file rather
  than once per read -- `classify_transcript` re-reads a subagent transcript for its first prompt
  and is not given the accounting dict. `non_integer_usage_fields` counts each present-but-not-int
  value, a `bool` included: `bool` is an `int` subclass, so `"output_tokens": true` used to pass the
  isinstance check and add one fabricated token, and it now adds none. An ABSENT field is still not
  a drop. The counts surface in `sources`, and so in the report's `meta.cost.tokens.sources`.
  `main` also prints ONE stderr line naming all three when any is non-zero, before the document is
  written or dumped; a clean run prints nothing new. That line reaches a terminal on a DIRECT run
  of the script: synthesize captures the collector's stderr and reads only its exit code -- #1576's
  own FLOOR line is swallowed the same way -- so on the wired path `sources` is the half that
  reaches an operator (follow-up #2171). No schema change was needed: `meta.cost.tokens` is an
  unconstrained object in `report-schema.json` and `load_run_usage` surfaces the document verbatim.
- **A malformed or empty diff-hunks payload is disclosed, not swallowed (#1783; ARC-2340795244).**
  `synth/delta.py`'s loader is total by design -- an unreadable or non-object `diff-hunks.json`
  yields `{}`, a non-object `hunks` becomes `{}`, and every range that is not a two-integer pair is
  dropped -- and it said none of that anywhere. The consequence is asymmetric. A payload with no
  `base` degrades to a full-repo review, which is the WIDER gate; a payload WITH a base and an
  empty hunk map stays an ACTIVE delta that matches no finding at all, so every finding classifies
  off-diff, `--gate-scope on-diff` scopes the gate to that empty set, and a change with findings
  reports a green gate -- indistinguishable from a genuinely empty diff, over an artifact the
  driver hands synthesize on file existence alone, from a fixed path inside the reviewed tree's own
  `.panopticon/`. The loader now returns a `HunksLoad` beside its data (the old name delegates to
  it, so every caller is unchanged), and `from_args` prints in the #957 register: the rejection
  reason with the path, a ZERO HUNKS warning naming what that costs the gate and how to tell an
  empty change from a broken artifact, and a count of the ranges dropped. The warning distinguishes
  the two shapes zero ranges can take, because `diff_map.classify` fails OPEN for a lined finding
  in a file the map NAMES without a range. `meta.coverage.delta` carries the same four facts --
  `hunks_files`, `hunks_ranges`, `ranges_dropped`, `payload_malformed` -- whenever the payload
  resolved a `base`, with `files_changed` left as the artifact's own claim beside the map actually
  classified against; a payload rejected outright leaves the review non-delta and that block null,
  so there only stderr carries it. The gate's scoping RULE is untouched: this is disclosure, and
  what an empty on-diff gate should DO is a policy call.
- **`dispatch.js` refuses an entry marked enforced that names no registered shell (#1783,
  ARC-204863095).** The session-mode Workflow script validated each entry's `id`, `marker` and
  `prompt_file`, then branched on `e.enforced && e.agent` -- so an entry carrying `enforced: true`
  with a missing or empty `agent` fell through to the UNENFORCED branch in silence: no registered
  `panopticon-*` shell, no host-enforced tool grant, no log line, while the request on disk still
  recorded that entry's launch shape as enforced. The driver holds the same rule one level up
  (`loop_batch.refuse_misrouted` refuses a request whose enforced entry does not name the shell its
  output role and checkpoint expect), so the reachable path was a session hand-copying the request's
  entries into `args.entries` -- exactly the reduction the script's own header asks for. The
  validation loop now refuses such an entry in the register of `loop_batch.misroute_refusal`, and it
  refuses THERE rather than in the dispatch loop: an integrity refusal must not leave a batch half
  launched, so no `agent()` call is made for any entry in it. No production path emits such an entry
  (all five request builders set `agent` to the registered name exactly when the entry is enforced),
  so the refusal costs no real request. The pin that had recorded the old fall-through as behaviour
  now pins the refusal, beside an empty-`agent` case and a two-entry case proving the good entry
  ahead of the bad one never launched.
- **The Kimi guard hooks run the driver's own interpreter, and `prepare` refuses one that cannot
  start (#1777; ARC-1774133676).** Both PreToolUse hooks in the per-run `config.toml` named the bare
  word `python3`, and nothing resolved it: the CHILD looks that name up in its own PATH, and the
  launcher rewrites PATH -- `runners/children.py` sanitizes the startup environment and then sets it
  from `executable.resolve`, which drops every entry inside the review root. An operator whose
  `python3` came from the reviewed repo's own `.venv/bin` therefore armed two hooks with a name the
  child resolves differently, or not at all, and a Kimi hook that does not start fails OPEN: read
  and write confinement silently unarmed -- the exact residual the runner's own C3 comment named
  while checking only the guard SCRIPT. The interpreter is `sys.executable` now (this process,
  chosen by neither PATH nor the target -- the binding `read_guard_hook` and `codex_host` already
  use), armed as its `realpath` so a venv symlink resolves to the binary that actually runs and the
  reviewed tree's own `site-packages` never joins the guard's `sys.path`; an empty, relative or
  unrunnable one is REFUSED rather than swapped back for a bare name. One function asks that whole
  question and returns the path it validated, so what was checked
  is what the hooks are armed with; `KimiRunner.prepare` asks it, with the guard script's presence,
  before any child launches, and the two probes that build the same home report the refusal instead
  of ending posture establishment in a traceback. Pinned with PATH emptied, so no `python3` shim on
  the machine running the suite can stand in for the name the child could not resolve, and with the
  interpreter path's own quoting -- it is interpolated into a shell string too, and one under a
  directory with a space in it is ordinary. What remains is stated where it was: a hook can still
  die for a reason no pre-flight sees (script or interpreter replaced mid-run, an exec that fails
  under load, an adjudication past the hook's 30-second timeout), so the shells' tool allowlists
  stay the primary control.
- **The scrub funnel binds a deterministic repo root, and reconcile's comments go through it
  (#1777 ARC-1735086130, #1780 ARC-163067013).** `sanitize._detect_repo_root` fell back to
  `os.getcwd()` and nothing refused a degenerate root. Probed with an empty PATH at `/`, `scrub()`
  deleted every `/` in the text it was handed (the literal `str.replace`), `re.escape("")` left the
  second substitution an empty-match pattern, and `repo_relative` ate the leading slash. The mirror
  is worse: a filer run from another checkout gets a prefix that strips nothing, so the operator's
  absolute paths land in a public, permanent issue, which is the one thing that module exists to
  prevent. Both detection branches now go through one normaliser that REFUSES a filesystem root, a
  non-absolute root and a root that is not an existing directory, and returns a realpath'd prefix
  (realpath normalises an operator-supplied LOGICAL root to the physical form locations carry;
  measured here, `git rev-parse --show-toplevel` and `os.getcwd()` both report the physical path
  already, so it is a no-op on the two detection branches and defence should a git report a logical
  one). `scrub`/`repo_relative` take an explicit `root=` that REPLACES the detected root, normalised
  and refused alike but with its own remedy, since a caller who passed a root cannot act on "pass
  the root explicitly"; the cached detection stays the default, so no filer changes a call. That
  determinism is what the second half needs. The module header claimed `scrub()` is the one point
  every filer shares, but `reconcile_apply._comment_body` posted `action["comment"]` with only
  `neutralize`'s markdown pass -- no path stripping, no redaction -- while the `reason` it
  interpolates is built from report locations that `_source_records` proves can be absolute. The
  comment is now scrubbed BEFORE the `<!-- panopticon-reconcile:KEY -->` marker is appended, so the
  marker (keyed on the raw action, so no receipt is rebound) survives byte-for-byte and
  `_comment_present`, which compares the FULL body on the resume path, reconciles against the
  scrubbed body that was posted. A body that cannot be reproduced is still refused, but the refusal
  now names the likely cause: a comment posted from a different repo root.
- **The fixture runner's two containers launch under `run_tools`' container policy (#1767;
  ARC-3859414366).** `run_tools` owns that policy and its docstrings said so: cap-drop,
  no-new-privileges and the memory/CPU/pids ceilings "applied to every tool/adapter container".
  `run_fixture_tests.py` imported no part of it, so the two could not agree by construction -- and
  the container that runs the whole adapter suite on a developer machine launched with none of them:
  the real scanners over live attacker-shaped inputs (a planted `eslint.config.js` and a shadow
  `node_modules` plugin eslint must refuse to load, a planted `.gitleaks.toml` rule set and a
  `GITLEAKS_CONFIG` hijack gitleaks must ignore) plus the dotnet/MSBuild and JVM toolchains over the
  baked goat trees. The `hostile-csproj` corpus is baked into that image too, but its build is
  opt-in under `PANOPTICON_CONTAINMENT_PROBE=1`, which only the containment lane sets, so
  `evil.csproj`'s `curl` target does not fire on this path. The fixture-presence probe beside it had
  no `--network none` either. The two helpers carry public names now (`privilege_drop_flags`,
  `resource_limit_flags`; the underscore spellings stay identity aliases, so no call site moved) and
  the fixture runner splices both lists into both `docker run` argvs, plus `--network none` on the
  probe. Pinned as parity rather than resemblance: the flags between `run --rm` and the rest of the
  argv are exactly what `run_tools` returns, and one test retunes a ceiling inside `run_tools` and
  watches both launches follow -- a copy passes a spot-check and then drifts. The envelope's failure
  modes now name themselves instead of arriving as a bare number: the probe quotes docker's refusal
  when the daemon rejects a ceiling, rc 137 is reported as the memory ceiling's OOM kill, and rc 124
  as a timeout with the CPU throttle named as the likely cause. What this cannot prove: Docker is
  out of
  reach in the fixing session, and the daily `adapter-integration` workflow runs its own
  `docker run` rather than this script, so the first local `run_fixture_tests.py` is the end-to-end
  check. The ceilings are the ones these same scanners already run under (6g memory, 4 CPUs, 1024
  pids), and all three stay retunable through `PANOPTICON_TOOL_MEMORY` / `_CPUS` / `_PIDS`, an empty
  value dropping that ceiling -- which the fixtures guide now records beside the command.
- **The CLI advisor renderer confines claim locations and pins the review root (#1767, run-14
  ARC-3314534783).** Advisor-prompt assembly existed twice. The driver's two advisor rounds rewrite
  an escaping `location.file` to a redaction marker and pin `Repo root: <review_root>` before
  rendering `advisor.md` (#run8 ARC-F2A); `dispatch.render_advisor_prompts` -- reachable as
  `--render-advisor QUEUE`, and documented -- did neither: the finding went into the claim JSON
  VERBATIM and the root pinned was `os.getcwd()`. An advisor's Read/Grep/Glob are unconfined, so a
  redteam target whose planted `location.file` is `../../../.ssh/id_rsa` steered this path straight
  out of the review tree, on the exact channel the project had already ruled closed. Both halves now
  live in one stdlib-only leaf, `skill/scripts/claim_scope.py`, reached from both sides: the
  confinement predicate moved DOWN out of `phases/runio`, because a leaf is the only module
  `dispatch` and `phases/*` can share -- `runners/*` import `dispatch`, and layout rule 3 forbids
  them from reaching the phases package -- and `runio._confined_to_root` /
  `verify_tools._confine_claim_location` keep their names as aliases whose identity a new test pins,
  so a second implementation cannot reappear behind either. The renderer takes `--review-root` and
  otherwise resolves the root from the queue's own `.panopticon` path, REFUSING when it cannot
  (a wrong root points the advisor at another checkout, which is what the cwd fallback did). The
  driver's own prompts are byte-identical, pin paragraph included.
- **One spelling of the read-scope keys, and the guard hooks' read-scope copies pinned (#1767;
  ARC-1784455652, ARC-2812051140).** The read guards are three deliberate copies of one rule, and
  each of the three runs with no package on sys.path -- the hooks because a hook is invoked by
  absolute path, as its own process, the broker because it is launched `-I`. None of them can
  import a sibling. But only the BINDING half of that copy was pinned, and the read-scope half had
  already drifted in logic. `kimi_guard_hook._load_scope` looped over an inline literal of the
  four scope keys while `read_guard_hook` looped over its `SCOPE_KEYS` constant, so a fifth key
  added to the read guard would have been honoured by Claude's hook and silently ignored by
  Kimi's: one entry, confined two ways. Kimi's loader now reads a `SCOPE_KEYS` of its own, and a
  new parity class pins all seven read-scope helpers plus both constants AST-identical, docstrings
  stripped (each copy explains itself where it stands; prose is what a copy may differ in, code is
  not). That net also caught the one place the Codex broker's `_under` answered a grant
  differently from the hooks': with `/` as a directory grant, `rstrip(os.sep)` left "" and every
  absolute path was admitted, where the hooks' `or os.sep` reads a `/` grant as the root directory
  ALONE. The broker takes the hooks' edge. Two residuals close with it: the write guard's atomic
  writer has a public `atomic_write_json` (the underscore spelling stays an alias, and a source
  pin keeps `runners/batch.py` off the private surface) so a package module no longer reaches into
  a hook script's private function, and a measured flags pin now holds the writers that spell the
  no-follow open by hand -- the three stage-and-rename writers (the two guard hooks' and
  `runners/kimi_home`'s) and `safe_write`'s artifact pair -- with `O_NOFOLLOW` on every one, the
  three stagers identical at mode 0o600, and the artifact pair differing only in the two ways
  that were decided.
- **The codex enforcement shells are encoded by the shared TOML encoder (#1763, run-14
  ARC-981076646).** `emit_host_agents`'s codex branch flattened its policy with a nested
  `emit_values` that spelled every value with a bare `json.dumps` and carried its own copy of the
  bare-key regex, duplicating `skill/scripts/toml_values.py` -- the encoder `codex_host` and
  `kimi_toml` both already go out through. `json.dumps` defaults to ASCII mode, which writes a
  non-BMP character as a surrogate pair, invalid in TOML: one emoji in a template `description`
  registered a shell `tomllib`, and codex's own parser, refuses ("Escaped character is not a
  Unicode scalar value"), and a lone surrogate went out escaped instead of refused. The three
  inputs -- a template description, the codex charter, the resolved model -- are ASCII today, so
  nothing had fired yet. Emission now calls `toml_values.key` / `toml_values.value`, the
  flattener's nested-table-to-dotted-key shape is untouched, and a new test re-emits every ASCII
  role's file through the old flattener and demands the same lines back.
- **The TST global floor now recognises the test-file suffix conventions discovery already
  knows (#1770; run-14 ARC-3682668884).** `coverage_model._TEST_FILE_HINTS` gated the TST floor
  on substring hints -- `.test.`, `/tests/`, `test_` -- and knew none of the SUFFIX conventions
  `discovery.TEST_PATTERNS` has always matched: `AppTest.java`, `AccountTests.cs`,
  `AuthTest.php`, `app_tests.py`. So a flat Java layout and every standard C# or PHP repo drew
  no guaranteed TST cell, while the floor's own docstring promised the opposite -- that a
  mis-reporting scout "cannot suppress a floor domain whose surface objectively exists". For
  three languages it could. `applicable_global_floor`'s TST signal is now the UNION of
  `discovery.is_test_file` and the hints: the hints stay, because they cover the plumbing the
  naming rule misses (`conftest`, a `/tests/` corpus, `.feature`), and the union ends the drift
  between two independent derivations of "is this a test file" -- a convention added to
  `TEST_PATTERNS` floors TST from then on, and a parity meta-test fails if one arrives without
  a fixture. The behavioural ratchet on this repo is nil: every group in the committed
  `panopticon.yml` matrix, and both chunks of the residual sink, already had a TST floor cell.
- **The adapter-integration lanes run as the user production scans run as (#1771, ARC-2930403871).**
  `Dockerfile.fixtures` ends on `USER root` -- right for its build, which installs toolchains and
  writes build artifacts -- and the daily workflow passed no `--user`, so the one gate where the
  adapters meet real tools and real fixtures proved them as uid 0 while every production scan runs
  the tools image as `scanner` (its `useradd -m -u 1000 scanner`, then its closing `USER scanner`).
  A root-only adapter regression, the #1877 class, passed the only gate that could catch it. Both
  jobs now pass `--user scanner` with production's `HOME`, and each asserts `id -u` inside the
  container before running a probe. `Dockerfile.fixtures` says that build-time root is not a runtime
  posture and that the image is no longer local-only; it moves the .NET package cache out of root's
  0700 HOME (`NUGET_PACKAGES`, then `a+rX`) so `project.assets.json` names a path uid 1000 can read;
  and it hands `scanner` back the four cargo subtrees this build dirties as root -- `registry`,
  `git`, `.package-cache`, `.global-cache` -- leaving the RustSec `advisory-db` beside them
  root-owned and read-only, which is what the scan needs and all it needs.
- **The 700-line ceiling now covers the flat modules and the entry scripts (#1761, #1762,
  #1763; run-14 ARC-2609514778).** `tests/test_layout.py` rule 5 ratchets only the `synth`,
  `phases`, `runners` and `probes` packages, so the largest modules in the tree were the
  unmeasured ones: `skill/scripts/run_tools.py` went from 1231 to 2215 lines in the six days
  after that finding was written, because every new scanner policy landed there and nothing
  pushed back. `tests/test_flat_module_ceiling.py` applies the same `LINE_CEILING` to every
  `*.py` directly under `skill/scripts/`, the repo-root `scripts` directory and the `tools`
  adapter package (which rule 5 does not name either), as a shrink-only allowlist: twenty
  modules pinned at the count they have today, each free to shrink and never to grow, and a pin
  that reaches the ceiling has to go. Raising a number is not a fix -- the allowlist is the list
  of splits owed.

- **Requirement hash refreshes preserve extras and environment markers (#1847).** The updater
  replaces hash options while retaining the requirement clause and comments, and requests
  artifact hashes for the base distribution. Root configuration also requires integer
  `version: 1`; YAML `1.0` is refused with the existing version diagnostic. Reconciliation
  rejects boolean `schema_version` values before action planning.

- **The seven residuals this SEC round re-found are written down where each is decided (#1831,
  #1836, #1838, #1839; run-14 SEC-3334394305, SEC-589720899, SEC-882922343, SEC-1915770944,
  SEC-136999130, SEC-3084426934, SEC-2589722723).** All seven are BY DESIGN and the sentences
  describing them were false, in four places. `workflow_guard`'s pin-rule rationale claimed the
  image a `docker run` step executes is pinned by digest elsewhere; it is not -- every workflow
  that consumes it pulls the tools image by its mutable `:latest` tag, which is the residual
  DEVELOPMENT.md already accepts -- and the same claim one level out in `scripts/workflow_forms.py`
  went with it. DEVELOPMENT.md itself said "weekly rebuild" in one place and "monthly" in another
  about an image CI republishes nightly. The rest state the decision where it lives: the floating
  .NET SDK channel joins the Dockerfile's own list of the inputs its hash closure does not cover;
  the report's exclusion line and schema say those globs prune review CELLS, not just the tool
  axis; `family-pr-review.js` says its finders and refuters are unconfined by design, and now
  `JSON.stringify`s the three finding strings `evidence` already went through; and the readiness
  remedy's mutable pull gains the `gh attestation verify` step an operator can take, in the guide,
  the README and GETTING-STARTED. One test was owed and is here: `evil.csproj` must hold exactly
  one target, hooked to `Build` and nothing else, or its `curl` fires on the networked
  fixtures-image builder.
- **Malformed Kimi usage records remain unknown data (#1847).** Invalid counters are skipped
  as a whole record while adjacent valid turns still count. Wire lookup rejects non-string,
  traversal and glob identifiers. Runner refusal diagnostics redact credentials before taking
  their 200-character excerpt, including credentials crossing that boundary (#1853).
- **Gitleaks root ignore file follows the scan mode (#1924).** In `standard`, a
  repository's regular `.gitleaksignore` is honoured. In `redteam`, an existing
  regular file is covered by a scanner-owned empty file mounted read-only at
  `/src/.gitleaksignore`; an absent file needs no mount. The staged file is 0644,
  its private directory stays 0700, and the target is unchanged. A symlink,
  other non-regular mountpoint, or staging failure leaves Gitleaks missing from
  coverage while other scanners continue. A produced Gitleaks scan records
  `ignore_files.gitleaks` as `honoured`, `neutralised`, or `absent` in the
  manifest, separately from inline `suppression_comments`; the gate discloses
  the same observed value. A scan that did not produce output makes no claim.

- **The SEC floor's catalog now names the build/CI surfaces that execute code
  (#1838, SEC-71240568).** Makefiles, setup.py, Terraform, second-tier CI
  systems, MSBuild project files, and lockfiles were live misses -- a target
  omitting SEC and a scout that never asks for it left those files unreviewed.
  The rejected-exclude disclosure now says whether the domain actually ran,
  instead of always claiming it "still runs".
- **A path or artifact this run did not create is not this run's evidence (#1841, run-14
  SEC-579863541 + SEC-3360368617).** `driver setup`'s two done-predicates were bare "does this file
  parse" tests on fixed `.panopticon/` paths a reviewed tree can plant or `git add -f`: a planted
  `setup-proposal.json` made the TARGET's own proposal the ingest's input, and a planted
  `setup-complete.json` satisfied BOTH, so the verb ran no phase and reported "setup complete" over
  a tree nothing classified. They now bind to THIS run with bindings that already existed -- the
  marker's own `run_id` (stamped by the writer, stable across resumes because `run_setup_flow` pins
  the setup manifest once) and git tracked-ness (`runio._manifest_committed`, the #1093 manifest
  guard's non-forgeable signal) -- and the refusal is reported once per invocation, naming the file
  and a remedy that can work. On the other side, `--pr` acquisition checked exactly one thing about
  its deterministic worktree leaf, `os.path.islink`: a pre-created real, EMPTY directory passed, and
  `git worktree add` populates one rather than refusing it, leaving the planter create and rename
  rights inside the tree under review. `acquire_pr` now refuses a leaf it did not make (a directory,
  `os.geteuid`-owned, writable by no one else, empty) before the fetch, creates the leaf itself in
  the statement before the add, and runs the same check on the reuse branch a resume takes. The
  guard is on ownership and group/other WRITE, not on every group/other bit: the tools image runs
  as `scanner` and mounts the review root — which under `--pr` IS that worktree — read-only, so
  traversal by another uid is required, and the leaf's parent must be sticky or private. The path
  stays deterministic, because `--pr` resumability depends on it — and `phases/setup.py` gave back
  the room under its 700-line ceiling before any of it: the #1737 unenforced-scan
  acknowledgement is now `phases/setup_ack.py`.
- **A heredoc handed to an interpreter is read as the script it is, or reported as unread (#1839,
  run-14 SEC-3915165799).** `scripts/workflow_guard.py` is CI's only enforcement of the #1529
  fetch-and-exec rule -- `tests/test_workflow_pins.py` runs it over every `run:` step in
  `.github/workflows/*.yml` -- and its standing requirement is to fail CLOSED: a shell form it
  cannot read is REPORTED, never accepted, and the accepted silent gaps are the list its docstring
  keeps. A script on an interpreter's STANDARD INPUT was in neither (`bash -s <<'EOF' … curl … | sh
  … EOF`, `sh <<'EOF'`, `python3 - <<'EOF'`): the reader filed the body under `Stage.heredoc`, and
  nothing above it asked whose script that body was, so a `curl … | sh` written inside one passed
  the gate clean. The split is the one the parse already knew, with no expansion model added. A
  QUOTED body reaches the interpreter as the text it was written as, so it is now READ -- in place
  and in order, exactly as an `eval '<script>'` string has been since #1697, which is what makes a
  step hardened inside its own heredoc come out hardened rather than unread. An EXPANDING body
  (`<<EOF`) is REPORTED unread instead of read, because its `$(...)` were lifted into the enclosing
  parse's table before that text was reached; so is a body handed to a language this guard has no
  grammar for (`python3 -`), which is the answer a `shell: python` step already gets. A heredoc that
  is a program's INPUT rather than its program is untouched (`bash x.sh <<'EOF'`, `sh -c '…'`, a
  `sha256sum -c` sums list), and so is the `<<<` here-string that is the only heredoc-ish
  construct the fleet writes. The two facts this needed were already parsed and are now carried:
  `shell_reader`'s `Stage.stdin_heredoc` (which body descriptor 0 finally reads and whether it
  expanded, copied in the same lexical redirect order as the output sinks) and
  `workflow_forms.stdin_program` (whether a command's program is its standard input at all, or a
  file, a `-c` string or a `-m` module). No step in the fleet writes the form today, so no check
  changes verdict: what changes is that the next one that does is read or reported, not waved
  through.
- **The rest of the configuration a scanned repository used to choose for the scanners (#1839,
  run-14 SEC-284952751 + SEC-1202454595).** #1924's scan-root class, split in two, because the two
  kinds of in-tree suppression are not the same claim. An ignore FILE the reviewed repository
  commits is scanner CONFIGURATION, and two more of them are now replaced with a scanner-owned one
  in BOTH security modes: trivy runs with `--ignorefile=/panopticon-config/.trivyignore` (a
  constant naming no advisory, staged the way bandit's ini is, in a read-only FILE mount of its
  own). That flag is BELT ONLY: the real-image round measured trivy 0.74.0 resolving the default
  `.trivyignore` against the WORKING DIRECTORY -- a per-launch scratch since #1877 -- so a
  scan-root `.trivyignore` was already not read on main either, and this closes nothing that was
  open. It pins the posture against a version that reads the scan root. And osv-scanner runs with
  `scan --config <its own scratch>/osv-scanner.toml`
  (an empty document; osv-scanner resolves `osv-scanner.toml` per DIRECTORY inside the scanned
  tree, so a committed `[[IgnoredVulns]]` list dropped the target's own advisories -- the one
  adapter of the four SEC-1202454595 named that #1742 left standing). Each file is staged per
  launch and fail-CLOSED: one that cannot be written skips that tool into the manifest's `missing`
  rather than taking the scanners queued behind it down with it. An inline suppression COMMENT is
  the other kind: it lives in the target's SOURCE, in the diff a reviewer reads. Under `--security
  redteam` the tree is untrusted and every scanner whose knob was verified against the pinned
  image stops honouring one (semgrep `--disable-nosem`, bandit `--ignore-nosec`, gitleaks
  `--ignore-gitleaks-allow`); under `standard` it STANDS, because `standard` is an operator
  scanning their own repository, who made a reviewed, in-diff decision. This repository's own CI
  (`security.yml` and the fork-PR `security-fork.yml`) scans in `redteam`, so nothing
  target-authored is honoured on either check. For semgrep the flag is BELT and the INGEST is the
  lever: at the 1.177.0 pin semgrep reports a `# nosemgrep`'d result either way, marked
  `"suppressions": [{"kind": "inSource"}]`, with and without `--disable-nosem`, so
  `sarif_to_findings` is what decides: it DROPS such a result under `standard` and counts it, and
  keeps it under `redteam`. The count is published per tool
  (`meta.coverage.adapters.<tool>.suppressed_in_source`, and on the gate's verdict line beside the
  excluded counts), and every ingest on both paths now carries the run's mode so no two of them
  disagree about which findings exist. It stands DISCLOSED: `tools-manifest.json` carries
  `suppression_comments` (`{"<tool>": "ignored" | "honoured" | "n/a"}`), one row per assessed tool,
  read off whatever decides it -- the argv the runner built for bandit and gitleaks, so taking a
  flag away changes the claim rather than leaving an intention behind, and the run's mode for
  semgrep, whose lever is the ingest and whose flag is belt; a tool with NO row was not assessed,
  which is not the same claim as
  `n/a`. Two residuals are disclosed there rather than guessed at on an argv -- gosec's `#nosec`
  and eslint-security's inline config, whose knobs were not verified at the pin, since a flag a
  scanner rejects is a tool that exits non-zero and writes no SARIF. A `.semgrepignore`
  committed at the scan root still narrows the scan in both modes with no flag to disable
  it at the pin (tracked on #2055). Gitleaks'
  allow-comment flag is appended by the adapter that builds its argv inside the container, so
  every adapter dispatch now names this run's mode as an explicit `--security <mode>` argv pair
  (not an environment variable, which a target's own hooks could set; an unrecognised token fails
  that tool closed).
  Bandit moves the other way in the same breath, by the owner ruling of 2026-09-25 on #1924: the
  bullet below pinned a scanner-owned ini in BOTH modes, which exceeded the ruling, so under
  `standard` a `.bandit` the scanned repository committed is pinned again (`--ini /src/.bandit`,
  explicit, so #run7's multiple-config ERROR stays bypassed) and honoured -- which takes the
  runner's own `-s B101,B404,B110,B112` off that argv, since bandit 1.9.4 exits 2 on a pinned ini
  whose `tests` key overlaps the CLI list and writes no SARIF at all (#1452's
  selected-but-unproduced class): their file chooses the checks. `redteam` keeps the scanner-owned
  ini and the `-s` list, and adds `--ignore-nosec`. `tools-manifest.json` says which of the two
  each run used, in `scanner_config` (`"target .bandit (its skips and tests)"` |
  `"scanner-owned"`). An operator sees: a
  `.trivyignore` or `osv-scanner.toml` committed to the scanned repository no longer decides what
  its own scan reports in either mode, their own `.bandit` is theirs again under `standard`, and
  `tools-manifest.json` says per scanner which config it ran under and whether the repository's own
  suppression comments were honoured. And CI scans in redteam, so the suite's two `shell=True`
  calls name the shell instead of carrying a `# nosec` (`tests/_test_helpers.py`,
  `tests/test_hook_command_quoting.py`: `/bin/sh -c` is what `shell=True` already ran).
- **This repository's own CI scans in `redteam` on both routes** (owner ruling 2026-09-26,
  #1839). Today the mode changes the virtualenv skip (off under `redteam`) and the
  gate's policy-C re-admission of name-suppressed findings; #1839's PR 5 adds the split that
  motivates the switch, where `standard` honours a target's own `.bandit`, `# nosec`,
  `# nosemgrep` and `gitleaks:allow` and `redteam` honours none of them. `standard` is an
  operator scanning their own repository; the fork-PR route (`security-fork.yml`, the required
  `fork-scan` check) scans a fork-authored tree, and the same-repo route (`security.yml`) must
  capture in the same mode because its captures are the baseline the next PR's gate diffs
  against and nothing records the mode. `--security redteam` is now on every scanner run,
  every gate call and the scheduled backstop snapshot (`security-backstop.py report
  --security`, new, so the snapshot counts the population the gate on the same step counts).
  Pinned per step in `tests/test_security_fork_workflow.py`. Measured on main through the
  tools image before the switch: the strict gate sees the same 29 HIGH under either mode and
  the first cross-mode delta run reports zero new.
- **The code-scanning upload now carries the gate's scope, and the bandit ini is a file mount.**
  #2117 stopped bandit honouring the reviewed repository's `.bandit`, which on this repository had
  kept it out of `tests/`; the next security run filed 476 test-suite idioms as open alerts and
  tripped the post-merge audit. `code_scanning_reports.py --exclude` (repeatable, the same
  gitignore-style globs `security_gate.py` takes, matched by the same `groups_schema.matched_glob`)
  drops those results from the Security SARIF only -- the gate still sees `tests/`, no AI
  inventory result is dropped -- and the excluded count is printed and written into the step
  summary.
  The scanner-owned bandit ini is bind-mounted as a FILE (0644) from a scratch directory that keeps
  `mkdtemp`'s 0700: the `chmod 0755` that made the directory traversable for the image's `scanner`
  user is gone, along with the two alerts it earned.
- **Tool and target text is inert wherever it is rendered -- so a scanned repository cannot steer
  the operator's terminal (#1829: SEC-4277410777, SEC-798292895, SEC-2200312865; closes #2069, the
  residual of #1752).** Three surfaces printed strings a target or its scanner wrote, with the
  control bytes still live: the terminal summary's Top-findings line, group line, target path,
  cross-domain note and target-config line; the `target-discovery-surface` probe's `detail` and
  its stderr disclosure; and the stored finding's `title`, `category`, `location.file`, `impact`,
  `remediation` and tool `rule_id`. A crafted SARIF message or a committed filename could
  therefore clear the screen (`\x1b[2J`), overwrite the line just printed (`\r`) and reprint it as
  `driver: all clear` -- `sarif_to_findings` only collapsed WHITESPACE, and the run-9 escape
  covered two fields on the other builder. One neutralizer now lives in `tools/base.inert_text`
  and runs at the normalization boundary -- both finding builders and `normalize_finding`, so
  every renderer inherits it -- with belt-and-braces calls for the target path, the group name,
  the agent-authored cross-domain note and the target's own config values, which normalization
  does not own. What an operator sees changes: a control byte reads as `\x1b` rather than acting,
  over-long target text is cut with a marked ellipsis (never mid-escape), and an ordinary
  multi-line tool message still renders as one line; a PATH is escaped and bounded and otherwise
  kept byte-for-byte, so a real `src/a  b.py` still resolves on disk. The JSON artifact was
  already escaped on disk; what is new is that the STORED strings are inert too, so anything that
  prints a field raw is safe as well.
- **A file the reviewed repository commits no longer chooses what the scanners look at (#1839,
  run-14 SEC-1486247143 + SEC-752508850).** Three levers, all on the path CI's merge gate runs
  (`run_tools.py` -> `security_gate.py`, which has no agentic axis to compensate). A single
  committed `src/pyvenv.cfg` was enough for the runner to hand `src/` to semgrep's `--exclude`,
  trivy's `--skip-dirs` and bandit's `--exclude` in BOTH security modes, untallied: a directory is
  now flagged on the marker only when it also has the SHAPE of an installed environment (an
  interpreter under `bin/`/`Scripts/`, or `lib/python*/site-packages`), and a bare marker beside
  real source is reported as `pyvenv.cfg-without-shape`, walked into, and never skipped. The INGEST
  half of that same lever is closed with it, which is the half the driver's own report reads:
  `ingest_tools` dropped every finding under a marker directory at ANY depth in both modes and said
  nothing at all, so the planted `src/pyvenv.cfg` emptied the report of `src/` even where the scan
  had looked. One predicate now answers for both stages (`run_tools.has_venv_shape`), so a bare
  marker prunes nothing at ingest either; and where a real virtualenv is still pruned there, the
  drop travels the disclosed channel under a `pyvenv.cfg:<dir>` key of the new
  `virtualenv-by-marker` class -- named per directory, counted in `meta.coverage.tools_suppressed`,
  and re-admitted to a `--security redteam` gate when the finding is CRITICAL or secret-class,
  exactly as #1740 does for a directory NAME. An operator's own `--exclude` glob outranks it. A
  directory literally named `*` became `--exclude=*` / `--skip-dirs=*` -- both flags take GLOB
  PATTERNS, so one `mkdir` took the whole tree out of two scanners; a path with any component
  outside `[A-Za-z0-9._-]` is never passed to an exclusion knob, and its manifest row says
  `skipped: false` with a `note` saying why. Under `--security redteam` NO virtualenv now reaches an
  exclusion knob (#1740 ruled
  that for a directory NAME; a file the same target wrote is more attacker-controlled than a name),
  and under `standard` the #1638 P09 walk saving stands but stops being silent: the skipped
  directories are counted as DIRECTORIES under `virtualenv-by-marker` AND `virtualenv-by-name` in
  `meta.coverage.tools_suppressed` -- the name-only skip a bare `mkdir .venv` buys is tallied too,
  because it also produced no finding for anything downstream to disclose -- named on the gate's
  verdict line (`3 directories removed from the scan as virtualenv-by-marker ('.venv', 'env');
  virtualenv-by-name ('venv') -- re-run with --security redteam to scan them`, with every
  target-authored name escaped and the list capped at ten), and on the manifest rows. Redteam trades
  the #1638 P09 walk saving for that re-admission: all three scanners walk `site-packages` in full,
  which is wall-clock and tool-timeout cost rather than report noise (the ingest still drops those
  findings and hands back only the CRITICAL and secret-class ones), and the only knob for it is
  `--exclude '**/.venv/**'` -- gate POLICY, which takes those paths out of scope in every mode and
  is never re-admitted, not a shorter walk. Third, bandit no longer runs with `--ini /src/.bandit`:
  the target's own config set bandit's `exclude`, `tests` and `skips`, so a committed `tests = B999`
  reduced the merge gate's Python SAST to one check. It gets a SCANNER-OWNED ini instead --
  generated per run into a scratch directory, bind-mounted read-only, pinned unconditionally (so
  #run7's multiple-`.bandit` ERROR is bypassed whether or not the target ships one), and carrying a
  CONSTANT text: bandit's own parser defaults plus `.worktrees`, no `tests`/`skips` key, and no
  target-derived string of any kind, since its one job is to pre-empt bandit's `.bandit` discovery.
  This run's virtualenvs ride on the CLI instead, as attached `--exclude=` values, each path
  component checked against an allowlist (`[A-Za-z0-9._-]`, no leading `-`) so a name holding a
  comma, a brace or a newline is scanned and NAMED rather than expressed. This is the first
  increment of #1924's scan-root half. An operator sees: a `pyvenv.cfg` planted on source no longer
  removes it from a scan, a gate verdict line that names every virtualenv the scan skipped, by
  marker or by name, a report that carries a `virtualenv-by-marker` count where the tool axis used
  to go quiet, and bandit reporting the checks panopticon selected rather than the ones the target
  left it.
- **Deleting a run's own integrity evidence is reported, not repaired -- so a substitution
  survives the `rm` that used to launder it (#1832, SEC-377944137).** #1208 made an owed-but-absent
  `out-file-hashes.json` fail closed, because deleting that baseline had been the cheapest way to
  erase evidence of a findings substitution. It did not hold on a live `driver run`: the synthesize
  phase opens by calling both artifact writers, and each re-armed the moment its file went away, so
  the snapshot was simply re-taken OVER THE SUBSTITUTED BYTES -- the tampered findings file became
  its own baseline, `content_mismatched_files` went empty, and the plan was re-created so its
  deletion left no trace either. One file up, absence also still read as "not measured": every check
  keyed on `dispatch-plan-driver.json` treats a missing plan as owing nothing (`_owes_a_snapshot`
  returns False, so #1208's guard goes quiet; the planned-vs-ingested reconciliation returns
  `([], [])` by design; `duplicate_out_files` sees nothing; and `empty_dispatch_plans` counts empty
  LISTS, of which there are none when there are no plan FILES), while `plans_seen` -- the one key
  that noticed -- was not in `integrity_ok`.
  Both artifacts are now OWED ONCE: their writers stamp the run manifest as they write
  (`driver_plan` carries the plan's canonical content hash, `out_file_snapshot` the cell count), the
  stamps are MONOTONE, and a stamped artifact that is gone is never re-created -- the driver says so
  on its own stderr, naming `--reset` for a run folder that was cleared on purpose. Synthesis then
  reports `meta.integrity.dispatch_plan_missing` for a deleted plan and `dispatch_plan_mismatched`
  for one that is present but is not the plan this run wrote (replacing it is the same erasure and
  cheaper: a narrower plan declares fewer cells), both failing the gate closed beside their #1208
  sibling. The manifest is the anchor because a plan cannot attest to its own existence and the
  manifest is the better-defended file (#1727) -- and a durable stamp rather than the rolling
  dispatch-request slot, which read `verify` on any run that verified anything, could be rolled
  BACKWARD to `scout` by the same tamper it was meant to notice, and could not tell a tool-advisor
  verify dispatch from a review one. A run that never wrote a plan -- a direct `synthesize.py` call
  over hand-collected findings, a target with no declared cells, a run resumed across this upgrade
  -- stamps nothing, keeps the benign reading every other key here has, and still gets the #5.0-16
  first-snapshot fallback when its verify phase was vacuously done. **A run already IN FLIGHT across
  this change should be `--reset`, not resumed:** with nothing stamped, its first snapshot is taken
  over whatever bytes are on disk at that moment, so a substitution made before it still reads clean
  -- the one window the old laundering survives in. The obligation is never inferred from the
  findings files present, which the same writer could arrange.
- **A target-committed write allowlist can no longer hand a reviewer a peer cell's findings file
  (#1831, SEC-611772336).** `write_guard_hook.install` carries a still-live grant forward so that a
  re-arm never revokes a concurrent fan-out (#11), but the filter deciding what MAY be carried
  anchored on the `.panopticon` segment and checked a prefix only -- so every path under the whole
  artifact tree qualified. Entry ids are `review-<group>-<domain>` and the target authors
  `panopticon.yml`, so a `.panopticon/write-allowlist.json` committed in the scanned repo and keyed
  with a REAL reviewer id added a PEER cell's `findings-<group>-<domain>.json`, the run's
  `out-file-hashes.json` integrity snapshot and `dispatch-plan-driver.json` to that reviewer's own
  grant: the per-entry confinement #1571 exists to establish, re-opened through the one path that
  fix did not close, on every self-scan and every calibration run started inside the clone. A
  carried path is now kept only when it is EXACTLY the artifact its own entry id declares, in one of
  the RUN FOLDERS (`.panopticon/runs/<tag>/`) this install writes into. The path is DERIVED from the
  id rather than matched against its name -- `review-<cell>` may hold `findings-<cell>.json` and
  nothing else, `verify-<cell>-<stage>` its `verdicts/verdicts-<cell>.json`, `verify-tool-<queue>`
  its `verdicts/<queue>.json`, and `scout-<group>` its `scout-<group>.json` -- so a real reviewer id
  carries that reviewer's own out_file and no peer's, even where one group's name ends with
  another's (`Core` and `X-Core`), and a previous round's tag is not in flight. Deriving per family
  is also what keeps #11: a verify or scout arm carries a concurrent fan-out's grant as readily as a
  review arm does. Everything else is dropped, and the operator is told on one stderr line, counts
  first, with each entry id bounded and quoted (`write guard: dropped 5 carried allowlist path(s) in
  1 entry(ies) -- not this run's folder, or not the artifact that entry itself declares:
  'review-Core-SEC' (5)`) -- a grant narrowed in silence is the #calibration-4 shape, every later
  write denied and nothing pointing at the allowlist, and an id out of a planted file is
  target-authored text that may not forge a line of the guard's own output.
- **A torn retry-budget ledger no longer refunds every attempt the run spent (#1809,
  DAT-3555180994).** Four retry ledgers -- `cell-attempts.json`, `verify-attempts.json`,
  `scout-attempts.json`, `discovery-attempts.json` -- were read at six sites (persist's give-back
  path among them), and every one resolved "absent" and "present but unreadable" to the same empty
  dict, so a file torn by an interrupted write read as a fresh run: a cell that had spent
  `MAX_CELL_ATTEMPTS` became dispatchable again and the count restarted at 1, discovery's "one free
  re-run and no more" stopped bounding anything, and each refund was paid for in launches. One
  reader now draws #run9 COD-B1A's line for all six (`runio._load_state_json`, the rule
  `file_issues.load_ledger` already applies one directory away): `{}` only when the file is ABSENT
  -- a legitimate first run -- and a `DriverError` naming the path and `--reset` for everything
  else, a dangling symlink (`lexists`) and a deeply nested document (`RecursionError`, previously a
  bare traceback) included. `driver run` turns that into an `error` status naming the file from
  every site: the terminal `exhausted_cells` call reads the same ledger and sat outside every `try`,
  so that block speaks the status protocol now too. The remedy the message names is real:
  `verify-attempts.json` and `discovery-attempts.json` join `cell-attempts.json` in the legacy flat
  sweep's `_RESET_GLOBS` (`scout-*.json` already covered the fourth), and a live run's whole folder
  goes. Fail closed rather than fail-quiet -- a false refusal costs one `--reset`, a silent refund
  costs launches and invalidates the run's own bound.
- **The clean-tree baseline is written atomically, and an unusable one is classified instead of
  blamed on the v1 upgrade (#1809, DAT-4027033499).** `tree-baseline.txt` was the one artifact
  writer in `phases/` that truncated in place, and it sits behind an exists-means-done guard that
  must NOT re-probe `git status` on resume (re-probing would baseline the reviewer's own writes as
  clean). A write torn mid-way was therefore PERMANENT: every later resume accepted the partial
  document, the run failed closed at validate forever, and `--reset` -- throwing a paid run away --
  was the only exit. Both baseline writes (the snapshot and the probe-failure sentinel) now confine
  the final name, then stage `<baseline>.tmp` through the same `_open_w_nofollow` and `os.replace`
  it into place -- `runio._write_json`'s shape AND order, byte content and file mode unchanged --
  and on failure remove only the staging file this call opened, or a symlink planted at its name,
  never a file it never opened (with `.panopticon/runs` force-committed as a symlink, that name
  resolves outside the tree). An interrupted process therefore leaves the last complete baseline or
  the new one; nothing here fsyncs, so a power loss can still tear the file, which is what the
  classifier below is for. **Operator-visible:** a present-but-unusable baseline now says which kind
  it is -- CORRUPT for anything that cannot be a porcelain record (a first byte outside the XY
  status set, or JSON that parses to something that is not an object); EMPTY for a 0-byte or
  whitespace-only one (a torn write, or a v1 baseline of a clean tree) -- and both name `--reset`
  as the remedy and deleting `tree-baseline.txt` as the non-remedy it is (the next capture would
  re-baseline the reviewer's own writes as clean). All of them used to read "predates content
  digests (schema v1)": a resume across an upgrade that never happened, with no remedy named -- and
  0 bytes is the likeliest shape the old writer's torn write left behind. A genuine v1 baseline (raw
  porcelain, which always opens with an XY status byte) still reads as v1, a deeply nested one fails
  closed here instead of ending the invocation with a `RecursionError` traceback, and `--reset` now
  also sweeps a staging file orphaned by a SIGKILL. Staging opens
  without `O_EXCL` project-wide (#2093) and an `OSError` from this write still reaches the operator
  as a traceback rather than a status (#2094) -- follow-ups, not fixed here.
- **A catalog gap with no file location is disclosed, not dropped (#1807, DAT-2501524861).** The X0X
  emitter drops a candidate cluster when no finding in it carries a `location.file`, because the
  schema requires a `file` on every occurrence — and a locus-free finding is the CANONICAL shape for
  a repo-wide catalog gap, which `synth/findings.py` produces deliberately (#1522 COD-D1B pops the
  empty location rather than quarantine the finding). So the emitter whose whole purpose is to carry
  catalog gaps into OCRDb's adjudication pool was discarding exactly the repo-wide ones, in silence,
  and `synthesize`'s `X0X artifact: <path> (N candidates)` line printed a count that was quietly
  short. Nothing is invented — a file cannot be. The count the report had to leave out is now
  published as `candidates_dropped_locus_free` (omitted when zero), an optional integer DECLARED in
  `skill/reference/x0x-report-schema.json` so a downstream ingester has a documented field to read;
  that key is the carrier that survives a `driver run`, because the driver keeps a child's output
  only on failure. Run `synthesize.py` yourself and each dropped cluster is named on stderr too —
  the domain, the lead title or, untitled, its finding id, and how many findings the cluster held —
  with the count appended to the `X0X artifact:` line. Every agent-authored field in either
  diagnostic is squeezed to one line, bounded with the cut MARKED, and rendered inert with `%r`, so
  one hostile finding cannot repaint the operator's terminal or forge a line that reads as the
  tool's own honest output. `strain_report.advisor_recode_signals` — the offline catalog-MIS-FIT
  companion, which has no pipeline caller — makes the same disclosure at its own locus-free drop;
  `cross_run_signals`'s line-window join is left alone, being intrinsically file-keyed. Residual,
  filed as #2090: a MIXED cluster still reaches the pool with its locus-free member absent from
  `recurrence`, silently.
- **A run3 that never reviewed the file can no longer corroborate a "fixed" close (#1807,
  DAT-1268532600).** Stage 1 (`skill/scripts/reconcile.py diff`) read "no run3 record on this (file,
  panel)" as evidence of a fix, and its two whole-run guards only fired when run3 was EMPTY or
  shared no path at all with run2 -- so a NARROWER re-run (`--scope-file a.py`, one directory, one
  group, a PR diff) overlaps on a single path, defeats both, and every still-unfixed finding on the
  files it never opened landed in the `closed` cohort, which `scripts/reconcile_apply.py apply
  --confirm-close` turns into a real GitHub close commented "**Reconciliation: fixed (area
  clear).**". That `(file, panel)`-clear read is now gated on ONE further thing, and only that
  thing: run3's own claim to have reviewed the file -- `groups[].files`, merged across the report
  and every part. Nothing stands in for the claim, a record on the file included: a record proves
  some scanner or cell read the path, not that the (file, panel) whose silence is read as a fix was
  reviewed. So the diff refuses three ways: a finding on a file run3 does not list goes to
  `ambiguous` (kept open), reading "<file> was not reviewed in run3 -- absence of findings is not a
  fix", or, when run3 does carry a record on that path, "run3 produced records on <file> but its
  report does not list it among the files it reviewed (groups[].files)" -- an under-stated
  `groups[].files` is a report-side bug, named rather than trusted; a run3 whose report states no
  files at all guards the whole run (`run3_files_unstated`); and a run3 whose report does not
  declare `meta.review_type: "repo"` -- a scoped review, an absent, empty or unreadable value, or a
  part contradicting it -- guards it too (`run3_not_repo_wide`). Missing information fails CLOSED,
  with no flag to opt back into the old reading. Stage 2 words every one of those refusals as
  "**Reconciliation: not corroborated.**", where it used to claim the area was still active and the
  finding probably re-worded -- which for a zero-record or path-drifted run3 was simply false.
  **Operator-visible:** a close now needs a repo-wide run3 that says what it looked at, and the
  summary names an active guard once on its own `guard:` line instead of only repeating it per
  finding; a run3 that is merely NARROWER by file list still closes the findings on the files it
  does list. Still open as follow-ups: #2084 -- a run3 that declared itself repo-wide but LOST cells
  (`meta.coverage.cells.missing_floor` non-empty, `summary.coverage_certified` false) still lists
  every file in `groups`, so it can corroborate closes on files no review cell actually reached; and
  #2087 -- the claim is per FILE and per RUN while the silence read as a fix is per `(file, panel)`,
  so a panel or tool axis that never ran on a listed file still reads as clear.
- **Three run-artifact readers in `synth/` no longer end a run on a file a target can pre-commit
  (#1811, #1812 — DAT-2808086775, DAT-3713947858, DAT-1553408299).** `coverage-*.json`,
  `dispatch-plan-driver.json` and the agent findings files are read back out of the run folder,
  which on the agentic path is globbed out of the SCANNED repository — and all three readers
  announced a "tolerant: never abort a run" contract their guards were narrower than. A deeply
  nested document raised `RecursionError` (a `RuntimeError`, so outside
  `except (OSError, ValueError)`) in every one of them, and nothing bounded the coverage read at
  all; a scalar dispatch plan (`5`, `true`, `null`, `1.5`) raised `TypeError` on the iteration that
  counts review cells; and the out-of-scope counter re-read the findings files with neither the
  parser nor the shape repair the canonical loader uses, so a fence-wrapped file — the shape run-9
  saw from 94 of 95 tool advisors — silently disclosed ZERO out-of-lane findings while the report
  ingested them, and a mistyped `location` (string, list, number) or a non-list `findings` raised
  out of `PlanInputs.load`. That second read now goes through `evidence.load_json_tolerant` and
  `normalize_finding`, the same two the first read uses, so these two readers of the same files
  cannot disagree about what the file IS or about what a row means. **Operator-visible:** a report
  that used to be lost after every dispatch had already been paid for is produced instead — the
  coverage file skipped and NAMED on stderr (its READ bounded to 1 MiB, so a symlink to a bigger
  file or to a character device is bounded too, not just one whose declared size is honest), the
  plan counted as 0 review cells and said so, the fence-wrapped file's out-of-lane findings
  actually counted, and one unusable finding row costing nothing but itself. Scope: these three
  readers. Sibling readers in `synth/plan.py`, `synth/cost.py` (`usage.json`) and
  `synth/integrity.py` still catch only `(OSError, ValueError)` (#2081), a skipped coverage record
  still fails OPEN on the floor audit rather than recording itself in `meta.integrity` (#2080), and
  a FIFO named like an artifact still blocks at `open()` (#2082) — follow-ups, not fixed here.
- **`--max-budget-usd` is re-read after every entry, not once per checkpoint (#1760,
  AGT-4265600920).** The cap was compared with the ledger exactly once per loop iteration, at the
  top and ahead of arming — and a checkpoint is ONE batch, so a whole review round (every pending
  cell, each charged at dispatch) launched before the cap was looked at a second time, where the
  guide promises launching stops once the ledger's cumulative reported cost crosses it. It is now
  the batch's THIRD stop rule, beside the host-outage and identical-launch-failure ones (#1721,
  #1732): the queue is cancelled the moment the ledger reaches the cap, whatever is already in
  flight drains, persists and is charged as usual, and the run still ends on the same terminal
  `--max-budget-usd X reached` error one iteration later, off the same gate and the same ledger. So
  the overshoot falls from the whole checkpoint to the pool — up to `--concurrency` launches
  already in flight, plus the one worker that can turn over while the loop is still ledgering the
  result that reached the cap, which is the bound an outage has. The predicate fails CLOSED on a
  ledger line whose cost cannot be read as money, because `iter_batch` reads a `stop` that raises
  as "carry on" — #1648's fail-open one level down. **Operator-visible:** the batch's stderr line
  names the rule that stopped it as `the --max-budget-usd cap`, where a cap used to be rendered as
  "0 host-class failure(s)" — a host to go and wait out.
- **Two prompt boundaries now bound the untrusted text they quote (#1752,
  AGT-1863884584 and AGT-2822331063).** A retry prompt quotes the rejected
  record's `attempt`, and the tool-aware review map quotes each tool hit's path,
  rule id and title. Both are written by something outside the run — the record
  is a file, and for `driver setup` it is a file at a FIXED path in the flat
  `.panopticon/` (`rejected/setup-scan-1.json`) that a target repo can commit;
  the hits come from scanner output, and `.panopticon/tools/*.sarif` is another
  path a target can commit — and both were interpolated with no type and no
  bound, beside neighbours that had one (`reason` at `REASON_CAP`, the 40-line
  `_TOOL_HITS_CAP`). A planted `attempt` put 10 kB of prose into the prompt, into
  `prompt_file`, and into the entry's `prior_rejection` stamp, which is hashed
  into the dispatch request; one hostile hit put 20 kB into a review prompt under
  "verified independently … do **not** re-file them", and forty put ~760 kB.
  `attempt` is now an int in `1..ATTEMPT_CAP` (99) or nothing at all — the block
  then reads "Your previous attempt was refused", with no number, because an
  unusable field must not be paraphrased into a claim about the run — and
  `prior_rejection` carries that same sanitized value, so the prompt and the
  request cannot disagree. The map's three untrusted columns go through one
  helper at the rendering boundary: `runio._prompt_safe`, whitespace collapse,
  and a per-column cap (200 / 120 / 200) whose cut is MARKED with `…`, so a
  truncated line cannot read as a complete one, and an empty column reads `?`.
  **Residual, filed separately:** the generic SARIF path still leaves control
  bytes in the ARTIFACT's `title`/`rule_id`/`category` (this fix cleans the
  prompt, not the normalization contract; #2069), and `.panopticon/tools/*.sarif`
  is still ingested with no run binding (#2070).
- **The guide now says where the second witness is spent (#1759, AGT-1456823651 /
  AGT-381210818).** A REJECTED advisor verdict was always settled by one advisor — the
  adversarial backup round is summoned only for primary-CONFIRMED findings in categories at or
  above `score_gate.BACKUP_FLOOR`, and the tool axis has no backup round at all — but the
  evidence chapter never stated the asymmetry or why it is deliberate. It does now, beside the
  sentence that says rejected claims keep their full advisor prose in `discarded_claims`.
- **A batch record names its MACHINE, and one record can be discarded without
  the run (#1912).** The owner stamp that `driver loop` recovers a crashed batch
  from carried the pid and `socket.gethostname()`, and a hostname is not a machine
  identity: on macOS the same laptop answers `mac.local`, `mac.lan` or a
  DHCP-assigned name depending on the network it woke up on, so a crash and the
  resume after it saw two different names — the resume read its own record as
  another machine's and offered `--reset`, the whole run of paid cells, as the
  only way forward. The record now carries a hardware machine id
  (`uuid.getnode()`, absent when that function falls back to its random
  multicast value) beside the hostname, and either id matching means this
  machine; a record from before the field, or one whose field is unusable, is
  judged by its hostname exactly as before. Comparing the first DNS label is
  deliberately NOT done — this repo lives on a mounted volume, so `mac.office`
  and `mac.home` really can be two machines sharing one run folder.
  **Operator-visible:** `driver loop --discard-batch N` is a new, narrow remedy
  for the two refusals that mean "the liveness question could not be answered"
  (another machine / no owner stamp). After confirming no other loop is working
  on the folder, it gives record `batch-N.json` exactly the rollback a dead
  owner's gets — artifacts deleted, entries ledgered as cancelled/rolled back,
  attempts refunded, record unlinked — and the invocation carries on with the
  rest of the run. It applies to that one number: a live owner still refuses (no
  flag can help), a dead one needs no acceptance, a second unreadable record
  still refuses, and an absent one is an error naming the folder. Both refusals
  now name `--discard-batch N` first and `--reset` second, the acceptance is
  recorded in `discarded-batches.json` in the run folder (with the owner stamp as
  found) and counted on the run manifest, and `--discard-batch` with `--reset` is
  refused as contradictory.
- **An unenforced claude launch now denies the tools a reviewer must not hold
  (#1753, AGT-4053314873).** An `--agent` launch lands in a registered shell
  whose `tools:` frontmatter the host enforces; the `--model` fall-through
  binds no shell, and `--setting-sources user` deliberately keeps the
  OPERATOR's user-scope `permissions.allow` — so a `Bash(*)` convenience rule
  in the operator's own settings reached a reviewer whose job is reading
  hostile content. That argv now carries
  `runners/claude.UNENFORCED_DENIED_TOOLS` — 24 names, grouped by what each
  would hand a reviewer: code execution, delegation, egress and off-machine
  publication, the write tools no reviewer role is granted, and the two
  read tools its `Read|Grep|Glob` matcher never sees — and deny rules beat
  allow rules, which is the point. **Measured on 2.1.276, and the reason for
  the `=` form:** `--disallowedTools` is VARIADIC, so the space form eats every
  following non-flag token including the prompt — `claude -p --output-format
  json --max-turns 2 --disallowedTools Bash "<prompt>"` exits 1 with no
  envelope and "Input must be provided either through stdin or as a prompt
  argument" — while `--disallowedTools=Bash,Glob "<prompt>"` runs and the
  reviewer reports "I have Read available; Bash and Glob are not in my current
  tool set". One token cannot swallow a neighbour, wherever it is placed. The
  ENFORCED argv is byte-identical to before: it is measured behaviour and its
  shell is already the control. **Residual:** a tool name this list has not
  heard of that the operator has allowed at user scope — a CLI upgrade is how
  one arrives. MCP tools are not part of it, since the same argv passes
  `--strict-mcp-config` with no `--mcp-config`.
- **`driver setup` refuses an unenforceable setup-scan (#1737, AGT-B1D).** The
  one dispatch that reads the whole untrusted tree was the only role with no
  registered shell: its tool grant was whatever the host hands a
  general-purpose agent, and the template's `Read, Grep, Glob` travelled as
  advisory prose in the brief. `setup_scan` is a driver role now, so
  `--emit-host-agents` writes `panopticon-setup-scan` for every host that
  registers shells (tools `Read, Grep, Glob`; **no bound model** — the
  session's own model runs the classification, R-F4-2), `registered-shell-tools`
  proves it grants no Bash, and the `scan` checkpoint dispatches that shell and
  only that one. `enforced` is derived from this invocation's measured posture
  like every other dispatch, and both entrypoints — `driver setup` as much as
  `driver loop --setup` — probe the host for themselves before the gate reads
  the evidence. **Operator-visible:** on a machine that has not registered its
  shells, `driver setup` now stops and names two remedies —
  `python3 skill/scripts/dispatch.py --emit-host-agents <host>` (the fix) or
  `--allow-unenforced` (the acceptance, recorded in
  `.panopticon/setup-unenforced-ack.json` and discarded once the posture
  proves enforcement). Registering the shells is a one-time step; until it is
  done `tool_policy_enforced` reads REFUTED for review runs too, which is the
  registry honestly reporting itself incomplete. The refusal names the remedy
  that can actually change the answer: emitting shells where the capability is
  REFUTED, and `driver loop --setup --host <h> --mode headless` where nothing
  measured it at all — on Codex that is the ONLY invocation that can, since its
  tool-policy probe needs a headless settings path and `driver setup` has no
  `--mode`. Probing costs no paid turn and, Kimi's `kimi --version` and `kimi doctor` reads aside,
  launches no host CLI at all: everything `driver setup` measures is a
  filesystem read.
- **`usage_ledger` follows the mode.** The probe is now `usage-source` (was
  `transcript-dir`): in headless mode it measures the launch envelope path —
  a run folder that can hold `dispatch-ledger.jsonl`, the host CLI on PATH,
  that CLI's `--help` advertising the runner's own `ENVELOPE_FLAGS` (`-p`,
  `--output-format`; an executable merely named `claude` is refuted), and,
  once launches are ledgered, their envelopes having carried usage — and never
  consults transcripts; in session mode it measures the session's transcript
  directory exactly as before. A headless run launched from any directory
  without transcripts (every fresh target) used to be *refuted* while its
  ledger was exact. The `--help` interrogation goes through the runner's own
  launcher, the seam the suite refuses real launches at.
  `runners.base.LEDGER_FILE` is the one owner of the ledger's name (the
  `Ledger` and `usage.json`'s `source` both read it); the remedy line names
  both modes' fixes.
- **`driver loop --reset` resets once.** The flag reached `driver.run` on every
  iteration, so each one cleared the run folder and re-minted the manifest and
  the loop re-launched its first checkpoint until `--max-iterations` (this
  branch's second real run: the same three scouts ten times). The first call
  consumes it.
- **`prompt_file` is granted to the entry's read scope.** The guide let a host
  point an agent at `prompt_file` (marker line first, pointer second), but every
  entry's `scope.reads` was empty, so the read guard denied the agent its own
  prompt. Stamping the file now grants it through `reads`.
- **The SEC cell may read the checklist its prompt points at.** The first real
  headless run's ledger recorded the SEC reviewer's Read of
  `skill/reference/security-checklists.md` as a denial: the prompt named the
  file, the scope did not. `review._cell_reads` grants it through `reads`,
  from the one path the pointer is rendered from.
- **Session-mode dispatch on Claude Code is templated.** `skill/workflows/dispatch.js`
  runs one workflow subagent per pending entry — inside its registered shell
  when the entry is enforced, on the entry's model otherwise — marker line
  first, and returns replies keyed by id, a skipped or dead subagent under
  `missing`; SKILL.md mandates it over one-off Agent calls. The read-guard
  probe's round trip now also binds a fake subagent through the Workflow
  transcript layout (16 rows).
- **The suite refuses the real `claude` binary by default.**
  `runners.claude.DEFAULT_RUNNER` is read at construction and `tests/conftest.py`
  swaps it for a refusal on every test (was per-test discipline; #1616); only a
  launcher a test injects explicitly runs, and none injects the real one. The
  same file now also points `HOME` at one throwaway directory for the whole
  process, before the registry expands `~`, so no probe or test reads the
  operator's real `~/.claude`.
- **`Glob`'s pattern is adjudicated (#1917).** Both read guards decided a
  `Glob` on its `path` alone, and the pattern is a PATH pattern expanded
  against it, so `Glob(path=<granted dir>, pattern="../Src/*")` could name
  entries outside the `dirs` grant — names, not content, since a following
  `Read` still meets the per-file rule, but it was the one read primitive whose
  second argument nothing looked at. Over a granted directory a pattern that is
  absent, empty, non-string, absolute, `~`-rooted or holds a `..` segment is now
  denied. `Grep`'s pattern is a regex over content and stays unadjudicated.
- **In-tree hard links keep their directory `Grep` (#1917).** The walk behind a
  directory read grant recorded every regular file with `st_nlink > 1`, so a
  `cp -al` fixture or a pnpm store — whose links all sit inside the review
  root, naming content the grant already covers — denied every directory
  `Grep`/`Glob` above it for nothing. It now counts the in-tree names of each
  inode and records a file only when its link count EXCEEDS them. A `git clone
  --local` target is deliberately NOT cleared: its links name the source
  repository's objects, it still overflows the cap and still loses its
  directory `Grep`, with `--no-hardlinks` named on stderr as the remedy.
  **Operator-visible:** the walk is now always complete (the count is only
  known at the end), so `CAP` bounds the findings rather than the files walked.
- **`read-guard-armed` measures the planted hard link (#1917).** The Claude
  readiness probe now does what the Codex one has done since #1642: it plants a
  hard link inside a directory grant naming a file outside it, records it with
  the driver's own walker, and requires the directory `Grep` to be refused **by
  the hard-link rule** rather than merely denied. A volume that cannot plant a
  link — or that plants one and then reports `st_nlink=1`, as some FUSE and
  network mounts do — makes that sub-check `unknown` instead of refuting a
  healthy host.
- **The guide is an index plus one chapter per section.**
  `skill/docs/PANOPTICON.md` keeps Overview, Required sub-skills, Modes and
  Global flags plus a Contents list; each H2 lives in `skill/docs/guide/`
  (`docs/guide` is symlinked onto it), wrapped at 100 columns with no prose
  changed. `driver readiness`'s `guide` row is true only when every chapter
  file is present (`hosts.guide_documents()`), and its remedy names the
  missing ones.

## Unreleased — 5.2 grouping engine, plan 1

Setup now front-loads the grouping work so every later run reuses it
(spec: panopticon-docs `superpowers/specs/2026-09-06-panopticon-5.2-grouping-engine-design.md`).

- **Catalogs, full prose:** the capability roster grows from the R1 13 to 45
  entries harvested from the 5.2.0 vocab panel (>= 10 repos each), every entry
  carrying `definition`/`boundary`/`aliases`/`examples`; a 9-entry **layer**
  catalog (`layer_vocabulary.yml`) for splitting one oversize vertical; a
  `tests_catalog.yml` for the test-tree seeds. Both catalogs render into the
  setup-scan brief in full — the calibrated prose finally reaches the
  classifier (#1500). Proposed labels normalize through aliases. The reserved
  names `Tests`, `Commons`, `Ungrouped` and `Core` may not be catalog entries,
  aliases, or proposed layers; a proposal may name a `Tests` group (a committed
  `Tests` suppresses the run-time sweep) but not `Commons` or `Ungrouped`,
  which the engine mints.
- **Proposal v2:** per group, optional `layers` (`{layer, match}`) and a
  `profile` (`purpose`, `surfaces`, `entry_points`, `trust_boundaries`);
  `custom:` groups and catalog entries without an affinity row get their
  review floor from the profile's surfaces (#1490 for setup-time groups).
- **Size policy (stage 3):** cap = `--max-per-group` > `config.json
  max_per_group` > 48; ceiling = `--max-groups` > `config.json max_groups` >
  `max(4, 2 * ceil(code_files / cap))`. A layer under 6 files merges back, a
  vertical over the cap splits by its layers (residual `Core`), over the
  ceiling the smallest layers collapse first, verticals are never merged.
  Committed groups always win; the outcome is written to `setup-report.md`
  / `setup-report.json`.
- **Setup engine fixes (from the first 5.2 self-scan, run-11):** the ceiling
  budgets CODE leaves only — `Tests` and the Commons categories hold exactly
  the files its numerator subtracts, so charging them to it made any repo of
  <= 96 code files with two verticals "over ceiling" by construction and told
  the owner to merge verticals (#1506). `chunk_files` packs to decided sizes,
  so an oversize group splits into exactly `ceil(files / cap)` near-equal
  chunks whatever its directory shape — it used to emit a phantom cell, and a
  starved trailing chunk, depending only on directory names (#1503). The
  Commons `CI` category claims the top level of `.github` (`*.yml`, `*.yaml`,
  `*.sh`, `*.json`), so `labels.yml` and friends stop reading as a catalog
  coverage gap (#1508). Globs: a trailing-slash directory pattern (`docs/`)
  now compiles as gitignore reads it instead of silently matching nothing,
  and a character class (`*.[ch]`) is refused at validation time instead of
  being escaped into a literal that claims the wrong files (#1501).
- **Tests axis:** a vertical's wildcard `tests` glob is scoped (under its
  `match` dirs or naming the vertical/an alias); the cross-cutting test trees
  form a `Tests` group last, at run time, from the leftovers.
- **Stage 1 spine:** `setup-spine.json` — depth-2 tree, languages, manifests
  and frameworks, already-claimed counts, test trees and the size arithmetic,
  bounded and sanitized (#1120) — is computed once with the sizes pinned in
  `setup-manifest.json` and rendered into the brief.
- **Compatibility (5.1 -> 5.2):** the `groups.yml` schema is unchanged and a
  5.1 setup proposal still validates; re-running `driver setup` is optional
  and never overwrites a committed `groups.yml`. Three run-time behaviours DO
  change without re-running setup: a wildcard `tests:` glob (`**/*_test.go`)
  is scoped to the vertical's own directories and files that name it (the
  files it used to credit elsewhere are reported once, to stderr and
  `scoped_tests_warnings`); leftover test-tree files sweep into a `Tests`
  group; a committed `Tests` (or `Tests:*`) suppresses that sweep. Escape
  hatch when the old crediting was intended: move the glob from `tests:` to
  `match:`.
- Deferred: `driver run --max-per-group` still chunks at run time and does
  not read `config.json`; the durable profile (`profiles.yml`) and the scout
  short-circuit, and `--seats` calibration, are plan 2.

## 5.1.0 — Measurement

The release where the scanner's own numbers became worth reading. 231 commits,
37 issues.

- **A grade that discriminates:** the max-severity rollup had SATURATED — ten Ds
  and one F across eleven runs, unable to tell any two codebases apart. It is
  replaced by a bounded health index (#1473, #1456, #1146).
- **A cost ledger that reproduces:** `meta.cost.tokens` goes from usually-null to
  collected automatically, over a window bounded at BOTH ends, so a run's ledger
  still reproduces after the fact (#1450, #1453, #1494).
- **Grouping becomes controllable rather than implicit:** `--max-per-group` is
  exposed and defaulted to 48 after a measured cap series (#1462, #1488),
  subgroups roll up to their parent in the report (#1305), and a chunk states its
  parentage instead of having it inferred from its name (#1480).
- **Per-run folders** (#1130) and **X0X catalog-gap emission** (#1132) land as
  planned. Tool-aware review ships as a SEC-cell proof of concept (#1307); the
  full treatment is deferred to 5.2 (#1131).
- **The tool axis is repaired end to end:** dependency-check no longer certifies
  off a build file alone (#1474), a tool verdict is keyed to its dispatched cell
  rather than an echoed id (#1475), and the void gosec axes were re-measured
  rather than caveated (#1477).
- **The remaining 136 fixes** are self-scan remediation from runs 6-10, plus the
  calibration apparatus that made five targets measurable — including two
  pre-registered predictions, one of which failed and was recorded as failed.

## 5.0.1 — Honest instrumentation

The first 5.0 point release: the residuals surfaced by the BursarBuddy
calibration and the 5.0 PR sweep, all keeping the pipeline's self-reporting and
gating honest.

- **Honest cost ledger:** `meta.cost` enumerates every 5.0 driver dispatch class
  from its own on-disk artifact — review cells, verify primary/backup, the tool
  round, and the scan — instead of only scout + a lumped advisor row (#1030).
- **Cheaper verify:** the second-witness backup re-reads only its scoped claims'
  files (not the whole cell), and the per-finding tool-advisor runs on a lighter
  model — the biggest cost lever, with zero coverage loss (#1029).
- **Honest tool certification:** coverage certifies against the runner's
  deterministic adapter manifest (`selected/produced/missing`), not the scout's
  free-form tool list, so a scout naming an absent/inapplicable tool no longer
  sinks the gate (#1031); `eslint-security` reports empty-valid on a
  nothing-to-lint target instead of a skip (#984).
- **Nightly image health:** a push-triggered keep-alive re-enables the
  `panopticon-tools` schedule, and a freshness heartbeat fails loudly on a stale
  image (#1032).
- **Driver robustness:** the clean-tree tamper guard reads `git status -z` and
  checks both rename endpoints, plus atomic manifest writes, spawn-error
  wrapping, and a tools crash-vs-skip marker (#1033).
- **OCRDb consumer & matrix hardening:** a distinct exit code for a corrupt
  bundle, a `ZZZ-X0X` sentinel for a domainless code, `code_domain_mismatch`
  disclosure, and the `{criteria}` advisor lens — the domain-advisor now grades
  against a code's explicit pass/fail criteria where defined (#1034, #1035).
- **Config dedup:** `model_resolver` is the single owner of the host
  role→model map; the duplicate `EMIT_MODEL_POLICY` is retired (#1036).
- **Severity discipline:** an explicit CRITICAL-vs-HIGH bar in the reviewer
  prompt so CRITICAL is earned, not defaulted-to (#1038).
- **OCRDb feedback groundwork:** an `x0x-report-schema.json` — Panopticon's
  catalog-gap findings as candidate records for OCRDb's new-code pool (schema
  only; emission wires up in 5.1).

## 5.0.0 — The matrix flagship

- Review is now a single resumable **driver** (`skill/scripts/driver.py`,
  subcommands `setup`/`run`/`next`) that the host drives through a status
  protocol; the legacy orchestrator is retired (P6 collapse). Phases:
  discovery → coverage → tools → review → verify → synthesize → validate.
- **Coverage:** per-group `scout` profiles widen a committed capability floor;
  the universal-tier floor `{COD,DAT,TST,ARC}` is injected but **surface-gated**
  per group — a testless / db-free / single-module group drops the floor cells
  it has nothing to review, disclosed at `global_floor_suppressed` (#5.0-19).
- **Verify:** every finding is adjudicated by an independent advisor; gate-
  eligible findings get a second (backup) witness, and deterministic tool
  (SARIF) findings are routed through a per-finding advisor so they can reach
  `tool_confirmed` and stop forcing spurious `INCONCLUSIVE` (#5.0-03).
- **Integrity:** driver-path anti-tamper controls are wired —
  `dispatch-plan-driver.json` declares every review cell (undeclared-file
  reconcile) and `out-file-hashes.json` snapshots each cell's bytes at the
  review→verify boundary (content-substitution check) (#5.0-16).
- **Enforcement:** fan-out reviewers/advisors hold a write-guarded, single-file
  `Write`; hostile-target path confinement and status-protocol crash hardening
  across the #1014–1027 series.
- **Reporting:** every report carries `meta.cost` (dispatch ledger) and
  `meta.integrity`; the CI gate keys on `summary.gate` + `summary.coverage_certified`.
- Validated end-to-end against the BursarBuddy answer-key corpus: recall 8/11,
  precision 1.0, perfect decoy discrimination, all controls firing on a real
  hostile target.

## 4.3.2 — 4.x freeze closer

- Added `meta.cost` dispatch ledger — `{phase, role, model, count}` rows derived
  from scout profiles, dispatch-plan union, and verify queue, plus a `tokens`
  slot reserved for host-reported usage.
- Fixed a ledger bug: `dispatch.build_plan` stamped `security_mode` on
  `lens_sweep` but omitted it from `panel_review`, so `plan_contract` rejected
  every plan with a panel and synthesize silently dropped all fan-out rows.

## 4.3.1 — External review point release

- Path-variant clustering: `evidence.norm_path` is the single owner of finding-path
  normalization so prefix/backslash dressing cannot split clusters.
- Delta discovery uses `--find-renames` for rename-semantics parity with
  `diff_map.hunk_map`.
- Un-loadable verdicts count as a gate-relevant coverage gap: a PASS with lost
  verdicts reads `INCONCLUSIVE`.

## 4.3.0 — 4.x series wrap

- Codex host support: `codex` model profiles, `--emit-host-agents codex`, and
  codex-runner wiring.
- Added `meta.integrity.empty_dispatch_plans` to the certification gate.

## 4.2.0 — Tool-policy enforcement

- Uniform read-only/return-JSON role contracts for every reviewer role.
- `--emit-host-agents` generates registered enforcement shells (claude/kimi
  dialects) from host-neutral templates.
- Per-role `enforced` plan entries dispatched via `subagent_type`;
  `meta.coverage.tool_policy_mode` records the runtime posture.
- Added clean-tree check in the validate step.

## 4.1.0 — Claude Code port

- Deterministic rendered prompts: dispatch-plan entries carry `prompt`, and
  `--render-advisor` renders verify-queue entries.
- Agent templates get host-neutral frontmatter (`tool_policy` as data);
  advisory-by-prompt on raw-prompt hosts.
- Explicit host selection (`--host`) with fixed env fallback (`CLAUDECODE`).

## 4.0.0 — Epistemics core

- Two-axis severity × evidence model: severity is never mutated; evidence.status
  is the pipeline verdict.
- Verification moved out of synthesize into an orchestrator-dispatched verify
  phase (`--emit-verify-queue` → advisor fan-out → `--verdicts-dir`).
- Gate/grades key on confirmed evidence by default, with `--gate-unverified` opt-in.
- Reinforced (tool+agent) findings gate as `tool_confirmed`; legacy confidence
  bumps removed.

## 3.0.0 — Multi-model reviewer dispatch

- Added role-based dispatch layer: `scout`, `lens_sweep`, `panel_review`, `advisor`.
- Added `scripts/model_resolver.py` for cross-platform model selection (Kimi / Claude / OpenRouter).
- Added `scripts/depth_planner.py` for depth-aware lens spawning.
- Added `scripts/dispatch.py` to emit `DispatchPlan` JSON for agent fan-out.
- Added `scripts/synthesize.py` advisor trigger and verdict application.
- Added Kimi Code custom agent files under `agents/`.
- Updated `SKILL.md` frontmatter and fan-out step.
- Added CI workflows for tests, lint, CodeQL, and full static-analysis scans.
- Updated `pyproject.toml` with project metadata; added `LICENSE`, `README.md`, `CODEOWNERS`, `CONTRIBUTORS.md`, `CONTRIBUTING.md`.

## Earlier releases

See [DEVELOPMENT.md](DEVELOPMENT.md) for the detailed pre-3.x version history.
