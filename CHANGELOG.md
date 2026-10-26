# Changelog

## Unreleased

- **Fix: a second headless `driver loop` on the same run no longer re-arms, and then disarms, the live loop's guards (#3227).**
  - The batch record's O_EXCL create is the batch's lock, but it came after `Guards.arm`, the launch backoff and the shape proof. A loop that lost the race had already rebuilt the run folder's settings file and re-installed the same entries' grants. It was then refused, and its exit took those grants down under the loop still running.
  - Headless mode now opens the batch record first, so a refused loop has armed nothing. If arming, the backoff or the proof raises after the open (an interrupt included), the record is closed and the failure reads as before. A process killed in that window leaves a record with no artifacts and a dead owner, and the next loop rolls it back as an ordinary stale batch.
  - The guards now come down before the record is released, on the clean end of a batch and in that failure window, as the interrupt path already did. Released first, the lock let a second loop open in the gap and arm the same ids, only to have them stripped.
  - `Guards.disarm` now drops what it disarms from `armed_entries`. The error-exit teardown no longer takes down ids this loop had already disarmed, which may by then be another loop's.
  - Session mode is unchanged: it arms and prints the batch without opening a record.
- **Fix: `--pr` no longer launches `gh` and the PR fetch's `git` by bare name from the operator's PATH (#3222).**
  - These are the two launches that keep the operator's environment, which the credential helper needs. They were found on the inherited PATH and ran before #3270's PATH check, which applies only once the worktree is acquired. A `.` or `<repo>/bin` entry could run a binary the target planted.
  - Both now go through the new `executable.operator_launch`, which resolves them the way `safe_git` resolves its own git (against the checkout boundary). Relative entries are dropped, and an entry inside the checkout halts with `TargetPathEntry` before anything launches. They launch by absolute path with PATH replaced by the resolved one.
  - Their environment also goes through `sanitize_startup_environment`, the existing policy for trusted CLI launches. It removes loader and interpreter startup hooks (`LD_*`, `DYLD_*`, `PYTHONPATH`, `NODE_OPTIONS`, ...), and `GIT_EXEC_PATH` is removed too: a fetch execs its transport helpers from there, and `-C` does not override it. HOME, `GH_*` and other `GIT_*` variables still arrive, so private-repository auth is unchanged.
- **Fix: a findings link re-pointed after the fan-out snapshot no longer drops out of the integrity check (#3249).**
  - The snapshot records each review cell by its realpath. A link re-pointed afterwards resolved to a key the snapshot never saw, so `verify_out_file_hashes` skipped it and the recorded cell went unverified. `reconcile_findings_files` could not see it either, because it realpaths the plan and the ingested path at the same moment, so both moved together.
  - Every recorded cell must now be re-read. One that no ingested path resolves to is listed in `meta.integrity.content_mismatched_files` under its recorded path, and the run is not certified. No legitimate path removes, renames or rewrites a recorded findings file between the snapshot and synthesize, so a clean run is unchanged. No schema change.
- **Fix: a `--pr` run no longer writes its reports through a `.panopticon` the target committed (#3225).**
  - In `--pr` mode first contact vets the throwaway worktree, never the caller checkout, so the caller's `.panopticon` is whatever the target's default branch committed. A committed `.panopticon -> /elsewhere` link redirected the surfaced `<tag>-report*.json` and `.html` there.
  - The surface now checks the root (`plan_contract.artifact_root`) and then holds it open (`O_DIRECTORY|O_NOFOLLOW`). Every staging write, publish and `report.json` relink is made relative to that directory fd, so a swap of the name after the check cannot move a write out of the tree. A path-based confinement check (`safe_write.confine_artifact_path`) would not catch that swap, because it anchors on the link's own target.
  - A refused root, a source over 16 MiB, a platform without the `*at` calls, or a relink that cannot land is now a failed surface. The worktree is kept and stderr says why, instead of a partial copy or a traceback after the copies.
- **Tests: the kill path's known escape is pinned, and so is what keeps the reviewed tree out of it (#3294).**
  - A descendant that calls `setsid()` or `setpgid()` leaves the process group `procgroup.kill_group` signals, so it outlives a timeout or a Ctrl-C. `test_procgroup.py` now pins that as a strict xfail, so a future sweep has to update the docs it would make wrong.
  - The reviewed tree cannot start such a descendant: no role grants an exec tool, Claude and Kimi deny their shell tools on every launch (the setup scan included), and Codex runs with `shell_tool`, `unified_exec` and `shell_snapshot` off. The new `tests/test_no_exec_grant.py` fails on any change to that, and its message names the sweep designed in #3294 as what has to land with the grant.
  - Today only a vendor CLI's own helper process can escape. `procgroup.kill_group`'s docstring and DEVELOPMENT.md's known-limitations section say so. No runtime behaviour changes.
- **CI: the security gate no longer excuses a HIGH that changed file, and the one-time Semgrep scope rescan is gone (#3273 cut 6).**
  - Withdrawn: #2309's "pre-existing (moved)" category. A head finding the exact baseline match leaves new used to pair with an unspent base copy of the same tool, rule and message at another path, and did not gate. That let a deletion in one file excuse an addition in another, which on a fork PR is a placement the author picks. The identity is path-keyed again, so a relocated HIGH is new.
  - The cost: a verbatim extraction that carries a standing HIGH into another file reds the required `scan`/`fork-scan` check on that PR, as it did for #2305. There is no in-repo way through: `# nosemgrep` is ignored under the `--security redteam` every CI route passes, and the gate does not read Security-tab dismissals. The owner can merge past the red check (branch protection on `main` does not enforce it on admins). The next PR is clean, because the merge's own captures carry the finding at its new path. `DEVELOPMENT.md` says the same.
  - Removed: the #2109 Semgrep scope transition (`tools_manifest.py`'s `semgrep-scope-transition-needed` / `prepare-semgrep-scope-baseline` CLI and the three workflow steps that called it on each route). It rescanned the base commit only when main's artifact predated the `test-paths-v1` marker, and every main capture since b8ddb8e2 carries it. The manifest's `scanner_scope` field and its validation stay.
  - Unchanged: the exact baseline match (#1790), its multiset rule, the five-ancestor walk, and every fail-strict path for an unusable baseline.
- **Changed: a `paused` run no longer prints a composed resume command, and the "uniform instant failure" stop is gone (#3273 cut 10).**
  - The host-outage pause now ends with the way back in words: re-run the same command with the same flags once the host is back, the bounds included (`--max-budget-usd`, `--max-iterations`, `--concurrency`, `--entry-timeout`, `--max-turns`). `runners/resume.py` is deleted. The engine still refuses a resume that changed an anti-drift flag.
  - The second stop rule (#1732: a batch whose first results were one identical sub-2-second entry-class failure) is removed. A broken launch of our own is now stopped by the per-entry cap after three rounds, as before #1732. The host-outage classifier, the trailing-run tally, the budget stop and the launch backoff are unchanged.
  - Tests: the classifier's five test classes are one table of 150 cases, each tagged with the review finding it came from, and none was dropped. The 50 KB backtracking bound stays its own test. About 9 s comes off the suite.
- **Internal: `procgroup` docstrings trimmed (#3273 cut 13).** The own-group check in `_pgid` stays: a reaped pid recycled to one of the driver's own same-group children can reach it while `terminate_children` races `launch`'s reaping thread.
- **Internal: the three guard hooks share one `guard_rules.py` instead of three copies (#3273 cut 11).**
  - The read scope, the binding, the findings component walk, the v2 allowlist and the settings plumbing now live once, in `skill/scripts/guard_rules.py`. `read_guard_hook`, `write_guard_hook` and `kimi_guard_hook` load it by path from their own directory when they run as hooks (`<python> -I <abs path>`). They never use `import scripts.*`, which a foreign `scripts` package in site-packages could answer. Imported under our package, they take the sibling module, so a patch lands where the hook looks.
  - Any failure to load it (a missing file, a raise or a SyntaxError in it, a name it lacks) denies every call the hook guards, exit 0 with the deny JSON. Never a crash, which would fail open.
  - The settings helpers take the hook's script path as a parameter. The Codex broker keeps its 24-line copy of `_under`, `_in_dir_grant` and `SCOPE_KEYS`, now byte-identical and pinned by the same single test as the three hooks' loader stanza.
  - The hooks' docstrings no longer overstate `-I`: it keeps PYTHONPATH, the user site and the script's directory off `sys.path`, not the interpreter's own site-packages.
  - `read_guard_hook.py` goes from 726 to 486 lines and leaves the ceiling list; `write_guard_hook.py` goes from 1184 to 875; `kimi_guard_hook.py` from 571 to 344.
- **CI: the AI-usage inventory leaves the Security tab again.**
  - Since #1335 and #3193, every Semgrep capture carries Panopticon's own run stamps, `panopticon_scanned_files` and `panopticon_size_skipped`. `code_scanning_reports.py` read them as unreviewed metadata and failed closed, so all 270 `detect-generic-ai-*` notes stayed on the Security tab and kept main's alert audit red.
  - Those two keys, in exactly their writers' shapes, are now a reviewed run context. Any other key or shape still keeps the run actionable.
  - On the live captures, 1,544 inventory results now route to the AI inventory; 0 did before.

- **Fix: the fixture runner no longer leaves a container running after a timeout (#3246 S4, #3273).**
  - On a timeout, `subprocess.run` kills the `docker run` client, which cannot forward the kill, so the `--rm` container kept running and was never removed. For `run_tests` that was a 30-minute pytest container with CPU and memory caps.
  - Both `run_fixture_tests.py` launches now name their container. A timeout or an interrupt removes it with `docker rm -f <name>`. A failed removal is reported with that command.
  - Tests: `tests/test_orchestrate_outage.py` stubs the backoff sleep (the schedule is still the shipped one), so it runs in about 10 s instead of 37 s.
- **Internal: `safe_git` stops policing its callers' argv (#3273 cut 17).**
  - Removed: the refusal of redirecting global options (`-C`, `--git-dir`, ...), of a caller `-c` that undoes a pin or re-enables a neutralized driver, of `--ext-diff`/`--textconv`, and `mutate`'s three-shape allowlist. Every caller is our own code and puts a literal subcommand first, so no target-derived token reaches a global-option position.
  - Unchanged: everything that bounds the target's repository, namely the environment scrub, the trusted git outside the checkout, the fsmonitor and hooks pins, driver neutralization with its confirmation re-read, the submodule bounds, `--ignore-submodules=none` on `status`, the shared deadline, and `mutate`'s unskippable preflight.
  - A target file named like a global option (`-C`) after `--` is no longer falsely refused. `safe_git.py` goes from 852 to 745 lines, and its ceiling pin moves down to match.
- **Internal: synthesis drops read-side repairs that first contact made dead weight (#3273 cuts 12 and 16).**
  - The tools manifest's `sanitized`, `network`, `cleanup_failures` and `language_detection_skips` blocks are read as written. Their producers bound each one, and first contact (#3271, #3296) halts on any `.panopticon/` this machine did not create. An honest run's coverage output is byte-identical.
  - `groups.json` is no longer repaired row by row. A file whose shape the report cannot carry (`groups` not a list, a row not `{name, files, parent}` strings, a non-string `mode`, or an unknown `security_mode`) is rejected whole and announced like an unreadable one. This matters only for a hand-named `--groups`: the driver's own file is discovery's.
  - The repairs of target-carried text stay: exclusion globs, the SEC carve-out, Git-driver keys and suppression counts.
- **CI: main is gated and audited nightly, not on every push (#3292, cut 18).**
  - `security.yml` and `codeql.yml` drop their `push` triggers; a merge commit's baseline is its PR's own captures (#3295).
  - New nightly `main-audit` route (06:41 UTC): delta gate against the commit the previous scheduled run scanned, Security tab upload, raw captures, and the zero-alert audit. Its check name is `main-audit`.
  - CodeQL runs nightly at 05:41 UTC, plus on dispatch.
  - A merge between the two nightly runs reds that night's audit (fail-closed); the next night retries.
  - The weekly `strict-full-tree` run is unchanged; its history lookup now selects the previous strict run by run title.
  - Each step selects on one job-level `ROUTE`.

- **CI: a merge commit inherits its PR's scanner captures as the security gate's baseline (#3292).**
  The baseline walk in `security.yml` and `security-fork.yml` falls back, at each main commit with
  no run of its own, to the merged PR's own `security.yml` run. It accepts that run only when it is
  a same-repository `pull_request` run for the merge's second parent and its head tree is the merge
  commit's tree, so the capture is exact. A fork's run is never read. This is the first step toward
  dropping the full rescan on every push to `main`; the push trigger is unchanged in this change.
- **Fix: a large setup proposal wrapped in prose or code fences is read as its OUTER document.**
  `tolerant_json.first_balanced_object` kept at most 256 closed spans in closing order, so a reply
  nesting more than that (a monorepo proposal: one object per group, layer and profile) lost the
  outermost object, and ingest refused the proposal ("'groups' must be a non-empty list") after
  a paid setup dispatch. Seen twice on langfuse in the 2026-10-24 calibration batch. A closing span
  now supersedes the inner spans it encloses.
- **Operator-visible: hand-run `synthesize.py` and `discovery.py` make first contact's `.panopticon/` half (#3273 P1).**
  Before they read or write a run artifact, they check H1-H3 and the ownership mark on every tree
  one of their artifact paths lies in (`--groups`, `--run-dir`, `--tools-dir`, `--verdicts-dir`,
  `--diff-hunks`, `--out`, as spelled and as resolved), and `synthesize.py` checks its cwd too. A
  tracked, planted or foreign `.panopticon/` now exits 2 with the first-contact line instead of
  being read.
  - An absent or empty `.panopticon/` is marked ours only when that invocation writes into it.
    The mark is the one first contact writes, and on a new machine this creates the stamp key.
    So `discovery.py` → `synthesize.py` by hand, and synthesize's two passes, keep working.
  - Findings collected by hand belong outside an unmarked `.panopticon/`.
  - A link planted in `.panopticon/` now halts synthesis at first contact (H3), before the
    writers that refuse it. The halt leaves the link in place for the operator to remove.
  - `run_tools.py` (CI) stays markless. The driver's own steps are unchanged: their tree is
    already ours.
- **Operator-visible: a resumed run no longer trusts two stored files it did not bind (#3280, GHSA-wjpr-jxg9-rmwh's family).**
  - **The readiness tail on `driver setup` / `driver loop --setup` completion.** It is read off
    `setup-report.json` only when those bytes are the ones this setup run recorded (their sha256, in
    the stamped setup manifest). A replaced, deleted or unrecorded report now ends the line with
    "— readiness: not verified for this run; see setup-report.md", never a stored "readiness OK".
  - **The output-schema shape verdict (#1732)** is now a once-per-run stamp in the run's manifest,
    or in setup's own manifest. Every reader decides from the stamp. `host-capabilities.json` only
    displays the verdict, so a replaced one can neither skip the run's one shape proof nor strip
    `--output-schema` from its entries.
- **Operator-visible: first contact replaces the older provenance and symlink checks (#3271 B2).**
  `driver loop` and `driver loop --setup` now make first contact (H1-H3, and on the operator's
  checkout too under `--pr`) before they read the run's host off the manifest, read the outgoing
  dispatch request, or recover a crash record. A planted or tracked `.panopticon/` halts the loop
  there, before any runner is built.
  - The "ignoring foreign run-manifest.json / setup-manifest.json" stderr lines are gone. Such a
    manifest halts at first contact (H1 or H2) instead of being discarded and rebuilt.
  - **Contract change:** a directory symlink planted at the active run folder (`runs/<tag>`),
    `tools/` or `verdicts/` used to be unlinked by `--reset` cleanup while the run went on. It
    now halts the run (H3). `--reset` moves the whole `.panopticon/` aside, and the link's
    referent is never read or deleted.
  - When trusted git cannot be launched for first contact's tracked-path check, the run now halts
    with one H5 line rather than raising.
  - Standalone `run_tools.py` (CI runs it directly) does not make first contact. It keeps its
    read-only check that `.panopticon` is a real in-tree directory, and writes no stamp key and no
    mark. (Standalone `discovery.py` and `synthesize.py` make the `.panopticon/` half since #3273.)
  - `driver readiness` keeps its own foreign-manifest check, since it writes nothing.
- **Operator-visible: a manifest first contact cannot read whole halts the run (#3271 F0).**
  A `run-manifest.json` or `setup-manifest.json` that is present but oversize (over 1 MiB),
  not a regular file (a FIFO no longer hangs the run), unreadable, not valid JSON, nested past
  the JSON depth bound, or not a JSON object now halts with H2 (`--reset` discards it). Before
  this, such a file could pass first contact as "no manifest". Only an absent manifest means
  "no manifest". Every reader of the two manifests (first contact, the driver's own loaders,
  and `collect_usage`) now shares one bounded reader and one cap, so the manifest first
  contact verifies is the one a resume acts on.
- **Operator-visible: hard links are a first-contact halt, not a per-read rule (#3271 B1).**
  The read guards (Claude, Kimi) and the Codex read broker no longer refuse a multiply-linked file
  inside a directory grant, and `driver setup` no longer walks the tree for them or prints the
  "re-clone without hard links" line: a file hard-linked out of the tree halts the run at first
  contact (H4), and `driver setup` now runs that walk on every invocation. So:
  - an in-tree pair (a `cp -al` fixture, a pnpm store) reads like any file, Codex included;
  - the Codex `[skipped ...]` search note is gone;
  - a directory grant never covers its own `.git` store. Every reader refuses a path under
    `<grant>/.git`, and a `Glob` pattern naming `.git` is denied. `.github/` and `.gitignore` still read;
  - the Codex read-scope probe makes two reads instead of three, and Claude's `read-guard-armed`
    probe drives eighteen payloads instead of seventeen.
- **Tool findings in run artifacts and generated bytecode no longer disappear silently
  (#3269 G4, 5.3).** Findings under top-level `.panopticon/`, `.worktrees/` and `.git/`,
  or under `__pycache__/` / ending in `.pyc` or `.pyo`, remain out of the report body but
  now enter the disclosed suppression channel as `run-artifact` or `generated-bytecode`.
  Their counts and reasons appear in `meta.coverage.tools_suppressed` and both rendered
  reports. Both reasons are disclosed in both modes and gated in neither; under redteam,
  they are also counted in `tools_suppressed_not_gated`. Other suppression reasons retain
  policy C, and explicit operator exclusion globs retain precedence.
- **Artifact writers loudly refuse final symlinks instead of deleting them (#3269 G9, 5.3).**
  The overwrite and append guards no longer unlink and replace a symlink at a `.panopticon`
  artifact path. They leave the link and its referent untouched and return one typed refusal,
  which the driver reports as `status:error`. First contact remains the run-level halt for a
  planted link. Explicit output paths outside `.panopticon` retain their safe replace-without-
  following behavior; intentional artifact removal and the run's owned compatibility links are
  unchanged.
- **bundler-audit never retries without its scanner-owned config (#3269 G6, 5.3).**
  The image-pinned 0.9.3 invocation runs once with the generated empty `--config`. A rejected
  option or scanner failure now remains a coverage failure instead of launching a legacy second
  command that could read the target's `.bundler-audit.yml` ignore list. The legacy text parser
  remains for existing captures; the runner no longer downgrades to an unpinned command shape.
- **The HTML report CSP authorizes only its exact built-in script (#3269 G11, 5.3).**
  `script-src` no longer admits every inline script or same-origin script. Its sole source is a
  SHA-256 hash derived from the exact `_JS` bytes embedded in the self-contained report, so a
  script injected into report content does not share the authorized digest. Editing `_JS`
  automatically updates the policy instead of leaving a copied hash stale.
- **Dependency coverage is now a visible, certifying receipt (#3269 SCA, 5.3).**
  `meta.coverage.dependency_audit` records which dependency ecosystems were applicable and which
  dedicated SCA adapters were selected and produced output. If a dependency surface exists but no
  dedicated adapter produces output, coverage is NOT CERTIFIED, a would-be PASS is INCONCLUSIVE,
  and both rendered reports say “no SCA tool produced output on an applicable tree”. An empty
  generic Trivy SARIF earns no SCA credit.
  - osv-scanner applicability now matches the automatic parsers in the pinned v1.8.2 binary and
    the npm, PyPI, Go, RubyGems, crates.io and Maven databases baked into the tools image.
    `pyproject.toml` is covered by pip-audit when online; without that output it is not audited and
    the receipt is NOT CERTIFIED. `Cargo.toml` and `go.sum` alone are not audited and are NOT
    CERTIFIED (their `Cargo.lock` and `go.mod` counterparts select the offline scanners).
    `build.gradle` requires resolved JVM artifacts for dependency-check; without them it is not
    audited and is NOT CERTIFIED. `npm-shrinkwrap.json`, also absent from v1.8.2's parser table, is
    covered by npm-audit when online and otherwise is not audited and NOT CERTIFIED.

- **Operator-visible: first contact halts on a `.panopticon/` this machine did not start (#3271).**
  `driver run` and `driver setup` now assess the target once, before any phase writes, and halt
  with one fixed line on: a `.panopticon/` tracked in git; a `.panopticon/` holding anything but
  no `owner.json` carrying this machine's run stamp (planted, copied from another checkout, or
  left by a run from before this change); a symlink under it other than the run's own
  `runs/latest` and `report.json` links; or a file hard-linked to something outside the target
  (a git work tree's own `.git/` is not counted). The stamp is an HMAC keyed by 32 random bytes under
  `$PANOPTICON_STATE_DIR` (default `~/.local/state/panopticon`, 0700/0600), so a target cannot mint
  one. **Upgrading:** a checkout with a `.panopticon/` from an earlier version halts once; move it
  aside (`mv .panopticon .panopticon.old`) or pass `--reset`, which moves it aside for you and
  starts fresh. A tracked `.panopticon/` is never moved; remove it from the index. Starting over an
  earlier run by another host on the same machine is disclosed (`meta.prior_run`), not halted on.
  The published report now spells the operator's home as `~` in `meta.apps[].path`.
- **Operator-visible: a PATH entry inside the target now halts the run (#3270, owner ruling D2).**
  An entry inside the reviewed tree -- or one whose program is a symlink into it -- used to be
  skipped silently. It is hostility or a badly broken machine, and most often the operator
  activated the target's own virtualenv or the target's direnv `.envrc` ran. The run now stops at
  first contact with one line naming the entry and the fix: "PATH entry <entry> is inside the
  target; remove it (deactivate the target's virtualenv or direnv) and re-run". Empty and relative
  entries are still ignored.
- **The tools image is named by its id, and the scan runs by that id (#3270).** `run_tools` resolves
  the `panopticon-tools` tag to the image ID (`docker image inspect`'s `.Id`, which every local
  image has, offline included) and dispatches every container by it, so a tag moved mid-run cannot
  swap the image. `tools-manifest.json` and the report's `meta.tools.image` record the id, any
  registry digests (informational; a local build has none) and `adapter_code`, one sha256 over the
  checkout's `skill/scripts` that every dispatch mounts over the image's baked copy. An image whose
  id cannot be read halts the run; no docker or no image is still the disclosed skip.
- **Every external app a run launches is named (#3270).** The host CLI (claude, codex or kimi) and
  docker are recorded with their path, version (`--version`) and sha256 -- in
  `host-capabilities.json`, `tools-manifest.json` and the report's `meta.apps` -- and each gets one
  line on both views. The host probes now launch through the hardened launcher (trusted PATH,
  own session, group kill, bounded capture) instead of a bare `subprocess.run`.
- **roslyn-secguard is opt-in, off by default (#3265, owner ruling 2026-10-23).** It is the only
  adapter that executes the target's own code (its MSBuild/analyzer build), so a hostile repository
  got code execution inside the tools container. It now runs only with the operator flag
  `--allow-target-build` on `driver run`/`loop` (carried to `run_tools` off the run manifest, and
  into a resume). A target's `panopticon.yml` cannot set it: the key is operator-only and refused.
  Without the flag a C# target is still covered by Semgrep, and the report says once, in
  `meta.coverage.target_build_not_run` and on both views: "roslyn-secguard not run: it executes the
  target's build; pass --allow-target-build to enable." Off by default never counts as a coverage
  loss. The containment armor stays for the opt-in path.
- **roslyn-secguard names the projects its one build does not reach (#3248).** It analyses one
  solution or project. The `.csproj` files that solution does not reference -- found by the same
  pruned walk, never read off the solution's text -- are now listed in the coverage manifest's
  `sanitized` block and on the coverage line ("N projects not analysed"), not only on stderr.
- **Language-keyed scanners no longer disappear silently behind the selection prune (#3247,
  5.3).** Automatic language detection still keeps #1138's vendored/generated/sample-directory
  prune, so a stray foreign-language file does not select a scanner that can produce no useful
  output. It now observes that reviewable surface in the same walk and records bounded
  `meta.coverage.language_detection_skips` rows when a language exists only there, naming the
  scanner not selected and the fixed reason. The terminal and HTML reports render the disclosure
  on one coverage line. Explicit `--languages` remains authoritative and omits this automatic
  measurement; dot directories and dependency/cache trees remain noise. The disclosure changes
  neither automatically selected tools nor certification.

- **`--online` pip-audit no longer builds a target-named source distribution (#3223, 5.3).**
  pip-audit resolves the generated requirements with pip in a temporary venv, and for a name
  published only as an sdist pip ran that package's `setup.py` / PEP 517 hook inside the online
  container. The launch now sets `PIP_ONLY_BINARY=:all:` (measured: pip-audit's inner pip reads
  it) and drops any inherited `PIP_NO_BINARY`. Cost: one name with no wheel fails pip's whole
  resolution, so pip-audit audits nothing for that target. That is still fail-closed, and the
  tool is now recorded `failed` with one fixed reason (no package name from the target);
  osv-scanner still covers the requirements. The `egress.py` disclosure of the Docker-gateway
  route now says it relies on this.

- **A host CLI that launches while a batch is being interrupted is ended (#3250, 5.3).**
  `terminate_children` copied the child registry and then replaced it with no lock, so a
  registration landing between the two went onto a list nobody read again; and a worker whose
  `Popen` returned after the terminate registered into the fresh list. Either way that child
  outlived the guard files. The registry now has one re-entrant lock (kimi's SIGTERM stripper
  terminates from a signal handler on the main thread, which also launches) and a closed flag:
  `terminate_children` closes it, and a later registration ends the child through
  `procgroup.kill_group` and fails the launch the normal way.

- **A host CLI's output is bounded (#3246, 5.3).** Every family launches through
  `HostRunner.launch`, which used `communicate()`: both streams kept in full, with no byte cap, up
  to eight launches at once. Codex `exec --json` and Kimi `stream-json` echo tool results, so a
  hostile target could steer a reviewer into printing whole files. The launch now reads both pipes
  through the scanner runner's own bounded pumps (`tools/base.read_capped`, lifted out of
  `run_tool`, and `drain_stderr_async`): stdout up to 50 MiB, stderr's last 1 MiB. A CLI that
  prints past the stdout cap is stopped (its whole process group) and its reply refused as a
  launch failure, never parsed from a prefix. Timeouts behave as before. Known cost: the ledger's
  stderr excerpt is the HEAD of what is kept, so for a CLI that prints over 1 MiB to stderr it now
  starts mid-stream. Also: `semgrep_targets.oversized` iterates each directory lazily under its
  entry cap.

- **A code group with no security review cell is now named (#3245, 5.3).** SEC reaches a group from
  its committed `panels:`, the filename-keyed SEC floor, or the scout, so a config that never lists
  SEC plus a scout steered off it left a group of ordinary-named web handlers with no SEC cell, and
  only `coverage-<group>.json` said so. `meta.integrity.sec_less_groups` now names every group whose
  plan has no SEC cell and whose files have code (or whose file list is unknown), and both the
  terminal summary (`**Note:**`) and the HTML report print it, on certified runs too. It is a
  disclosure, not a gate: SEC was never those groups' floor, so certification is unchanged. The
  floor itself is unchanged: a content signal (framework imports, route decorators) was declined as
  a heuristic catalogue a hostile target dodges by renaming an import, and SEC on every code group
  (+13 cells on this repository's 27-group plan) is left as a cost ruling.

- **SpotBugs skips empty bytecode roots and discloses no-scan outcomes (#3252, 5.3).**
  The first existing `target/classes` or `build/classes` directory used to win even when empty,
  letting an empty Maven directory hide populated Gradle output. SpotBugs now receives every
  candidate containing a `.class` file at any depth, which its XML records under
  `Project/Jar`. With no populated candidate, automatic selection says `none scanned` and an
  explicit invocation exits non-zero instead of silently scanning nothing.

- **A deleted or gutted tree baseline no longer reads as a clean tree (#3255, 5.3).** Three ways to
  get "clean" from a baseline that measured nothing are closed. (1) `driver run` captures the
  baseline at the start of every invocation, so one deleted mid-run was re-captured by the next
  invocation with the reviewer's writes in it, as clean; it is now re-captured only until the run's
  first dispatch is recorded. (2) A missing baseline at validate read as a non-git target; on a git
  target it now reports the clean-tree check NOT MEASURED. (3) A v2 baseline without an `entries`
  object skipped the content-digest pass; it now reads as CORRUPT. All three fail validate closed,
  the way every other unmeasured baseline state already does, and name `--reset` as the remedy. No
  new manifest field: the dispatch signal is the existing #1727 request record.

- **One reviewer can no longer corroborate itself (#3254, 5.3).** A finding kept the `panel` its
  reviewer wrote, so one cell could label two adjacent findings with different panels and both came
  out `corroborated`: that evidence status with no advisor, at triage priority 0, spending the
  `--max-verify` budget on them. An agent finding's panel now comes from its review cell, the
  `findings-<group>-<domain>.json` name the controller chose; the reviewer's own `panel` value is
  not read, and the finding's `domain` is not used either, because filing across domains is
  allowed. A file whose name names no cell is one source, panel `code`. Findings from two
  different cells, or a tool and a reviewer, at one spot corroborate as before. Consequences: a
  cross-domain finding is shown under its writer's panel; the cvss/exploit rule for agent security
  HIGHs follows the cell; agent findings no longer carry the `redteam` panel. A finding whose
  reviewer-chosen panel differed from its cell's changes identity once across this upgrade: its
  `fingerprint`, which reconciliation groups runs by, includes the panel, and so does the coarse
  cross-run key of a finding with no OCRDb code.

- **A refusal note the target planted no longer reaches the setup retry (#3253, 5.3).** A refused
  reply is kept under `rejected/`, and the entry's next prompt quoted that record's reason as the
  controller's own words. Under `--setup` the run folder is the flat `.panopticon/` and the entry id
  is the fixed `setup-scan`, so a target that committed `.panopticon/rejected/setup-scan-1.json`
  spoke in the controller's voice on the first setup dispatch. The record now carries the run's
  `run_id`, both writers stamp it (the loop and `driver persist`), and the retry quotes a record
  only when that id is this request's: a planted record, one from an earlier run, or one written
  before this change gets no note. The reason itself is quoted as a JSON string, one line, because
  it can still echo a hostile reply.

- **Codex advisor instructions match the advisor verdict envelope (#3221, 5.3).** The shared
  Codex charter told every role to include `_panopticon`, but `panopticon-advisor` serves both
  single-finding and tool-finding checks whose seven-field schema forbids that extra property. In
  the owner's arm64 Ubuntu confirmation run, 211 of 588 first replies paid for this contradiction.
  The advisor shell no longer requests the stamp; domain-panel and domain-advisor shells still do,
  and the host profiles were re-emitted. An isolated replay of the 133 macOS entries that had
  previously failed for `_panopticon` accepted all 133 on their first pass, with zero rejected
  replies and zero returned stamps. All three production receipt schemas remain outside Codex's
  strict generation subset; the exact blockers and compatible provider-schema directions are
  recorded in the host-capabilities guide and follow-up #3241.

## 5.2.1 — Security patch

Fixes [GHSA-wjpr-jxg9-rmwh](https://github.com/panopticon-scanner/panopticon/security/advisories/GHSA-wjpr-jxg9-rmwh)
(high). Affects 5.1.0 through 5.2.0. Upgrade before running headless setup or review
on a tree you do not trust.

- **Headless guard settings are built fresh, not merged from disk.** A headless run's
  `host-settings.json` (setup's in `.panopticon/`, a review's in `runs/<tag>/`) now
  holds only the read and write guards' own entries, exactly as their installers write
  them, so nothing else a file on disk held reaches the host CLI's `--settings`. A
  session's `.claude/settings.local.json` is the operator's and is still merged.
- **`driver setup --reset` clears setup's `host-settings.json`.**

## 5.2.0 — Host expansion and hardening

The release where Panopticon runs on more than one host, and each host's
safety claims are proven by probe rather than declared. 653 pull requests,
1,223 issues.

- **Three first-class hosts:** Claude, Codex and Kimi each ship a family runner, and
  their capabilities come from a verified registry: a probe either PROVES a claim or the
  run says it does not hold (#1344). Gemini stays registered but not selectable (#1621);
  `--host generic` remains the unenforced, acknowledgement-gated fallback.
- **The orchestrator is on rails:** `driver loop` runs every step in order, headless or
  in session, so no step depends on the operator remembering it (#1615).
- **Read and write guards:** each headless entry reads only its own bounded scope (#3219),
  a review cell can write only its own out_file, proven by a real-CLI write canary (#3218),
  and a guard hook denies a payload too deep to parse instead of crashing open (#3186).
- **Grouping becomes a designed engine** (#1505), configured by a root `panopticon.yml`
  with a settings ratchet, and requests carry integrity checks end to end.
- **An all-exhausted run no longer reports success** (#3220): it exits non-zero with null
  grade and health instead of health 100, risk LOW, grade S.
- **Self-scan remediation through run 14**, then a red-team corpus of six runs on three
  platforms and two hosts plus two confirmation reruns. Every HIGH was fixed before the
  cut or verified below HIGH on the tagged commit.

The review-quality theme (tool-aware review, roster R2, economics, health-grade tuning,
multi-seat) moved to 5.3.

### 5.2 Claude first-class host (#1344, family PR)

The Claude family's first-class-host PR under `docs/FAMILY-PR-GUARDRAILS.md`:
Claude already shipped its runner, probes, emit branch, registry row and both
guards, so this PR is the evidence a real `driver loop` gives, plus what that
evidence exposed.

- **Codex readers bind one bounded scope document per entry (#3219, 5.2 blocker).**
  Whole-repository tool verification put every entry's grants into one shared file; at 584 entries
  it crossed the broker's 1 MiB input limit, so every advisor was blind and most returned noisy
  NEEDS_MORE_INFO verdicts. Headless launches now bind `read-scope/<entry-id>.json`, containing
  only that entry's normalized grants, while the shared hook registry remains available for
  session enforcement. The Codex runner validates the binding before launch, and the required MCP
  broker exits on a startup binding error, so a missing, malformed, or oversized binding is a
  retried and ledgered entry failure rather than a verdict. A 600-entry regression keeps the
  deliberately oversized shared registry while successfully loading all 600 isolated readers.

- **Codex shape proof distinguishes stderr from a structured error event (#2940).**
  A Codex launch rejected before JSONL could copy bare stderr into `host_error`, making the
  output-schema probe report `proven` without evidence that Codex accepted the argv. The result
  now records that provenance: a fast stderr-only failure refutes the shape and a slower one is
  unmeasured. A slow failure with neither stderr nor any JSONL event is likewise unmeasured, while
  ok launches, reply envelopes, and structured JSONL error events remain proven. Outage
  classification and other host families are unchanged, and disclosure names the actual
  stderr-only observation.

- **The NVD cache sync verifies the DependencyCheck zip fail-closed (#3224).** The keyed sync
  step in `nvd-cache.yml` ran without `set -e`, so a failed download or a `sha256sum -c`
  mismatch did not stop it, and the unverified zip ran with `NVD_API_KEY` in its environment. The
  step now runs under `set -euo pipefail`; the sync's own exit status is still captured as before.
  A test runs the step's real script against stub tools.

- **An empty review round stops and says so (#3220).** A run whose every review cell was
  exhausted ended `complete` with exit 0, and its report read health 100, risk LOW, grade S over
  zero review findings. A batch whose every self-writing entry was denied its own `out_file` was
  dispatched three times over (the 5.2 redteam amd64 run: about $14 on two identical rounds), because
  nothing read `denials`. Now such a batch stops after that attempt with an `error`. On Claude only:
  Codex's denial rows are read-broker failures and Kimi reports none, so the rule cannot fire there.
  A `complete` with every review cell exhausted carries `review_axis_empty: true` and exits 1.
  Partial exhaustion is unchanged. When no review cell answered, the report's `health.score`,
  `overall_grade` and `provisional_grade` are null; `risk_level` is the worst gate-eligible finding
  (a lower bound), or null when there is none; `coverage_note` leads with "no review cell answered".
  The gate is untouched: with `--fail-on` the missing floor cells still read INCONCLUSIVE. A write
  guard the #3218 canary left UNKNOWN because it measured nothing now asks for a re-run before
  `--allow-unenforced`.
- **Enforced Claude reviewers can write their own findings file (#3218, 5.2 blocker).** `claude -p`
  auto-denies a Write nothing approved, and the enforced launch kept only the operator's user scope
  (`--setting-sources user`), so on a box whose user settings grant no Write every enforced review
  cell was denied its own `out_file` (a 5.2 redteam run: 498/498 rows, no review at all). The
  enforced argv now carries one `--allowedTools=Edit(//<absolute out_file>)` token naming exactly
  that file. Measured on Claude Code 2.1.305 with no permissions in user scope: the create is
  allowed and a peer path stays denied; `Write(...)` grants nothing. The write guard still denies
  first. An `out_file` path holding `* ? [ ] { }` or a backslash is refused before launch, because
  the rule reads those as a pattern (an unescaped `*` granted a peer) and the escape cannot express
  `?` or a backslash. The unenforced argv is unchanged. `artifact_write_guard` on a headless Claude
  run now also takes one real `claude -p` canary launch (about $0.0005 on haiku), so a CLI that denies
  every granted Write no longer proves it. The canary is REFUTED only on evidence (a denial row naming
  its own file, or a peer written); a launch that measured nothing is retried once, then UNKNOWN.

- **Semgrep 1.181.0 (supersedes #3216).** The tools image ships semgrep 1.181.0, re-resolved
  the #3214 way; its declared requirements are 1.179.0's, unchanged. Also filelock 4.2.0 and
  pydantic-settings 2.16.0. tomli stays on 2.4.x (`tomli~=2.4.0`), and Dependabot no longer offers
  its minor or major updates. Measured with 1.181.0 on the pinned rules corpus: the corpus
  validates, and the timeout (#2957), size-skip (#3193) and scanned-file (#3194) readings are
  unchanged.

- **Semgrep 1.180.0 and a coherent Python closure (supersedes #3063, #3172, #3189, #3213).** The tools
  image ships semgrep 1.180.0 (was 1.179.0); its declared requirements are 1.179.0's, unchanged. The
  closure was re-resolved as a whole (`uv pip compile`, Python 3.12, both linux targets, the
  7-day cooldown): bracex 3.1, filelock 4.1.1, jsonpickle 4.1.3, pbr 7.1.3, platformdirs 4.13.0,
  pycparser 3.11, pydantic 2.14.1 with its exact partner pydantic-core 2.50.1, rpds-py 2026.9.1
  (also in the gate's closure), starlette 1.8.0 and zipp 4.1.1, plus certifi 2026.10.19 (a
  Dependabot security update, exempt from the cooldown); the fixtures image takes
  iniconfig 2.3.1, and the ruff floor is 0.17.0. Not taken, because semgrep 1.180.0 still
  requires the old line: mcp 1.30.0 (`mcp==1.29.0`) and tomli 2.5.0 (`tomli~=2.4.0`). Measured
  with 1.180.0 on the pinned rules corpus: the corpus validates, and the timeout (#2957) and
  size-skip (#3193) disclosures and #3194's scanned-file count read as they did under 1.179.0.

- **An absent severity fails closed too (#3210).** A reviewer finding with no `severity` (the
  key missing or null) used to read as INFO, so verify never engaged it and the gate PASSED,
  measured through the real driver at `--fail-on high` and `critical`. It is now read as CRITICAL,
  as #2990 reads an unknown spelling, and listed in `meta.integrity.unknown_severity_findings`.
  Its `severity_as_written` is null (the schema now allows it), so "none written" stays distinct
  from a spelling, and a new stderr line counts the two kinds apart. Tool findings are unchanged:
  both tool builders always set a severity.

- **An unknown severity fails closed, and a bad verdict entry is counted (#2990).** A finding
  whose severity is not one of CRITICAL, HIGH, MEDIUM, LOW or INFO (in any case) used to read as
  INFO. INFO is not owed a verdict, so on main a reviewer's `SEVERE` finding was never verified and
  the gate PASSED, measured through the real driver at `--fail-on high`. It now reads as CRITICAL,
  the one reading that fails closed at every `--fail-on`: verify engages it and the advisor's
  answer decides. The value as written stays on the finding as `severity_as_written` (inert,
  bounded), and the new non-gating `meta.integrity.unknown_severity_findings` lists those findings'
  ids, on the terminal summary and in the HTML report. A finding with no severity at all is
  covered by #3210 (next entry).
  Contract change: `meta.coverage.verdicts.unloadable` now counts verdict files or ENTRIES. A
  bundle entry that is not an object, names no known verdict, or echoes no `finding_id` used to be
  skipped and named nowhere; it is now counted per entry with a fixed reason (its values are never
  echoed), and the stderr line names files and entries apart. A non-zero count already makes a PASS
  INCONCLUSIVE, so such a bundle no longer certifies. Its finding stays unverified, as before.

- **Literal backslashes no longer select another tree's policy (#2988).** Finding paths and
  diff-map keys now treat only `/` as a separator. A HIGH finding on a root-level POSIX file
  named `docs\x.py` keeps its severity and fails a HIGH gate, instead of borrowing `docs/*`'s
  INFO downgrade. Literal backslashes also stay distinct in finding identities and clustering.
  Contract change: the old raw-backslash/slash alias is retired. Current Linux-image producers
  emit slash-separated repository paths; any producer with a different separator convention
  must convert at its own boundary before publishing a finding. Existing `./` prefix and
  in-repository absolute-path handling remain supported.

- **JWT redaction stays linear on repeated opening prefixes (#2986).** The JWT rule
  restarted at every embedded `eyJ` in a delimiter-free run and rescanned the remaining
  suffix, making a crafted 4 MiB refused reply take quadratic time before persistence.
  The rule now visits each maximal dot-separated base64url chain once and masks its
  legacy leftmost token in a linear segment walk. Text glued before the token is kept,
  while every token shape the old rule masked stays masked. A 256 KiB equal-size timing
  ratio pins both standalone and glued prefix runs, and the 4 MiB allowance is unchanged.
- **A failed synthesis stays pending on resume (#2930).** The driver records a pending attempt
  before launching synthesis and clears it only after an accepted result and a usable report.
  Invalid artifacts, scope refusals beside an old report, and interrupted children therefore
  retry on resume instead of silently skipping to complete. Reports remain available for diagnosis;
  a successful retry clears the marker, and a fresh run uses its own run folder.
  Compatibility: a run started before this version is not covered; an unmarked old report on
  first entry is also outside this guarantee.

- **A finding no longer borrows another claim's verdict (#3202).** When dedupe kept a survivor with no
  verdict of its own, #1476's id aliases let it take the verdict of a claim dedupe had dropped.
  Measured by id on main: an unanswered CRITICAL beside a REJECTED HIGH at one locus was published
  as rejected and the gate PASSED, where the CRITICAL alone is INCONCLUSIVE. The same happened for
  #1476's own pinned pair (an agent HIGH and a tool MEDIUM), for two equal-severity twins, and with
  NEEDS_MORE_INFO. The borrowed verdict was also counted as matched, which hid the survivor from
  `unanswered`.
  - **Contract change: #1476's alias binding is withdrawn; #2991's restore covers its
    CONFIRMED-loss case.** `evidence.match_verdict_by_id` binds a finding's own id only. The
    `_merged_ids` carrier (`record_merged_id`, `merged_ids`, the report strip) is retired. Nothing
    outside binding read it: a grep of code, tests and fixtures found only binding, #2991's alias
    cleanup and the tests pinning them. A collapsed member is still kept, as #2991's `_absorbed`.
  - An unanswered survivor is now unverified (or `tool_reported` where a tool reinforced it), and
    counted in `unanswered`. The gate is INCONCLUSIVE when the survivor is owed a verdict, and FAIL
    under `--gate-unverified`. A survivor's own verdict binds as before.
  - The verify queue's fingerprint path (`evidence.match_verdict`) never read aliases, so it is
    unchanged.
  Pins: `tests/synth/test_report_evidence.py::TestAClaimsVerdictIsItsOwn` covers the four cases,
  `unanswered`, and a survivor's own verdict. `tests/test_verdict_binding.py` is rewritten to the
  new contract and keeps #1476's concern: a collapsed CONFIRMED is still reported confirmed,
  through the restore. `tests/test_driver.py` runs the real driver with an advisor that answers the
  HIGH and leaves the CRITICAL unanswered: on main the report PASSES, now it is INCONCLUSIVE.
- **A confirmed finding is no longer absorbed by a decoy at the same locus (#2991).** Dedupe keeps
  the most severe finding at a file, line and category, and runs before any verdict is bound. A
  REJECTED CRITICAL "decoy" beside an honest CONFIRMED HIGH therefore survived, bound its own
  REJECTED, and took the HIGH out of the report: the gate PASSED where the HIGH alone FAILs.
  - Measured on main through the report builder, by fingerprint and by the driver's per-cell id
    bundles. A NEEDS_MORE_INFO or unverified CRITICAL absorbed the CONFIRMED HIGH the same way, and
    so did a tool's REJECTED CRITICAL beside an agent's HIGH (that pair collapses across
    categories). By id, an unverified CRITICAL survivor instead took the HIGH's CONFIRMED through
    its #1476 alias and was published as a confirmed CRITICAL.
  - Dedupe now keeps each dropped member on its survivor; what survives, and the pass-1 queue,
    are unchanged. After the queue is built, a dropped member whose OWN verdict (its own id or
    queue id, never an alias) is CONFIRMED is restored as its own finding and queued. That happens
    unless the survivor's own verdict is CONFIRMED too. The restored member's ids leave the
    survivor's aliases, so its CONFIRMED no longer stands in for a different claim.
  - Unchanged: two REJECTEDs collapse as before, and a CONFIRMED survivor still absorbs. A stale
    (other-run) or misrouted CONFIRMED restores nothing.
  Pins: `tests/synth/test_report_evidence.py::TestAConfirmedFindingIsNotAbsorbed` covers both
  binding paths and both orders, the NEEDS_MORE_INFO, unverified and tool-decoy variants, the
  unchanged collapses, stale and misrouted verdicts, and the carrier never reaching the report.
  `tests/test_driver.py` runs the real driver: per-cell verify lands both verdicts by the ids the
  driver assigned. On main the report PASSES with no findings; now it FAILS on the HIGH.
- **Semgrep's scanned-file count is read from what its real argv prints (#3194).** #1335 reads
  Semgrep's closing "Ran N rules on M files" line from stderr, so that a run that scanned nothing
  gets the `noscan` disposition instead of coverage credit. The adapter passed `--quiet`, which
  removes that line, so the reader never matched in production and `noscan` could never fire. The
  tests stayed green only because they fed the line in directly.
  - Measured with the pinned Semgrep 1.179.0 and the adapter's argv: under `--quiet` the line is
    missing on every target. Without it, the line is stderr's last (681 files on this repository;
    0 on an empty, an all-excluded, or an over-limit-only tree), in about 3 to 5 KB of stderr.
    That is well inside the capture's retained 1 MB tail.
  - The argv drops `--quiet`. The reader now takes the LAST line that starts with the summary, so
    target-authored text earlier on stderr, such as a file name in an error message, cannot stand
    in for the count.
  - Probed alongside, as asked: no other capture signal is parsed from stderr. At the time of this
    fix, bundler-audit's `Unknown switches` compatibility fallback read stderr; #3269 G6 later
    removes that fallback entirely.
  Pins: `tests/test_tool_capture.py` holds that the argv carries no `--quiet` and that the closing
  line wins. `tests/tools/test_legacy_sarif_integration.py` runs the real argv in the tools image,
  where the count is the number of files scanned and a real zero-file run reaches `noscan`.
- **A file over Semgrep's size limit is disclosed, not silently skipped (#3193).** Semgrep skips every
  regular file over 1,000,000 bytes and leaves no trace in its SARIF, so a target could hide a payload
  from every Semgrep rule simply by making its file large.
  - Measured with the pinned Semgrep, the vendored rules and the adapter's argv: the size check
    applies to any kind of file, binary included. It applies after the argv's `--exclude` patterns,
    and a symlink is never selected.
  - The host now lists those files when the capture lands (`scripts/semgrep_targets.py`) and stamps
    the capture with them. The walk never follows a symlink. It drops a path only for one of the
    argv's own exclude patterns, in a form whose result was compared row by row with Semgrep's own
    target listing; any other form keeps the file listed.
  - Each file lands in the semgrep `file_coverage` as `size_skipped`, so it reaches
    `meta.coverage.tools_file_partial` and coverage is not certified. A capture with no listing,
    a malformed listing, or a walk cut short counts as partial too.
  - The argv now states `--max-target-bytes=1000000`, Semgrep's default.
  - This repository excludes `.test_durations` (pytest-split timing data, 1.3 MB). It was the only
    file Semgrep skipped in the self-scan.
  Pins (`tests/test_semgrep_targets.py`): the matcher against the measured table, row for row; an
  unmeasured pattern form leaves its file listed; the symlink, exact-limit, awkward-name and bound
  cases; and a file over 1 MB with a canary goes through the stamp, ingest and report and is listed,
  with certification withheld.
- **Fixed-name staging writes refuse planted FIFOs and hard links (#2093).** The generic
  `.panopticon` writer opened `<path>.tmp` with `O_TRUNC` but not `O_EXCL`, as did the manifest,
  X0X and tree-baseline paths through that same primitive. A hard link at any of those names
  was therefore truncated along with its victim; FIFO opens were only bounded by the later
  nonblocking artifact fix. One shared staging opener now creates with
  `O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK`, reusing a leftover only when `lstat` proves it is a
  singly-linked regular file. The four writers use that opener, and reject symlinks, special
  files and multiply-linked files before writing. Pins in `tests/test_artifact_write_symlinks.py`
  put a FIFO and hard link at every fixed staging name, enforce a deadline and preserve the
  victim; `tests/test_safe_write.py` pins the exact flags and `tests/test_run_manifest.py` pins
  safe stale-file reuse and the stronger internal-symlink refusal.
- **A file Semgrep gives up on is disclosed, not silently dropped (#2957).** Semgrep stops running a
  rule on a file after 5 seconds, and it abandons the file once 3 rules have timed out on it. Either
  way that file's findings were missing, Semgrep still exited 0, and nothing in the report said so.
  - Measured on an idle machine with the pinned Semgrep and the vendored rules, using the adapter's
    command line: a target file holding one long string expression was abandoned on every run at
    400 KB. Every finding in it was lost, including the rule meant to flag `eval`.
  - Ingest now reads Semgrep's `Timeout` notifications from the SARIF, where the file is named only
    in the message text. Each timed-out file is listed in the adapter's `file_coverage` as
    `rule_timeout` or `timeout_abandoned`, with its count. That lands in the existing
    `meta.coverage.tools_file_partial`, so coverage is not certified and the coverage note names
    semgrep. Findings and the gate are unchanged.
  - A timeout whose file cannot be read off the message is still partial, counted as unlocated,
    and its text is never published. Semgrep's other notifications, such as `Missing plugin`, are
    not coverage gaps.
  - The limits are now stated on the argv at Semgrep's own values, `--timeout=5` and
    `--timeout-threshold=3`, and the guide says what each one does. They are not raised: with both
    off, a 900 KB file ran past 400 seconds, beyond the adapter's 300-second cap, which would lose
    the whole Semgrep run.
  - Not covered here: files over Semgrep's 1 MB limit are skipped with no SARIF trace (#3193).
  Pins (`tests/tools/test_legacy_sarif.py`): the real notification texts go through ingest into a
  report, which shows the gap, withholds certification, and keeps the same gate. A run with only
  `Missing plugin` notes stays complete. Unreadable notes count as partial and unlocated. The
  argv pins the two limits.
- **Review scope labels are complete and explicit (#2088).** Inventory mode `changed` now
  publishes `review_type: changes`, and mode `pr` publishes `pr`. Missing, unsupported or
  repaired-away modes halt synthesis with a named reason before writing a report. Standalone
  synthesis must declare its scope with `--repo` or `--changes`, or supply a groups inventory
  with a known mode; the two explicit scope flags are mutually exclusive.

- **A verify return that never answers is dispatched at most three times (#3185).** Verify charged
  an attempt only to a labeled bundle that answered nothing. A return that never loaded (nested past
  the depth bound, not JSON, or never written) re-dispatched its cell on every resume, so the run
  never ended: 44 dispatches over 25 resumes, still at the verify checkpoint.
  - Every verify dispatch is now charged when it is sent, the first one included, for primary and
    backup cells and for the tool round (key `tool/<queue_id>`). The cap is verify's own
    `_MAX_VERIFY_ATTEMPTS`, 3. A cell at its cap counts as done, and the run completes.
  - The labeled bundle that answers nothing is charged at dispatch too, so it now gets 3 dispatches
    instead of 4.
  - Nothing new is added to the report. The cell shows up in the existing keys:
    `meta.coverage.verdicts.unanswered`, `verify_matrix.unverified_engaged` and, for the tool
    round, `tool_axis.unanswered`. Coverage is not certified.
  - A paused verify checkpoint gives its charge back, as review's does.
  - Behaviour change: a verify entry that is refused or fails every time now ends the phase
    `complete` and uncertified at this cap, before the orchestrate loop's per-entry error cap is
    reached. The loop-cap tests lift the phase cap so they still test their own mechanism.
  Pins: the driver end to end, per return shape (`tests/test_driver.py`): exactly 3 dispatches per
  cell, then complete with the cell disclosed. The tool round, a backup cell, the pause refund, and
  charging from the first dispatch (`tests/test_driver_tool_verify.py`, `tests/phases/test_verify.py`,
  `tests/test_driver_verify.py`).
- **Tool output is bound to the scan invocation that wrote it (#2070).**
  `tools-manifest.json` now records the exact canonical capture basenames beside its run id. The
  tools marker, review prompt map, verification queue, synthesis, and security gate all filter
  through that receipt before the directory cap is counted; direct ingestion without a receipt
  remains compatible. Stale, unselected, alternate-suffix, or otherwise unreceipted captures are
  never parsed. Reports disclose them as certification-sinking
  `meta.integrity.unbound_tool_outputs`; a missing or foreign driver receipt also fails closed, and
  an unbound baseline makes the security gate fall back to strict gating.
- **A guard hook denies a payload too deep to parse instead of crashing open (#3186).** The read,
  write and kimi guard hooks parsed their stdin OUTSIDE their fail-closed envelope and caught
  `ValueError` only. A deeply nested payload raised `RecursionError`: a traceback and exit 1, which
  Claude Code and Kimi both treat as NON-blocking, so the tool call went ahead unguarded.
  - Measured: N=1,000 on 3.11 and N=100,000 on 3.14.
  - `RecursionError` and `MemoryError` at the parse now DENY on each hook's own channel, the deny
    JSON with rc 0, as their crash envelopes already do. The reason is named: "<read|write|kimi>
    guard: payload too deep to adjudicate (<error>)". Exit 2 was ruled out because it is fail-open
    on Kimi.
  - The tolerated malformed-JSON path is unchanged, and so is an ordinary payload. Where the
    interpreter parses the payload (N=1,000 on 3.12+), it is adjudicated like any other.
  - Whether a host passes a model-chosen nested value through to the hook was not measured.
  Pins: one per hook (`tests/test_{read,write,kimi}_guard_hook.py`): a `json.load` raising
  RecursionError or MemoryError gets the named deny; real payloads at N=1,000 and 100,000 never crash,
  getting either the deny or an ordinary adjudication where the interpreter parses them (the
  overflowing depth depends on the platform's C stack: 100,000 parses on x64 3.14).
- **A value nested past the interpreter's stack no longer ends a run in a traceback (#2959).**
  A finding or a verdict can carry one through the schema: a finding is an open object, and a
  verdict's `citations` is open. At 1,000 levels and past, the run died with `RecursionError`, status
  1 and no report.
  - Where it died: the driver's review and verify done checks (`runio._load_json`), synthesize's
    `redact_tree` and `group_runner.entry_is_done`. `persist.write_reply` RAISED out of both of its
    callers instead of refusing.
  - Onset by interpreter: 900 levels on 3.11, 1,000 on 3.12+, the codec alone at 20,000 on
    3.12/3.13 and at 100,000 on 3.14.
  - The fix is one primitive, `tolerant_json.depth_checked`, with `MAX_JSON_DEPTH = 64`; the deepest
    document this tree carries nests 13. It is an iterative scan run BEFORE every decode of an agent's
    or a scanner's document. Past the bound it raises the `JSONDecodeError` each reader already treats
    as malformed, so no new key is added. The scan is linear: a LONE quote, a string that never closes,
    ends it, so a truncated reply full of escaped quotes no longer rescans to the end at each one
    (review round 1: 64 KB took 5.8 s, quadratic).
  - What that does to each case:
    - a self-written cell is re-dispatched to its cap, then listed in
      `meta.integrity.malformed_findings_files`, and the run is not certified;
    - a reply is refused and retained, its reason naming the bound;
    - a scanner capture is `failed: unparseable: nested deeper than 64 levels`, and the other tools
      keep their findings;
    - the tolerant reader no longer digs a shallow inner object out of a too-deep reply, while #2531's
      prose braces before a real bundle still give it up.
  Pins (RED on main):
  - `tests/test_json_depth.py`: the bound, strings and escapes, one row per decoder at 65 and 100,000
    levels, and linear growth on an unterminated string of escaped quotes (str and bytes);
  - `tests/phases/test_persist.py`, `tests/test_ingest_tools.py` and `tests/test_tools_manifest.py`;
  - `tests/test_driver.py`: a self-written findings file reaches a report, and a verdict bundle is an
    ordinary checkpoint; its uncapped re-dispatch is #3185.
- **A target holding a file or directory whose name is not UTF-8 gets a report that says so
  (#2962).** On Linux such a name is legal, and the first run died on `UnicodeDecodeError` with
  no report: `safe_git` launched git in text mode, which decodes strict UTF-8, and its preflight
  `ls-files --stage` (under `status`, from `run_manifest`, discovery and `diff_map`) printed the
  name.
  - Both text launches now decode with `errors="surrogateescape"`, as `os.fsdecode` decodes a
    name, so `os.fsencode` returns the exact bytes and `_encoded` already round-trips them.
  - Behind the crash, #2964's key never saw such a name. `synth/artifacts.read_json` spells every
    lone surrogate (#2951) before `unreadable_name_files` read `groups.json`, so `caf<0xff>.py`
    arrived as the carryable `cafU+DCFF.py`, and the run was certified though no prompt could
    name the file.
  - `plan.load_groups_json` now reads once through the same capped regular-file read with
    `spell=False`, and hands the unspelled cell lists to that one check. Every other reader
    keeps the spelled document.
  - This closes #3183's surrogate path end to end.
  Pins: `tests/test_safe_git.py` (an index path with byte 0xff, on the unguarded and the guarded
  launch, on every platform); `tests/test_lone_surrogates.py` (the real synthesize child lists a
  lone-surrogate file and withholds certification, while its spelled twin is listed nowhere; a
  group NAME stays byte-for-byte its twin); `tests/test_driver.py` (a full run to `complete` that
  lists both names and is not certified, while a file literally named `okU+DCFF.py` stays out;
  Linux only, since macOS refuses the name).
- **A file named with a character the prompt escapes no longer goes unreviewed in silence
  (#2964).** A reviewer is handed only its prompt, which spells a TAB, a bidi control or a lone
  surrogate in a path inertly (`runio._prompt_safe`), and that spelling names no file on disk.
  Nothing compared the files a reviewer opened with the files it was given.
  - `meta.integrity.unreadable_name_files` now lists, in that inert spelling, every file in the
    run's own `groups.json` cell lists whose prompt spelling is not its name. It is read in
    `synth/integrity.py` through `scripts.inert.inert_spelling`, pinned equal to `_prompt_safe`.
  - It is a sinking `IntegrityKey`, "NAMES THE PROMPT CANNOT CARRY", so the run is not certified
    and the summary and HTML name the files.
  - The prompt is unchanged.
  Pins: `tests/synth/test_report_coverage.py`, covering a TAB, U+202E and a lone surrogate, plus
  the well-named control.
- **A finding's title is redacted before it is cut (#2971).** `normalize_finding` bounded the
  title (`inert_text`, 2,000 characters) and cut `short_title` (100) from the RAW title, and
  `redact_tree` ran later. A credential across either cut was left as a prefix no pattern
  recognises, and was published in `report.json` (`findings[].short_title`, `title`) and in the
  X0X (`candidates[].summary` and `proposed_name`). The title now goes through
  `redact.redact_diagnostic` first, the tree's redact-then-bound helper, so every bounded form is
  cut from redacted text; an unterminated private-key header discards its tail. Pins
  (`tests/synth/test_findings.py::TestATitleIsRedactedBeforeItIsCut`, fake tokens built at run
  time) cover a key across each cut, a PEM block whose END is past the cut, an unterminated header
  and the X0X candidate.
- **Workflow guard: in this repo's own lint, a step a download reaches reads UNVERIFIED outside the
  understood subset (#3141).** The guard runs only as this repo's CI lint over its ten workflows
  (`tests/test_workflow_pins.py`), never on a target, so the owner scoped #3141's fail-closed rule
  to a minimal self-lint. `scripts/workflow_subset.py` holds a small understood subset derived from
  what those workflows run where a download reaches -- the step that fetches and every step after it
  in its job, today five steps (`docker-build-pr.yml`'s hadolint steps, `nvd-cache.yml`'s sync and
  image steps): sixteen commands and the one path the NVD sync runs from its checked archive,
  wrappers such as `sudo` and `timeout` taken off; `if` and `case` with their arms and `{ }` groups;
  assignments, pipes, lists, and command substitutions held to the same rule.
  `fully_read(statements, script)` names the first construct outside it, with its line found in the
  step's text: a private-use character anywhere in the step first, then another command (a command
  word built from an expansion or a substitution among them), another keyword (a loop, `!`), a
  function definition, a process substitution. `job_defects(steps, subset=True)`, which the fleet
  lint alone calls, adds `step not fully read: <construct> at line N; review by hand` for each such
  step no finding names: a step the guard reports keeps its REPORT alone, and every other caller
  reads as before. `EXEMPT_UNVERIFIED` (workflow, step, reason) in `tests/test_workflow_pins.py`
  excuses such a step and is held to `EXEMPT_FETCHES`'s checks (no stale entry, no privileged
  workflow); it is empty, and the fleet passes. Pins: `tests/test_workflow_subset.py` (in-subset
  CLEAN, each construct UNVERIFIED at its line, the private-use check first, a REPORT kept alone, a
  download reaching forward only, the gate off elsewhere, one linear pass) and
  `TestEveryStepADownloadReachesIsFullyRead` (the lint reads the fleet through the subset; the
  exemption checks). Sizes: `scripts/workflow_guard.py` 677, `scripts/workflow_subset.py` 87.
- **`driver setup` reads a setup proposal only as the return of its own scan dispatch (#2130).** An
  untracked `.panopticon/setup-proposal.json`, and on a non-git target any proposal, was read as
  this run's scan result. A target could ship one and have its own grouping ingested.
  - A proposal now satisfies `scan_done` only when setup's sha-bound dispatch request
    (`requests.load_bound_request`, #1727) carries this run's id and names that path as its
    setup-scan `out_file`.
  - `scan_execute` clears the path before it writes that request, so what is there afterwards came
    after this run's dispatch.
  - Otherwise the proposal is ignored with the `driver setup --reset` remedy, and the scan runs.
  Pins: `tests/phases/test_setup.py::TestSetupDonePredicatesBindToThisRun` (git and non-git
  targets). Five `TestDriverSetup` tests that played the host's return without a dispatch now use
  the registered-machine fixture, so their first invocation really dispatches.
- **Skipped coverage artifacts prevent certification (#2080).** Unreadable, malformed,
  oversized, non-object and group-less coverage files are disclosed in
  `meta.integrity.coverage_files_skipped` and make an otherwise passing gate INCONCLUSIVE,
  including when valid coverage files remain. Rejected scout domains are capped at 32 entries
  of 120 characters with an explicit truncation marker, keeping coverage records readable.

- **An unenforced claude launch is checked for its tool controls before it starts (#2061).**
  `--tools=` and `--disallowedTools=` remove tools rather than deny calls, so neither ever shows
  in `permission_denials`. A run whose argv lost or altered either token would ledger exactly like
  one that kept it. Both are now `probes/common.CONTROLS` rows (`--flag=` prefix form, pinned
  live in `tests/probes/test_discovery_surface.py`). `runners/claude.unenforced_argv_problem`
  checks every unenforced argv against them, each token present once with exactly the derived
  value. `run_entry` refuses a failing argv before launch. Pins:
  `tests/runners/test_claude.py::TestAnUnenforcedArgvWithoutItsToolControlsNeverLaunches`.
- **The driver binds `out-file-hashes.json` to the exact bytes it wrote (#2115).** A writer in
  the run folder could replace the snapshot with hashes of substituted findings; because the
  snapshot's manifest stamp recorded only its cell count, synthesis verified the forged findings
  against the forged baseline and certified the run. A snapshot planted before the
  review-to-verify boundary was cheaper still: the idempotent writer left it in place and never
  stamped it. `group_runner.snapshot_out_files` now serializes canonical, newline-free JSON and
  returns its sha256 with the per-cell hashes; `run_manifest.claim_artifact` stamps evidence
  derived from that writer result only after the file lands. The synthesis child receives the
  stamped digest and publishes sinking `content_snapshot_mismatched` when a plan-owed run's
  present snapshot differs or has no driver-written digest, so both substitution forms make the
  gate INCONCLUSIVE and coverage uncertified. The shared integrity registry carries that reason
  through `integrity_ok`, terminal and HTML output, and the report schema. The artifact helpers
  moved mechanically from the 700-line `phases/requests.py` into `phases/run_artifacts.py`, with
  their old names re-exported. Pins: exact serialized-byte digest and post-write stamp; CLI/plan
  threading; honest, deleted, unreadable, legacy/manual, forged-replacement, and pre-planted
  snapshots; the live review-to-verify-to-synthesis rows; schema, key order, gate, and both human
  renderers.

- **The unenforced claude launch holds the role templates' tool grant as an allow-list (#2060).**
  The `--model` and model-less launches carried only a deny-list, which cannot close a tool name it
  has never heard of that the operator allowed at user scope. MEASURED on claude 2.1.304 with the
  run's own argv: eleven such names were live (CronCreate, CronDelete, CronList, RemoteTrigger,
  ScheduleWakeup, PushNotification, DesignSync, ListAgents, ReportFindings, ToolSearch, Edit).
  Changes:
  - The unenforced argv now carries `--tools=Glob,Grep,Read,Write` as one token. It is derived from
    the templates (`dispatch.allowed_tool_union`, which Kimi's deny-list now reads too) and leaves
    exactly those four tools; the `--settings` guard still fires.
  - The deny-list stays as belt and braces.
  - `prepare` refuses a run whose CLI does not offer `--tools`, rather than launch unconfined.
  - `--restricted` was measured for the record. It removes only CronCreate and RemoteTrigger, so it
    is not adopted.
- **The verify advisors are handed each claim's title bounded and inert (#2074).** A title is
  reviewer- or tool-authored text about the target, yet it reached both advisor prompts whole and
  raw while the description was capped. `runio.capped_title` now renders control characters inert
  (`_prompt_safe`) and cuts the title at 200 characters with a marked cut. It is used by
  `verify._render_findings` and by the tool-advisor claim (`verify_tools._tool_verify_entry`).
  Pins: `tests/phases/test_verify_backpressure.py::TestClaimTitleIsBounded` (a 20 kB title holding
  `\x1b[2K`, through both renderers).
- **Scanners no longer take their config from the scan root they review (#2055).** Three scanners
  read files the reviewed repository commits, so it could narrow or silence them. Measured on the
  pinned tools:
  (1) npm audit ran with `--prefix <target>` and read its `.npmrc`, so `omit=dev` dropped the whole
  dev tree (npm 10.9.9: a dev-only minimist gave two advisories, and none with that file). It now
  audits a scratch project staged with `package.json` and the lockfiles only.
  (2) osv-scanner's walk honoured the target's `.gitignore` in a git checkout (1.8.2: a committed,
  gitignored `requirements.txt` beside a second manifest gave 4 advisories instead of 10). It now
  runs with `--no-ignore`.
  (3) dependency-check's bundle-audit and go-mod analyzers ran bundle-audit and go inside the
  target, where those tools read its `.bundler-audit.yml` and `go.work`. Both analyzers are now off
  (`--disableBundleAudit`, `--disableGolangMod`); the bundler_audit adapter and osv-scanner audit
  those manifests.
  Already closed on `main` and pinned:
  - semgrep's `.semgrepignore` and `.gitignore` (#2462);
  - osv-scanner's `osv-scanner.toml` (#1839);
  - brakeman's `config/brakeman.yml` and `config/brakeman.ignore`: owned `--config-file` and
    `--ignore-config`, and brakeman 8.0.6 reads only the first config file it finds;
  - eslint's argued exception.
- **A finding names a substitution run as a standard-input runner `$(...)`, never the reader's
  marker (#3156).** `workflow_uses.use`'s standard-input branch named the runner by
  `os.path.basename(argv[0])`; for a command substitution as the command word (`$(echo sh)`, its
  backquoted form or `"$(command -v sh)"` handed the download as `3<> tool <&3` or `3< tool <&3`:
  std.tsv `own:AV011`, `own:AV013`, `own:AV015`, `owntw:AV011`, `owntw:AV013`, `owntw:AV015`) that
  word is the reader's marker, `@@shell-<hex>-N@@`, whose hex each parse mints afresh: no two runs
  printed the reason alike, and the main pass and the guard's second walk gave the one finding two
  texts, so the job held it twice. The branch renders the token with `shell_reader.readable` before
  taking its basename, so the reason reads "running it under `$(...)` from standard input", and a
  nonce duplicate collapses: each of the six rows reports one finding where it reported two, in
  every setting and layout. No reading moves. On `main` 117b11d4 the std rows (31,046 rows, 714,930
  cells) print 300 marker lines, the six rows by 25 cells by two; with this line on 117b11d4 the
  whole mkkit assembly (88,902 rows, 2,139,850 cells) prints none. Pins:
  `tests/test_workflow_reason_markers.py` (the six rows in five settings, two fresh interpreters
  byte for byte, a runner the step names as the control).

- **Workflow reader keeps the reader's attributes on a word it weighs (#3164).** Since #3153 a
  printer's word whose value fetches gets its `weighed` text on a fresh token in three places: a
  forked child's printer, a test's, and rule 6's take-back (`_as_weighed`). That fresh token
  dropped every attribute the reader had set on the word as written (`double`, `kept`,
  `live_dollar`, `exact_dollar` on a `"$X"`), so a later reader branching on one would read the
  weighed word as unquoted. `workflow_annotate._rebuilt` now makes annotate's tokens: a `weighed`
  one keeps every attribute and reads as written. A `spelled` one stays the bare token it always
  was: it is read as its value, and `main`'s answers rest on that bare token, so it stays as
  `main` has it. Pins: `TestAWeighedWordReadsAsWritten` (each of the three places against the
  word a fresh parse writes, the spelled word, and `_rebuilt`'s own two: a word the reader left a
  plain string, a word's markers). Core sample `core-20261018` (10,000 rows) plus the 4 pins as
  rows, head against `main`: byte-identical (nonce-normalized), 0 REPORT->CLEAN, no main-pass
  movers; 68 core rows go through a weighed rebuild.
- **Workflow trap and option-word matching avoid quadratic backtracking (#2981).** A long
  `rm -r ... !` trap action or `$aaaa...!` option word repeatedly split the same text between
  overlapping regex repetitions. Trap options now use the existing path-word repetition, and
  variable names and parameter sequences are consumed possessively. Both keep the same accepted
  language; serial regression tests check scaling when a failing input doubles.
- **Workflow guard reads a command word it cannot resolve as a possible runner of the fetched file
  that is its first operand (#3143).** `curl -fsSLo t URL` then `$SHELL ./t` ran the download under
  every parent and read CLEAN: `workflow_uses.use` reported a run only where the command word named
  an interpreter, so `$SHELL`, its braced form, `"$SHELL"`, `$RUN` (unset, or set by the runner or
  `env:`), `"$@"`, an expansion in front of `sh` and a modified reference fell through, and `cat t |
  $SHELL` with them -- the #3140 seat's N1 root. `RUN=sh` set in the step resolved through the
  table, a shell's default read as `sh`, a spliced array at its splice, and `$SHELL < t` read the
  value word as a stdin runner already. Now, in the guard's second walk, a command word holding a
  live `$` expansion whose name may end as a shell's does (`_value_command`: the text after its last
  expansion ends a shell's name and holds no `/`) and that the value table gives no value at all
  (`_unvalued`) reports as running the fetched, unchecked file that is its first non-option operand
  ("a command word this guard cannot resolve"), and behind `cat t |`, with nothing but options after
  it, as piping it: the union rule, fail-closed. The main pass stays `main`'s answer word for word,
  and the walk's use follows every one `main` names, so `main`'s finding stands wherever it names
  one -- a body's `$RUN` its call resolves to `sh`, a locale string read bash's way. What stays as
  `main` reads it: a default the reader reads its own way (`${X:-cat} ./t`; `cat t |
  x"${SH:-bash}"`, read as `xbash`), a spliced array, a value in front of a name the reader knows
  (`$S head -n 99 t`), a value after a value, a value the table names (`cmd='$1'` then `"$cmd"`), a
  value handed no fetched file, a name no shell's can be (`$S/x ./t`, `a$ ./t`, `$'bash\ue004'
  ./t`), and a command substitution as the command word (`` `echo sh` ./t ``, `$(which sh) ./t`),
  which the reader lifts before the walk: #3157's limit, named. With a credited check before the use
  the step reads as the gate rows do (CCCRR). The prices, named: a value naming a non-runner or
  nothing -- `$EDITOR ./t`; `${X#y} ./t` with `X` unset; `${A:+echo} t`, an alternate, which reads
  as the bare reference in its place (#3003), and with it a quoted alternate whose value holds a
  blank -- is an over-report, as #3141 would read it UNVERIFIED; `$"sh"` gains a second finding
  beside `main`'s, the walk reading dash's kept `$` as the reference `$sh` (#3048); and in a folded
  job the first fold's held fallback text takes its place over a later fold's main-logic text: fuzz
  `F09407`, whose words that may be nothing are read in halves folds, names its use `${C+true}` in
  the job where `main` named it `bash`. The row reports in every cell as before and every step
  `main` reports still reports; the text changes in all 25 cells (45 findings), and in the 20 of one
  step a line the job also gains a finding for step `s4`. The core differential at this head
  (a757ba32 against `main` 68f11045: the core sample, 10,000 rows, and this issue's 44): 108 rows
  move, 62 with cells from CLEAN to REPORT (1,336 cells) and 48 with a second finding (765 cells;
  #3127's two `p.alt` rows are both), none from REPORT to CLEAN, and the main pass is unchanged on
  every row -- this issue's rows and the core's copies of them, #3140's `$RUN`/`$SHELL` rows,
  seat-hunt13's whose shell is set in a step of its own, seat-hunt16's, seat-hunt18's two quoted
  alternates (the price), #3127's `p.alt` rows and 15 fuzz rows; F09407 is the one text price. Pins:
  `tests/test_workflow_guard_reader_forms.py::TestAValueCommandWordMayRunTheFetchedFile` (thirteen
  rows report in all five settings, six that reported already still do, sixteen controls stay CLEAN,
  the checked row reads CCCRR, `main`'s finding stands, the main pass is unchanged, the predicate,
  and the second walk's lookup sharing `uses()`'s one lazy table, #3145's). Sizes:
  `scripts/workflow_uses.py` 670 (699 on `main`: the command-word block moved whole to
  `scripts/workflow_use_words.py`, 132).

- **Workflow uses shares one value-table walk and one fork index across sibling calls (#3145).** A
  step with `n` function definitions followed by `n` calls rebuilt `static_values` at every call:
  each rebuild walked all earlier calls and `_forked` rescanned every statement through `_openers`.
  Doubling 16 to 32 siblings therefore raised value-walk visits 136 to 528 and opener visits 784
  to 3,104, nearly 4x. The first value lookup still takes the exact fresh path, and `uses` builds no
  `_StaticValues` object before a second lookup can reuse it; only then does it classify the bodies,
  index the child ranges and advance a compatible top-level table through statements not already
  read. `_ForkedIndex` represents the ranges covering a statement and the target's same-child ranges
  as integer bit sets. Reuse requires every step-defined call to leave values unchanged; a body that
  may assign, `eval` or source a file keeps the previous fresh walk, `record_called` budget and
  stand-ins. The pins measure 17 to 33 value visits and 98 to 194 opener visits for 16 to 32
  siblings, while one call among 32 definitions takes zero whole-step `_writes` classifications
  (64 before the lazy boundary). On current `main`, a parsed sibling pass at 80 / 160 / 320 / 640
  took 0.139 / 0.635 / 2.725 / 13.099 CPU seconds; it now takes 0.020 / 0.037 / 0.058 / 0.112.
  Serial n=640 pass/job minima, base to head, are: siblings 23.046/23.945 to 0.332/1.139;
  nested 0.092/1.317 to 0.072/1.215; three-line bodies 0.083/7.373 to 0.078/7.002;
  one called 0.123/0.725 to 0.090/0.570; none called 0.079/0.560 to 0.071/0.479. No
  shape slows; the three-line job remains superlinear in gating (#3128 item 2), outside this pass.
  No readings move: a refreshed 1,340-row mixed-body value/use differential, including every
  statement's table, is byte-identical. Pins: `tests/test_workflow_positional_handoff.py`; sizes:
  `scripts/workflow_uses.py` 699, `scripts/workflow_use_scopes.py` 222.
- **Driver reports measure LOC from the review root, keeping the target name for display
  (#3163).** From 2026-09-24 (#2038) until this fix, synthesis treated the target's display name
  as a filesystem root beneath the reviewed tree, producing zero LOC and a null grade or counting
  a same-named subdirectory instead. The driver now passes the actual review root through
  `--root` for grading; PR worktrees retain the original target name in JSON and HTML.
  Standalone synthesis without `--root` keeps using its `--target` path.
- **Workflow reader reads what #3117 named and `main` reads CLEAN while the payload runs (#3153).**
  Beside `main`'s reading, never instead. (1) A printer of a variable whose value fetches, where a
  forked child inherits the value (a piped brace group, a subshell, a compound body), in a test (`if
  echo "$X" | sh`), on a `then` or `do` line, or with a lifted `$(...)` in it: the value is WEIGHED
  beside the printer's unspelled words, never spelled -- `workflow_annotate._spell` sets it on the
  word as `weighed` (`_Fold.at`'s `forks`; `workflow_values._lifted` writes a lifted substitution as
  `$(...)`, text no one knows) and `workflow_printers._inherited` hands it to the printer's weighing
  in the second walk, so a value that fetches makes that reading LOUD while every other reader reads
  the word as written and the main pass gives `main`'s answer; where rule 6 takes a spelling back
  the value is weighed too (`_as_weighed`), and a weighed word is no mark (it vetoes nothing, and a
  step no mark stands in still weighs). In a forked child the fold holds the values from before the
  fork and the child's own assignments unsure, so a name the child assigns holds two candidates and
  none is taken -- pinned against `static_values` over 406 steps, 400 of them seeded random. (2) A
  compound header's own test command writes to the pipe too (`if echo P; then :; fi | sh` runs P):
  read as a pipeline of the compound (`workflow_groups._Header`, asked for by `group_reading` alone)
  beside the body's reading (`_beside`), unless it is a test that writes nothing (`_SILENT_TESTS`),
  a no-op of the body passed over in that reading only (`_noop`). (3) #3095's pairing reaches the
  closer through pass-through stages (`} | cat | sh`): the carried finding alone, as for a brace
  group. (4) A piped call whose definition lies past `_CALL_REACH` reads LOUD (`_past`'s stand-in),
  as main read it CLEAN while the body ran. (5) `_GROUP_LINES` counts parsed statements, not lines
  (documented in the code). Prices, named: a header test that writes nothing but is no known silent
  one (`grep -q`) reads LOUD, as #3026 reads a group holding a statement no printer's; a clean call,
  or any one-word program, piped to a shell past the reach reads LOUD; a weighed value behind a
  stage that rewrites it reads as its literal twin does (LOUD where the text fetches); the pairing
  through pass-through stages drops the duplicate `main` gave (2 findings to 1). Limits that stay,
  CLEAN on `main` and here: a printer in a loop body (an earlier pass may have changed the value),
  in a step that defines a function (rule 7), or inside a command substitution's script (no table
  reaches it), and a header's output inside a substitution's script or a written file. Differential
  against `main` 117b11d4, pinned nonce, five postures: #3153's 1,215 rows (26 families x 46 and 19
  controls and prices; truth under the eight parents: 888 run, `main` misses 809, this reading 102
  -- the three limits) and the #3117 and #3142 rows (4,419): 0 REPORT->CLEAN, every new family
  reading as its literal twin variant by variant; the full review kit as assembled before these rows
  joined it (`kit-adds/mkkit.py`, 86,382 rows): 0 REPORT->CLEAN, no verdict moved and no finding of
  `main`'s lost. Kit rows added (`kit-adds/3153-*-rows.tsv`): typed 1,067, nested 34, forged 24,
  planted 968, typed-closer 132, and #3153's own 1,215 with the #3117 kit's 644 and 1,114. Pins:
  `tests/test_workflow_printers.py` (`TestTheLimitsOf3117AreRead`; the four #3117 limit rows leave
  `LIMITS`). Sizes: `_literal`, its name patterns and the names bash sets moved from
  `scripts/workflow_annotate.py` (691) to `scripts/workflow_values.py` (580), imported back under
  each name's own; `scripts/workflow_printers.py` 691, `scripts/workflow_groups.py` 401,
  `scripts/workflow_forms.py` 461.
- **Large written shell programs stay linear through workflow job analysis (#3128, items 1, 3 and
  4).** A quoted 1 MiB heredoc written to a file and then run still grew superlinearly after
  #3105: `workflow_forms.flattened` and the guard walk copied the growing statement prefix once a
  stage, and the written-file binding wrapped an already-spelled output in one synthetic `printf`
  whose megabyte argument the shell reader parsed before it parsed the file itself. The program
  readers now receive a `StatementFront` view, readable in either direction, only where a pipeline
  can consume it, and an exact sequence of written-file printers whose output contains no `$`
  carries its `SpelledOutput` to `substituted`, `unsubstituted` and `fed`. Dollar-bearing
  output keeps the old synthetic-`printf` parse, including its existing cost, because its dynamic
  argument produces an observable fail-closed reading. The round-two seat measured the 1 MiB job at
  51 s here against 362 s on main when the output contains no `$`; the retained dollar-bearing path
  costs 241 s at 1 MiB and remains superlinear as on main. The round-two full kit was byte-identical
  over 86,765 rows after nonce normalization. A size-scaled structural pin forbids re-entering the
  printer parser, so the proof does not depend on a machine-speed budget. #3105's read pin uses
  300 -> 1,200 program forms so its old quadratic tree fails with margin; and a committed corpus
  compares all 13 analysis-aware helper answers with and without a shared statement analysis over
  both parsed and handed-program statement lists.
- **Function-body gates index their calls and closing runs once per statement list (#3128, item
  2).** `_gating_function_call` and `_piped_function_end` each scanned the suffix after a function
  body, once per body, to find a redefinition, a call, or a shell-posture change; `_stops_step`
  likewise walked the remaining `}` / `)` run once per statement. The shared function index now
  records definitions, direct calls, posture barriers, and the structural group around each call;
  those two proofs visit only events for the function they are answering. A separate lightweight
  closing index records each closer run and memoizes its first detached or uncredited-pipeline
  boundary for the caller's pipefail posture. The all-on/all-off posture vectors are shared, a
  recursive wrapper call carries one backtracked name set, and the existing later-command index
  answers whether a wrapper returns its call's status. The index also records the legacy net group
  depth and the depth of the nearest piped frame, so an unmatched closer handed in by a child shell
  stops the lookup at the same fail-closed boundary instead of reaching an outer pipeline. One
  production caller deliberately retains the `analysis=None` scan: `swallowed` asks about a
  zero-based `stmts[index:]` carrier slice that excludes enclosing context and cannot reuse the
  full-list analysis. A structural pin counts both formerly
  repeated predicates as definitions double, independently of machine speed; the sampled helper
  corpus still compares every indexed answer, including the reported call chain, with the legacy
  path. A committed deterministic 153-program sample separately compares 4,465 indexed group
  answers and 4,465 `_piped_function_end` answers with the legacy scans over source and handed
  statements, including the review seat's exact 22 `div*` / `hp*` rows and three generated movers.
  A direct recheck of the seat's 3,000 generated rows compares another 113,229 group answers and
  113,229 function-end answers with zero mismatches.
  On the forge, serial process CPU at 160, 320 and 640 definitions was
  0.160/0.331/0.731 s for nested bodies, 0.161/0.335/0.737 s for one-line nested bodies,
  0.250/0.497/0.989 s with one function called, 0.239/0.478/0.951 s with none called, and
  0.281/0.560/1.117 s for three-line bodies. The sibling-call shape remains superlinear at
  2.184/7.915/30.002 s in the separate `workflow_uses` pass (#3145): its profile spends 6.07 of
  7.09 s there at 160 definitions, while indexed function gating takes 0.06 of 1.98 s for 640
  nested bodies. The original 86,382-row corpus has no answer differences after normalizing six
  rows that carry per-process parse nonces, and the separately deduplicated 2,520-row addition is
  raw byte-identical.
- **Workflow reader follows a group piped to a shell through what #3026 passed over (#3117).** #3026
  read `{ P; } | sh` and `( P; ) | sh` back from the closer to the opener, one level; the #3111
  seat's rows and the kit's twins ran the download under every parent and read CLEAN: a nested group
  (`{ { P; }; } | sh`), a keyword compound's body (`if`, `while`, `until`, `for`, `case`, piped at
  `fi`, `done` or `esac`), a step-defined function's body at its piped call (`f | sh`, in every form
  of header and body), a compound inside a string a shell is handed (`eval`, `sh -c`), a group as a
  substitution's script (`sh <({ P; })`, `x=$({ P; } | sh)`), `source /dev/stdin` and `. /dev/stdin`
  fed by a group, and a group piped on through a pass-through stage (`{ P; } | cat | sh`).
  `workflow_printers._walk` now reads back through the structure a stage carries (`_structure`:
  braces, subshells, headers and their closers), each body statement's pipeline once its opening
  words are dropped (`_stripped`: `{`, `then`, `do`, `else`, `time`, a case arm, a function header),
  a nested group's body kept where its closer hands the stdout on (`| cat` passes, `| tr` stands in
  LOUD, `> f` drops it), every branch of an `if` or `case` (fail-closed), a loop body's `break` or
  `continue` as writing nothing, and a function's body from the closer of the definition last met
  before the call (`_function_body`). BESIDE `main`'s reading, never instead: every finding `main`
  gives stands (pinned per shape and posture). Statements read into place from a string now carry
  their script's `key` (`Inlined.key`, granted), so the walk inside a string never meets the program
  the group's own text hands on -- read into place before the closer's statement under the same
  region -- and a body statement inside an `if` within the string is kept; and #3095's pairing
  reaches a `fi`, `done` or `esac` closer (granted), so a carried printer in a compound body gives
  the one carried finding, as in a brace group. Bounded, fail-closed: a group of more than 64
  statements (`_GROUP_LINES`) is read LOUD as "a group of more statements than this guard follows",
  never read, never CLEAN; a function body whose closer lies further back is the same; a piped call
  looks for its definition 256 statements back (`_CALL_REACH`), beyond which the word reads as
  `main` reads it; the stand-in word the walk leaves past the bound is told by its type
  (`_PastGroup`), never by its text, so a step typing that text reads as any other word reads (round
  1). A `{ }` or `( )` group is read as `main` reads one, wherever it stands: braces and subshells
  its only structure and every statement a pipeline (`strict`), since the reader hands a keyword a
  step types as a quoted word back as the keyword's text, and a walk reading such a group by its
  keywords lost `main`'s findings to typed ones (round 2; 1,067 typed-word rows, 0 REPORT->CLEAN
  now); a compound piped at its own closer is read in full, a closer counting only as a statement's
  sole word, a header word alone a word, no printer's, and a walk that popped a nested level and ran
  out reading LOUD. A case arm's marker is the parser's own (`shell_reader.is_arm`, nonce-aware),
  never a typed lookalike (round 2's N4: a typed marker emptied its statement and cleared `main`'s
  report). Named limits, filed: (a) a printer of a variable holding a literal download text inside a
  piped brace group or compound body stays CLEAN -- `workflow_annotate._Fold.at` holds no value in a
  forked child (the var-group family's 34 running rows, the seat's `p.var-assign` rows); a printer
  FIRST in a piped subshell is spelled and reported; (b) the pairing does not reach through a
  pass-through stage (`} | cat | sh`: two findings); (c) a compound header's own test command writes
  to the pipe too and is not read; where the reader keeps no quoting, a word typed in a keyword's
  shape where `main` reads nothing reads as the keyword: (d) `then`, `do` or `else` alone inside a
  compound body at its own closer, (e) `break` or `continue` alone in a loop body, (f) `{` alone in
  any group, the opener to `main` too (a quoted-word mark in the lexer would close them). Prices: a
  group holding a statement no printer's reads LOUD as #3026 read it (a `break` outside a loop among
  them), now inside a string too (the seat's five `brace-cat` holder twins of a shape `main` reports
  plain); the bounds report a clean group of 65 statements and a clean 65-line function body; a
  group inside a function body is reported once at its definition, and the per-call copies `main`
  gave are dropped by #3050's rule (#3130's `m2.func-body-group2` probe: 3 findings to 2; verdict,
  reasons and the carried statement unchanged); a keyword compound nested in a `{ }` or `( )` group
  reads LOUD wherever the group stands, as `main` reads one at the top of a step (the kit's clean
  `eval-if-body` twins: CLEAN -> REPORT); a group written to a file and holding a statement no
  printer's is handed on LOUD beside `main`'s forwarding finding (#3125's PR-A-025 and R2-F-034
  rows: two findings, as `main` gives `{ F; echo ok; } > tool` then `sh tool`). Differential against
  `main` 4285dc5e, the base #3142 merged on, pinned nonce, five postures: 3,273 rows -- the kit's
  644 (14 families x 46), 1,114 more (24 families x 46 + 10 controls), the seat's 390 re-read from
  its TSVs, and the round-2 typed, nested and forged rows (1,125) -- 0 REPORT->CLEAN; misses by
  truth 34 + 34 + 4, all limit (a) and (c), read since #3153; the seat's full kit (36,144 rows): 0
  REPORT->CLEAN; the pairing line changes no kit row's finding count; the reading costs 1.33x to
  1.39x `main`'s time on the group-heavy rows (the three rounds' chains and the seat's), the suite's
  time unchanged. Pins: `tests/test_workflow_printers.py` (`TestTheGroupsThisGuardFollowsNow`,
  `TestTheGroupWalksParts`; the #3026 classes moved to the new reading),
  `tests/test_workflow_guard.py` (#2430's compound pin, one finding under #3095),
  `tests/test_workflow_written_files.py` (the nested group, #3110's named limit, read now). Sizes:
  `scripts/workflow_groups.py` 382 (new: the walk and the pipe's plumbing, split out of the printers
  module at its size and imported back under each name's own, as #3013 did),
  `scripts/workflow_printers.py` 591 (-31), `scripts/workflow_forms.py` 454 (+1),
  `scripts/workflow_annotate.py` 699 (+0), `scripts/workflow_programs.py` 496 (+2).
- **Workflow reader marks the direct `$?` inside `[[ ... ]]` with a mark of its own, from the step's
  text (#3116 item 1 and the reader part of item 2).** The lexer escapes every pattern character
  inside a conditional, so a direct `$?` reached the exact-dollar pass as `$\?` and was never
  marked, while `$"?"`, `$""?` and `"$"?` lex to the same bare `$?` word -- and a user's own `$\?`
  reaches the stage spelled as the lexer spells the direct one, which bash rejects there (`[[: $?:
  syntax error`, status 1: a handler behind it never runs). Now `shell_reader` records whether the
  step's text spells `$\?` anywhere, and where it does not, the direct `$?` of a stage that is a
  conditional at its head -- behind `if`, `!`, a function header -- and ends with `]]` carries
  `conditional_status`: a `_Token`, never `_Expanded` (bash expands no pattern there), and neither
  `exact_dollar` nor `live_dollar`, so the status gate, which credits an exact, live `[[ ]]` operand
  in bash steps today, credits nothing until item 2 (Daybreak's) reads the mark: no verdict moves,
  the 36 gate-reaching rows (six spellings, three handlers, with and without `set +e`) read as they
  did. `"$?"` keeps the exact, live mark it had; `$"?"`, `$""?`, `"$"?`, `$'?'`, `$?x` and `${?}`
  keep their types and stay unmarked; a user's `$\?` is never marked, inside a conditional or out
  (`echo [[ $\? ]]`, `printf '%s' [[ $\? ]]`, `eval [[ $\? -ne 0 ]]`); an arithmetic command and an
  array literal are untouched. The mark asks only whether the stage is a conditional, one pass over
  its words: no span is searched for (a `[[` with no closer, n times in one stage, reads in linear
  time, pinned). Prices, named: a step that spells `$\?` anywhere marks no conditional's `$?`; one
  that types the mark itself -- U+E008 before a word, round 2's seat's `<U+E008>exit`, which
  `_stage` stripped to `exit` and the status gate then credited as a stop under the `{0}` settings,
  fail-open -- keeps every typed word whole as a plain literal and reads the rest as any step
  (#3138's rule, `_STATUS` in `_MARKS`; round 3 read such a step with no conditional's `$?` marked,
  a price gone with the fold, its gate dead code under the translation and removed); a conditional
  spanning lines, one that is not the whole stage (a trailing redirection), one whose words tabs
  part, a second conditional in a list (`[[ a ]] && [[ $? -ne 0 ]]`), one inside `{ }` or `( )` or
  after `time`, and one in a `case` arm are unmarked -- fail-closed each. Item 1's audit of the
  str-to-`_Token` re-wrap of exact words: the seven callers that test `type(word) is str`
  (`shell_command` 267, `workflow_options` 136, 164, 225, 350, 507, `workflow_programs` 408; the
  seat's six more, none affected) ask of a word whether it is `bash`/`sh`, a `--`/`++` option, an
  exit-or-file option, `--pretty-print`, or a command name that spells no option -- none of which an
  exact word (`$NAME`, its braced form, `X=$Y`, `$?`) can be -- so the re-wrap changes no answer.
  Forge differential of 4ea470db against `main` b61bbc76 over the 27,612-row kit (the kit's rows,
  the 13 status rows, the 36 gate rows and the 23 forged rows; three readings a cell, 2,045,220 in
  all, 80 min): byte-identical dumps -- no row differs, no multiplicity gained or lost in the job,
  main-pass or walk readings: the mark credits nothing yet, and a typed mark reads as `main` reads
  it. `tests/test_shell_reader.py` pins the mark, the lookalikes, the user's escape, a typed mark
  kept whole, the named prices, what else stays unmarked and the linear reading;
  `tests/test_workflow_positional_handoff.py` the 36 gate rows and the twelve forged forms as on
  `main`. Sizes: `scripts/shell_reader.py` 553 (+29).

- **Workflow reader reads a private-use mark the step types itself as a plain literal -- every mark,
  in one place (#3138).** The reader puts eight private-use characters into a step's text while it
  reads it -- `MARK`, `QUOTED`, `QUOTED_DOLLAR`, `DOUBLE_DOLLAR` (`shell_patterns`), `_ESCAPED`,
  `_BLANK` (`shell_split`), `_NAMED`, `_EXACT_DOLLAR` (`shell_reader`) -- each a mark one pass
  writes and another reads off a word. One the step typed itself was read as the reader's own and
  taken off: `<U+E007>exit` read as `exit`, so a handler behind a check was credited as a stop where
  bash prints "command not found" and runs the payload, and `sh <U+E007>$T` as a run of the fetched
  file where bash finds no such file -- six of the eight (U+E000, U+E001, U+E003, U+E005, U+E006,
  U+E007), fail-open on `main` (the #3131 round-2 seat's finding, filed as #3138); `_ESCAPED` and
  `_BLANK` read as a plain literal already (#2856 round 8). Now `statements` moves every typed mark,
  once, where the text enters, to the private-use character 0x100 past it (`_MARKS`,
  `_LITERAL_MARKS`), which no pass writes or reads: the step reads as `main` reads one that spells a
  plain literal character there -- U+E0FF, the reference the pins use: `<mark>exit` behind a check
  CCCRR (the `{0}` settings report, where the check does not stop the step), a typed mark before a
  fetched file's name or inside a word CLEAN, as the file bash would run is another -- and the rest
  of the step reads as any step does (the exact-dollar and named-command readings of the other words
  stay). The round-8 guard that read a whole step as `main` read before its kept-whole words, where
  it spelled any of five marks (`context.blanks`), goes: its one pin moves, under the rule the
  coordinator set for this issue ("a step whose text spells a mark must read as main would read it
  if the character were a plain literal"): `${SH:-bash -s}` behind a typed mark keeps its kept-whole
  reading, `bash`, `-s`. Forge differential of ea49b4f2 (the code; the two test commits after it
  leave `scripts/` the same by patch-id) against `main` b61bbc76 over the 27,644-row kit (the kit's
  rows and this issue's 55; three readings a cell, 2,047,620 in all, 84 min): 27,480 rows identical,
  164 move -- every one a step that types a reader mark: this issue's 29 and 135 of the #2856
  round-8 seat's rows in the kit (`cost-std-sample.tsv`, the `seat-hunt` families) -- and none a
  control. 34 CLEAN->REPORT: the round-8 rows where a mark sits in an `echo`, a comment, a heredoc
  body or an `X<mark>=1` word and `${X:-bash -s} <<EOF`, `${RUN:-sh tool}` or `| ${SH:-bash -s}`
  runs the download, which the whole-step guard read as `main` read before its kept-whole words (22
  rows; truth: the payload runs under bash 3.2.57 and dash, the three `X<mark>=1` rows without
  `-e`), and the twelve forged handlers (truth: the payload runs where the check does not stop the
  step). 32 REPORT->CLEAN: the round-8 rows whose mark sits in the download's name alone -- `-o
  <mark>tool`, `> tool<mark>`, `wget -O <mark>tool`, then `sh tool` -- where `main` took the mark
  off and matched the names (15 rows; truth: what was fetched is not run), and this issue's `sh
  <mark>$T`, `sh <mark>t`, `s<mark>h t` (17; truth: nothing runs). 98 REPORT->REPORT with the
  finding's text changed: the mark in the name on both sides (`tool<mark>x`, `${D:-tool<mark> }`,
  `bash -s<mark>`, a URL) now shows as the literal where `main`'s text had it taken off or the word
  split (the round-8 families 11, 15, 17 and `m06`; truth: the payload runs where both names carry
  it, nothing for `bash -s<mark>`, an over-report on both trees). No row loses a report in one
  setting and keeps it in another. Pins: `tests/test_shell_reader.py` (every private-use constant of
  the reader's eleven modules is in `_MARKS` and moves to a non-mark -- the test that fails when a
  module gains one; a typed mark stays a literal in its word; it decides no reading of the rest) and
  `tests/test_workflow_positional_handoff.py` (each mark, five shapes, as U+E0FF reads; the controls
  as they did), RED on `main`. Sizes: `scripts/shell_reader.py` 529 (+5).
- **Workflow guard reads a step's function definitions once a pass, not once a use or a body
  (#3124).** A step of n siblings each called cost the job about x6 a doubling on `main` (1.2 / 6.6
  / 46.5 s at 80 / 160 / 320; the #3132 seat's rows read cubic) and n nested definitions x3 (0.03 /
  0.09 / 0.23 s at 40 / 80 / 160): `workflow_uses.static_values`, run once a call or a statement
  holding `$`, rebuilt `_function_ranges` without #3126's shared analysis (a `_function_scope` scan
  of the step a definition), `_body_end` a definition and its nested set at every use;
  `_possible_called_readonly`, run once a definition by the carried pass, rebuilt `_function_ranges`
  a body; and `_reached` and `_calls` walked every definition a call site and a reached body. Now
  `workflow_called._Definitions` indexes the step's definitions once a pass on the per-step memo
  (`_Step.definitions`; `_Step.ranges` is `_function_ranges` with the shared analysis, once): each
  name's definitions and, for each statement, the innermost body holding it -- three sweeps: ends as
  `_body_end` finds them, as the `}` was found, found bodies only -- asked a statement by
  `_reached`, `_calls`, `_possible_called_readonly` and, granted, by `static_values` and `uses`
  (`workflow_uses`) and `_called_assignments` and `carried` (`workflow_carried`). Readings unchanged
  by construction: Forge differential of a8ff2aa7 against `main` 5c88603d over the 27,657-row kit
  (the kit's rows and this issue's 45; three readings a cell, 2,048,295 in all, 83 min):
  byte-identical dumps -- no row differs, no multiplicity gained or lost in the job, main-pass or
  walk readings. Measured, `job_defects` CPU, `main` -> here: siblings each called 80 / 160 / 320:
  1.2 / 6.6 / 46.5 s -> 0.34 / 1.1 / 3.9 s, still x3.2-3.6 a doubling, since the uses pass walks
  every earlier statement a use (`walk`) and scans the step a use (`_forked`) -- `main`'s design
  (round 8: "`main` is quadratic"), a follow-up for Blue; nested 40 / 80 / 160: 0.03 / 0.09 / 0.23
  -> 0.03 / 0.05 / 0.12 s; one of n called, or none, 80 / 160: 0.08 / 0.18 -> 0.07 / 0.12 s (0.23 s
  at 320). What the job still grows past that is the gating side's (`_gating_function_call` once a
  definition, each a scan of the step: #3128). Pins:
  `tests/test_workflow_positional_handoff.py::TestEachDefinitionIsIndexedOnceAPass`, `static_values`
  at the step's last statement past n definitions and n calls (640 -> 2560: `main` 0.33 -> 4.5 s,
  the bound 2.9 s; here 0.07 -> 0.30 s) and `_possible_called_readonly` over n bodies (80 -> 320:
  `main` 0.30 -> 18.1 s, the bound 2.6 s; here 0.01 -> 0.07 s), both RED on `main`; no job-level pin
  until #3128 makes the gating side linear. Sizes: `scripts/workflow_called.py` 561 (+76),
  `scripts/workflow_uses.py` 593 (-4), `scripts/workflow_carried.py` 676 (-2).

- **Workflow reader parts a nested function header behind a group's `{` in a one-line body
  (#3123).** `f() { { g() { sh t; }; g; }; }` ⏎ `f` ran the download under every parent and read
  CLEAN: the splitter parted a header's `{` from a nested header after it (`f() { g() {`, #2975 part
  A) and a group's `{` from a header after it (`{ g() {`, #2664), but not a run of braces, so `f() {
  { g() {` kept `{`, `{` and `g` -- its `()` lost -- as words of the header's statement, and no
  reader found `g`; the own-line twin and the top-level group reported. Now
  `shell_split._NESTED_HEADER` takes a run of `{` words: the statement ends after the header's `{`,
  the next starts at the group's `{`, which ends after the brace, and the nested header stands as it
  does on a line of its own -- the row and a run of three braces report, the twins and the controls
  read as they did (a group with no header in it, a subshell with one, stay one statement). The
  issue's second row, a never-called gate in a subshell inside a body (`f() { ( g() { sha256sum -c
  sums || exit 1; }; ); }`), reads REPORT on `main` 68c75d2c already (its CCCRR was an earlier
  `main`'s) and is pinned so it stays. Forge differential of fd7140ff against `main` 68c75d2c over
  the 27,627-row kit (every reader; the parse changed): 27,625 rows identical, 2 moved -- both this
  issue's (row 1 and the three-brace run), CLEAN to REPORT under every parent in the job, main-pass
  and walk readings -- 50 cells gain a finding, none loses one, no multiplicity lost. Pins:
  `tests/test_shell_reader.py` (the parse) and `tests/test_workflow_positional_handoff.py` (the
  rows' marks). Sizes: `scripts/shell_split.py` 431 (+0: one regex).
- **Grouped quiet printer reasons pair with loud reasons at the printer's statement (#3095).**
  A carried download printed through `{ echo "$payload"; } | sh` produced two findings: `carried`
  put the loud hand-off reason on the printer's statement, while #3026 put the quiet unread-printer
  reason on the group's closing shell statement, so `kept` could not pair them as it does for the
  plain `echo "$payload" | sh` twin. A quiet grouped answer now records its printer's source
  statement, and `kept` uses that source when looking for a louder reason. The brace, newline,
  subshell, and stderr-redirection forms return the one carried finding; no verdict changes.
- **Workflow reader follows the function calls the #3047 fold did not (#3127).** The #3121 seat's
  rows and its combined-tree round ran under every parent and read CLEAN: a positional with a
  default (`f() { sh "${1:-t}"; }; f`), a slice of the call's words (`"${@:2}"`), `$10`, an unquoted
  positional holding a command (`f() { $1; }; f 'sh t'`), a one-line body opening a subshell or a
  group (`f() { ( sh "$1" ); }`, `run() { ( "$@" ); }`, `f() { { echo P; echo hi; } | sh; }`), a
  definition inside `if`, a call inside `eval 'f t'`, and a forwarding `f() { cat; }` between a
  printer group and a shell. Now `workflow_called_fetches` binds `${N:-d}` / `${N-d}` to the call's
  word or the default and `${N:+x}` / `${N+x}` to the alternative where the word is given,
  `"${@:N}"` / `"${@:N:M}"` to the slice, `$10` to the first word with a `0` behind it as bash and
  dash read it (`${10}` the tenth; zsh's tenth for `$10` named), and splits an unquoted positional's
  word on blanks as bash and dash do (zsh does not: named); reads a `{` body whose first statement
  is a subshell on the header's line like any brace body (`f() ( … )`, a subshell body, stays
  `main`'s) and stands for a body holding a group piped on (`{ P; echo hi; } | sh`) even where it
  reads nothing of its call (`main` reads the group behind the header's words, `f() { {`, so #3111's
  reading never found the opener; no other such body is: a gate in it keeps `main`'s reading); reads
  an `eval` of one literal word that is one statement of one stage as that statement's call (a live
  `$`, a substitution, two statements or two stages -- `eval 'f t | cat'` -- stay `main`'s, named;
  `bash -c 'f t'` runs a child shell without the function, nothing); and takes a one-stage `cat`
  body out of the pipe at its call, so `{ P; } | f | sh` reads as `{ P; } | sh` (#3111's group; `tee
  f` stays in place -- the `| tee |` and `| cat |` links are #3111's `_grouped`, which reads the
  stage in front of the shell alone: named). A definition that may not have run -- under `if`, in a
  loop, behind `&&` -- stays no function to stand for (#3047's rule and the guard's B43 pins: `main`
  installs none from it; an `unset -f` takes a name away only where it surely ran, as `main` reads
  it), so `if true; then f() { sh "$1"; }; fi; f t` is the issue's one row left, a named limit. The
  issue's cost: `called()` was quadratic on `main` (Blue's `_function_ranges` asked
  `_function_scope` once a definition without #3126's shared analysis); now `CalledFetches` builds
  the shared analysis once (`statement_analysis`) and `_function_ranges` takes it -- two lines in
  `workflow_use_scopes.py`, granted -- so a chain of n definitions is read in time linear in n
  (x21.8 -> x4.1 for 200 -> 800; n unrelated definitions x16.8 -> x4.2), pinned; the names defined
  at each statement are a dict, not a scan a statement. `alias r=sh; r t` runs under dash alone: a
  reading that needs the step's shell, which the fold is not handed -- a named limit. Forge
  differential, fd7ca507 against `main` 68c75d2c over the 27,612-row kit (the kit's rows and this
  issue's 61; three readings a cell, 2,045,040 in all, 79 min): 33 rows differ -- 30 CLEAN->REPORT,
  the issue's and the seat's rows and the kit's `coll.18` (`run() { ( "$@" ); }`), every one a run
  under bash and sh; 3 REPORT->CLEAN, the `$10` rows, where `main` took `$10` for the tenth word and
  bash and dash read `${1}0` and run nothing (zsh runs the tenth: named); the other 27,578 rows
  byte-identical; the multiplicity audit: those three alone lose a text, `main`'s over-report. Pins:
  `tests/test_workflow_positional_handoff.py::TestTheCallsTheFoldDidNotFollow`, truth in the
  comments. No pin moved. Sizes: `scripts/workflow_called_fetches.py` 593 (+86),
  `scripts/workflow_use_scopes.py` 154 (+1, the two granted lines).
- **Workflow written files: a group of printers written to a file and then run is read as their text
  (#3110).** `{ echo "sh -c 'curl … | sh'"; echo ok; } > s.sh` ⏎ `sh s.sh`, and the `{ echo P; } >
  s.sh` and `( echo P; ) > s.sh` forms, ran the download under every parent and read CLEAN
  (Claudia's 138 rows from the #3026 kit, 102 running), while the single printer written so was
  reported: `workflow_written._writer` took the stage that writes the file for the printer, and for
  a group that is the closer -- `}`, or the empty stage that closes a subshell -- which prints
  nothing. Now `_writers` reads a closer's writers through #3026's group reading
  (`workflow_printers._grouped`, `_printer_of`): the printer of each pipeline of the group, in
  order, each a writer of the file, so `_script` spells the file as it spells any sequence of
  writers and `stdin_scripts` reads the run; the group reads exactly as its single-printer twin
  reads, the lifted letter (`sh -$(echo c)`, #3065) included. A pipeline of the group that is no
  printer's (`{ echo ok; cat f; } > s.sh`) stands in as a writer the printers cannot spell, so the
  whole group is handed on as the expanding heredoc behind `$UNSPELLED_WRITER` -- reported as any
  expanding body a shell runs, fail-closed, the spelled payload beside it kept, as #3026's
  `_GROUPED` reads the pipe twin; a group with no printer in it binds nothing, as `cat f > s.sh`
  binds nothing (a limit, `main`'s). The walk back to a group's opener reads the statements in front
  of the closer through a view, no copy, and only where the closer writes a file -- the first cut
  copied the front once a closer, quadratic in the step (round 1's seat: x8.6 for 3,200 -> 12,800 on
  4n plain lines then n groups) -- so the binder stays linear: that shape binds in linear time at
  3,200 and 12,800, and n groups written and run read in linear time (pinned beside #3126's). Limits
  and prices, named: a nested group (`{ { echo P; }; echo ok; } > s.sh`) is #3117's shape and reads
  CLEAN; the lifted-letter rows the printers cannot spell (`sh -$(echo x) '…'`: 18 of the 138,
  nothing runs) read LOUD, as their single-printer twins do on `main` -- its price, inherited; every
  write is still an append (#3027). Forge differential, 65e56576 against `main` 9a2a7257 over the
  27,538-row kit (the kit's 27,372 rows, Claudia's 138, ten controls and the 18 single-printer
  twins; three readings a cell, 2,039,670 in all): 124 rows differ, every one CLEAN->REPORT -- the
  102 running rows, the 18 lifted-letter rows (LOUD, as their twins read on `main`), and four
  controls (`{ echo ok; cat f; }`, `. ./s.sh`, `bash s.sh`, `>> s.sh`); 0 REPORT->CLEAN; the 27,372
  rows of the kit and the 18 twins read byte-identical; 0 rows lose a same-text multiplicity in the
  job, main-pass or walk reading. Pin moved, authorized by its own comment: the `written-group` row
  of `tests/test_workflow_printers.py` (#3026's named limit, "A limit of #3027's reader, not this
  reading's: #3110") from CLEAN to REPORT. `tests/test_workflow_written_files.py`: the issue's rows,
  the LOUD and no-printer controls, the twins, the nested limit, two growth pins. Sizes:
  `scripts/workflow_written.py` 193 (+19).

- **Workflow reader reads a call of a function the step defines as its body, the call's words in its
  positionals (#3047, the function half; #3091).** `run() { "$@"; }; run sh cuda_1.run`, a retry
  loop around `"$@"`, `f() { sh "$1"; }; f cuda_1.run` and a fetched file handed to a body
  indirectly (`f tool`, `cat tool | f`, `T=tool; f $T`, `f ~/tool`, a heredoc or here-string of
  `$(cat tool)`, `f <(cat tool)`, a nested `f() { g "$1"; }`) ran under every shell and read CLEAN:
  no reader took a call's words for the body's `"$@"` or `$1`. Now, in a fold of its own beside
  `main`'s (`shell_folds._CALLED`, read only for a job that holds such a call), each call of a
  function the step certainly defines before it whose body reads the call's words (a positional,
  `"$@"`, `$*`, `$#`, a `shift`) -- or, one stage reading standard input as a shell, its input,
  where the call gives one -- stands for that body as the call makes it
  (`workflow_called_fetches.called`): `$N` the call's word, `"$@"`, `$@` and `$*` the words spliced
  in, `NAME=$N` (`local` or not) the name set to the word, a `shift` of the body's own dropping the
  words for the statements after it, a `set --` giving the body its own, a `cd` leaving the absolute
  ones live (a relative word named a file where the call stood), the header's words and the `}` off,
  the definition stood for emptied where it stands (its header's words and its `}` kept, so the step
  still defines the name; the body read at its calls alone, so a body that fetches after it runs is
  no run of its own fetch where one call makes it, and two calls are that run, once -- a definition
  inside a body stood for emptied in the copy the same way), a certain `unset -f` leaving no
  function to stand for, the call's keywords in front and its separator behind; a one-stage body
  takes the call's place in its pipeline with the call's input (`with_call_stdin`, as #2973 binds
  it), output and substitutions; calls among the body followed `_DEPTH` (8) deep, the step grown by
  `_INLINED` (64) statements at most. `main`'s reading of the call is untouched, so a check a body
  credits is credited in the fold alone and takes no report away (the issue's trap), and a body that
  reads nothing of its call is read where it stands, as `main` reads it: the carries, checks and
  gates of a call keep their readings. The guard reports where either fold reads a run. The prices,
  named: `"$*"` (one word) is read spliced, an over-read; a `return` or a `local` stands at the
  step's top level in the fold; a call in a pipeline or under a redirection around a body of more
  than one statement, a call inside `$(…)` or a `-c` string, a body whose header's line opens a
  group (`f() (…)`), and the rest past the depth or the budget read as `main` reads them; a
  definition after the call is no function, and the last before it is the body; a definition inside
  `if`, `&&` or a loop is not certain and not followed (#3127); a body that does `exit 0` or `return
  0` before its run is read past them, an over-report; a call before its definition under `-e` stops
  the step at `f: command not found`, which the guard does not model (`main`'s reading too);
  `function f`, `time f` and a `declare -f` are read bash's way, where dash takes none of them (a
  syntax error, the external `time`, which runs no function, and a command not found): over-reports
  under `sh`; a `shift` in a branch is read as written; the fold is not combined with the
  read-through or the locale fold (#3118's shape); `sh < <(cat tool)` and its call twin stay CLEAN
  (#3120). Forge differential, d9ba0c0e against `main` 7771fc2a over the 27,372-row kit (the kit's
  rows, the issue's 59 and ten emptying rows): 433 rows differ -- 37 CLEAN->REPORT: 33 where truth
  runs (the 16 `fn` rows, 11 of the 12 #3091 rows, `coll.16` and `coll.19`, two seat-hunt rows of
  the `f() { sh $1; }; f tool` shape, `ae.function-value`, and one row where two calls make a body's
  run of its own fetch), and four over-reports, prices named: `ae.function-value-quoted` (`f "$p"`
  with `p=./cuda_*.run`, a quoted glob that names no file) and `reg:s56:seat-hunt13:SC53d` (`>
  ${D:-tool x}`, a redirection to two words) never run; `emp.twice` and `emp.nested-twice` (two
  calls of a body that runs `t` before it fetches it) run under the two plain settings alone, the
  step stopping at the first call's failed `sh t` under the three `-e` settings; 0 REPORT->CLEAN; 24
  REPORT rows gain a finding read at the call that `main` lacks (a bound word named, `t` beside
  `main`'s `$1`; `verifies t only AFTER` a body's run; a bound printer's run), 126 repeated a
  finding `main` has with the same text (the guard keys a finding by its fetch's statement index,
  and the fold's list ran the body's copy, or an emptied multi-line definition, ahead of that
  fetch): the called fold's same-step, same-text repeat is dropped now
  (`workflow_guard._job_defects`, the `texts` set beside `seen`, read in that fold alone, granted as
  #3111's duplicates were ruled) -- `main`'s folds are filtered by key alone, as before, so a text
  `main` finds under two keys across its halves keeps its multiplicity (the first cut filtered every
  fold, and lost one in 86 rows of the kit; review round 1), and a later fold's finding of another
  text is kept; seven rows repeat a text once more than `main`'s job (a body with two identical
  `"$@" eval 'curl … | sh'` statements, read at the call as two findings, both runs real: a price,
  pinned); the key stays positional, so a called-fold finding whose fetch of the same tool, url and
  destination stands at the shifted index would be dropped as `main`'s -- none in the kit, a limit
  named; 18 reorder theirs, 228 change a pass's reading alone, the job's kept. Pins moved,
  authorized: the two #3091 rows of `tests/test_workflow_called_bodies.py` report; the five `w() {
  "$@"; }` rows of `tests/test_workflow_printers.py` gain the download-runs finding beside `main`'s
  unread one, and the four `w env 'A=…' curl …` gap rows (two words, two shells) close; the `sudo()
  { "$@"; }` row of `tests/test_workflow_behind_a_wrapper.py` with `sudo -s eval 'T=x'` in front
  reports: the fold reads the function as bash runs it, `-s` no command, the `eval` never run, `T`
  kept and `t` run (truth CCCRR; an over-report under the three `-e` settings, where the step stops
  at `-s: command not found`, which the guard does not model -- a price). `workflow_guard.read`
  wraps the statements in `called` and imports it, two lines granted, and `_job_defects` drops the
  called fold's same-step, same-text repeat, three lines granted (the ruling of #3111's duplicates;
  review round 1 scoped it to that fold, `main`'s folds filtered by key alone, as before);
  `shell_folds._locale` is `_flip(state, on)` now, clearing `_STALE` for either flag. Sizes:
  `scripts/workflow_called_fetches.py` 507 (+275), `scripts/shell_folds.py` 204 (+14),
  `scripts/workflow_guard.py` 646 (+3). `tests/test_workflow_positional_handoff.py`.
- **Workflow program flattening grows linearly with the text a job hands to shells (#3105).**
  `flattened` asked `swallowed` how each handed program's parent command failed, and that proof
  rescanned the outer statement list twice even when the list contained no structural group or
  function definition. Jobs with repeated `echo … | sh`, process-substitution, heredoc, or
  written-file programs therefore grew superlinearly. The shared source-order statement analysis
  now indexes each statement's structural depth, next executable command, enclosing piped group,
  and function definition. The status proof uses that same index for conditional group tails,
  function scopes, and step stops; each function body also shares one cached call proof.
  Indexed and legacy answers match across 23,948 statements and 95,792 step-stop comparisons from
  the workflow test corpus. Three serial pins cover `read`, all four program forms at job level,
  and repeated programs inside one piped group and one function body. For fourfold input locally,
  those paths grew 0.400→3.568, 1.671→15.784, and 1.016→12.514 seconds on `main`; here they grow
  0.238→0.951, 0.903→3.551, and 0.303→1.180 seconds, with no finding in either job reading.
- **Workflow reader reads a group's printed text down the pipe (#3026).** `{ echo "sh -c '...'"; } |
  sh` ran the download the string names under every parent shell and read CLEAN, and so did `( P; )
  | sh` and a group of two statements with the printer first: the parser keeps `{` as a word and a
  `;` or a newline before the closer ends the statement, so the pipe into the shell had no printer
  in front, and the subshell twin was read only with no `;` before its `)`.
  `workflow_printers.group_reading` reads such a group BESIDE the pipe's own reading, never instead
  of it: `producer` and the readers above it answer as on `main`, so where `main` reads the closer's
  own pipeline (`( X; echo P ) | sh`) its finding stands, inline strings included. `_grouped` walks
  back from a group's closer -- a bare `}`, or a stage closing a subshell -- through the statements
  in front of its own to the opener, and hands back the pipelines `main`'s walk never reaches,
  passing over the statements `workflow_forms.flattened` reads into place, a pipeline whose stdout
  goes elsewhere (`> f`, #2430) and an opener alone on its line. Where each ends in an `echo` or
  `printf` (through pass-through stages), their texts are joined in order once per reading of the
  runner -- the printers of one group run under one shell, so two texts at most, and each is handed
  on once; where a reading spells none, their words are weighed as an unspelled printer's, quiet;
  where one is no printer, the answer is LOUD, fail-closed; with none a printer, the group is the
  stream reader's (#2430). The readers take the statements from their callers: four argument-only
  lines in `workflow_forms.py` and `workflow_guard.py`, granted under this issue. The issue's first
  shape, a word that may be nothing in front of the printer (`${S:-} echo ... | sh`), was read
  before this change by #3007's second walk: 276 derived rows with truth from eight parents, the 240
  that run all reported at the job, pinned here as a control. Measured against `main` on the review
  kit's printer families and the rows derived from them (`k3026`, truth from eight parents): the
  brace group's 34 running rows and the derived group families' go CLEAN -> REPORT, and no report of
  `main`'s is lost. The price, named: an option made of a substitution that prints `x`, `s` or
  nothing (`sh -$(echo x) '...'`) leaves the string a file and runs nothing, and the group reads as
  its written twin, which `main` reports; a group holding a statement no printer spells beside a
  printer (`{ echo ok; cat f; } | sh`) is LOUD, and beside a stream `main` reports (`{ curl ... &&
  echo ok; } | sh`) it is a second finding; and #2430's carried twins (`{ echo "$payload"; } | sh`
  after `payload=$(curl ...)`) carry one more finding, the quiet printer reason the plain pipe makes
  too, which `kept` cannot pair here, the shell standing at the closer's statement: #3095 pairs
  them. Open, filed: a nested group, a compound or function body, other consumers (#3117); a group
  written to a file and then run (#3110).

- **Workflow guard carries a compound's closing output by stage (#2937).** A keyword compound
  closed beside a subshell, such as `{ for ...; done | ( curl ...; ); } > tool`, and a fetch after
  an inner file close, such as `{ if ...; fi > /dev/null | curl ...; } > tool`, both ran the
  downloaded `tool` under every parent but read CLEAN. The output map kept one depth and one close
  for the whole pipeline statement: it ignored the subshell boundary in the first form and lent
  the inner `/dev/null` close to the following fetch in the second. Compound-output accounting is
  now stage-level. It includes executable group markers while subtracting array-literal
  parentheses, retains the function-header balancing from #3069, and reverse-walks the closing
  stage's suffix so an inner close applies only to stages inside it while a following fetch
  inherits the outer close. The three M5a rows HNP-012/013/014 and six M9c rows
  HNC-403/412/421/430/439/448 now report in all five shell settings (45 cells). An inner
  subshell's own file, array literal, disconnected close, and later sibling remain cut off. The
  stage-level map also avoids the old `level = after` alternative's named no-run price:
  HNP-016, `{ for ...; done | ( curl ...; ) > f; } > tool; sh tool`, fetches in all eight parents
  but runs in none because the download went to `f` and `tool` stayed empty, and remains CLEAN in
  all five settings. Its no-fetch twin remains CLEAN too. Review found that an inner close piped
  through a forwarding `cat`, `tee`, group, subshell, or loop then stopped at that consumer and
  lost the consumer stage's own outer `> tool`. The stage map now retains the local pipe beside
  that consumer route, but restores it only when it reaches the same unshadowed file boundary
  `main` carried; all 24 forwarding rows from review report again without reopening the accepted
  no-run cells or the out-of-scope top-level forms. Finally, dash 0.5.12 drops `> f`, `>> f`, or
  `> /dev/null` from a subshell that is the last command of a redirected group, sending the bytes
  to the group's outer file. Those three `ffffRffR` truth rows keep `main`'s RRRRR reading. The
  corresponding bash over-report is an existing, named fail-closed price. The round-two seat's
  wider compound hunt found two more forwarding routes through a brace producer and a compound
  consumer (R2-F-034/037), plus dash's descriptor close and an intervening unredirected brace
  (R2-G-013/023). They now keep `main`'s RRRRR reading: a forwarding brace route is admitted only
  when its pipeline enters another compound, and the dash fallback crosses only consecutive
  lexical `}` closes to the first redirected brace. A reader stage that combines two subshell
  closes and their inner and outer files is instead cut at the inner file, keeping the all-no-run
  R2-G-007 CLEAN in all five settings. A descriptor dup or close (`>&N`, `1>&2`, `>&-`) on an
  inner subshell wrapped in further subshells and redirected to a file is reported, though the
  outer file stays empty: an over-report beyond main, named. The previous 667-row probe and 1,106
  HN/HNP rows are unchanged from the round-two head; the accepted baseline loss set in the former
  is 44 rows / 220 no-run cells, not 44 cells. Compound-output tracking moved without other
  behavior changes to `workflow_compound_outputs.py`, restoring the helper documentation while
  leaving `workflow_fetch.py` at 477 lines (the new module is 272).
- **Workflow reader reads a function header immediately after an outer function's opening brace
  (#2975 part A).** `f() { g() { sh t; }; g; }` ran the downloaded file under every parent and
  read CLEAN: the splitter took the inner `()` as a subshell and the rest of the inner body as
  arguments to `g`. The outer header now ends at its `{`, as it does at a newline, when the next
  words form a nested header; the inner header and body therefore become their own statements and
  both definitions enter the function table. This covers the spaced and tight `name()` forms and
  the `function name {` form without changing a group's existing `{ name() {` reading. A gate in
  the inner body belongs only to that function: an outer call with no inner call still reports,
  while an inner call before the use receives its gate. Calls lexically inside a nested definition
  are likewise excluded from the outer body's direct-call set and followed only through an
  explicit call, so a parenthesized nested body cannot make its child's `readonly` effect escape
  into the caller. The #2954-side kit's five S6 rows now report under every setting (the download
  runs in 16 of 16 runtime pairings), their five already-reported controls keep their marks, and
  #3069's nested one-line compound-balance pin reports under all five shells.
- **Workflow reader reads a locale string `$"…"` both ways, as bash and as dash read it (#3048).**
  `sh $"cuda_1.run"` ran the download under the bash parents and read CLEAN: the reader kept the `$`
  -- dash's reading -- and read `$cuda_1.run`, a name the step never sets. Bash drops the `$` of
  `$"…"`; dash keeps it. The reader now reads both: `main`'s fold as it did (dash's), and, where a
  job holds one, a fold of its own bash's way (`shell_folds.folds`, `shell_folds._LOCALE`), the
  guard reporting where either reads a run -- the union, `main`'s reading never lost. So `sh
  $"cuda_1.run"`, `sh $"$T"`, `$"sh" cuda_1.run` and `sh -c $"sh cuda_1.run"` report; and a file the
  step downloaded to a name with a `$` in it, run as `sh $"NAME"`, still reports, as on `main` (dash
  runs it). The price, named: the bash reading reports under a dash parent, where `sh` keeps the `$`
  and runs nothing, and the dash reading under bash. `$'…'` is read as on `main` (its dash reading
  stays #3115's). Differential on the 27,308-row forge kit, 0e576f6f against `main` 90272a5f: 8 rows
  CLEAN->REPORT (the issue's four, each held twice), 0 REPORT->CLEAN, 27,300 identical; the seat's
  27,426-row run the same. One pin pair moves, authorized: `wget $"-qO-" URL | sh` and its `$""`
  twin report (the download runs under bash). `workflow_programs._parsed`, a cache keyed on the text
  alone, held bash's reading of a `$"…"` past the fold for the jobs after it (review round 2); the
  fold's flip clears it (`shell_folds._STALE`, `_locale`), so each fold reads a string its own way.
  `tests/test_workflow_locale_strings.py`. After the #3112 split (`folds` in
  `scripts/shell_folds.py`): `scripts/shell_split.py` is 415 lines (+9), `shell_folds.py` 190 (+25),
  `workflow_programs.py` 488 (+4).

- **Workflow guard: an immediately handled checksum status, or a top-level Bash `ERR` trap, is a
  failure gate (#2440).** Under `set +e` and a shell template without `-e`, the guard refused
  `CHECK; rc=$?; if [ "$rc" -ne 0 ]; then exit 1; fi`, its `[ "$rc" -ne 0 ] && exit 1` and
  `[ "$rc" -eq 0 ] || exit 1` spellings, a direct `$?` test, and `trap 'exit 1' ERR` before the
  check, although each stops the shell before a later use. `workflow_status` now gives only an
  immediate, live `$?` capture in an ordinary lowercase variable to a numeric zero test whose
  failed-check path reaches a literal non-zero `exit`; the bound keeps a use inside the handler
  reported, and a soft step clears only
  its own later use. It also follows a literal top-level `ERR` trap through Bash steps, stopping at
  a replacement, a scope or step boundary, sourced/evaluated text, a dynamic command, or a
  shadowed primitive at any brace depth. Status operands receive credit only for the exact `$?`,
  `"$?"`, `$NAME`, `"$NAME"`, `${NAME}`, and `"${NAME}"` lexemes. A failure-true `[ ]` test used by
  `&& exit` or `if` must quote that complete operand; an unquoted success-true test used by
  `|| exit` remains a gate because splitting makes the test fail and takes the exit path, and
  Bash `[[ ]]` does not split. This structural rule covers every way the step can write `IFS`
  without enumerating writers. Bash alias and builtin lookup state anywhere in the step still
  withholds both status and trap credit. The declared step shell travels with the checksum:
  default, `bash`, and `bash {0}` receive trap credit, while `sh` and `sh {0}` remain reported;
  inlined child shells inherit none. Literal or escaped `$?`, an intervening command or
  reassignment, a readonly or nameref capture, wrong polarity, `exit 0`, wrapped or redirected
  test/exit/trap commands, a subshell, non-stopping/replaced traps, and `continue-on-error` across
  steps all stay fail-closed. Named conservative prices are an unquoted operand in the `&&` or
  `if` polarity, `"${?}"`, and `declare rc=$?`. Runtime
  evidence on Bash 3.2.57, Bash 5.2.21 (default, template, and POSIX modes), and dash confirms all
  five POSIX status forms and their success/non-stopping controls. It also corrects the issue
  text: dash rejects the non-POSIX `ERR` signal and carries on to the payload, so only Bash gets
  that credit. A 900-row grid over two fetchers, three use forms, five shell postures, and 30
  target/control handlers is byte-identical on the issue's three historical baselines and current
  `main`; the branch changes only 234 intended REPORT -> CLEAN rows, with 636 REPORT -> REPORT and
  30 CLEAN -> CLEAN.
- **Workflow reader reads a heredoc reached through its descriptor path as the program (#2972).** `.
  /dev/stdin <<'EOF'`, `source /dev/stdin <<'EOF'` and `sh /dev/fd/3 3<<'EOF'` ran the body under
  every parent (`source`: bash) and read CLEAN: a shell's own stdin operand was read as its program,
  but `.`'s and `source`'s FILE operand was read as a file, and a body on a descriptor other than 0
  was exposed by no field of the stage. `shell_reader` now keeps every descriptor's final heredoc or
  here-string body but 0's on the stage (`fd_bodies`, last, with a default; fd 0's is
  `stdin_heredoc`) and resolves `/proc/self/fd/N` and `/proc/thread-self/fd/N` to N, as
  `output_alias_fd` already reads them; `workflow_written.bind_written` binds a FILE operand whose
  descriptor path names such a descriptor to that body, read as #3098 reads a file the step writes.
  `. /proc/self/fd/0 <<'EOF'` and its thread-self twin, CLEAN on `main` and running on Linux, report
  too. The prices, named: an expanding body is read as `sh <<EOF` is on `main`, so `. /dev/stdin
  <<EOF` holding `echo $(date)` or `echo $HOME` reports; and `source /dev/stdin` reports under the
  `sh` settings, where dash has no `source` and nothing runs. `cat /proc/self/fd/5 | sh` with fd 5
  not open now reads CLEAN, as `main` reads `/dev/fd/5` (nothing runs; with `5<&0` both report).
  Differential on the forge, 95eb83ab against main a16e0fa3 on 27,293 rows: 0 failures, **0
  REPORT->CLEAN cells**, 27,282 rows identical, **11 rows CLEAN->REPORT** -- the #2939 kit's six
  rows, three of this PR's, and two of the kit's own of the same shape, each running.
  `tests/test_workflow_descriptor_heredocs.py`; the Stage field-count pin moves to 15, authorized.
  `scripts/shell_reader.py` is 494 lines (+4), `workflow_written.py` 174 (+22).

- **Workflow reader reads a file the step writes with its own printer, and then runs, as the
  writer's text (#3027).** `echo 'curl … | sh' > s.sh` ⏎ `sh s.sh` ran the download under every
  parent and read CLEAN: the reader bound a `<(…)` FILE operand to the printer that fills it, and a
  fetched file to the run that uses it, but nothing bound a path the step itself WROTE -- with
  `echo`, `printf`, a `cat` and its heredoc, or `tee` -- to the later run of that path.
  `workflow_written.bind_written` now marks, in statement order, a FILE operand (a shell's, `.`'s or
  `source`'s) that names a path an earlier stage wrote, with the writer's script on the word;
  `workflow_printers._filed` reads it as it reads a `<(…)` FILE's script, and `workflow_guard.read`
  binds before it flattens, so `stdin_scripts` reads the file's text and the walk reads its
  statements. The writers' texts are joined in order under one `printf`; a writer the printers
  cannot spell (`echo "$T"`, a `printf` with two words, a printed word holding `$(…)`) is handed on
  as written, each lifted substitution restored around its own script, so a lifted letter in it is
  read as the letter (#3065); beside other writers, or past 64 of them, every text is kept in an
  expanding heredoc the guard reports, so an unspelled line never hides a spelled payload (and two
  benign writers one of which is unspelled report: a price). A lone unspelled writer (`echo "$T" >
  s.sh`) stays unread, a limit: `main` reports the pipe twin, its value reading spelling `$T`. The
  prices, fail-closed where the reader cannot know: every write is read as an append (the stage
  keeps the written words, not the operator), so a benign re-write after the payload still reads it;
  a write under a condition counts; a write in a function body counts where the definition stands
  before the run (never called, or called after the run, over-reports); a write after the run binds
  nothing. A `cat` writing an EXPANDING heredoc (`cat > s.sh <<EOF` ⏎ `curl … | sh $(echo -s)` ⏎
  `EOF` ⏎ `sh s.sh`) is read as its `cat <<EOF | sh` and `. <(cat <<EOF …)` twins are on `main`:
  reported -- and so, as there, is a benign expanding body (`echo $(date)`). Limits named and
  pinned: a command-word run of the written file (`chmod +x s.sh` ⏎ `./s.sh`), a run inside a `-c`
  string (`bash -c 'sh s.sh'`), a value path (`echo … > "$F"` ⏎ `sh "$F"`). The issue's four rows
  and 33 more (every writer, `>>`, `tee -a`, a subdirectory, a subshell or group, a conditional or
  function-body write, the payload written last) report under every setting; the controls (another
  file, a benign file, the run before the write) read as they did; `. s.sh` runs under bash and sh
  (zsh's `.` searches PATH), `echo -e` under bash and zsh. Differential on the forge, 76a4c705
  against main 3e083f96 on 27,258 rows (the 26,982-row kit, 15 of the #2973 rows, the 103-row
  #2954-side kit, this PR's 37 and the 121 file-then-run rows of the #3020 hunt): 0 failures, **0
  REPORT->CLEAN cells**, 27,166 rows identical, **92 rows CLEAN->REPORT** (460 cells) -- 27 of this
  PR's rows (the 10 that stay CLEAN are the controls, the limits and the unspelled writers), 61 of
  the hunt's (a written file that runs the payload, and the lifted-letter rows), and 4 of the kit's,
  each a write-then-run the download runs under (the two rows of the pin that names #3027, and
  `export T=cuda_1.run` ⏎ `echo 'sh $T' > run.sh` ⏎ `sh run.sh` and its `.` twin); 4,478 s wall on
  eight shards at nice 10. `tests/test_workflow_written_files.py`, with a growth pin (n writes then
  n runs, CPU time). Three pins of the old gap move with it, authorized by name, and one that names
  #3027 (the PR body quotes each). `scripts/workflow_written.py` is new (129 lines);
  `workflow_printers.py` 523 and `workflow_guard.py` 639 (+1, the import).

- **Workflow reader reads a function header behind a group's `(` and a name bash takes, and the
  header test costs one lookup a `(` (#2977; #2975 parts B and C).** `( f() { sh t; }; f )` and
  `a.b() { sh t; }` ⏎ `a.b` ran the download under every parent (the bash parents for the name: dash
  refuses it) and read CLEAN: the splitter asked, at every `(` behind a `()`, whether every word in
  front was a keyword, and the group's own token stood in front; and `shell_command._NAME` stopped
  at `[A-Za-z0-9_-]`, where bash takes `.`, `:`, `+` and `@`. To ask, the test joined and split the
  whole stage buffer, and the `esac` test at every `)` joined it again, so one statement of n
  headers cost n joins and a walk over n words each: 8,000 `f() ` took 6.1 s on the forge, about
  x3.4 a doubling (#2977). The three facts the header test asks -- the word the `(` closes, whether
  every word in front is a keyword, whether the one before is `function` -- and the one the `esac`
  test asks are carried word to word now; a group's `(` starts the front over, a closed group `)`
  and any other word end it, and a case arm's token starts it over as `main`'s slice did. `_NAME`,
  `_FUNCTION` and the function table's two patterns (`workflow_function_calls`, by grant) take the
  four characters, so a never-called `a.b() { CHECK || exit 1; }` is no gate, as `f() { … }` is none
  (#2949). The #2954-side kit's three S2 and six S3 rows report under every setting; its own-line,
  `function` and substitution twins read as they did (the S3 own-line rows over-report under `sh` as
  they did: `main`'s posture); `( f() { CHECK || exit 1; }; f )` ⏎ `sh t` reads as the plain `(
  CHECK || exit 1 )` ⏎ `sh t` does on `main` (CLEAN under the `-e` settings, where bash 5.2.21 and
  dash stop the step at the subshell's status and bash 3.2.57 runs on -- #2846, inherited, on both
  trees; REPORTED under `{0}`), where `main` reported it with the function unread. Part A, a header
  on the line of another header's `{` (`f() { g() { sh t; }; g; }`, the five S6 rows), is held back
  and pinned as a limit: read as a header there, a gate in the inner body is credited as the outer
  body's own -- the function table holds no nested one-line definition -- and `f() { g() { CHECK ||
  exit 1; }; }` ⏎ `f` ⏎ `sh t` (`g` never called, every parent runs the download) would read CLEAN;
  #2975 stays open for it. Differential on the forge, 61d0db7c against main d88f89c8 on 27,100 rows
  (the 26,982-row kit, 15 of the #2973 rows and the 103-row #2954-side kit): 0 failures, **0
  REPORT->CLEAN cells**, 27,091 rows identical, **9 rows CLEAN->REPORT** (225 cells) -- the three S2
  and six S3 rows -- and nothing else; no REPORT->REPORT change; 4,378 s wall on eight shards at
  nice 10. The growth pin's text on the forge (CPU time, load 14-17): `f() ` x 1,000 / 2,000 / 4,000
  / 8,000 reads in 0.10 / 0.21 / 0.41 / 0.82 s here, x2.0 a doubling, where `main` takes 0.19 / 0.57
  / 1.93 / 6.91 s, x3.1 to x3.6. `shell_reader.output_alias_fd` drops its unreachable `or "/"` (the
  root is dropped only in front of a `/`). Pins: `tests/test_workflow_function_headers.py`, and the
  growth pin in `tests/test_shell_reader.py` (`f() ` x 1,500 and x 6,000, `main`'s shape, CPU time).
  `scripts/shell_split.py` is 406 lines (+15); `shell_command.py` 699 and `shell_reader.py` 490 (0
  net); `workflow_function_calls.py` 0 net.

- **Workflow reader reads an expansion in FRONT of an option word as that option word too (#3042).**
  `sh $X-c 'curl ... | sh'` runs the string under every parent shell with `X` unset, and read CLEAN,
  and so did `wget $X-qO- URL | sh`, `wget $X-O f URL && sh f` and `sh $(true)-s <<'EOF'` with a
  download in its body: every reader took an option word to be one that begins with a written `-` or
  `+`, so `$X-c` was the FILE the shell runs and the string that FILE's parameter.
  `workflow_option_words.uncovered` reads a word whose leading expansions may print nothing -- `$X`,
  `${X:-}`, `"$X"`, `$X$Y`, `$(true)`, `$1`, `$@` -- as the option word written behind them, where
  that begins with `-` or `+`. The search for the `-c` string, the second walk's strings, the search
  for a value and the second walk's program on stdin read the words that way too, after reading them
  as written, and hand on the step's own words alone; the fetch reader takes the transfer the words
  then name where it has a URL, its stream beside the first. The reading has a switch of its own
  (`as_main`), because `main` has had #2889's rule on since that merged: with it off every reader
  answers as `main` does, and wherever it answered the job's floor reads `main`'s whole answer first
  -- the job with this reading off, #2889's floor in it -- so what `main` reports stands first and
  whole (an independent pre-review found fourteen steps a floor of #2889's one switch would have
  lost). Measured against `main` `c4690b3c`: on 421 rows in seven hunts with truth from eight parent
  shells, 249 rows a parent runs and `main` reads CLEAN report, 60 that run nothing are newly
  reported (the price above), 5 stay open (`main`'s own limits: a dynamic program beside no
  download, and `wget $""-qO-`, `$"-qO-"` and `{,}-qO-`), and no report of `main`'s is lost; on the
  14,322 rows of #2889's thirteen grids no row moves, under either marker (195 stay open on both
  trees, as #2889 left them); with the reading off the findings equal `main`'s byte for byte on
  240,847 rows in 111 sets, in strict mode too; where it answered, 550 rows, the head reports more
  in 458 and loses none; in 36,000 fuzzed steps a third of whose option words are fronted the job
  loses no report of `main`'s -- the first pass alone reads 221 fetcher steps quieter, and the job's
  floor keeps `main`'s marks in every one -- and reports 648 more, 116 of which a parent runs. The
  price, as #2889's: the guard follows no value, so `X=x; sh $X-c '...'` is reported and runs
  nothing; a quoted or escaped `$` reaches the readers unquoted; an expansion that always prints
  (`$0`, `$_`, `${#+c}`, `<(...)`) is read as any other; and a word after such a word is read as one
  that may be the string or a value, as its written twin is on `main` (`bash
  ${TOOL}-${VERSION}/install.sh "$PREFIX"` beside a download is reported, as `bash
  -${VERSION}/install.sh "$PREFIX"` is).
  `workflow_guard.py` and `workflow_options.py` are untouched.

- **Workflow reader reads a call of a function the step defines as the body's shell reading the
  call's input, and as the body's use of the file (#2973, #2982).** `f() { bash -s; }` ⏎ `curl … |
  f` ran the download under every parent and read CLEAN: the fetch's consumer is the call's command
  word, `f`, which names no executor. And `f() { sh tool; }` ⏎ `curl -fsSLo tool …` ⏎ `f` ran it and
  read CLEAN: the use reader weighed a body's stage as written only on a call that passes the file,
  and a body before the fetch is one the walk never reaches.
  `workflow_called.CalledFetches.consumers` now puts, where a call stands behind a fetch -- or a
  bare `{` or `(` that opens a group on its own -- the stage of the body (the group's statements,
  and the bodies they call, eight deep) that reads the call's standard input as a shell: the first
  such stage, or the first behind one that pipes on (`cat | sh`, `tee log | sh`); one reading a file
  or a heredoc of its own, or no shell at all, is passed over, fail-closed. One price, named: where
  the call redirects the fetched file in, a body whose shell runs a file other than the call's input
  (`f() { sh other; }` ⏎ `f < tool`) is still read as the call's consumer, as `main` reads `sh other
  < tool` -- an over-report, fail-closed. The stage carries the call's own input (`with_call_stdin`:
  the pipe, a file, a here-string, the descriptors its redirections leave), and
  `workflow_guard._walk` hands the fetch's following stages and a stage's substitutions through it
  (`f <<< "$(curl …)"`, `f < <(curl …)`). `workflow_uses._function_use` weighs each body stage as
  written on any call, with the call's input (`f < t`). The kit's twenty S9 rows and Z01 report
  under every setting; s9.benign (a body that counts lines), the group and inline controls and Z02
  read as they did; a piped group on lines of its own with a plain shell inside, CLEAN on `main` by
  the same cut, reports now. Differential on the forge, c4d29f3b against main c3528daa on 27,020
  rows (the 26,982-row kit and 38 of this PR's own): 0 failures, **0 REPORT->CLEAN cells**, 26,995
  rows identical, **25 rows CLEAN->REPORT** (185 cells) and nothing else -- the kit's twenty S9
  rows, Z01, its check-between twin (an unbound `sha256sum -c sums || exit 1` between the fetch and
  the call: reported as `main` reports it before a plain `sh tool`, no `sums` written), the kit's
  owntw:AV036 (`f() { sh "$@"; }` ⏎ `f /dev/fd/3 3< tool`: the body's `sh` on the call's descriptor,
  runs), and the two own-line piped group rows. No REPORT->REPORT change. The first run, at
  2ec9f11b, had moved ten more rows of the halves kit's `xr.*.function` family -- a body that holds
  the fetch behind a run of the file, called once, which runs nothing -- and that is 668d15cb's fix
  (the definition must close before the fetch); 4,379 s wall on eight shards at nice 10; run 2, at
  668d15cb, moved the same 25 rows (4,475 s). `tests/test_workflow_called_bodies.py`.
  `scripts/workflow_called.py` is 589 lines (+98), `workflow_guard.py` 629 (+5), `workflow_uses.py`
  597 (+7).
- **Workflow guard fails closed when a whole-word expansion may name `wget`'s output
  (#3034).** `X='-O tool'; wget $X URL; sh tool` read CLEAN under all five `shell:`
  settings while every truth runner wrote and ran `tool`; so did the quoted attached form
  (`X=-Otool`), an unquoted substitution, a bare `-O` before a written name, and the row whose
  checksum names the URL basename that was never written. The file reading now refuses a bounded
  basename where an expansion operand stands beside a written-scheme URL and stdout has no pipe or
  redirect, yielding the existing unresolved-transfer finding. That reading is under #2889's
  switch and therefore stands beside the old basename view; its separate stream reading opts out,
  preserving every direct-pipe report and leaving #3035's routed `tee`/redirect shapes pinned.
  The price, named: an otherwise unused `wget $OPTS URL` now reports; a `wget` whose words hold an
  expansion stays reported even where a bound checksum of the named file precedes its run, as
  `curl` already does; and so do #3045's two dynamic process-substitution rows through the
  unresolved file view (their direct stream binding remains the more precise follow-up). Two
  unknown operands with no written URL remain bounded CLEAN.
  Local differential on 14 rows under five settings and both guard passes: the five issue rows,
  unused-options price and two #3045 rows move CLEAN -> REPORT (80 cells, 40 in the job reading),
  six controls are unchanged (60 cells), and 0 cells move REPORT -> CLEAN.
- **Workflow compound depth stays balanced after a function definition (#3069).** A definition
  such as `f() { :; }` was read as an opening statement with delta zero and a later `}` with delta
  -1. The negative depth made a subsequent brace group, `if`, or `while` lose the pipe or redirect
  on its own close, so downloads inside it read CLEAN. `_compound_delta` now uses the existing
  function-syntax reader to count every compound opener after `f()` / `function f` in the header's
  statement: both the structural `{` and an immediate `if`, `while`, `for`, or `until`. Twenty-three
  issue shapes—including multiline and consecutive definitions, each keyword-body form, nested
  groups, pipes, and a file redirect—now report under all five shell settings; this also retires
  #3050's named `{ f; } | sh` limit. A nested one-line definition remains a named CLEAN limit of
  #2975 part A rather than treating its inner header's `{` as an ordinary group. The #3034 wget
  expansion rule also distinguishes a fetch stage's own output from a pipe or redirect inherited
  from its enclosing compound: five definition/compound interaction rows keep `main`'s REPORT, the
  group redirect, tee and discard twins now report, and a harmless inherited `| cat` is the named
  fail-closed price; the corresponding stage-owned outputs remain #3035's CLEAN limits. A
  subshell's trailing redirect is attached to its inner stage, so its redirect and discard rows
  report too; the indistinguishable `( wget $X URL > tool )` is the named fallback price. Local
  differential on 47 pinned row IDs (46 distinct scripts), under the direct reader plus five job
  settings: 180 CLEAN -> REPORT cells across 30 issue/price rows, 102 unchanged cells across nine
  prior controls/limits, five interaction IDs and three #3035 limits, and 0 REPORT -> CLEAN cells.

- **Workflow reader keeps a stage's second `${…}` word whole where it still stands before the
  command word (#2976).** `curl -fsSLo t …` ⏎ `${Y:+/usr/bin/env true} ${Z:+/usr/bin/env true} sh t`
  ran the download under every parent and read CLEAN: `shell_split._split` kept a `${…}` with bare
  blanks whole only while no word kept whole stood in front of it (#2856 round 8's one command word;
  the #3002 round's `leads` flag stopped at a word kept whole, naming this as #2976's), so the first
  word was read whole, the second cut at its blanks, and the reading in which both are nothing --
  `sh t` -- was never read. The flag now carries past a word kept whole as it carries past any word
  bash may make nothing of, so a `${…}` word is whole wherever it still stands before the command
  word; the round-8 invariant holds -- once the command word is set, every later `${…}` word is
  `main`'s split words -- and `shell_command._command_result` reads the second word as it reads the
  first (the empty half on to the next word, the W half to its words). The kit's six rows (s7.two,
  s7.three, s7.two-fetch, s7.two-pipe, s7.two-same, s7.two-sudo) report under every setting; s7.one,
  s7.sudo-two, s7.two-default and s7.two-check read as they did. The price, named: both halves of
  every such word are read whatever the step sets (#2856 round 13), so `Y=1` ⏎ `${Y:+…} ${Z:+…} sh
  t` (s7.two-set, nothing runs) now reports as its one-word twin did on `main`; a read that knows a
  name set for sure before the stage is #3077's. Differential on the forge, b449b260 against main
  1cfb16de on 27,010 rows (the 26,946-row kit and 64 of this PR's own): 0 failures, 0 REPORT->CLEAN
  cells, 26,139 rows identical, 156 rows CLEAN->REPORT -- 150 where a parent runs (138 of them the
  halves kit's rows that carry `${S:- } $T ${U:+sudo -E} sh -c '…'`, the #3002 shape whose pin named
  #2976), 6 where nothing runs (s7.two-set and five set-before twins, the price) -- and 717 rows
  REPORT->REPORT with a finding added or sharpened. `tests/test_workflow_second_whole_word.py`, and
  the splitter's side in `tests/test_shell_reader.py`; the two pins of the named limit (#2954's in
  that file, #3002's in `tests/test_workflow_words_that_are_nothing.py`) move with it.
  `scripts/shell_split.py` is 391 lines (+1, the comment); the reader's other modules are untouched.

- **Skill: `description`/`whenToUse` scoped to what Panopticon is -- a comprehensive, heavyweight
  multi-agent audit, not a default review.** The frontmatter listed "code, pull requests, branches,
  security posture, test quality, architecture, or database surfaces", which reads as "use for any
  review" and drew agents to Panopticon as a first-reach tool for small or routine work. The line
  now names the shape -- discovery, scouting, parallel specialized reviewers, a validated CI-gating
  synthesis -- and says to reach for it when breadth and depth justify the cost. The line keeps the
  `Use when` trigger form, so `test_skill_md.py`'s trigger-only/host-neutral guard holds. No
  behaviour change; `dispatch` still mirrors `whenToUse` from the description.
- **CI: the `test` job timeout is 60 -> 90 minutes (stopgap, #2933).** The 3.11 matrix leg
  was cancelled at the 60-minute job limit when its parallel pass ran slow under runner
  contention, leaving no room for the serial timing pass. 90 minutes restores headroom while
  the suite stays unsharded, and drops back once #2933 shards it.
- **CI records per-test durations for the coming shard split (#2933).** The parallel test
  pass now runs under `pytest-split`'s `--store-durations`, writing `.test_durations` and
  uploading it per Python version. The data lets the eventual shard split balance groups by
  measured time rather than test count; no gate or behaviour change.
- **CI: the test suite is sharded (#2933, rough first cut).** One job per Python version ran
  both passes, and the 3.11 leg took 18 to 56 minutes depending on runner contention. Now
  `test-cov` (3.12, unsharded) carries both passes, the single 90% coverage gate and the
  complete `.test_durations` profile; `test` runs the parallel pass for 3.11/3.13/3.14 in two
  groups balanced by the committed `.test_durations` (`pytest-split`, `least_duration`);
  `test-serial` runs the timing-bound tests alone on a fresh runner; and `tests-passed` is the
  one always-reporting gate over all of them, so branch protection names a single check from
  here. Coverage is interpreter-independent in this repo (no version-gated branches), so gating
  it on one version loses nothing. The matrices no longer fail-fast, so one red leg no longer
  cancels the others. Expected: about 12 minutes per 3.11 shard.
- **Workflow reader: a written path a pattern, a `cd`, a link or `/proc/self/root` gives names the
  descriptor it reaches (#3051).** `curl -fsSL URL > /dev/stdou[t] | sh`, `cd /dev` then `> stdout |
  sh`, `ln -s /dev/stdout o` then `> o | sh`, and `> /proc/self/root/dev/stdout | sh` read CLEAN
  while every shell ran the download (the pattern: under bash): #2744's reader read a written path
  as written. `output_alias_fd` now reads an unquoted pattern bash expands as the one listed
  descriptor name it matches, where it matches one (dash expands no redirection's pattern, a price
  under `sh`), and drops `/proc/self/root` and `/proc/thread-self/root`, the process's own root, in
  front of a path as often as they stand; and the stage's redirections ask `sources` for a written
  path as they do for a read one (#2919), so a `cd` or a link the step may have made adds the
  descriptor's reading beside the file's, fail-closed as the reads are (a `cd` in a subshell, or one
  a later `cd` replaced, still counts: two prices, pinned). Measured on 26,946 rows, `main` f5c66d7f
  against this change, under each of the five `shell:` settings, in three readings (the job, its
  main pass, its walk pass) and, for a row of 2 to 12 lines, in four step forms beside the one-step
  reading: 26,924 rows read the same, byte for byte -- #3064's kit of 26,836 and #3050's 63 among
  them -- and 22 move CLEAN -> REPORT (390 cells): the issue's 16 rows whose truth runs (the four
  patterns, `>` and `>>` to `/dev/stdou[t]` and `/dev/fd/[1]`; `cd /dev` then `> stdout` and `cd /`
  then `> dev/stdout`; `ln -s /dev/stdout o` and `ln -s /proc/self/fd/1 o` then `> o`; eight
  spellings through the own root, `-o` and a `tee` operand among them) and six twins (`2>&1 >
  /dev/fd/[2]`, `2>&1 > /proc/self/root/dev/stderr`, `cd /proc/self/root` then `> dev/stdout`, `ln
  -sf`, and the two prices, `( cd /dev )` and `cd /dev; cd /tmp`); none moves the other way or
  changes a finding it had. The 160 cells of those rows that stay CLEAN are the pattern rows under
  `sh` and the `cd` or link rows split so the `cd` or link is a step of its own. 1,996,230 cells, 0
  failures. Limits, pinned: `-o o` behind a link (`stdout_named` asks the path alone), and a link to
  a link (`sources` follows one). Sizes: shell_reader.py 466 -> 484.

- **Workflow reader: a function that streams a download is read where a shell reads its output
  (#3050).** `f() { curl -fsSL URL; }` then `f | sh` -- and `sh <(f)`, `eval "$(f)"`, `sh -c
  "$(f)"`, `f > t; sh t`, a download helper `dl() { curl -fsSL "$1" -o "$2"; }; dl URL t; sh t`, a
  body of several statements, and a function the body calls -- read CLEAN while every shell runs the
  download: the stream rule asked the stage's command, the function's name, and a `$(f)` was a
  substitution the guard did not follow into the body. A call of a function the step defines is now
  read as the body's fetches where the call stands (`workflow_called.CalledFetches`, the walk): the
  last stage of each statement of the body, and of the bodies it calls `_DEPTH` deep, with the
  call's words in its positionals (`$1`, `"$1"`, `$@`; in single quotes none). A stage whose output
  leaves on the function's standard output -- `stdout_to_pipe` at every link, so `> /dev/null` and
  `g() { f > /dev/null; }` leave nothing -- takes the call's stage, so the call's pipe, substitution
  or redirect is its consumer, and its own redirects read as the inline twin's do (`2>&1 >
  /dev/stderr` streams, `> /dev/stderr` does not, #2744); one that writes elsewhere keeps its own
  stage. A file the body names as written (`-o t`) was read at the definition and is not read again
  at the call; a wrapper in front of the name runs no function (`env f`); a definition after the
  call is no function yet. Measured on 26,899 rows, `main` 04e06272 against this change, under each
  of the five `shell:` settings, in three readings (the job, its main pass, its walk pass) and, for
  a row of 2 to 12 lines, in four step forms beside the one-step reading: #3064's kit of 26,836 rows
  reads the same, byte for byte, and of this lane's 63 -- the issue's 17, their 14 context rows, 32
  inline and compound twins -- 27 move CLEAN -> REPORT as one step (135 cells: 11 of the issue's 12
  CLEAN rows, 12 of the 14 context rows, and `f 2>/dev/null | sh`, `f | tee t | sh`, a body of
  several statements and a body with `&&`), each as its inline twin reads, and none moves the other
  way or changes a finding it had; split one step a line they stay CLEAN, a function not crossing
  steps. 1,992,705 cells, 0 failures. Limits, pinned: a download held in a variable (`x=$(f)`, `eval
  "$x"`: `workflow_forms.carried` reads `$(f)` as no fetch), a body's own `| tee t` (the file, not
  the stream), and a `{ f; } | sh` group behind a definition, whose consumer the compound reader
  loses as it does the inline group's. Sizes: workflow_called.py 388 -> 491, workflow_guard.py 586
  -> 601.

- **Workflow guard recognizes bounded, named download clients (#2829, adapter slice).** aria2c,
  Axel, FreeBSD `fetch`, HTTPie `http`/`https`, `gh release download`, network `git clone`, and a
  direct `pip download --no-deps` archive now bind the URL to the file or fetched tree their own
  option grammar names. Documented stdout forms bind a following shell, exact checks clear exact
  files, and an unknown
  option fails closed as an unresolved transfer. Tool-specific controls keep diagnostics, HTTPie
  offline/quiet output, plain local clones, non-download subcommands, and literal `-` output files
  clean.
  A file checksum cannot bless a cloned tree, including one moved or copied before execution;
  server-chosen HTTPie filenames and dependency- or index-selected pip artifacts remain
  deliberately unresolved; the raw-stream complement is the next entry.
  The Dockerfile integrity suite documents one owner-accepted exception: the exact RustSec
  `advisory-db` clone into `/home/scanner/.cargo/advisory-db` is fresh-required security-advisory
  data, not a binary, and checksum-pinning it would stale the advisories the scan depends on. No
  other recognized fetch is exempt.
  Across 165 targeted cells under five workflow shell settings, report cells rise 15 -> 105 with
  90 new detections, no REPORT -> CLEAN cell, and no pre-existing reason lost; `aws s3 cp` stays
  CLEAN while `gh release download` moves to REPORT in all five settings.
- **Workflow guard fails closed on raw network streams handed to executors (#2829, network
  slice).** `/dev/tcp` and `/dev/udp` input, connecting `nc`/`ncat`/`netcat` and `socat` forms,
  `openssl s_client`, and foreign one-liners naming `urllib`, `requests`, HTTP modules or `fetch(`
  now become destination-less fetch records when their bytes feed a shell directly, through
  pass-through stages, inside a literal child-shell body, or through command/process substitution.
  Explicit netcat/socat listeners, other OpenSSL subcommands, plain foreign code, redirected output
  and producers not feeding an executor remain clean. The descriptor form
  `exec 3<>/dev/tcp/...; cat <&3 | sh` is paired conservatively: because the flattened reader does
  not retain descriptor numbers across statements, a hidden close or reassignment can over-report.
- **Workflow guard keeps an explicit stdout download through an adjacent `tee` (#2916).** `curl`
  or `wget` naming `-`, `/dev/stdout`, or descriptor 1 now binds the file `tee` writes before the
  stdout marker is discarded; `/dev/null` and an inferred remote filename `-` remain non-streams.
- **Workflow guard recognizes four more shells that consume downloaded programs (#2792).** `csh`,
  `tcsh`, `fish`, and `mksh` now bind fetched stdin and file operands without claiming support for
  their command-string option grammars; non-shell consumers and unsupported option forms stay clean.
- **Workflow guard resolves fetch commands held in array command words (#2770).** A whole
  `${array[@]}` or `${array[*]}` command word is read through the step's value table when an
  alternative starts with a modeled fetcher; scalar defaults and unrelated dynamic commands keep
  their existing boundaries.
- **`scripts/workflow_guard.py` splits the judgment of one fetch into `scripts/workflow_defect.py`
  (for #3050, #3051 and #2433, reader lane).** A pure move at the module's size: 700 of its 700
  lines, before #3040 and after it. Two pieces move, each byte for byte with the comments above it
  and in their old order. Lines 405 to 422 (of `main` after #3040) hold the three reasons a checksum
  the job ran clears nothing (`_SOFT_STEP`, `_UNSHARED_IF`, `_UNSHARED_BRANCH`) and `_unshared`,
  which picks the half of a check's condition that a use lacks. Lines 427 to 521 hold
  `_runs_after_failure`, `_binds` (whether a check may clear a use) and `_defect` (why one fetch is
  unverified). The new module imports nothing from `workflow_guard`, which imports all seven back
  under their own names. Each of the new module's 14 imports is the import `workflow_guard` held, so
  every name the moved code reads is the object it read before. `uses as _uses` stays importable
  from `workflow_guard` for `tests/test_dockerfile.py`. No caller moved and no test moved. The tests
  swap five names on `workflow_guard`: `_job_defects`, `read`, `_defects` and `statements` by patch,
  and `folds` by assignment. The new module binds none of them, so each swap still reaches every
  lookup. The step walk stays where it is, because it looks up `statements` there. The new test
  module holds these facts. No verdict changes, on 26,836 rows: this lane's kit, the #2942 seat's
  three samples, and 360 rows that put a checksum in a branch its use is not in. Every finding of
  every row, its name and its reason, is the same under `main`'s scripts (d8581828, after #3040) and
  under the move's. That holds under each of the five `shell:` settings and in each of three
  readings (the job, its main pass, its walk pass). Each row is read as one step and, where it has 2
  to 12 lines, also as a job of one step a line in four forms: no `if:`; every other step under
  `always()`; every step but the last under one `if:`; and every step but the last under
  `continue-on-error: true`. That is 1,989,000 cells holding 1,570,117 findings under each tree. Of
  the job's 619,284 findings, 533,960 are `_defect`'s, and 28,180 carry a moved reason: 15,497
  `_SOFT_STEP`, 12,203 `_UNSHARED_IF` and 480 `_UNSHARED_BRANCH`. The two dumps are equal byte for
  byte. The guard's command line, run as a script over 4,635 jobs, prints the same 4,256 findings
  under both. Sizes: 700 -> 586, and 138 for the new module.

- **Workflow guard retires a carried stdout download after a certain same-shell replacement
  (#2437).** A plain `x=1` or `unset x`, an assignment in `{ ...; }`, and an assignment in a
  function the step then calls all left `x=$(curl ...)` held at a later `eval "$x"`; a literal
  argument `{`, balanced `{}` arguments, and a line-only closing `)` exposed the same stale
  answer through either the carried-download reason or #2483's generic dynamic-program fallback.
  The carried-value walk now records the exact `(statement, variable)` where an expansion-free
  replacement proves that fallback cannot be the download, and the existing quiet reason carries
  the variable metadata needed to remove only that reason. A brace compound is read as the step's
  shell unless its enclosing list can skip it, a boundary redirection can stop it, or the shell
  forks it. A directly called function contributes
  only caller-visible, unconditional assignments from one top-level definition that still exists;
  a local, return path, branch, nested compound, child definition, `unset -f`, `eval`/source, or an
  intervening known function keeps the old value fail-closed. Failed redirections, unseen writes
  (`read`, arithmetic and parameter assignments), tilde expansion, aliases and traps retain the
  generic reason. The child and skipped controls still
  report, byte for byte: a 675-cell extension covering those boundaries under three fetch forms,
  five uses, and five `shell:` settings is identical to `main`.
  Across the 2,175-cell target/control cross-product against `main` 1cfb16de, 1,275 reports are
  identical, 780 target reports become CLEAN, no CLEAN row becomes a report, and 120 reports keep
  reporting with a narrower reason. Those 120 are the eight brace/function/literal target
  spellings printed through `printf ... | sh`: the stale carried reason leaves while the existing
  conservative printer fallback remains, a retained price. Runtime truth on Bash 3.2.57, GNU Bash
  5.2.21 in default and POSIX modes, and dash suppresses the payload for all seven target families
  and runs it for all seven must-trip controls. The state layer moved from the 700-line
  `workflow_forms.py` into `workflow_carried.py` (441 and 655 lines) so the new proof stays below
  the flat-module ceiling; the compatibility imports remain in `workflow_forms`. Review round 2
  found that the performance gate used a file destination where the holder uses stream capability:
  a wget option supplied through `$WOPTS` may write stdout while its parallel file reading names the
  URL basename. The gate now calls the holder's own assignment predicate, restoring the carried
  verdict for that form while file-only fetches retain the fast path. Replacement state is also
  shell-aware at a POSIX special-builtin prefix (kept under the two `sh` postures, discarded under
  the three Bash postures), and stays fail-closed after a Bash nameref target, a possibly-readonly
  name, `time` around an assignment, `command read`, or a dynamic command/function call. On the
  review seat's 189 rows under five shell settings (945 cells), 675 remain REPORT and 30 remain
  CLEAN across `main`, round 1 and round 2; 139 intended REPORT -> CLEAN cells remain, and round 2
  restores all 101 unsafe round-1 CLEAN cells to `main`'s REPORT, with no errors. The 150-line,
  150-call file-fetch timing guard still passes; the measured stdout-fetch state pass costs about
  14% over `main`, the bounded cost of tracking values that can actually carry a download. Review
  round 3 carries a certain called body's global `readonly` or `declare -gr` attribute back to its
  caller, so an assignment that can fail there cannot retire the held download; local and child
  attributes still do not escape the body. Both review rows and their late-call control report
  under all five shell postures. Review round 4 applies that rule fail-closed when either the call
  or the caller-visible readonly declaration is conditional, nested, redirected, or found through
  multiple definitions. All seven review shapes now REPORT under all five shell postures; a prior
  pipeline call also retains #3083's finding and the later eval refusal. Dead and child calls,
  local attributes, and a replacement made in the body before readonly remain CLEAN. A
  caller-side assignment after that last control conservatively over-reports because the readonly
  makes the assignment uncertain. After folding #3086, the expanded 1,000-cell review matrix has
  811 cells that stay REPORT, 139 intended cells that stay CLEAN, 15 controls that stay CLEAN, and
  35 round-4 target cells that move from CLEAN to REPORT. The 960 previously banked cells and all
  120 workflow-guard cells from #3083 are byte-identical. Round-4 module sizes are 699 lines for
  `workflow_carried.py`, 607 for `workflow_called.py`, 441 for `workflow_forms.py`, and 638 for
  `workflow_guard.py`. Review round 5 makes the skip exception a proof: negated conditions and a
  step-defined `true` or `false` cannot prove a call dead. A dynamic command word now makes later
  plain replacements uncertain for the rest of the step, and the once-per-body attribute scan
  reads readonly declarations folded into one-line nested definitions. The complete 54-row review
  seat has 270 cells under the five shell postures: 195 expected reports and 75 expected clean
  readings, with no mismatches. Exactly the 11 rejected rows, 55 cells, move from round 4's CLEAN
  to REPORT; all other seat cells keep round 4's answer. An expanded 1,150-cell differential keeps
  all prior 1,000 cells byte-identical, moves 75 target cells to REPORT (the 11 rows plus nested
  declaration spellings and a redefined-`true` boundary), and leaves 70 clean control cells plus
  the five accepted `while false` reports unchanged. The cached scan keeps the existing serial
  cost gate green; alternating round-4/round-5 measurements were +4.6% for the file-only shape and
  -5.7% for the stdout-holder shape. Round-5 module sizes were 677 lines for
  `workflow_carried.py` and 663 for `workflow_called.py`; the other two remained 441 and 638
  lines. Review round 6 follows a known function command folded behind an inner definition's
  opening brace as a possible transitive call, rather than losing that call with the nested
  function header. A certain `return` ends only the body at its own function depth, so a nested
  body's return cannot stop the outer body's readonly scan. In a 285-cell round-5/round-6
  differential, all 270 banked seat cells are byte-identical, Q14 and Q20 supply the only ten
  CLEAN-to-REPORT changes, Q21 remains REPORT under all five shell postures, and no cell errors.
  Review round 7 takes option A: one command-view enumeration applies the call, status-shadow,
  negation, dynamic-command and readonly proofs at every brace depth, including definitions folded
  into an outer header stage. A nested redefinition of `true` now defeats the dead-branch proof,
  and a dynamic command inside an inner function makes the reachable body unknown; nested calls in
  pipelines, background lists and parenthesized bodies remain CLEAN. In a 1,515-cell replay of all
  posted seat rows, only W609b and W616 change from CLEAN to REPORT under the five shell postures.
  Final module sizes are 678 lines for `workflow_carried.py` and 686 for `workflow_called.py`; the
  other two remain 441 and 638 lines.

- **Workflow guard applies a prefix assignment after its command's words expand (#2433).**
  `x=$(curl ...) eval "$x"` and its `sh -c` twin reported as handing the new value straight to
  the executor, although the live `$x` expands before the assignment applies; both now read CLEAN,
  as does a prefix before `true`, while `x=$(curl ...); eval "$x"` remains the must-trip control.
  The reader gives each quoted dollar its own live-double-quote provenance, so embedded strings and
  equal-looking arguments retain their lexical distinction: single-quoted and escaped references
  are re-read after the prefix applies and still REPORT. The hand-off follows only a substitution
  that contributes to the final scalar assignment; a replacing assignment drops earlier values,
  while `+=` keeps them. A live reference can still read the old value, which remains reported when
  an earlier statement supplied a download. The issue's claim that every prefix expires with its
  command has a POSIX boundary: dash and Bash POSIX mode retain assignments before special builtins.
  The guard therefore carries those values to later commands, while `command eval`, `unset x`, and
  `export x=...` discard or replace them as the shells do. Conservative readings remain for an
  executor with no known script word and for a program string whose construction loses quote
  provenance. On a 154-row cross-product, the 63 base-REPORT/head-CLEAN rows produced zero payload
  runs in 189 executions across Bash 3.2.57, GNU Bash 5.2.21, and dash. Eight additional rows now
  report; all eight run under dash and Bash 5.2.21 in POSIX mode and stop under both default Bash
  versions.

- **Workflow reader reads an expansion in a shell's option word as text the word does not write
  (#2889).** `X=c; sh -$X 'curl ... | sh'` runs the string under every parent shell and read CLEAN,
  and so did `HOME=-c; sh ~ '...'`, `sh -$(echo oc) errexit '...'` and `wget $(echo -qO-) URL | sh`.
  The readers of the programs lane asked an option word for its letters, and `-$X` writes none: they
  read the NAME's instead, so `-$cmd` was a `-c` and `-$s` was not. #3020 gave a lifted `$(...)` in
  such a word both readings a shell may give it; this is that rule for every other expansion, in
  four parts. A parameter reference in an option word -- `$X`, `${...}`, `$1`, `$@`, `$-` -- is
  text the word does not write, as a marker is (`workflow_option_words`), so every reader of #3020
  reads the word both ways and a name's letters are no option letters; a reference that prints
  digits alone (`$#`, `$?`, `$$`, `$!`, `${#X}`) stays written. A word that holds an expansion may
  print an `o` or an `O`, which takes the next word: each word after it that may be a NAME may be
  its value, however many, at every option word the walk passes -- one search beside `main`'s own
  walk past the options (`_reached`), `main`'s operand first -- and a refusal by NAME is read only
  from an `o` written before the word's first expansion (`X=O; bash -c${X}o extglob errexit '...'`
  runs the string, and read CLEAN as a refusal). No table of names is asked: bash's `-O` takes a
  shopt name and zsh's `-o` one of its own, so a word shaped as a name may be one. A tilde alone
  (`~`, `~+`, `~-`, `~1`) is a value, as `$X` is, read beside `main`'s reading of it as an operand.
  And `wget` handed a whole-word expansion may be handed `-O-`: where its stdout is piped the
  stream view is added, and the file view stays `main`'s. Every new reading stands BESIDE `main`'s,
  never instead of it -- and since a reader handed more may still choose a quieter reading of a
  step (an independent pre-review of the first build found 13 shapes `main` reports that it read
  CLEAN: two `-c` strings joined into one, a quiet stdin hand-off before the loud reason, a
  candidate where the dynamic program was), the JOB is the floor. The rule has one switch
  (`workflow_option_words.ruled`, off under `as_before`) that every reader it changed answers
  through, and where it answers in a job, `job_defects` reads the job again with it off and keeps
  those findings first and whole (`passes`; in strict mode a text only the rule reads that the
  reader refuses leaves `main`'s reading the answer). What `main` reports is reported, in `main`'s
  words, by construction: with the rule off the findings equal `main`'s tree byte for byte wherever
  `main` answers, on 224,074 rows -- the grids, my standing sets, the #2942 seat's, and the first
  pre-review's own texts -- where the rule's reading alone would have read a setting `main` reports
  CLEAN on 305. The walks are loops that read each word a bounded number of times (a standing
  test), and the readers they feed look words up in sets: a command of 8,000 option words reads in
  seconds (the first build took 178 s on 200 pairs and raised RecursionError at 1,100 words). The
  floor's price is that second reading, about 1.6x over the cost sets: #3020's and #3019's
  grids hold such a word in most jobs, my standing sets in almost none, and none of the seat's sets
  or of this repository's workflows does. The rule's price was
  measured and ruled before the code: the guard follows no
  value, so a word that MAY spell `-c` is read as one whatever the step assigns -- `X=e; sh -$X
  '...'` is reported and runs nothing, as its whole-word twin `X=-e; sh $X '...'` has been since
  #2344. On 14,322 rows in 13 grids with truth from eight parent shells, the rows a
  parent runs and the guard read CLEAN go 699 -> 195, each one left another
  issue's or open with its letter written out too; 507 rows that run are newly reported
  and 1,089 that run nothing, of which 937 are steps that fail where they stand (the
  shell takes the program text for a FILE's name) and 139 more are the `X=s` rows, whose
  string is a positional parameter; no report of `main`'s is lost, and no mark depends on a
  marker. The issue's own rows -- 36 of PR #2858's round-5 matrix and round 9's
  tilde case -- all report. Left for other issues: a `$` command word whose cluster is not its
  first word (#2671, #2900), three shapes of `wget` (#3033, #3034, #3035), four families a probe
  of the rule's own nouns found open on `main` as well -- an expansion in FRONT of a written
  option word (`sh $X-c '...'`, #3042), a substitution where the `-c` string stands (#3043), the
  value of a written `-O` (#3044), a stream read through a `<(...)` (#3045) -- and the tightening
  that would follow the step's own assignment, which needs the value table.
- **Workflow reader: the other words bash makes nothing of in front of a command (#3002, #3007,
  #3038).** `$T ${S:+sudo -E} sh -c 'curl ... | sh'`, `${S:- } sh -c '...'`, `${SUDO:-sudo} -E sh
  -c '...'`, `$SUDO echo '...' | sh` and `S=command; ${S:-sudo} eval '...'` each read CLEAN under
  every `shell:` setting while the parent shells ran the pipeline: three holes in one reader,
  `shell_defaults._optional`, which drops a `$` word in front of a name it knows. It kept only a
  stage's first `${…}` with a bare blank whole, and read an empty default but not one that is only
  a blank (#3002); it dropped a default naming a wrapper only where the very next word is a known
  name, and knew no printer behind a dropped word (#3007); and it read such a default as its
  wrapper whatever the step set its name to (#3038). The limits #2997's and #3003's fixes pinned as
  shared with `main` were the same reader's: the other words that are nothing with their name
  unset -- `$1`, `$@` and a double-quoted `"$@"`, an array, an indirection, a pattern taken off, a
  substring, a case change, a default that holds one more name, an alternate of any of them. The
  second walk reads them all now, **in folds of its own** (`_drops`, `_masks`): every fold `main`
  reads is read as it was, and each once more with these words read as nothing, so the guard
  reports where either reading does and the main pass is `main`'s. That is what keeps a check
  behind such a word from taking a report (#3037's class): a first port that dropped the words in
  every fold of the second walk turned 195 of 4,960 check rows from REPORT to CLEAN, and this one
  turns none. The reader now says where a kept word stood whole in double quotes (`double`), as
  `'$@'` is two characters; `_split` keeps a `${…}` whole behind words that may each be nothing;
  and the names a job's steps set to `command`, to `builtin` or to nothing are read beside the
  wrappers they define (`shell_wrappers.set_to`). Five pins move from limit to fixed, three of them
  by the coordinator's ruling as they name no issue; `shell_command.py` stays at 699 lines. Against
  `main` on 12,502 rows with 16-run truth -- the three issues' kits, a hunt of the new rule's whole
  grammar, a hunt of checks behind each new word, and every row the new tests assert: **no cell
  goes from REPORT to CLEAN**, the main pass's own marks move on none, and 15,139 cells report that
  a parent runs. The price, named and pinned: a form dash refuses reports under the two `sh`
  settings too, as #2997's `source` does (the reader has one grammar); a word is read as nothing
  whatever the step did to its name, so `set -- echo; $1 sh -c '...'` reports though it only
  prints; and a check the guard does not credit still stops the step where its written twin
  reports the same. Left for their own issues: a substitution that prints nothing (#2693), two
  references glued (#3016), `coproc` (#2894), a quoted reference to a name the step set (#2769),
  and the shapes the hunt found and this PR pins as limits, a double-quoted default naming a
  wrapper (`"${SUDO:-sudo}" sh -c '...'`), a `$` word where a default wrapper's own words end and
  an alternate naming a wrapper in front of its own words among them.
- **Workflow guard binds downloaded files whose bytes become a shell program (#2428).** After
  `curl -o tool …`, `eval "$(cat tool)"`, `sh -c "$(cat tool)"`, and
  `echo "$(cat tool)" | sh` reported only through a generic dynamic-program fallback, which also
  reported the unrelated `cat other.sh` twin and could not name the file a checksum must gate;
  `bash <(cat tool)` remained CLEAN. A new file-reader layer now carries the exact inputs of
  `cat`, `head`, `tail`, `sed`, `tr`, and Bash's `$(< file)` shorthand from a command substitution
  to the `eval`/`-c`/printed program that executes their bytes. The same source binding follows an
  input process substitution used as a shell or `source` script operand. A checksum of that file
  ahead of the handoff clears it and one after the handoff does not. The existing generic verdict
  remains beside the exact source-bound verdict so the change is a strict reporting superset; an
  unrelated reader beside a download keeps that generic verdict, while a job with no download
  stays CLEAN. Narrowing that pre-existing generic over-report is tracked separately in #3059.
  Dynamic reader paths, unsupported reader arguments, output
  discarded inside the substitution, in-place `sed`, non-stdin descriptors, and a reader file an
  earlier redirect or bounded writer generated retain the generic fail-safe. `shell_text.Process`
  now records `<` or `>`: the input form binds, while `bash >(cat tool)` stays CLEAN as runtime
  does; the older printer rule's documented output-side over-report is unchanged. The narrower
  `bash < <(cat tool)` stdin-redirection form remains a pre-existing CLEAN gap. A 16-row
  no-network probe under GNU Bash 5.2.21, GNU Bash 3.2.57, and dash marked the payload for the
  direct command-substitution forms under all three, and for the process-substitution target
  under both bashes; dash refuses that syntax. It never marked the output-side or unrelated-file
  controls; the failing checksum control ran and stopped the payload under every shell.
- **Workflow reader: `cat` reads a download on redirected standard input (#2884; the pipe half of
  #2793).** `cat < tool | sh`, `cat 0< tool | sh`, `cat 3< tool <&3 | sh` and
  `cat 3<> tool <&3 | sh` read CLEAN although all four run the download: 32 of 32 runtime cells
  across eight parent-shell postures. `Stage.stdin_reads` now records the ordinary-file origins
  descriptor 0 finally reads, following opens, descriptor copies and moves, descriptor-path
  aliases, replacement and close in shell order; a heredoc replaces the origin too. That fact is
  separate from the broad `reads` and `writes` lists: an `N<>` path remains one write and one
  standard-input origin, while an unused side-descriptor read or a write-only redirect is not a
  `cat` input. `workflow_uses` adds those origins to a `cat`'s mentions only when its existing
  `_cat_reads_stdin` predicate says it reads standard input and its standard output still reaches
  the next pipeline stage. Thus a later fd-0 replacement, a file-only operand, an unused side fd,
  a write-only fd and disconnected stdout remain CLEAN, while `cat - other < tool | sh` reports.
  The predicate's documented conservative option price remains deliberate: 11 report-only rows
  (`-n`, `-b`, `-e`, `-E`, `-A`, `-l`, `--number`, `--number-nonblank`, `--show-ends`, `--help`
  and `--version`) account for 55 guard cells and zero of 88 runtime cells; the transforming
  options still expose the downloaded content, and distinguishing the two GNU informational
  options would make this shared GNU/BSD rule platform-specific. Six byte-preserving option rows
  (`-T`, `-v`, `-s`, `-u`, `--show-tabs`, `--show-nonprinting`) run in all 48 runtime cells. On a
  5,948-row targeted, product and fuzz differential, reports across five shell settings rise from
  2,535 to 9,715 -- 7,180 gained cells out of 29,740, with no lost verdict or reason. Six mutants
  show each boundary matters: substituting broad reads, substituting writes, dropping the `cat`
  stdin predicate, dropping the stdout-pipe gate, dropping `<>` input provenance, or dropping
  descriptor-copy provenance each fails its own pin. Copy-then-run and intermediate-command forms
  remain the unclosed parts of #2793.
- **Workflow reader: a written path of one of the stage's own descriptors (#2744).** `curl -fsSL U
  > //dev/stdout | sh` read CLEAN and runs under every shell: the reader knew `/dev/stdout` and
  `/dev/fd/1` as written, and descriptor 1 alone, so `> /proc/self/fd/1`, `2>&1 > /dev/stderr |
  sh`, `3>&1 > /dev/fd/3 | sh` and `2> t > /dev/stderr; sh t` (the download lands in `t`) read
  CLEAN too, and so did the issue's own rows, `tee //dev/stdout` and `tee /dev/stderr 2>&1`
  between a printer and a shell. `shell_reader.output_alias_fd` reads a path a stage writes as the
  descriptor of its own that it names -- `/dev/stdout`, `/dev/stderr`, `/dev/fd/N`,
  `/proc/self/fd/N`, `/proc/thread-self/fd/N`, in any spelling a kernel opens as that file:
  repeated slashes, `.` and `..` among them, a climb to the root -- and `_stage` sends what is
  written there where THAT descriptor points when the redirection is read: the pipe, a file,
  nowhere. Linux refuses `/dev/stdout/` and `/dev/fd/01`, which macOS opens, and macOS has no
  `/proc`; the reading is of either kernel, measured on both. The stage now says which descriptors
  feed the next stage (`Stage.pipe_output_fds`, the twin of `pipe_input_fds`), and two readers
  that asked the literal tables ask the reader by one line each, as the coordinator ruled:
  `workflow_printers._passes_through` for a `tee` operand that is the pipe (`writes_pipe`), and
  `workflow_fetch` for a `-o` that spells descriptor 1 or another descriptor on the pipe beside it
  (`stdout_named`: `curl -o //dev/stdout U | sh`, `curl -o /dev/stderr U 2>&1 | sh`). One pin of
  another lane moves by that ruling, the `Stage` shape from 12 fields to 13; the six-argument
  shape still builds. On a 635-row hunt with 16-run truth against `main`: 1,229 cells in 261 rows
  report that a parent runs, 10 in 2 rows stop reporting a file `main` took the path for (`curl …
  > //dev/stdout; sh //dev/stdout`: the fetch alone), and none goes from REPORT to CLEAN where a
  parent runs. The price, REPORT where no parent of that setting runs, is 256 cells in 74 rows: a
  spelling Linux refuses, of which macOS opens two of the three (165), a dash setting of a
  bash-only form such as `&>` or `|&` (76), and a climb from `~` that the harness's home is too
  deep for (15). A fuzz of 3,000 random redirection chains with truth: 765 cells in 175 rows
  report, none stops, and none goes from REPORT to CLEAN; 500 cells in 133 rows are price -- a
  redirection that fails, so that the command never runs (360), the dash settings of bash's forms
  (110), a group's own redirection read behind the ones inside it (20), a closed descriptor (10)
  -- as `main` reads the same shapes for a dup or a listed spelling. Its 265 cells still CLEAN
  where a parent runs are three classes with no path of a descriptor in what makes them: a file's
  or a printer's text through `cat` or `tee` to a shell, a group whose own redirection carries
  another descriptor, and a printer's text into a file a later line runs (#3027). None of the
  31,046 standing rows, the #2939 seat's 2,164 class rows or its 20,000 fuzz rows moves, with the
  parse nonce pinned under `0` and under `c`: 93 standing rows redirect to a path of a descriptor,
  4 hand one to `tee` and 14 give one to a fetcher's `-o`, and each reads as it did. Still as
  `main` reads them, each pinned and named: a target a value or a pattern decides (`> $O`, `>
  /dev/stdou[t]`), a path a `cd` or a link gives, a group whose own redirection carries another
  descriptor (`( curl … >&2 ) 2>&1 | sh`), a fetcher or a `tee` that writes the pipe by another
  descriptor while its standard output is elsewhere. The cost, `job_defects` against `main` on the
  forge, three passes, each a process of its own: the standing sample (3,881 rows) 67.09 / 66.86 /
  66.23 s on `main` and 67.58 / 66.72 / 66.81 s on the head (-0.1% by the medians); the hunt (635
  rows) 8.93 / 9.09 / 8.99 s on `main` and 9.16 / 9.10 / 9.10 s on the head (+1.3% by the
  medians); my fuzz's first 1,500 rows 26.97 / 27.08 / 26.97 s on `main` and 27.02 / 26.73 / 27.00
  s on the head (+0.1% by the medians) (32 cores, Neoverse-N2, Python 3.12.3; load 14.31 to 3.61).
  The load at the start was another run's marks; `main` and the head alternate within each pass.
- **`scripts/workflow_options.py` splits the readers of a word in a shell's option slot into
  `scripts/workflow_option_slots.py` (for #2889, programs lane).** A pure move at the module's size
  (699 of its 700 lines), in two pieces, each byte for byte with the comments above it and the two
  in their old order: lines 534 to 586, the patterns `_ONE_PARAMETER`, `_ONE_DEFAULT` and
  `_DEFAULT_PARAMETER` with `_one_word` and `_literal`, which the second walk asks of a word that
  may expand (#2858); and lines 664 to 699, `_VALUE` and `_value`, `_BARE` and `_before_operand`,
  and `_may_spell_option`, the three readers of a value where a shell reads its options (#2344).
  The ten names are a leaf of the module -- none reads one of the 38 defined outside them -- so
  the new module imports `re` and `shell_reader` and nothing from `workflow_options`, which
  imports every moved name back under its own; `workflow_programs` re-exports the five it did
  before. No caller moved and no test moved. #2858's watch table (`WALK_ONLY`) patches each of
  the walk's readers on the module that LOOKS IT UP: the two that moved are looked up by readers
  that stayed (`_run`, `_in_every_reading`, `_stdin_walk`, `_value_after_dash_c`), and no reader
  that moved calls anything the table watches; its tables are watched by object, every binding
  wrapped, and the three patterns are one object under both modules' names. The new test module
  holds both facts. Before the first push every test module that reads `workflow_options` or
  `workflow_programs` was run on the move. No verdict changes: on 6,180 rows in 34 sets -- the row
  sets of #2955, #2963 and #2997, and the probes behind #3002, #3003 and #3007 -- every finding of
  every row, its name and its reason, is the same under `main`'s scripts and the move's, under
  each of the five `shell:` settings and in each of three readings (the job, its main pass, its
  walk pass): 92,700 cells holding 56,153 findings under each tree (56,528 before #2861 was
  folded in, the count this entry first carried), and the two dumps are
  equal byte for byte; and the eleven grids of #3019, #3020 and #2889, 14,238 rows that put an
  expansion in or beside a shell's option words, read the same under each of two pinned markers,
  marks and findings. The room is for #2889's rule, the next change to this module. Sizes:
  699 -> 612, and 112 for the new module.
- **Workflow reader: who runs the word behind a wrapper (#2670, #2836).** `env eval 'curl … | sh'`
  was reported though no shell runs it, and `T=t; curl -o t U; env unset T; sh $T` read CLEAN
  though every shell without `-e` runs the download: the reader read a builtin through any
  wrapper, and a wrapper that execs looks for a program. `_command_result` now carries who runs
  the word behind each wrapper (`shell_wrappers.behind`): the step's own shell, a program a
  wrapper execs, or a shell handed the words. Behind a wrapper that execs -- `env`, `sudo`,
  `nice`, `nohup`, `exec`, `timeout`, `xargs` and their kind -- a builtin's name that is no
  program leaves the stage the wrapper's own (`runs_behind`): nothing behind it is read as run,
  and nothing it would set is set. `[`, `echo`, `false`, `kill`, `printf`, `pwd`, `test` and
  `true` are programs and read as before; `command` and `jobs` are scripts on macOS (`builtin NAME
  "$@"` under /bin/sh) that hand their words to a shell of their own, where `env command eval 'P'`
  runs, and stay read. A shell handed the words runs a builtin in itself: what its `eval`, `.`,
  `source` or `builtin` reads is read in the folds that read a `builtin` through (#2665) and the
  stage is the wrapper's in the others, so `sudo -s eval 'P'` reports and `sudo -s eval 'T=x'`
  sets nothing of the step's. That `sudo -s`, `-i`, `--shell` and `--login` hand the words to a
  shell is sudo's manual, doc-pinned and not forge-verified (the forge's `sudo` is a stand-in
  written from it); `doas -s` is read as sudo's is. `time` is bash's keyword only where a command
  starts: behind an assignment, a `$` word bash drops, `command`, `jobs -x` or a `|` it is
  /usr/bin/time, which execs, so `echo x | time eval 'P'` reads CLEAN and `X=1 time unset T`
  unsets nothing; the reader marks the first word of a pipeline's later stage for it. `jobs -x
  curl … | sh` read CLEAN while both bashes run the pipe (#2836): the reader follows bash's own
  reading of the options -- clusters of the letters `lnprsx`, an `x` among them, no `l`, `n` or
  `p` in front of it; 50 spellings measured under 5.2.21 and 3.2.57 -- in folds of their own
  beside the ones that leave the word alone, as for `builtin`, since dash has no `jobs -x`. A
  wrapper that may not be the program it names is read both ways, as `main` reads it and as
  written in the folds that read a `builtin` through, so that no report of `main`'s is cleared: a
  word a table or a default made (`workflow_uses._resolved` hands `command()` the argv it made one
  of), the W of a word a parameter expansion decides, and a wrapper's name the job's steps define
  as a function or an alias (`shell_wrappers.shadows`; behind `sudo() { "$@"; }` an `eval` runs).
  `${S:-sudo eval} 'P'` shows why: nothing runs with `S` unset, and the string runs with `S='sh
  -c'`. On a 5,008-row hunt with 16-run truth against `main`: 1,874 cells in 648 rows report that
  a parent runs (two of them only the forge's GNU bash 3.2.57, which under `-e` goes on past a
  failing subshell where Apple's 3.2.57 stops), 2,038 in 434 rows stop reporting what no shell
  runs, and none goes from REPORT to CLEAN where a parent runs. The price, REPORT where no parent
  of that setting runs, is 2,420 cells in 802 rows: a `-e` setting of a step that runs without
  `-e` (1,331: under `-e` the step stops at the command not found, which the guard does not know);
  macOS's scripts (520: a Mac's own bash 5.2.21, bash 3.2.57 and dash run 495 of the cells
  reported among the 579 rows measured there, and none this fix quiets); the dash settings of a
  step bash runs (306; bash started as `sh` runs 600 of the 608 dash-setting cells a bash parent
  runs); a word that may not be the program it names, read as written beside `main`'s reading
  (165); `exec` of a builtin's name, where the step ends (46); a check behind such a wrapper then
  `|| exit 1` (35); and 17 others. A fuzz of 6,000 random steps with truth: 496 cells in 223 rows
  report, 671 in 142 stop, and two go from REPORT to CLEAN under `sh {0}` where dash runs -- `time
  unset T` under dash, #3024's class, beside an `eval` no shell runs: with that `eval` replaced by
  a command no shell finds, truth is the same and `main` reads both rows CLEAN. The fuzz also
  found why a word in doubt is read both ways and not as `main` reads it alone: `alias sudo=''` in
  front of `sudo -s unset T` kept `main`'s own miss. None of the 31,046 standing rows, the #2939
  seat's 2,164 class rows or its 20,000 fuzz rows moves, with the parse nonce pinned under `0` and
  under `c`: none of them holds these words. Pins that move: three of batch C's own (`sudo -s
  builtin`, which waited for this rule; `sudo command builtin`; a fold's stage), the `find` action
  forms (a builtin's name is no program behind a wrapper that execs either), the names a statement
  may set (`nohup unset T` sets none), and one row of the annotate tests that keeps its two
  sentences and gains "cannot read command" (#2836's fix shape). Still as `main` reads them, each
  pinned and named: `time` as the keyword under every shell (#3024's class), a quoted `time`,
  `time` in a `find` action, a word in doubt in front of a shell handed the words, a function of a
  wrapper's name in front of `builtin`, a shim of a wrapper's name the step's text does not spell.
  `scripts/shell_command.py` stands at 699 of 700 lines, four of them taken from three comment
  windows, every word kept. The cost, `job_defects` against `main` on the forge, three passes,
  each a process of its own: the standing sample (3,881 rows) 65.81 / 64.89 / 65.22 s on `main`
  and 65.57 / 65.86 / 66.28 s on the head (+1.0% by the medians); the hunt's first 1,500 rows
  35.82 / 35.65 / 35.68 s on `main` and 34.20 / 34.66 / 34.26 s on the head (-4.0% by the
  medians); my fuzz's first 1,500 rows 55.14 / 54.64 / 54.81 s on `main` and 62.32 / 62.99 / 63.08
  s on the head (+14.9% by the medians) (32 cores, Neoverse-N2, Python 3.12.3; load 7.40 to 1.23).
  The fuzz pays for the folds its rows are read in a second time (a `jobs`, a shell handed the
  words, a word in doubt), as a row with `builtin` has since #2665; no standing row holds such a
  word.
- **A checksum gate inside a shell function is credited only where the function is proved to run
  (#2949).** `f() { sha256sum -c sums || exit 1; }; sh tool` read CLEAN even when `f` was never
  called, was called after the use, or appeared only as `find -exec f`: the stopping-rescue path
  returned before the existing function-call bound was applied. That rescue now carries its
  outside reach through the same `_function_status` bound as an unrescued check. On 65,894 standing
  rows and five `shell:` settings (329,470 cells), 18 rows move, all in this class: 86 CLEAN to
  REPORT, no REPORT to CLEAN, and no reason-only changes. All 288 Bash 5.2.21, Bash 3.2.57 and dash
  truth cells for those rows run the payload. Called-after, one-line and skipped-call extensions
  add 30 true CLEAN-to-REPORT cells across six bad/right-digest rows. Bash's `function f { ...; }`
  spelling adds ten more; its two explicit-`sh` settings are the bounded fail-closed price (four
  scanner cells), because dash fetches the file but refuses that syntax before running it. A proved
  call before the use, a bare uncalled check and an inline rescue keep all 30 existing answers.
- **Workflow reader asks an option word for its letters, never its parse marker (#3020, #3023).**
  `sh -$(echo c) 'curl ... | sh'` runs the string under every parent shell and read CLEAN in one
  call and reported in the next; `curl -fsSL$(true) URL | sh` runs and read CLEAN in every call. A
  lifted substitution stands in a word as a marker of its parse, `@@shell-<hex>-N@@`, and the
  readers of the programs lane asked an option word for its letters as text: the hex is drawn at
  random for every parse, so a shell's word held a `c` or none by chance, and the marker's fixed
  text spells `h`, which is `curl -h`. Each reader now asks the word (`workflow_option_words`,
  new): what is written in it, and whether lifted text begins in it, anywhere or where a letter
  would be read. `main` had two readings of such a word and chance chose between them; the job now
  reads both. A finder of a `-c` cluster (`_after_dash_c`, `_candidates`' `$` rule,
  `_dash_c_operand`) takes a word that holds lifted text for one, `main`'s reading under a marker
  with a `c`; and where no `c` is written in the word the search goes on past it, as past `-x`,
  and so do the two walks for a value among a shell's options, `main`'s reading under a marker
  without -- the second beside the first, never instead of it (`Y=-c; sh -$(echo x) $Y '...'` and
  `sh -$(echo x) w.sh -c '...'`, `w.sh` an `eval "$2"`, run the string). The walks for the program
  on stdin read `c` as written and `s` as written or lifted, so a `c` the word only may print
  never makes them drop the body. The fetch reader leaves a transfer unread where lifted text
  stands among an option's letters or in a long option's name, as it does for a `$X` there; in an
  option's value it is a value still (`-o"$(mktemp)"`). A marker is known by the word that carries
  it and, in a text the guard reads again -- `echo "sh -$(echo c) '...'" | sh`, a candidate behind
  a `$X` option, what a `$(echo ...)` prints, where the first parse's marker stands in plain words
  -- by its shape and the nonce this process alone mints, so text the target writes in a marker's
  shape stays its text. Measured with the marker pinned, all `0`s and all `c`s, on five grids
  (6,540 rows, each run under eight parent shells in two passes): a shell's option word that holds
  a substitution or a variable, in six frames (4,356 rows: 636 read by the marker on `main`, 138
  open there under a marker without a `c`, 54 still, each a letter a VARIABLE makes, #2889); a
  fetcher's (77 rows: 39 open on `main` under every marker, 2 still, a variable in wget's word and
  a word that is all substitution); a text read again, each row beside a twin whose letter is
  written (1,150 rows: 206 read by the marker, and now 477 of the 575 read as their twin and the
  rest, whose substitution no printer spells, as a possible `-c`); a check behind the word (375);
  a word that prints no `c` (582). At the head no reading depends on the marker, no report `main`
  makes under either marker is lost in either pass, and no row is newly open. A seeded fuzz of
  12,000 steps -- up to three option words from a pool of 46 for a shell, up to four of 37 for a
  fetcher, in ten kinds of step -- run twice: the job's marks never depend on the marker, and a
  cell `main`'s job reports under any of five markers the job reports. The first pass gives one
  answer for stdin and cannot hold both readings: on 18 and 14 of those steps it reads CLEAN where
  `main`'s first pass reports under one of the markers, and the job reports every one. On the
  53,210 standing, class and fuzz rows the issue was measured on, the 12 rows `main` reads by the
  marker go from CLEAN to reported under a marker without a `c` and nothing else moves; on the
  #2942 seat's 68,248 round-2 rows and on 10,664 rows of this lane's own sets no row moves at all.
  The price: a shell's row `main` reported under one marker is reported under both -- most in 199
  calls of 200 already -- and a fetch whose option letters hold lifted text is reported as unread
  though nothing may run it (`curl -s$(true) URL`), as `curl -s$X URL` is on `main`. Left for
  other issues: a letter a variable makes, and a value a word may owe for an `o` it prints (`sh
  -$(echo oc) errexit '...'`, #2889); a `$` command word whose cluster is not its first word
  (#2671); the other readers that ask a marker for letters. `job_defects` costs 0.99x on the 35
  standing sets.
- **Workflow reader: an array literal's word carries its `elements` (the array-literal cluster,
  #2772, #2783, #2784, #2812; reader half).** A folded `NAME=(…)` / `NAME+=(…)` word, and the
  `NAME=` opener where a statement that only assigns is still handed unfolded, now carry the
  literal's words as bash splits them -- each the token of the same parse, a lifted `$(…)` keeping
  its marker -- beside the text they always read as; a word that only looks like a literal (`T='(x
  y)'`, a subshell's `T=`) carries none. Additive: nothing folds or unfolds differently and no
  verdict moves. With the parse nonce pinned, none of 64,031 rows reads differently: the standing
  sets, the #2939 seat's class and fuzz rows, the hunt and the fuzz of #2857, and 2,982 array
  literals -- 27 shapes behind 12 words by 9 uses, and in 11 places. `workflow_values` reads
  `elements` only when the cluster's switch lands.
- **Workflow reader: three words in front of a command (#2665, #2648, #2480).** `builtin eval
  'curl … | sh'` read CLEAN while both bashes run the pipe: the reader left `builtin` where it
  stood, a command the guard does not follow. Bash runs `builtin NAME …` as the builtin NAME; dash
  has no `builtin`, takes the word for a command not found, and without `-e` goes on. Taking the
  word off, as `command` is taken off, reads the step as bash runs it and forgets dash: read that
  way alone, 35 rows of the hunt below lose a report `main` gives, 13 of them in the cell whose
  shell runs the download, dash without `-e`, where under bash the builtin behind the word sets a
  name, leaves the directory or counts a check. So the reading is added. `shell_command.folds`
  reads a job that holds such a word in every fold it reads any job in, the word left alone, then
  in each of them once more with the word read through to the builtin it names; the second walk
  alone, the main pass as `main`. The word is read through in front of a builtin's name (`builtin
  sh tool` runs nothing; the 61 names of bash 5.2.21), past `--` and the `$` words that may each
  be nothing, behind a keyword, an assignment, `command`, the keyword `time` or a `$` word bash
  may drop, and where a one-word default names it or the builtin behind it; not behind a wrapper
  that execs (`sudo builtin`, `env builtin`, `command time builtin`), nor as the word a `find`
  action starts with, nor to an `exec` with nothing to run, whose redirections bash undoes behind
  `builtin` and keeps behind `command`. `env SHELLOPTS=noexec bash -s` credited a check no shell
  runs: bash takes `SHELLOPTS` from its environment, runs nothing of its program under `noexec`
  and its first command alone under `onecmd`, and exits 0. The reader now marks the `bash` or `sh`
  such an assignment stands in front of -- the step's own prefix, or one `env` or `sudo` hands on;
  the last decides; a value the guard cannot read counts (`shell_wrappers.idles`) -- and `unsure`
  and `sure_reader` make that shell's scripts ones no shell is sure to read, as for a `find`
  action: read, since dash ignores the variable and a bash step refuses to assign it, and nothing
  in them the step's own. And `"X=1" sh tool` reported though every shell runs a command named
  `X=1` and nothing of `tool`: a quote or a backslash in the name or the operator makes a word no
  assignment, and the reader took the quotes off first. `shell_reader._named` marks such a word
  where a command word may stand -- behind a keyword, an assignment, a function's header, a `(`, a
  `case` arm's token or a redirection -- and `_command_result` does not pop it; a quote in the
  value or a subscript leaves an assignment one, and a wrapper is handed the word with its quotes
  off. On a 1,839-row hunt with 16-run truth (the harness's `env` and `sudo` stubs drop the
  assignments they are handed, so this truth was taken with two that apply them) against `main`:
  1,078 cells in 370 rows report that a parent runs, 715 in 143 rows stop reporting what no shell
  runs, and none goes from REPORT to CLEAN where a parent runs. The price, REPORT where no parent
  of that setting runs, is 748 cells in 338 rows: the dash settings of a step bash runs (544; bash
  5.2.21 and 3.2.57 started as `sh`, the `sh` of a macOS runner, run every one), `command` by path
  (55, #2997's stance), the step's own prefix, which a bash step refuses to assign (48), a value
  the guard cannot read (24), `onecmd` over a script of one command (21), what the same step reads
  without `builtin` (20), an `sh` that is dash (19), `sudo` between the assignment and the shell
  (12) and a function named `builtin` (5). A fuzz of 6,000 random steps with truth, mixing the
  three words with the others the reader takes off the front of a command: 166 cells in 64 rows
  report, 717 in 148 stop, and one goes from REPORT to CLEAN under `sh {0}` where dash runs --
  `main` reported that row for the mis-read word and never saw the run, which stands behind
  `builtin read T`: the value table reads that as `read T` under every shell (#3024), and `main`
  reads the row CLEAN once the word is replaced by a command no shell finds. On the standing sets,
  the #2939 seat's class rows and its fuzz rows, marked with the parse nonce pinned, 8 of 53,210
  rows move, all from CLEAN to REPORT and each run by both bashes. Still CLEAN, each pinned and
  named: a wrapper that hands its words to a shell (`sudo -s builtin eval 'P'`, for #2861's rule);
  a function that hands its words to `builtin`; a step that exports `SHELLOPTS` earlier; `bash -t
  -s`, `main`'s gap already. Pins that waited for #2665 move with it
  (`test_builtin_in_front_was_2665`, its printer twin, the `builtin eval sh tool` row of the
  printers' catch-all test, `builtin command sh +c` in the plus cluster's), `SHELLOPTS=noexec bash
  -s` leaves the list of `main`'s gaps for the reported one, and `builtin` joins the words no
  `find` can run, with its row. The cost, `job_defects` against `main` on the forge, three passes,
  each a process of its own: 1.01x to 1.02x on the #2942 seat's 3,881-row sample of the standing
  rows, where `_named` looks at the head of every stage; 1.44x to 1.47x on the hunt and 1.31x to
  1.33x on the fuzz, whose rows all hold the words -- a job with a `builtin` it may read through
  is read in twice the second walk's folds, and no other job.
- **Workflow guard: downloaded-use scope readers move to
  `scripts/workflow_use_scopes.py`.** A pure move out of `scripts/workflow_uses.py`, which stood at
  its 699-line ceiling: function ranges and removal, the compound/group walk whose assignments
  live in another shell, and function-body bounds now live in a 153-line leaf. The old module
  re-exports every moved name and falls to 563 lines; no expectation moved.
- **Workflow reader reads a shell's `c` in a `+` cluster as its `-c` (#3019).** `sh +c 'curl ... |
  sh'` and `bash +xc '...'` read CLEAN under every `shell:` setting while every parent shell runs
  the string: a `+` turns an option OFF and `c` is none to turn, so bash, dash, zsh, ksh and
  busybox's ash all take the letter as `-c`. The three finders of a `-c` cluster asked for a
  leading `-` (`workflow_program_strings._after_dash_c` and `_candidates`,
  `workflow_options._dash_c_operand`) and now read the sign as they read the `-`: one `+`, not
  two, and a `c` anywhere after it. Two of them are `main`'s own finders, so the main pass reads
  the string too, and a check inside it counts where one in a `-c` string does. Where the sign
  turns a letter round it was read already: `+nc` runs the string and reports, `+ec 'check; use'`
  reports where `-ec` is CLEAN. The string is read BESIDE the one `main` found, never instead of
  it -- a FILE may run any parameter it is handed (`sh w.sh +check x -c P`), and an expansion may
  make the cluster take its string for a name (`X=o; sh +${X}c errexit -c P`) -- so the reader
  reads more than it did and never less: over every argv of one to four words from a 14-word
  alphabet, what `main`'s finders find is among what these find. Measured on a grid of 1,481
  pairs, the same step written `+` and `-`, each row run under eight parent shells in two passes
  (the cluster's other letter, a character that is no letter, `o` and `O` with their names, noexec
  and errexit, where the cluster stands, a `$` command word, a cluster an expansion makes, shell
  names, a long option's name behind a `+`, an `s` beside the `c`, statements, wrappers, strings
  and bodies) and on 1,645 rows that put a `+` word in front of words `main` already reads. Of the
  grid's 1,481 `+` rows, 638 that a parent runs read CLEAN on `main` and none does now; none is
  newly fail-open; 16 stay so, 15 where the `-` twin is too (a `$` word whose cluster is not its
  first word, #2671; a letter an expansion makes, #2889; zsh's `O`; `builtin command sh`; `busybox
  sh`; a value for a string) and one through #2671's hole. No report `main` makes is lost on
  either set but 21 rows where a check inside a `+c` string the shell is sure to run is now
  counted. The price is the mirror's: the sign is read whatever else the word holds, because `sh
  +c$X`, `sh +{c,x}` and zsh's `+c7` run, so 421 rows whose word every shell refuses are newly
  reported -- 417 as their `-` twin is on `main`, four alone (`+-c`) -- and a `$` word that is no
  shell, handed a `+` argument holding a `c` (`$TOOL +check all`), keeps its hand-off beside a
  reported fetch as `$TOOL -check all` does. On the standing row sets (4,848 rows in 28 sets, none
  holding a `+` word with a `c`) no row moves in either pass, and `job_defects` costs 0.99x on
  them.
- **Workflow reader drops an alternate that names no wrapper (#2943, #3003).** `${DRY_RUN:+echo}
  sh -c 'curl … | sh'` ran the pipeline under every parent and read CLEAN: with its name unset an
  alternate is nothing whatever it names, and `shell_defaults._optional`, which drops a `$` word
  in front of a name the reader knows, took an alternate for such a word only where it names a
  wrapper -- the test it applies to a default, whose word stays. The second walk now goes on past
  an alternate that names no wrapper, as it does past a bare reference: in front of a shell, a
  wrapper, an interpreter, a fetcher, `eval`, `.` and `source`, wherever the statement stands. It
  stops, as `main` does, at one the reader reads as the command it names (`_shell_default`: a
  shell, a fetcher, `eval`): `$T ${X:+sh} -c 'P'` is `sh -c 'P'` where `X` is set and reads so,
  now behind a dropped alternate too. The main pass reads as `main` does. So the job reads a step
  with such an alternate as it reads the same step with `$T` in its place (pinned; 596 of the 596
  rows that move in the hunt's third part). Two designs were measured and not taken. Keeping the
  blank-free word whole, the direction #2943 names, reports four lines of `${DRY_RUN:+echo} git
  push …` with nothing fetched -- the fourth word whose halves read apart is past the folds' cap
  -- and on the #2939 round-1 seat's fuzz rows adds 5,727 cells where no parent runs. Dropping the
  longest run of such words a known name stands behind lost 197 of 5,733 rows: a wrapper word
  counted as a known name, and the `eval` in `${E:+eval} ${V:+sudo} t` went with the run. On a
  6,879-row hunt with 16-run truth, in four parts -- 51 words in front by 14 commands; 28 places a
  statement stands and 29 runs of words; every run of one to three words of nine kinds in front of
  seven tails; the word in a stage a download is handed to -- against `main`: 3,750 cells in 760
  rows report that a parent runs, and none goes from REPORT to CLEAN. The price, REPORT though no
  parent of that setting runs, is 1,105 cells in 236 rows: an alternate that is the shell behind a
  dropped word, which runs where its own name is set (675 cells; `main` reports it behind `$T`);
  the step that set the name -- `S=1`, then `${S:+echo} sh -c 'P'` prints -- the word being
  dropped whatever the step did to its name, as `$S` is (150); a `python3 t` behind the word,
  which the harness's shell payload cannot show running (120); what `main` reports of the command
  behind (110); and a setting whose parent refuses the row, `source` under `sh` (50). On the
  seat's 10,004 fuzz rows with truth, where `main` misses 3,268 cells in 909 rows, 2,337 cells in
  616 rows report and 3,064 are added where none runs, in 722 rows; `main` reports 678 of those
  rows once the alternates are taken out of their text. Still missed, each for an issue of its
  own: an alternate naming a shell, a fetcher or `eval` in front of another command (`${X:+sh}
  curl … | sh`), read the one way `main` reads it (224 rows of the hunt); an alternate of a
  positional parameter, an indirection or an element, or whose word holds a reference (39 rows); a
  pattern or case operator, and `.`, `source` or `eval` inside a word (#2944), in the fuzz.
  #3003's ten pinned limits move with it (`test_an_alternate_naming_no_wrapper_was_3003`). On the
  standing sets and the seat's class rows, marked with the parse nonce pinned, 2 of 33,210 rows
  move, both from CLEAN to REPORT and both run under all 16. The cost, `job_defects` against
  `main` on the forge, three passes, each a process of its own: flat on the #2942 seat's 3,881-row
  sample of the standing rows (0.99x to 1.01x) and on the hunt's fourth part (1.00x to 1.02x), and
  1.10x to 1.11x on its first part, where the commands behind the words are read now.
- **`scripts/workflow_printers.py` splits how a printer's text is decoded into
  `scripts/workflow_printer_writes.py` (#3013, printers lane).** A pure move at the module's size
  (700 of its 700 lines), in two pieces, each byte for byte with the comments above it and the two
  in their old order: lines 90 to 136, the table `_ESCAPES`, `_OCTAL` and `_decoded`, which
  decodes an `echo`'s or a `printf`'s text under ONE reading for `printed`; and lines 434 to 570,
  what an unspelled printer WRITES (#2955) -- the tables `_CONVERSION`, `_ESCAPE`, `_PLAIN`,
  `_COUNT`, `_KNOWN`, `_PAD`, `_LONG` and `_WRITERS`, and `_written`, `_formatted` and `_echoed`,
  which render one text a shell family for the second walk. The 14 names are a leaf of the module
  -- none reads one of the 28 defined outside them; the writers alone are not, since `_written`
  reads the table `_decoded` reads -- so the new module imports `re` and `shell_reader` and
  nothing from `workflow_printers`, which imports every moved name back under its own; no caller
  moved and no test moved. What stays reads commands: which one prints, and what it hands a shell.
  No import leaves the source, and its docstring says where the half went. Before the first push,
  every test module that reads `workflow_printers` or `workflow_programs` was run on the move, and
  each was read for a `getattr` or a `patch.object` driven from a table of names (#3011's first
  head missed two): none reaches a moved name. No verdict changes: on 6,180 rows in 34 sets -- the
  row sets of #2955, #2963 and #2997, and the probes behind #3002, #3003 and #3007 -- every
  finding of every row, its name and its reason, is the same under `main`'s scripts and the
  move's, under each of the five `shell:` settings and in each of three readings (the job, its
  main pass, its walk pass): 92,700 cells holding 54,238 findings under each tree, and the two
  dumps are equal byte for byte. Sizes: 700 -> 523, and 208 for the new module.
- **Workflow branch and step credit has its own bounded module (#3005).** The
  byte-identical branch-region and shell-option credit readers now live in
  `scripts/workflow_step_credit.py`; `workflow_forms` re-exports the same
  objects, preserving every existing caller and answer while restoring
  headroom for the carried-download fixes.
- **Workflow reader reads a command glued to its `case` arm's `)` (#3014).** `case x in x)curl
  -fsSL … | sh ;; esac` ran the download under every parent and read CLEAN: at the `)` that ends
  an arm's pattern `_split` made one token of the arm's mark, the pattern and the `)`, and the
  word glued behind the `)` went into it, so the arm's first command lost its name and what was
  left of the stage was its arguments (#2715, closed into this). The token is now a word of its
  own, and that reads three things. A command glued to its arm's `)` reads as the arm with a blank
  reads, and as the same words read on a line of their own: a pipe to a shell, a fetch run behind
  the `case`, `bash -c '…'`, `eval "$(curl …)"`; behind `a|x)`, `(x)` and `*)`; in a second arm,
  nested, in a `$( … )`, in a program string, in a `;&` or `;;&` arm. A `${…}` at the head of an
  arm that starts its line is the command word it is on the `case` line or behind an indent: with
  nothing in front of it on its line the token counted as a word the stage had closed, so in `x)
  ${SUDO:+sudo -E} sh t ;;` the `${…}` was no command word and its empty half was never read. And
  a function's header at an arm's head (`x) f() { sh t; }; f ;;`) is a header, the header test
  passing the token by: it was a name and a subshell (a fourth spelling of #2975). On 211 rows
  with 16-run truth -- 15 commands by 6 layouts, #2715's acceptance shapes, and the probes around
  them -- against `main`: 385 cells in 79 rows report that a parent runs, and 15 in 6 that no
  parent of that setting does (an arm not taken; `function` under `sh`, which dash refuses; a `;&`
  or `;;&` arm under `sh`). `main` read a glued arm as the words behind its first one, so it also
  reported an arm by the word left behind, and such a report goes wherever `main` reads the whole
  words CLEAN on a line of their own (the coordinator's ruling on the class, quoted in the PR). On
  two more hunts built to find them, 1,207 rows with truth: 616 cells in 128 rows where nothing
  runs (`x)echo sh t`, `x)cat t`), and 134 in 30 where a parent does, each `main`'s own miss
  wherever the words stand and a named limit here -- a name bash sets, in front of the fetched
  file (`x)$SHELL t`, #2808); a substitution that prints the interpreter there (`x)$(echo sh) t`,
  #2695); a substitution that prints nothing, in front of a command (`x)$(true) sh t`, #2693); two
  values glued there (`x)$X$Y sh t`, #3016); an interpreter the table does not name, in front of
  the fetched file (`x)busybox sh t`, which all 16 runs run, #3017; `x)lua t` by its marks alone).
  Each kind is pinned as the equality it is. A check in a function an arm defines is credited no
  more than before (pinned). On the standing sets, the #2939 round-1 seat's class and fuzz rows
  (53,210 rows) and #2974's 943-row hunt nothing moves. The cost, `job_defects` against `main` on
  the forge, three passes, each a process of its own: flat on the #2942 seat's 3,881-row sample of
  the standing rows and on #2974's hunt (1.00x to 1.01x), and 1.15x to 1.16x on the 211-row hunt,
  whose glued arms are read now.
- **`scripts/workflow_programs.py` splits the program handed as a string into
  `scripts/workflow_program_strings.py` (#3011, programs lane).** A pure move at the module's size
  (700 of its 700 lines): `scripts`, `candidates` and `dynamic_program`, which read the program a
  command hands a shell as a STRING (`eval "…"`, `sh -c "…"`), the class `Opaque`, the eight
  readers they ask (`_main_scripts`, `_added_strings`, `_program_words`, `_joined`, `_script`,
  `_after_dash_c`, `_candidates`, `_all_expansion`) and the three tables those read
  (`_SHELL_STRING`, `_EDGE`, `_NAME`) now live in the new module, byte for byte with the comments
  above each and in their old order: lines 72 to 323, moved by number. The block is a leaf of the
  module -- no name in it reads one of the 22 defined outside it -- so the new module imports
  nothing from `workflow_programs`, which imports every moved name back under its own; no caller
  moved. What stays is the half that reads the program on standard input. The source drops five
  imports only the block read (`re`, `Process`, `Handed`, `_shell_candidates`, `_sure_string`) and
  keeps two it no longer uses, `_before_operand` and `_past_options`, as re-exports: PR #2850's
  move of the option grammar pins every name of that move through this module. One test moved with
  the readers. #2858's watch table (`WALK_ONLY`) patches each of the walk's own readers on the
  module that LOOKS IT UP, and fails a watcher that sees nothing run; it now names
  `_added_strings`, `_shell_candidates`, `_sure_string` and `Handed` on the new module, where
  `scripts`, `candidates` and `dynamic_program` look them up, and `_dash_c_strings` on both, each
  watcher counted by its module and its name. Its two assertions stand as they were: nothing of
  the walk runs in the main pass, and every watcher but the two tripwires is seen to run in the
  walk's. No verdict changes: on 6,180 rows in 34 sets -- the row sets of #2955, #2963 and #2997,
  and the probes behind #3002, #3003 and #3007 -- every finding of every row, its name and its
  reason, is the same under `main`'s scripts and the move's, under each of the five `shell:`
  settings and in each of three readings (the job, its main pass, its walk pass): 92,700 cells
  holding 54,238 findings under each tree, and the two dumps are equal byte for byte. Sizes: 700
  -> 455, and 280 for the new module.
- **Workflow reader reads a `case` that is not its statement's first word (#2974).** `curl -fsSLo
  t …` ⏎ `if true; then case x in x) sh t ;; esac; fi` ran the download under every parent and
  read CLEAN: `_split` looked for a `case` header only where `case` was its statement's first
  word, so behind `then`, `else`, `do`, `{`, `!` or a function's header the first command of an
  arm was read as the pattern's argument (a second command there was read). The header is now
  found behind what a command may stand behind -- a keyword, a function's header (`f() { case`,
  and `f() case`, where the `case` is the body), `time` -- each passed by without a probe, so a
  run of them is still read once (`header_at`). What stands in front of the header ends as a
  statement of its own, as on a line of its own, so each row reads as its own-line twin reads, the
  gates in its arms too: with those words left on the header's statement an arm was no arm to what
  reads a `case`, and a check in it was credited behind `!`, in a condition and in a function
  never called while all 16 runs ran the download (pinned). `time` is read through instead: a
  statement of its own, it is a wrapper with no command, and a `time case …` that runs nothing
  would report. No lead: `case` itself, so a keyword may be its subject; `for`, whose next word is
  a name, and `in`; an assignment, behind which bash reads `case` as a command's name. On a
  943-row hunt with 16-run truth -- 32 leads by 14 arm bodies, each with the `case` on the lead's
  line, with its arms below, and with the lead on a line of its own -- against `main`: 1,365 cells
  in 295 rows report that a parent runs (the issue's 17 rows and 83 cells among them), none that a
  parent runs reads CLEAN, and 584 of the 608 one-line rows read as their own-line twin reads on
  `main` (255 before; the other 24 stand behind an assignment, `time` or `time -p`, where the twin
  is another step). The price, REPORT though no parent of that setting runs: 215 cells in 76 rows,
  each a cell the own-line twin reports on `main` -- an arm that is not taken (70 cells, 14 rows),
  a one-line `case` with no `;;` before its `esac` (35, 7), and `function f`, `my-fn()` or `time`
  under `sh`, which dash refuses (110, 55). 125 cells in 25 rows go from REPORT to CLEAN, no
  parent running: a pattern that is the fetched file's name, on a line below a header behind a
  lead, which `main` read as a command. `time -p case …` is still unread (10 rows, 30 cells,
  bash's alone): `time`'s option is no lead. On the standing sets and the #2939 round-1 seat's
  class and fuzz rows (53,210 rows) nothing moves. The cost, `job_defects` against `main` on the
  forge, three passes, each a process of its own: 1.12x to 1.14x on the hunt, whose arms are read
  now, and flat on the #2942 seat's 3,881-row sample of the standing rows (0.99x to 1.00x); a
  `case` behind n keywords is read in linear time (pinned).
- **Workflow reader drops a word bash may drop in front of `eval`, `.` and `source` (#2997).**
  `$SUDO eval 'curl … | sh'` read CLEAN under every `shell:` setting while every parent shell runs
  the pipeline, and so did `$SUDO . ./t` and `$SUDO source ./t` after a fetch. The reader dropped
  an unquoted `$` word only in front of a shell, a wrapper, an interpreter or a fetcher (#2472),
  and no builtin was among them. The second walk now knows the three behind such words, by name or
  by a one-word default naming them (`${X:-eval}`, #2963), where EVERY word in front may be
  nothing with its name unset -- a bare reference, an empty default, an alternate naming a wrapper
  (`${S:+sudo}`) -- or is `command`, which runs a builtin. A default naming a wrapper that execs
  is not dropped there (`${S:-sudo} eval '…'`): `sudo`, `env`, `nohup`, `exec` and `time` look for
  a file named `eval`, and nothing of the program runs. The main pass reads as `main` does
  (`shell_defaults.WALKED_DEFAULTS`), so the job REPORTs wherever either reading does and no cell
  can go from REPORT to CLEAN. On a hunt of 992 rows -- 47 kinds of front under 16 runners, and
  eight places the statement can stand -- 327 of the 442 rows a parent runs that read CLEAN now
  report. The 115 left are not this fix's and are pinned as they read: `builtin` in front (#2665,
  43 rows), and three fronts `main` does not drop in front of a shell either -- one that is no
  name (`$1`, `"$@"`; 48), a substitution that prints nothing (12), two references glued (12).
  Three probes after the hunt (1,708 rows) found more of that kind, each CLEAN in front of a shell
  on `main` too and pinned as it reads: a default that is only a blank and a `$` word in front of
  a default or an alternate of several words (`${S:- }`, `$T ${S:+sudo -E}`; #3002), an alternate
  naming a word that is no wrapper (`${DRY_RUN:+echo}`; #3003), and the other words that are
  nothing with their name unset -- a pattern taken off, a substring, an array, a default that
  holds a reference. Alone, a default or an alternate of several words is read by `main` already,
  in front of a builtin too (#2731). The price, named and pinned, is rows that report though no
  parent runs the program: the word is read whatever the step did to its name, so `S=sudo` then
  `$S eval '…'` reports (6 rows of the hunt); a default naming `command` by a path reports though
  the forge has no `/usr/bin/command` (5 rows; macOS has one, and it runs the builtin); and a
  quoted nothing beside the word (`$S"" eval '…'`) leaves an empty argument that bash fails to
  run, where the reader takes the quotes off first, as `main` does in front of a shell (9 rows of
  the last probe). Against `main` on 5,782 rows in 30 sets -- the hunt, a sweep of 32 runners, the
  probes, the test module's own texts, and #2963's and #2955's sets -- no cell goes CLEAN where it
  reported and the main pass is `main`'s on every row; `job_defects` over them costs 1.070x in one
  process, all of it on the rows where a builtin's program is now read (1.21x on the hunt), and
  nothing on the sets where no row moves. A `trap`'s action is still not read (#2830), nor a
  fetched file's text that the parent splices into a `-c` string (#2693).
- **`scripts/shell_reader.py` splits its statement splitter into `scripts/shell_split.py` (#3001,
  reader lane).** A pure move at the module's size (700 of its 700 lines, with #2974 to edit
  `_split`): `_split`, which cuts a lexed `run:` text into statements and pipeline stages, the two
  readers it asks (`_negated`, `_bare_blanks`) and the six tables they read (`_REDIRECT`,
  `_HEADER`, `_BRACED_HEADER`, `_NESTED_CASE`, `_ESCAPED`, `_BLANK`) now live in the new module,
  byte for byte with the comments above each and in their old order; `shell_reader` imports every
  name back under its own, so no caller and no test moved, and the new module sits between
  `shell_command` and the reader and imports nothing from the reader. The reader drops the three
  imports only the splitter read, and its docstring says where the splitter went. No verdict
  changes: on 108,094 rows (540,470 cells) -- the sets #2993's move was measured on, #2954's hunts
  and #2974's -- every finding of every row, its name and its reason, is the same under `main`'s
  scripts and the move's under each of the five `shell:` settings, but for 2 rows of #2911's,
  which read differently from run to run under either: each lost one cell in one of the two long
  passes, and in 6 fresh processes a tree every cell of both reports, the same under both. 6 rows
  hold the reader's parse nonce in a finding's reason, which is put aside before the comparison.
  Sizes: 700 -> 363, and 362 for the new module.
- **Reply-derived refusal reasons redact before their display cap (#2948).** A contradictory
  `_panopticon` stamp or invalid tool-advisor verdict could put a credential in its rejection
  reason, and the former `%.200r` formatting cut the value before downstream redaction saw it.
  Whole credentials reached the immediate refusal and stderr, while credentials crossing that
  boundary left sensitive prefixes in those surfaces, the rejection record and the ledger. Both
  reasons now redact every original string (including nested keys and values) before representation
  can rewrite token boundaries, then apply the incomplete-key guard and bounded excerpt. The
  verdict reason uses the reply's value rather than its upper-cased comparison copy; the retained
  reply and retry prompt remain redacted as well.
- **Workflow reader reads the first word of a function body on its header's line as a command word
  (#2954).** `curl -fsSLo t …` ⏎ `f() { ${Y:+/usr/bin/env true} sh t; }` ⏎ `f` ran the download
  under every parent and read CLEAN: `_split` kept a `${…}` whole only where every word its stage
  had closed was a keyword or an assignment, and a function's header is neither, so the word
  behind `f() {` was cut at its blanks and its empty half never read -- the same body on lines of
  its own reports. A header (`f()`, `f ()`, `f ( )`, the name after `function`, a tab for any of
  its blanks, behind a keyword too) now leaves the next word where a command word stands, as a
  keyword does (`shell_command.fronts`), carried from word to word in a flag of its own
  (`in_front`), through the keywords and assignments a body may open with. The flag is the whole
  word's alone, and behind a header only a default or an alternate is whole (`${X:-W}`, `${X-W}`,
  `${X:=W}`, `${X=W}`, `${X:+W}`, `${X+W}`), the word whose two halves the reader reads. `[[` at a
  body's head and a header on another header's line still read through `at_head`, as on `main`:
  with one flag for all three, `f() { g() { CHECK || exit 1; }; }` ⏎ `f` ⏎ RUN would read as
  `main` reads it on lines of its own, CLEAN while every parent runs the download (#2949: a gate
  in a function never called, or called after the run), where `main` reports it on one line; both
  rows are pinned as they report. And a pattern taken off or replaced (`${X#W}`, `${X/p/W}`) keeps
  `main`'s words behind a header: read whole, `D=x` ⏎ `g() { ${D/x/curl -fsSLo t …}; }` ⏎ `g` ⏎
  `sh t` would read as `main` reads that word on a line of its own, CLEAN while bash runs the
  download, where its cut words report it (pinned; the #2939 round-1 seat's fuzz row F06204 is
  one). So a word of that kind that vanishes on its header's line (`f() { ${Y#/usr/bin/env true}
  sh t; }`) is still unread there, as on `main`: the named limit (8 rows of an 80-row hunt over
  the kinds, 32 cells, their own-line twins reporting; the kinds read whole bring 26 cells in 6 of
  its rows back and report 14 in 4 that no parent of that setting runs, as their twins do). On 772
  hunt rows with 8-parent truth -- ten header spellings by 22 bodies, each beside the same body on
  lines of its own, headers behind keywords and in program strings, bodies that open with `[[`,
  nested and gating bodies -- against `main`: 561 cells in 129 rows report that a parent runs
  (FN1-union and FN1-mixed-run under every setting), none that a parent runs reads CLEAN, and 351
  of the 381 one-line rows read as their own-line twin reads on `main` (211 before). The price,
  REPORT here though no parent of that setting runs: 149 cells in 55 rows, each a cell the
  own-line twin reports on `main` -- a function never called, `${X:+sh t}` with `X` unset and the
  cap (65 cells, 13 rows), and `function f` or `my-fn()` under `sh`, which dash refuses (84, 42).
  And CPH15 and CPP14, #2856 round 9's rows for the head test, move from CLEAN to REPORT though no
  parent runs them (10 cells; the coordinator's ruling: the gate that kept them CLEAN is the one
  that hid their twins): `function f { ${X:-bash -s} <<'EOF'; }` ⏎ `f` ⏎ … ⏎ `EOF`, the call the
  heredoc's first line, beside the same with the call behind the heredoc, which every bash parent
  runs; and `curl … | f() { ${SH:-bash -s}; }` ⏎ `f`, the definition lost in the pipeline, beside
  one `lastpipe` keeps, which bash 5.2.21 runs -- `main` reports both shapes with a plain `bash
  -s`. 5 cells in 1 row go from REPORT to CLEAN, no parent running: a gate behind `${SUDO:+sudo
  -E}` on its header's line, read as `main` reads it on a line of its own. On the standing sets
  (31,046 rows) 9 rows of #2856's seat hunts 16 and 25 move, all to REPORT: 21 cells in 5 rows
  that a parent runs (`f() { ${RUN:-sh tool}; }`, `f() { ${X:-sh -c} '…'; }`), and 24 that none of
  that setting does (CPH14, CPH15, CPP14 and CPP15, the two ruled shapes in both spellings, 20;
  `function` under `sh`, 4); nothing else moves but one row of #2911's, which differs between two
  runs of one tree. On the #2939 round-1 seat's 20,000 fuzz rows, 2,091 of them with a body on its
  header's line, 154 rows move, all to REPORT -- 185 cells in 49 rows that a parent runs, 585 in
  127 that none of that setting does -- and each reads as its own-line twin reads on `main` (2,065
  of the 2,091 do now, 1,911 before; the other 26 hold a pattern taken off or replaced); none of
  its 2,164 class rows moves. The cost, `job_defects` against `main` on the forge, three passes,
  each a process of its own: 1.23x to 1.24x on the 574 rows of the first hunt and on the 62 nested
  bodies, where the words now read both ways, and flat on the 347 standing rows with a body on its
  header's line (1.00x to 1.02x), on the 136 rows whose body opens with `[[` and on the #2942
  seat's 3,881-row sample of the standing rows (1.00x to 1.01x each); a statement of `function f`
  after `function f` is read in linear time (pinned). `shell_reader.py` stays at 700 lines: the
  module's and `_split`'s docstrings close on their last lines, every word kept, for the line that
  carries the flag and the one that names it.
- **Workflow reader reads a one-word default as the command it names (#2963).** `${X:-curl} -fsSL
  URL | sh` read CLEAN under every `shell:` setting while every parent shell runs the download, with
  no printer near it. A command word that is ONE default-value word was followed only where its
  default names a shell (`${X:-sh}`, #2337) or holds a blank (#2731). Naming a fetcher (`curl`,
  `wget`, by name or by path) or `eval`, it stayed a word the guard does not follow -- written
  directly, in a `-c` or `eval` string, a heredoc, a group, a branch, a substitution, behind a
  wrapper -- and a `$` word in front of it (`$SUDO ${X:-curl} …`) was not dropped, since the reader
  drops one only in front of a name it knows. The second walk now reads such a default as the
  command it names, under each of the six operators (`:-`, `-`, `:=`, `=`, and `:+`, `+`), and knows
  the word after the ones it may drop by its one-word default too. The main pass reads the word as
  `main` does (`shell_defaults.WALKED_DEFAULTS`, off under `workflow_options.mains_answer`), so the
  job REPORTs wherever either reading does and no cell can go from REPORT to CLEAN. Of the issue's
  73 staged rows, the 30 that read CLEAN while every parent runs (22 fetchers, 4 `eval`, 4 behind a
  `$` word) now report and the other 43 are unmoved. On a hunt of 297 rows -- 26 places a fetch can
  stand, each under up to twelve spellings of the default beside its literal twin, and 48 rows that
  assign the default's name first -- the 220 rows a parent runs that `main` reads CLEAN now report;
  213 of 217 spellings read as their literal twin reads on `main`, with the twin's truth; one
  running row stays CLEAN as on `main`, a function's body (#2954's class). The price, named and
  pinned: the default is read whatever the step did to its name, as `main` reads a shell's default,
  so 28 of those 48 rows (`X=echo; ${X:-curl} …`) report though no parent runs the download, and so
  do an alternate whose name nothing sets (`${X:+curl} …`) and one in a child shell whose name the
  step set and did not export (4 rows of the hunt). Against `main` on 1,372 rows -- the hunt with
  seven more alternates, the issue's rows and #2955's twelve sets -- no cell goes CLEAN where it
  reported and the main pass is `main`'s on every row; `job_defects` over them costs 1.015x in one
  process, and 1.13x on the hunt's own rows. A printed line that begins with such a default needs
  #2979's printer readings as well, and with both it reports: #2955's PF-fetch-run and
  EVS-fetch-run, which both test modules pin, and all 184 such rows of that issue's first hunt, each
  one a row a parent runs. Not among the issue's rows, the same reading takes in a default naming a
  shell behind a word bash may drop: `$SUDO ${X:-sh} -c '…'` read CLEAN, though `main` reads either
  word alone, and now reports (15 measured rows a parent runs; an alternate there, `$SUDO ${X:+sh}
  …`, joins the price). `eval`, `.` and `source` behind such a word read CLEAN on `main`, as
  `$SUDO eval '…'` does (#2997), and a default naming one reads as that twin.
- **Workflow reader reads a path the step linked or moved to as the descriptor it may reach
  (#2919).** With #2881 a shell reads what `N<>` holds where it opens N's path, but a path the
  step's own state makes resolve to a descriptor carried nothing: `ln -s /dev/fd/3 fd3` ⏎ `sh 3<>
  tool <fd3 3<&-`, a link to `/dev/fd`, `/proc/self/fd` or `/dev` with a path below it (`<fds/3`,
  `<p/3`, `<d/fd/3`), and `cd /dev` ⏎ `sh 3<> /tmp/tool <fd/3 3<&-` read CLEAN while the parents
  run the file, and `main` reports the `N<` twin of each. `shell_command.track` records, stage by
  stage in the order the reader reads them, each link the step may make (`ln`, each target a name
  is given) and each directory a `cd` or `pushd` may move it to, and `sources` reads an input
  redirect's operand as written, as `main` reads it, and then by each other path those records may
  give it. A record adds a reading and takes none away: the reader does not know that an `ln` or a
  `cd` runs, succeeds, or lasts past a subshell, a branch or a function. Round 1, which read the
  operand only where the latest record put it, let a link or a move the shell never makes clear a
  report `main` raises -- `true || ln -s /etc/hostname /dev/fd/3`, or `(cd /srv/a/b/c)`, in front
  of `sh 3<> tool </dev/fd/3 3<&-`: the round-1 seat's 341 cells in 71 rows, which report again
  (round 2). Round 2 still read one thing in place of `main`'s: the heredoc or here-string body a
  record may put on a descriptor, taken wherever the operand as written names none. So `true || ln
  -s /dev/fd/3 /dev/stdin` ⏎ `echo 'curl … | sh' | sh 3<<'EOF' </dev/stdin`, its body harmless,
  read that body for the pipe, and CLEAN: the round-2 seat's 78 cells in 16 rows, each REPORT on
  `main` with a parent running it by the seat's truth. That body is now one more reading beside
  `main`'s (round 3): `shell_command.body_read` hands every fold `main` reads the body the operand
  names as written, or none, and `folds` reads the job again once for each other body a record may
  put there, so the guard REPORTs where either is the one read, and a finding `main` raises there
  is never lost -- and each of those readings holds #2935's folds too, every `find` the `find` and
  then each action in its place, so a shell an action runs that reads a body through a link
  reports as well (`ln -s /dev/fd/3 x` ⏎ `find /dev/null -exec sh \; 3<<'EOF' <x`, which every
  parent runs and neither PR reads alone). Those 16 rows report again, and a name linked twice is
  read with the body on each of its targets, where round 2 read the first alone. Past 16 places or
  paths a record may put any body held there -- round 2 named none, and the seat's CAPX-H16, -H40,
  -LH17 and -LH40 read CLEAN while every parent runs them (20 cells, which report). Each such body
  is one more reading of the whole job, on top of every fold `main` reads, so the folds read at
  most 4 of them a stage (`_BODY_FOLDS`): the steps that hold any hold one or two, 4 is twice
  that, and a stage with more is a step the reader refuses, reported whole and never read CLEAN.
  Where the paths reach two descriptors every file held is carried, as where a value decides the
  link's name or the directory (`ln -s /dev/fd/3 "$X"`, `cd "$D"`) and where they are more than
  16. A link or a `cd` that reaches no descriptor carries nothing, as before. The #2885 round-4
  seat's FL rows (30 rows, 150 cells) and probe 0's P0L rows (2, 10) report, and on the #2919 hunt
  -- 72 rows with 8-parent truth: six link spellings and four `cd` ones, each under `sh`, `bash`
  and `dash` on descriptors 3 and 9, and two benign ones -- 264 cells in 60 rows that read CLEAN
  on `main` while a parent runs them; on the round-1 seat's 343-row hunt, 583 cells in 128 rows,
  63 of them (14 rows) ones round 1 still read CLEAN (a `cd /dev` kept through a later `cd` the
  shell does not make, a link through a later `ln` that fails or one made below it), and no cell
  goes REPORT to CLEAN, there or on the standing sets. The price, CLEAN on `main` and REPORT here
  where no parent runs, on the seat's hunt: 227 cells in 54 rows -- a link name or a directory a
  value decides, every file held carried (65 cells, 13 rows); `cd /dev/fd` and `cd /proc/self`,
  which only dash resolves for the parent shell, under the bash settings (36, 12); a link later
  written over or removed, whose first target still stands (45, 9); a `cd` in a subshell, a
  branch, a function or a pipeline, or one that fails, before a relative read (25, 5); a `cd` the
  step has left again, by another `cd`, `popd` or a `pushd` swap (26, 9); an output redirect
  through a linked or moved path (20, 4); and, with round 3, a body a directory or a link name a
  value decides may put on standard input (10, 2). On the round-2 seat's 98 rows round 3 adds one
  more class: an operand that names a descriptor whose own body is harmless, where a link the
  shell never makes names another whose body is a program (5 cells, 1 row). The cap of 4 has a
  price of its own, met on none of these sets: a stage with 5 to 16 harmless heredocs on distinct
  descriptors, below a record that may reach any of them, is refused where it would read CLEAN. On
  neither hunt, nor on the #2919 hunt, does a cell go REPORT to CLEAN against `main` `23ebd281`.
  Still unread, as on `main` -- 230 cells in 48 rows of that hunt that a parent runs: a link or a
  move the reader does not read as one, made in a child (`sh -c`, `eval`, a heredoc's program, a
  substitution), by another tool (`busybox ln`, `cp -s`, `mv`, `xargs`), into a directory (`ln
  -t`, several targets), through a chain of links, a pattern, `CDPATH`, `~` or `HOME`, or a
  symlinked directory. On the standing sets -- the #2885 round-4 rows and twins, round 3's own and
  twins, the AX, P0, F6 and P4 rows, the round-3 kit's 20,533 and #2856's hunts, 31,046 rows, 436
  of them holding an `ln`, a `cd` or a `pushd` -- only those 32 rows move, beside #2911's (hunt
  37's `*-od`), which differ between two runs of `main` too. The cost, `job_defects` against
  `main` `23ebd281` in one process on the forge (a 32-core Neoverse-N2, Python 3.12.3; its load
  was 8.2 when these began, 2.4 after the worst-case rows and 5.7 at the end), by the #2935 seat's
  tool in three alternating passes: 1.02x on its sample of the standing rows, 1.05x on the round-1
  seat's 343 rows and 1.05x on the #2919 hunt, and 1.01x and 1.01x on #2935's own probes and
  differential in one pass each -- flat wherever no record meets a body -- and 1.34x on the
  round-2 seat's 98 rows, which were built to hold one. Each such body is one more reading of the
  job, and that multiplies with #2935's and #2929's folds: the worst step this round could build
  -- ten `find`s of 8 actions, three two-halved words and bodies a record may put on one stage's
  standard input -- takes 1.27 s with one such body, 1.92 s with two and 3.25 s with four against
  0.64 s on `main`, x5.1; a fifth is refused in 0.76 s. On a 10-core M4 under a load of 3 the same
  step is 1.33 s against 0.26 s.
- **Workflow reader reads a pattern below a link or a `cd` as `main` reads its whole path (#2919
  round 3, its own fix).** `main` reads `</dev/fd/[3]`, a path of whichever descriptor bash's
  expansion picks, as every file held and any pipe. Rounds 1 and 2 of #2919 read no word bash
  expands through the step's links and `cd`s, so its twin below a `cd /dev` or a link to
  `/dev/fd` read CLEAN: `cd /dev` ⏎ `sh 3<> /tmp/tool <fd/[3] 3<&-` runs the file under each of
  bash's six parents (dash expands no pattern in a redirection) and reported nowhere. The clause
  that kept such a word out of `shell_command._reached` is gone, found by a mutant the round-2
  seat listed as passing its suite: a word bash expands, or a value decides, is read through the
  records like any other. On this round's own hunt -- 18 records by 40 operands by 9 forms,
  6,480 rows, truth taken for every row that moves -- 12 cells in 4 rows that a parent runs go
  CLEAN to REPORT, and so do 976 cells in 224 rows that none runs, the price: a pattern below a
  name or a directory a value decides, or past the cap, where a plain path is every file held
  already; a pattern below `cd /dev/fd` that matches nothing (`<[x]`, `<{x,y}`) or more than one
  (`<fd/?`); and a value in front of `..` that folds onto a linked name (`<$X/../x`), whose body
  is read though `X` unset names no such path -- it runs where `X` names a directory of the
  step's. No cell goes REPORT to CLEAN, and none moves on the seats' sets or the standing sets
  (31,559 rows). Two clauses a mutant each showed to do nothing went with it: `sources` handed
  `read` a `derived` path, and `carrier` asked for `?` among two or more answers. Still unread,
  as on `main`: a pattern that spells no `/dev/fd/` once the record is applied (`cd /dev` ⏎
  `<f?/3`, as `</dev/f?/3` on `main`), one in place of a link's name (`<[x]` for a link `x`),
  and one in a `cd`'s own directory.
- **Tools-image pins move together: semgrep 1.179.0, pyjwt 2.15.1, filelock 4.0.9 (#2876).**
  Dependabot's requirements-only bump (#2946) failed the image's `pip check`: semgrep 1.179.0
  requires `pyjwt[crypto]<3,>=2.15.0` where 1.178.0 held it to `~=2.13.0`, and a `--no-deps` closure
  has no resolver to move a transitive pin with its parent. pyjwt moved to 2.15.1 with it, `ARG
  SEMGREP_VERSION` followed the pinned file, and the digests are `bump_pins.py`'s. `pip-audit` over
  the closure reported 14 known vulnerabilities before, all in pyjwt 2.13.0, and none after.
  Dependabot's `ignore` for pyjwt's minor updates is dropped: semgrep no longer holds pyjwt to one
  minor line, so the rule only withheld fixes such as these. Its major updates stay ignored, as do
  the lines semgrep 1.179.0 still holds `boltons`, `exceptiongroup` and `wcmatch` to. Stale cites
  follow the pin: the Dependabot comment, `DEVELOPMENT.md`, the image's rule-corrections README, and
  the two comments on a `# nosemgrep`'d result, which semgrep 1.179.0 still reports either way,
  `--disable-nosem` changing nothing in its SARIF (measured again at the pin); and the `Dockerfile`
  counts three tools in the python closure, not four.
- **No lone surrogate reaches an encoder (#2951).** `json.load` hands a lone surrogate over for a
  lone `\udXXX` escape, and no encoder of text takes one. One such string in one agent-authored
  finding ended `synthesize.py` badly, and how depended on the field. In a title, a file or a
  category the id's hash raised (`evidence.matrix_finding_id`): a traceback, status 1 -- which is
  also the gate's FAIL status -- and NO report. In a description, impact, remediation, exploit
  scenario, a reference or a provenance value the page's writer could not encode it: the page was
  left EMPTY, the report carried the surrogate, and the run ended status 4 as `artifact path
  refused` (before #2956, a traceback in `html_report.write_html` and status 1). In a nested value,
  a key, `location.function` or `lens` the run finished and the report carried the surrogate to
  whoever loads it next (`json.dump` writes one without raising, as the escape it was read from).
  The same string in an advisor's verdict, in a scanner's output (a SARIF `ruleId` or `uri`,
  dependency-check's `fileName`: `evidence.finding_fingerprint`) or in a group name discovery took
  from the target's tree did the same. Each is now spelled `U+D800`: six visible characters, so the
  text stays readable and every written file is valid UTF-8, and NO backslash. `evidence.norm_path`
  reads a backslash as a separator (#2988), so a name spelled with one would be read as a path into
  another directory: a root-level `docs<byte>x.py` as a file in `docs/`, where the doc policy takes
  a HIGH down to INFO and the gate passes. `inert.spelled` is the one spelling of every inert code
  point now, and the others keep the backslash escapes they had. Where: `findings.agent_finding` and
  `evidence._agent_verdict`, the one door each for findings and verdicts, and
  `tools/base.parse_json_bytes` with the SARIF adapter's parse for a scanner's output -- on the way
  in, because that text is hashed before anything is written, so the id and the fingerprint are
  those of the spelled text and the driver's loader and synthesize's agree;
  `synth/artifacts.read_json`, the one reader of the run directory's JSON (the tools manifest,
  groups, plans, coverage, the hunk map), so that every cap a caller applies comes AFTER the
  spelling -- spelled later, a manifest row of 59 characters and a surrogate that was cut to its 64
  would come out as 65, past the schema's bound; `synth/report.build_report`, the backstop, for what
  never was JSON, which meets its first encoder at a writer; and the policy's own set, which gains
  U+D800 to U+DFFF, so `inert_text`, the prompt's `_prompt_safe` and the X0X failure log cover a
  name that never was JSON (on Linux an undecodable byte in a filename is one). Only surrogates are
  spelled: an input holding none is read as it was, the same objects, and writes the same bytes --
  on 45 cases through both trees' children and on the schema-parity fixture's 26 files, ids and
  fingerprints included. One string of one input at a time over that fixture (13 files, 1,031
  strings; the queue pass 556), with one lone surrogate and again with 600 of them: on `main` 92
  fields end badly with one (10 raise, 82 leave the surrogate in an artifact) and 54 in the queue
  pass (10 and 44); now none raises, none leaves one in an artifact and none ends `artifact
  invalid`. In the suite's child runs -- the issue's rows, every place of a finding and of a
  verdict, a scanner's output, a name from the tree, a name with an undecodable byte on the doc
  policy's way, a manifest row at its cap, a hunk map -- a run on the lone surrogate writes, byte
  for byte, what a run on its spelled twin writes. Not covered: `--compare`, which reads reports
  already on disk; a diagnostic on stderr that names a run file by its path, and the last prints of
  the operator's own `--out` path; the driver's own readers of the run artifacts beyond what
  `_prompt_safe` and `inert_text` wrap; and a value nested deeper than the stack, which ends the run
  in `redact.redact_tree` with or without a surrogate (`main` does the same).
- **`scripts/shell_command.py` splits its `$`-word readers into `scripts/shell_defaults.py`
  (#2993, reader lane).** A pure move at the module's size (633 of its 700 lines, with #2919 to
  fold onto it): the shells and the other names a `$` command word may stand in front of, its
  default, alternate, optional and vanishing spellings, the halves the folds read of a word bash
  may expand to nothing, and the readers of one word (`_optional`, `_shell_default`,
  `_default_words`, `_strips`, `_alternate`, `_half`, `_masks`) now live in the new module, byte
  for byte with the comments above each; `shell_command` imports every name back under its own,
  so no caller and no test moved, and the new module imports nothing from it or from the reader.
  The `find` readers stay where they are: the walk calls into them and they call back, and
  #2935's pins bind their names to `shell_command`. No verdict changes: on 106,107 rows (530,535
  cells) -- the standing sets, #2929's seats' sets, #2935's differential and probes, and #2919's
  seats' rows, hunts and pins -- every finding of every row, its name and its reason, is the same
  under `main`'s scripts and the move's under each of the five `shell:` settings, but for 8 rows
  whose text differs from run to run under either: 6 hold a parse nonce in a finding's reason and
  are identical once it is normalised, and 2 are the copies of #2911's `*-od` row. Sizes: 633 ->
  490, and 174 for the new module.
- **Workflow reader reads a printed line as the shell that reads it gets it (#2955).** `printf '%s
  %s\n' curl '-fsSLo t URL' | sh` ⏎ `sh t` read CLEAN under the five `shell:` settings while the
  eight parent shells run the download, and so did the issue's word `${X:+curl … #}./t.sh` printed
  twice by `printf '%s\n'`, and `eval "$(echo LINE)"`. A printer the guard cannot spell out -- a `$`
  in a word, a `printf` format `printed` does not read, an `echo` option or escape two shells read
  two ways -- had its words weighed as ONE text, which begins with the printer's first word: an
  `echo`'s line, but a `printf`'s FORMAT and an `echo -n`'s `-n`, so the line after it read as an
  argument and never as a command; and a program word that is one `$(...)` was reported with a
  reason the guard may drop, its printer never weighed. The second walk now weighs, beside that
  text, what the printer WRITES with each word as written -- down a pipe, behind a stage that may
  rewrite the text, inside `$(...)` or `<(...)`: an `echo`'s line without its options, decoded where
  its shell decodes, and a `printf`'s format with its words in place. The rendering of a format is
  what the shell prints, to the character, or it is not followed and the step REPORTS. Followed:
  text and escapes in the format (an octal escape is a BYTE: `\543` is a `c`), `%%`, `%s`, `%b`,
  `%c`, `%q`, `%d` `%i` `%u` of a plain decimal, a `-`, a width to 256 on any but `%b`, a number's
  `0`, a precision on `%s`, a `*` that takes a plain decimal, the format used again while words are
  left, and a `$` word as it stands; the output ends at a character the shell does not know. Not
  followed: every other flag, letter, number, width and precision, and `%q` of a `~` or of a
  character outside printable ASCII, where the shells print their own ways (`%.b` is the whole word
  to bash 3.2 and nothing to 5.2; a width counts bytes; bash 3.2 dies of a `*` word past an `int`);
  a `$` word that a precision or `%c` would cut or a width pad with blanks; and a text past 4,096
  characters and four times the format and its words -- `printf` prints its format again for every
  few words, so what it writes can outgrow the step many times over. Each shell family is rendered
  on its own (bash 5.2, bash 3.2, bash 3.2 as macOS ships it, dash) and each distinct rendering
  weighed once, because the readings are not nested: a `\"` bash decodes in a format closes a quote
  and bares the command after it where dash keeps it hidden, and the other way about, and one pinned
  row runs under bash 3.2 and dash and not under 5.2. `unread_program`'s last resort weighs the one
  printer a program word's `$(...)` is. The main pass reads as `main` does, so the job REPORTs
  wherever either reading does. Measured against the shells' own builtins: in 10,000 random formats
  and 10,000 `echo` word lists on each of bash 5.2.21, bash 3.2.57 and dash 0.5.12, no rendering
  that is followed differs from the output but by a `\u` outside ASCII in a C locale. And on 932
  rows in nine bounded hunts, each under eight parent shells in two passes: no cell goes CLEAN where
  `main` reports, and of the 645 rows a parent runs, 309 that read CLEAN now report and 120 reported
  already. Still CLEAN though a parent runs, 216 rows, none of them claimed read: 184 whose printed
  line begins with a one-word default (`${X:-curl} …`), which #2963 reads, the issue's PF-fetch-run
  and EVS-fetch-run among them; 22 on routes `main` reads no printer on, spelled or not (its text
  written to a file that is then run, kept in a variable, printed by a group or a function, handed
  to `xargs`, read by `. /dev/stdin`); `builtin` in front of the printer, no wrapper to the reader
  on `main` either (#2665, 8 rows, run by the bash parents); and two copies of a line the guard can
  spell (#2953, 2 rows). The price, 82 rows where no parent runs a downloaded program and the step
  now reports, each kind pinned: a line that only FETCHES, as `echo curl | sh` reports on `main` --
  the word printed once with its name set (29) and a fetcher on a line with no run after it (9); a
  format that is not followed around a harmless line (26: `%x`, `%.1f`, a `$` word padded); the text
  in front of a stage that spoils it (`| tr a-z A-Z | sh`, 9), which `main` reports for an `echo` it
  can spell; a line only dash makes, on a route every family is read for (5); and a format printed
  again past the bound (4). A printer is weighed once a distinct rendering: `main`'s one text, then
  at most three more under a bash setting, one under a dash setting, four where each family is read.
  One existing pin's value changes: `unprinted` for `printf 'sh %s' "$X" | tee f | sh` gains the
  written text, its old value pinned under the main pass.
- **Workflow reader reads the command a `find` action runs, beside `main`'s reading of the `find`
  (#2935).** But for the reader that asks how a stage uses a file (#2918), no reader of the
  guard's saw the command an action of a `find` runs, the first one included: `find /dev/null
  -exec curl -fsSLo tool … \;` ⏎ `sh tool`, `find /dev/null -exec sh -c 'curl … | sh' \;` and
  `curl … | find /dev/null -exec sh \;` ran the download and read CLEAN. `shell_reader.acted()`
  answers with the action a fold reads (#2918's folds) in its `find`'s place -- a command line of
  its own, read as the step's own is: its wrappers stripped, a `$` word bash may drop in front of
  a known name dropped and a shell's default read (round 2; round 1 read them as words behind a
  wrapper, which reported benign finds) -- its command word a `shell_wrappers.Found`. `command()`
  is `main`'s, the `find` (round 3; rounds 1 and 2 unwrapped it for every reader), and `main`'s
  reading is never lost: `shell_command.folds` reads a job in every fold of `main`'s first, where
  `acted` is `command`, then, where one met a `find` with an action, in the same folds again with
  each action in place, and the guard REPORTs where either reading holds a defect. Fourteen
  readers ask `acted`, one line each (out of lane, granted by the coordinator), each named with
  the row that needs it in `TestEveryFindActionIsACommand.ACTED` and held to that list by a test
  that reads the scripts' AST: `workflow_forms.flattened`, `workflow_guard._walk` and
  `_unread_stdin`, `workflow_fetch.stdout_fetch`, `stream_consumer` and `compound_output`,
  `workflow_programs._details` and `stdin_scripts`, `workflow_printers.producer`, `handed`,
  `unspelled` and `_printer`, and `workflow_uses.copies` and `use`; `producer` and the three that
  take its answer read a stage one way, or `unspelled` raises. Every other reader reads
  `command()`: GNU `find` 4.9.0 exits 0 whatever a `-exec … \;` command returns (the round-1 seat:
  33 of 33 measurements, 1 only for `{} +`), and no `find` runs `exit`, `return` or a shell
  function, sets or clears a variable of the step's or changes its posture, so a stage's status,
  its call, its values, the sums file its check reads and its `xargs` walk are read off the `find`
  itself. Round 1 read `CHECK || find … -exec exit 1 \;` as `CHECK || exit 1` and a function an
  action names as called (its seat's 8,776 cells in 2,308 rows), and round 2 read `find … -exec
  read T \;` as the step's own `read`, a `tee` in an action as the step rewriting its sums file,
  an action's `echo` in place of what the `find` prints and an action as the end of its `xargs`
  walk (its seat's 12,163 cells in 2,541 rows, REPORT on `main` and CLEAN there); each reads as
  `main` reads it. No check an action runs is credited: an action that runs a checksum tool keeps
  the `find`, and a program an action runs, as its `-c` string or on its shell's standard input,
  has no shell sure to read it (`shell_command.unsure`, `sure_reader`, which
  `workflow_programs.scripts` and `stdin_scripts` call on their own lines; out of lane, granted),
  so `workflow_forms.flattened` reads it `Unsure`. A rule that keeps a `find` with an action as
  `main` reads it fires on sure input alone, and where it is not sure the step REPORTs (round 3).
  An action whose own first word is `.`, `source`, `eval` or `exec` -- a bare name, the one word
  `find` itself looks up -- runs nothing, since no system ships those as programs (`_NO_PROGRAM`;
  each word has the row that reports when it is dropped, and the eighteen other builtins round 2
  listed moved no row once `command()` was `main`'s, and left); behind a wrapper, which may hand
  its words to a shell as `sudo -s` does, or behind a path, the action is read. An assignment with
  no `/` in it is a name `find` looks up and no program has; one that names a path is read. A
  `find` an action runs is kept, since `find` ends an action at the first `;` or `{} +` and one
  written word by word holds none it can run; one a wrapper splits out of a single word (`env -S
  '…'`) may, and is a command the guard cannot read. A `$` word in front of the action's command
  is read as the step's own is only where it begins with a whole reference; a `${…}` that holds a
  blank is cut where the reader meets it, and is a command the guard cannot read. `command` is a
  program on macOS, which runs a builtin too, and stays read. The reads grow with a nest's depth,
  not as a power of it: each of the guard's two readings unwraps a nest of depth 2, 4 and 6 in 6,
  10 and 14 reads (round 2: 46, 74 and 102; round 1: 192, 2,560 and 25,600), and a nest of depth 8
  takes 167 ms a step on the forge, where `main` takes 13.5 (round 1: 22.8 s, by its seat). An
  action whose command word is `{}`, a substitution or a `$` word no known name follows, or a
  `find` holding more than 8, reads as #2918 reads it. On the round-1 seat's differential --
  27,902 generated steps, 139,510 cells, 8-parent truth on GNU find 4.9.0 -- 27,085 cells in 5,503
  rows that read CLEAN on `main` while a parent runs them report (a fetch in an action then a run,
  an action's `-c` program, an action running a download, a stream piped into an action's shell,
  heredoc and here-string programs; in every position and behind every wrapper), as at round 2. No
  cell that is REPORT on `main` reads CLEAN, before #2929 or after it: none on the two seats' sets
  (99,125 rows), the standing sets (31,046) or this round's hunt for readers that disagree about a
  `find` (46,454 rows: 51 commands as the action, the `find` in 54 places of a pipeline, a
  substitution, a string and a redirect), and none that round 1 or round 2 reported reads CLEAN
  where a parent runs. The round-2 seat's rows report again: the 12,163 cells of its four reader
  groups; its 38 rows with a builtin's name behind a wrapper or a path, 27 of which run under its
  model of `sudo -s` and 4 behind a path to `command`; its 6 split nests; and its 244 rows with a
  cut `$` word, 136 of which a parent runs. The price, CLEAN on `main` and REPORT here where no
  parent runs, is 20,945 cells in 4,318 rows of that differential, as at round 2 (round 1: 25,675
  in 5,264), each a `find` that never runs its action as written, which a reader cannot tell from
  one that does, or one of `main`'s own over-reports reached through an action: the test in front
  never matches, so the action is never reached (1,520 cells); no `;` ends the action, so `find`
  stops on a usage error (4,310); `command` is the action's first word, no program on Linux, where
  the truth was taken (1,630); `-ok` or `-okdir` with no `y` to read (7,900); `-execdir` or
  `-okdir` from `/dev/null`, which runs the action in `/dev` (2,464); `{}` handed on, so the shell
  or fetcher gets the root (1,040); a check that gates the run inside one action program, wrong
  digest (805), a fetch-only program in an action of a `find` rooted where the download lands
  (760) and a here-string program under dash (352), which `main` reports alike outside a `find`,
  164 more of those three behind an optional `$` word; and in its probes a `find` as another's
  action, which `find` itself rejects, the inner `-exec` read as an action of the first (25
  cells). Where round 3's rules are not sure and nothing runs, they add 540 cells in 108 of those
  244 rows, and 40 cells in 8 rows with a builtin's name behind a wrapper that runs nothing
  (`sudo`, `env`, `time`, `nohup`, `doas -s`, a `$` word, a `find` that matches nothing). Round 3
  takes two of round 2's price classes away: `find … -exec command set +e \;` in front of a
  failing check, which round 2 reported as the step's own posture though the step stops wherever
  `-e` holds, and an action read as the end of an `xargs` walk. Of the benign finds that fetch
  nothing, 5 cells read REPORT, one row with no `;` (round 1: 785 cells). No cell moves on the
  standing sets. The cost, `job_defects` against `main` in one process on the forge (a 32-core
  Neoverse-N2, Python 3.12.3), by the round-1 seat's own tool in three alternating passes: 1.07x
  on its sample of the standing rows (3,881 rows), 2.07x on its status probes and crossed set
  (2,867) and 2.88x on its sample of the differential (3,986), where every row holds a `find` with
  an action and is read in `main`'s folds and then in a fold for each action; the worst case is
  one `find` of 8 actions, 10x to 13x a step (143 to 156 ms against 11 to 15), and ten of them in
  one step 13x (1.26 s against 96 ms); nine actions are past the cap and cost 2.1x, and a nest
  reads as that many actions of the first `find`. Those worst-case ratios were taken with that
  machine's load between 3 and 9 and they move with it: the round-3 seat, at a load near 12,
  measured about 26x and 27x for the two, on shorter times at the head, and the same 2x past the
  cap. What holds on any machine is the count: at most 8 actions a `find`, one fold each. Still
  unread, as on `main`: a fetch in one action of a `find` and its run in another (#2941).
- **Workflow reader reads every mixed reading of the command words bash may expand to nothing
  (#2929).** #2856's union read a job twice: every such word -- `${X:+W}`, `${X-W}` and their kin
  -- as its W, then every one empty, two of a step's 2^k readings, so a payload only a mixed
  reading runs read CLEAN while every parent runs it: `X=1` ⏎ `${X:+curl -fsSLo tool …}` ⏎
  `${Y:+/usr/bin/env true} sh tool`, the fetch's W and the shell's word empty, and the #2856
  round-13 seat's 14 rows of hunts 49, 51 and 53 (70 cells). `shell_command.folds` now reads,
  after those two folds, every other set of such words whose halves read apart -- `_runs` reads
  another command in each, or one command word with other operands (`${Q:+/usr/bin/env cat sums}
  cat`) -- empty in a fold of its own, up to three words, so 4 folds read two of them and 8 three;
  halves that read one command (`${SUDO:+sudo -E} apt-get …`) add no fold. A word is one word by
  where it stands, never by what its text says (`shell_tokens._Parse.place`, round 2): a step at
  its index in the job, a `$(…)`, a backquote, a `<(…)` or a heredoc's body at its place in the
  text that lifted it, a program a shell reads on its standard input at its heredoc's, and in that
  parse the order it was kept whole. So a text read again in a fold holds the same words, no nonce
  of the reader's splits one, and one spelling at two places is two words -- two equal
  substitutions, two heredocs of one body, two steps of one text (a step's program strings aside:
  the limit below); round 1 keyed a parse by its text, which read those as one word (the round-1
  seat's IdB.two, IdC.subst and MS.same rows, CLEAN while the parents run them: all 16 runs, 12
  for IdC.subst-proc) and one word as many wherever a marker's nonce reached the text (its Idnonce
  rows, reported at the cap though nothing runs). A `-c` or an `eval` string is no lifted text: it
  reaches its parse by its text alone -- its parent's token, and `workflow_programs._parsed`, a
  cache keyed by the text -- so its parse is keyed by that text, less the reader's own nonce and
  nothing else (`shell_tokens._keyed`, round 3: every nonce this process mints ends in a tag of
  its own, so a word that may be a shell's program, read with its `$(…)` left as a marker, keeps
  one key whatever nonce its parent minted, and text of the target's that is only shaped like a
  marker stays in the key -- round 2 took every such text out, and read the round-2 seat's
  D.shcd-litmark and D.evq-litmark pairs CLEAN while every parent runs them, REPORT at round 1).
  And that text is the one `workflow_programs._script` hands the reader, in which a substitution
  no printer spells is already written `$(...)`. So two program strings that read alike once each
  such substitution is so written are one word: two identical strings at two places, and two that
  differ only inside a `$(…)`, a backquote or a `<(…)` that stands in them. That is the named
  limit (#2953, the hand-off of a program string's place, which crosses the programs lane): a
  payload only the mixed reading of two such strings runs reads CLEAN, as on `main`. On a capped
  hunt of 180 rows with 8-parent truth -- 9 spellings (`sh -c`, `bash -c`, `eval`, single- and
  double-quoted, an escaped `$`, `env sh -c`, `bash -lc`, `sh -ec`) by 5 program shapes -- all 45
  identical pairs read CLEAN under every setting (225 cells) while every parent runs them, here
  and on `main`; with one blank more in the second string each pair reports (CLEAN on `main`), one
  copy alone only fetches and reads CLEAN, the benign pairs read CLEAN, and no cell reads worse
  than `main`. On a second, of 200 rows -- 8 ways of differing inside a substitution (a `$(…)`, a
  backquote, a `<(…)`, a heredoc's body in one, its argument, one inside another, two of which one
  differs, a `$(…)` against a backquote in its place) by 5 runners -- all 40 pairs that differ
  only there read CLEAN under every setting, as their 40 identical twins do, while a parent runs
  each (192 cells either way: all 16 runs in 36 of the 40, the other 4 a `<(…)` only bash reads),
  here and on `main`; with one blank more outside the substitution all 40 report (CLEAN on
  `main`), and one copy alone and the pairs with nothing downloaded read CLEAN. The round-2 seat's
  18 such pairs are this class; where two strings differ in what a printer spells, in an
  arithmetic expansion or in a word of the substitution that holds the word itself, they are two
  words and report. An `eval` whose words bash joins is the same class. A string that ends in the
  download's name reports as one copy, on `main` too (`workflow_operands.covers` reads it as a
  mention), which is why the round-1 seat's 8 rows and a first hunt's 10 pairs showed no reach. A
  fourth such word reads as a command the guard cannot read, reported wherever it runs, a download
  or none, so the folds stop at 8. The price, CLEAN on `main` and REPORT here though no parent
  runs, counted at this head on the round-1 seat's rows: that cap (146 of its 20,000 fuzz rows;
  one spelling written at four or more places is four words now and meets it, 37 of the round-2
  seat's rows that round 1 read CLEAN), and, since every assignment of halves is read, a mixed
  reading no assignment of the step's names takes -- `${X:+curl …} | ${X:+/usr/bin/env true} sh`,
  one name in both words, reports though bash runs neither mix (618 of its 2,164 class rows, 408
  fuzz rows, and its two-step MS.same-pipe); neither is met in the seats' standing sets, and no
  cell of those 22,164 rows is REPORT on `main` and CLEAN here. The two folds the union read come
  first, as before, so nothing it reported reads CLEAN: across the #2885 round-4 seat's rows and
  their twins, round 3's own and theirs, the AX, P0, F6 and P4 rows, the round-3 kit's 20,533 and
  #2856's hunts 33-53, the only changes against `main` are those 70 cells, beside #2911's rows
  (S08n, S08p, hunt 37's `*-od`), which differ between two runs of `main` too; and on the round-1
  seat's rows the IdB.two, IdC.subst and MS.same rows report, its Idnonce rows read CLEAN as
  `main` reads them, and a capped hunt's six pairs of one heredoc or here-string read by two
  shells report; on the round-2 seat's 1,774 rows the only change against round 2 is its two
  litmark pairs, which report. Out of lane, granted by the coordinator, each net zero:
  `workflow_guard.job_defects` hands each step's index to its parse (`placed`), and
  `workflow_programs.stdin_scripts` keeps the place of the heredoc it reads (`at_place`). The
  cost, `job_defects` against `main` interleaved in one process, three passes on the final
  scripts: 1.9x to 2.4x on the 39 rows of hunts 45-53 that hold two such words, flat where one or
  none, 3.3x to 5.0x for three and past them (the eight folds, to 200 words; the round-2 seat's
  rows past the cap read 4.70x to 4.98x), and 1.06x on the #2885 seat's 1,945 rows (1.05x to
  1.07x, the round-3 seat's measure). Two such words in one stage stay #2856's named limit: only a
  stage's first `${…}` word is read whole. `shell_reader._stage`'s docstring is rewrapped at 96
  columns, every word kept, for the line that stamps the place.
- **Workflow reader reads every action a `find` runs (#2918).** `curl … -o tool` ⏎ `find
  /dev/null -exec true \; -exec sh /dev/fd/3 \; 3<> tool` ran the download and read CLEAN: the
  guard read one of `find`'s actions, the first of `-exec`, `-execdir`, `-ok` and `-okdir` in that
  order, its words to the end of the line, so a shell in a later action (`-exec true \; -exec sh
  …`, `-execdir`, `-ok`), behind the order's `-exec` (`-execdir sh … \; -exec true \;`), after a
  failing or negated test (`-exec false \; -o -exec sh …`, `! -name -exec -exec sh …`, `-name
  -exec -o -exec sh …`) or behind a wrapper inside its action (`-exec env sh …`, `-exec sudo sh
  …`) was never read, nor the file it runs. Every action is now read: the words after each of the
  four, wherever it stands, to its `;` or to a `+` right after `{}`, a test's operand that spells
  one read as one too, fail-closed, and its wrappers stripped as the guard strips them in front of
  a command. A shell any action runs reads what `N<>` holds (`reads_held`), and where the guard
  asks how a stage uses a file it reads one action a fold (`find_action`, `folds`), so it REPORTs
  where any action uses the file: a shell handed it, the file run, `{}` naming it, a shell's
  standard input, a printer piped into a shell. A command word an action leaves to `find` or bash
  -- `{}`, each path it walks (`find /usr/bin/sh -exec {} …`), a substitution (`-exec $(echo sh)
  …`) or a `$` word -- reads as a command the guard cannot read, as one behind a wrapper does, and
  so does a `find` holding more than 8 distinct actions, read with its first alone so neither the
  scan nor the folds grow with its words: the price, a report wherever such a `find` runs, a
  download or none (`find . -name '*.sh' -exec {} \;`). A check an action runs is still credited
  with nothing, as on `main`: `find` exits 0 though a `-exec … \;` command fails. On the #2885
  round-4 seat's hunt the 84 rows (420 cells) that read CLEAN while every parent runs the file now
  report, and their `N<` twins too; across its 956 rows and their twins, round 3's own 989 and
  their twins, the AX, P0, F6 and P4 rows, the round-3 kit's 20,533 and #2856's hunts 33-53, no
  cell goes CLEAN where `main` reports -- but for #2911's rows (S08n, S08p, hunt 37's `*-od`),
  which differ between two runs of `main` too -- and the only other new reports are 7 rows every
  parent runs (AF073-AF078, KGe26; 35 cells). The cost, `job_defects` against `main` in one process:
  1.49x on the seat's 288 FX rows and 1.04x on its 1,945 rows; a job holding a download is read
  once more for each further distinct action of its widest `find`, at most 8 times. Still unread,
  as on `main`, since `find` is no wrapper to the fetch, program and pipe readers: a fetch inside
  an action, an action's `-c` program, and a download piped into the shell an action runs (`curl
  … | find /dev/null -exec sh \;`), filed as #2935.
- **Workflow reader reads a read-write descriptor's file where an interpreter holds it, as `main`
  reads `N<` (#2881, #2608).** `curl … -o tool` ⏎ `sh 3<> tool <&3` ran the download and read
  CLEAN: the reader read `N<> file` as a write alone, so a dup of N onto standard input (`sh 3<>
  tool 0<&3`, a move `<&3-`, a chain `4<&3 <&4`), a path to it (`sh /dev/fd/3 3<> tool`,
  `/proc/thread-self/fd/3`, `//dev/fd/3`, a climb `../../dev/fd/3`, `/dev/stdout` with `1<>`, a
  path in a value) or a child program (`sh -c 'sh <&3' 3<> tool`, `( sh <&3 ) 3<> tool`, `find
  /dev/null -exec sh /dev/fd/3 \; 3<> tool`) gave the shell nothing it reads. An interpreter -- a
  shell, `python3` and its kind, `eval`, `source` and `.`, the command a `find` runs behind
  `-exec`, `-execdir`, `-ok` or `-okdir` (read as the guard reads it for a use), or a command word
  the step's values decide (`SH=sh` ⏎ `$SH 3<> tool <&3`) but for a checksum tool, which the check
  side credits by its basename (`$X/sha256sum`) -- now reads every file `N<>` still holds open when
  its redirections end, on any descriptor, as `main` reads `N< file`. A dup, a move or an open of
  N's path -- `/dev/fd/N`, `/proc/self/fd/N` or `/proc/thread-self/fd/N`, and `/dev/stdin`,
  `/dev/stdout` or `/dev/stderr` for 0, 1 or 2, each past a run of slashes or a climb
  (`//dev/fd/N`, `../../dev/stdout`) -- carries what N holds to its target, and one whose source a
  value decides (`<&$FD`, `<"$P"`) carries every file held, fail-closed; a later redirection of N
  ends what N held, and only that (`sh 3<> tool </dev/fd/3 3<&-` and `FD=3` ⏎ `sh 3<> tool <&$FD
  3<&-` run the download). Any other command is credited with none of it, so no check is credited
  with a file it only holds: `sha256sum tool | sha256sum -c 3<> sums`, `sha256sum -c self 3<> sums
  <&3` and `X=/usr/bin` ⏎ `$X/sha256sum -c self 3<> sums` check the download against itself, and
  the use stays reported. On the round-3 seat's rows -- its own 989-row hunt and the 20,533 rows of
  the earlier seats' hunts and #2856's round-10 seat -- none goes CLEAN where `main`, `5e58b019`,
  `f5a74db5`, #2856's round 11 (`b7f53f19`) or round 2 reports and a shell runs the payload
  unverified, but for #2899 (158 cells, 32 rows, against `5e58b019`); #2856's own `<>` on standard
  input, which credited a check after fd 0 was redirected again or one that names its own list (56
  cells, 20 rows, against `main`; its round-11 B5), closes with its round 12, folded here, which
  moves its own cells here as there: on the round-3 seat's CZ rows 56 close and 22 over-report as
  `main` reads them, and on #2856's rows 35 close and 70 clear. Round 4's own numbers, against
  round 3: 1,280 cells close where a shell runs the payload (256 rows: a path of N, 830 in 166; a
  dup a value decides, 120 in 24; the shell a `find` runs, 330 in 66), and 100 over-report in 20
  rows, none run by a shell and each reported by `main` as `N<`: a zero-padded `/dev/fd/03`, which
  the kernel resolves to no descriptor (50, 10); `find -ok`, which asks before it runs and is
  answered no (30, 6); and `sh -s /dev/fd/4 3<> tool 4</dev/fd/3 3<&-`, where the shell reads its
  input, not the operand (20, 4). At round 4's head, the fold's CZ rows counted, 1,336 close and
  122 over-report. The price below counts each cell where the head reports, the earlier tree reads
  CLEAN and no shell runs the payload, in the first of these classes it meets: a check (`sum -c` or
  `sum --check`) no longer credited with a file it holds; under `sh`, a row bash runs and dash does
  not (dash's limits: a move, then a leading-zero descriptor, then `source`, then a descriptor past
  9); a zero-padded `/dev/fd/03`; `find -ok`; `sh -s` given a descriptor path; `xargs` given the
  file on its input; and the rest, a shell that holds the file `N<>` opened and reads nothing of
  it, as `main` reads `sh 3< tool`. Against round 2 on the round-2 seat's four hunts (2,556 rows),
  757 cells in 270 rows: a check, 288 in 138; dash's `source`, 66 in 33, and a descriptor past 9,
  56 in 28; `sh -s`, 5 in 1; and a shell holding the file, 342 in 70. And where a shell runs a
  download that a pinned check verifies first, 277 cells in 101 rows are reported (among them L11
  and L12), as `main` reports them, fail-closed. Against `main`, `5e58b019`, `f5a74db5` and #2856's
  round 11 alike on those hunts, 7,078 cells close where a shell runs the payload (1,820 rows), and
  2,687 over-report in 1,142 rows: dash's limits -- a move, 706 in 353; a leading-zero descriptor,
  752 in 376; `source`, 126 in 63; a descriptor past 9, 426 in 213 -- then a zero-padded
  `/dev/fd/03`, 100 in 20; `sh -s`, 20 in 4; `xargs`, 5 in 1; and a shell holding the file, 552 in
  112. Round 5, on the round-4 seat's 956-row hunt and its 22-row probe 0, against round 4's head:
  521 cells close where a shell runs the payload unverified (117 rows: `/dev/stdout` or
  `/dev/stderr` as the path of a held fd 1 or 2, 185 in 37; a climb, 240 in 48; a checksum tool
  named through a value, 96 in 32), and 18 over-report in 6 rows, each a check (`$X/sha256sum -c
  3<> sums 0<&3`) that reads its `N<>` file through a dup onto standard input, as `main` and the
  literal `sha256sum` read it -- 9 cells where the pinned check verifies the download first, and 9
  where nothing runs. On every row set of both seats, no cell goes CLEAN where `main` or a
  reference tree reports and a shell runs the payload unverified, but #2899 and S08n, whose marks
  vary from run to run (#2911), as at round 4. Named open, as ruled, though `main` reports its
  `N<` twin: a symlink the step makes to a descriptor's path, or a relative path the step's own
  `cd` makes resolve to one, which the reader reads as the file it names (`ln -s /dev/fd/3 fd3`
  ⏎ `sh 3<> tool <fd3 3<&-`; `cd /dev` ⏎ `sh 3<> /tmp/tool <fd/3 3<&-`, the download at
  `/tmp/tool`; #2919). Still open, as on `main`: dash's two-digit `N<>`, which dash reads as the
  word `N` and `<>` on standard input, so `cat - 10<> tool | sh` runs the file under `sh`
  (#2903); `cat 3<> tool <&3 | sh` -- a `cat` piped into a shell is a use only where its words
  name the file, so `cat < tool | sh` reads CLEAN on `main` too (#2884); a compound's redirect
  or pipe (`{ curl …; } 3<> tool >&3` ⏎ `sh tool`, #2883); a function call's redirect (`f() {
  sh; }; f < tool`, #2888); a check credited with a file it holds by `N<` (#2886); and one
  credited with the sums on its standard input when it reads something else (`sha256sum -c self
  < sums`, #2908).
- **Workflow reader: a line ending in `|` continues, a command word's `${X:-bash -s}` is read
  whole, and `<>` opens its descriptor (#2756, #2731, #2657; #2733, #2608).** A line ending in
  `|` continues on the next (`curl … |` ⏎ `sh` ran the pipeline and read CLEAN, behind `eval`
  and in a printed or heredoc text too). A command word that is an unquoted `${X:-bash -s}` is
  read as bash reads it, expanded whole and then split at a blank no quote or backslash covers,
  so a shell default's words run as that shell (`${X:-bash -s} <<'EOF'` and `curl … | ${SH:-bash
  -s}` ran the download and read CLEAN). The whole word is read as bash expands it with its name
  unset: the default, a literal glued after the `}` joining its last word (`${X:-/usr/bin/env
  s}h` is `/usr/bin/env sh`; none bash would glob) -- a glued `$(…)` too, which keeps the word
  dynamic (`${X:-sh -c}$(echo) '…'`) -- split at a space, a tab or a newline, each word keeping
  what the reader marked in it, found in one pass over the word -- a lifted `$(…)` stays dynamic
  behind a wrapper, and a `<(…)` a file. A word bash may expand to nothing -- `${X:+W}` and
  `${X+W}`; `${X-W}` and `${X=W}`, empty where the name is set empty; and `${X#W}`, `${X##W}`,
  `${X%W}`, `${X%%W}`, `${X/p/W}`, `${X//p/W}` and a case change (`${X^^W}`, `${X,W}`), whose W
  is a pattern -- of a name, an indirection (`${!X…}`), an element (`${X[0]…}`), a positional
  parameter, `$@` or `$*`, `$!` with no background job, or `$-`, empty under dash with no
  options, is read both ways, as W and as the word after it -- the literal glued after its `}`,
  or nothing -- and the guard reports where either half runs, ranking neither (the round-13
  ruling: the union): it reads a job with W, as `main` reads it, and where a command word had
  both halves, reads it again with that word expanded to nothing (`shell_command.folds`), so
  `curl … | ${X:+/usr/bin/env true} sh` and `${X:+/usr/bin/env true} sh -c '…'` report the `sh`
  the empty half runs, `X=1` ⏎ `${X:+/usr/bin/env sh -c} '…'` the W that runs where `X` is set,
  and a check is credited only in the reading that runs it (`${X:+/usr/bin/env sha256sum -c
  sums} true` ⏎ `sh tool` reports, where `X` is unset). Two halves the guard may each report
  that run apart -- two among a shell's kind, a fetcher and a word it does not follow, but that
  word in front of a shell's kind -- are a command it cannot read (`${X:+curl -fsSL …} sh x |
  sh` runs the download where `X` is set). `$0` and `$-` are never unset, so `${0+W}` is always
  its W and `${--W}` never is; and a pattern's or a case change's other half is the name's own
  value, which no half names (#2899). No step's text decides a half: round 12 read W where the
  step set the name anywhere in its text, which took a set after the use, in a subshell, a dead
  branch, a string, a comment or a heredoc, and missed `set x`, `eval 'X=1'` and the shell's
  own variables. A default whose first word names a command the reader knows -- a shell, a
  wrapper, a foreign interpreter, a fetcher, by path too -- is that command, as `main` read the
  word by its basename (`${X:-/usr/bin/env sh -c} '…'`, `${X:-/usr/bin/curl -fsSL} URL | sh`,
  `${X:-/usr/bin/env $(echo sh) -c} '…'`); where no default reads -- a `$NAME` or a nested
  default in it, or a parameter that is no NAME -- `main`'s split words stay when their first
  names such a command by its basename (`${X:-$HOME/bin/env sh -c} '…'`, `${1:-/bin/sh -c}
  '…'`), the default's `}` off their last word at its first `}` and a word of it alone dropped,
  so a default ending in its program names it (`curl … | ${X:-$HOME/bin/env sh}`,
  `${1:-/usr/bin/env s}h <<'EOF'`, `D=/bin` ⏎ `${X:-$D/sh tool}`) -- but a word `main` reads as
  a pattern (`/usr/bin/ba}[s]h`), and `${#:-…}`, `${?:-…}`, `${$:-…}` and `${1:=…}`, which bash
  never expands or refuses, keep `main`'s words (not `$-`, empty under dash with no options, nor
  `$0`, empty in a `-c` text run with an empty `$0`; an indirection, `${!Y:-W}`, is read as a
  name is) -- and the whole word otherwise, as round 9 read it (`RUN='sh tool'` ⏎ `${RUN:-cat
  x}`, which the step's own values resolve, and `${X:-/bin/[s]h -s}`). Rounds 6 to 9 read CLEAN
  721 cells in 145 of the round-9 seat's rows that `main` and the base report, which round 10
  closed; round 10 another 657 in 133 of the round-10 seat's, which round 11 closed (180 of
  them, in 36 rows, a lifted `$(…)` round 10 read as a plain word); and round 11 another 843 in
  175 of the round-11 seat's that rounds 9 and 10 report (`main`'s split words kept the
  default's `}`) and 696 in 152 that round 10 reports (`${X:+W}`, `${X#W}`; 801 in 173 against
  round 9), which round 12 closed; and round 12 read CLEAN, of the round-12 seat's hunts 45-48,
  a default of `$-`, `$0` or an indirection (46 cells in 16 rows that round 10 reports), the
  spellings it did not read as expanding to nothing (110 in 38), the alternate where a set
  elsewhere in the step's text left the name unset (832 in 168), the next word where it missed a
  set (10 in 2 that `main` reports) and a checker naming its list (65 in 22 that `main`
  reports), all of which this round closes, a parent running the payload -- 1,456 cells in 335
  rows against round 12, none of round 12's going CLEAN. On the round-12 seat's 17,810 rows (the
  15,937 and hunts 33-48, its 12 rows whose reading changes from parse to parse aside), none
  goes CLEAN where `main`, either base or rounds 9 to 11 report and a parent runs the payload
  but #2899's (158 in 32 against round 9, and four of hunt 47, below) and #2906's two of hunt
  45; and on the #2885 round-3 kit's 989 own rows this round reads as round 12. Any other word
  is read as it always was, its default holding no blank, so `cat tool | "${SH:-bash}"` and
  `SH=1` ⏎ `"${SH:+sh}" tool` run the shell they name, as on `main`, and `${X:-"sh -c"}`,
  `${X:-sh\ -c}` and `"${SH:- bash}"` name none -- unless a bare blank stands beside the quoted
  one, as the whole word is read dequoted (below). `N<> file` opens the file on descriptor N for
  reading and writing: on 0 it redirects standard input as `<` does, so `bash -s <<'EOF'
  <>/dev/null` no longer credits a check no shell reads, and a check is credited with the file
  `0<>` opens only where fd 0 still holds it when the checker runs and the checker reads its
  standard input -- no list but `-`, `/dev/stdin` or `/dev/fd/0`, a word of digits an option's
  only right after `-a` or `--algorithm`, and every word past `--` an operand (`sha256sum -c 0<>
  sums 1`, `-c -- -x 0<> sums`) -- and reads `0<>` as `main` does, a write, otherwise
  (`sha256sum -c 0<> sums < self`, `-c <> sums 0< self`, `-c 4< self 0<> sums <&4`, `-c self 0<>
  sums`: 56 cells in 20 of the #2885 round-3 seat's CZ rows read CLEAN where `main` reports and
  the unverified download runs; `sha256sum -c <> sums` ⏎ `sh tool`, CK010-CK012 and CK22h, stays
  credited); on any other descriptor a later `>&N` or `1>&N` writes to it, so `curl … 3<> tool
  >&3` ⏎ `sh tool` reports (`main` read `3<` and a `> tool` the dup overrides: 32 rows, every
  shell running the payload), and with no dup nothing lands in it, which `main` and the base
  reported (`curl … 2<> tool` ⏎ `sh tool`, `9<>`, `10<>`, and `>/dev/fd/3 3<> tool`: 65 cells of
  the round-8 seat's rows). `&&` at a line's end and `${X:-bash} -s` read as they did. The whole
  word is the command word's alone (round 8, the coordinator's ruling): the reader keeps a
  `${…}` whole only where it starts a command -- a stage's first word past its keywords and
  assignments, no `case` subject, holding no newline or operator -- and every other word holding
  one is the words `main` split it into, so a download destination and its use, `xargs`'s input,
  a carrier, a value and a redirect's target all meet as on `main`, and every statement and
  stage is `main`'s. A program text that spells a mark the reader puts in its text
  (U+E000-U+E004) is read as `main` reads it, its command word too, and each text is its own:
  the step's, and each it hands a shell (`bash -c`, `eval`, a heredoc), so an inner text that
  spells none is still read whole. `$$` is bash's PID, read in the splitter as the pair before
  anything the second `$` could open, so `$${ | sh` and `${a:-$${b} x; sh tool; echo }` keep
  their pipe and their use; and only a space or a tab no quote covers is a blank, not `\v`, `\f`
  or a Unicode space -- to the reader's scan, and in a default's words, which bash splits at a
  newline too. On the round-8 seat's 13,052 rows, against the base (#2855's head `7fa1e0a8`,
  this PR's base since round 10's fold): 2,467 cells close where a shell runs the payload (511
  rows), none goes CLEAN where the base or `main` reports and a shell runs it, and 231 clear
  where the base reported and nothing runs (55 rows: the two-line check gate, `<>`, `$$`) --
  against `ca232d12`, the base before that fold, 2,481 close (515 rows) and the same 231 clear;
  and on 1,119 rows of my own of `N<>` and its dups, 302 close, none opens, and 240 clear. On
  the round-9 seat's 14,904 rows, none goes CLEAN where `main`, the base or round 9 reports and
  a shell runs it; against round 9, on its seat's hunts 18-23, 909 cells close (183 rows: the
  721 above, and 188 that `main` reads CLEAN too, `cat tool | ${X:-/usr/bin/env sh}`) and 45
  clear (9 rows: `${V:-python3 -m json.tool} <<'EOF'`, and `${X:+bash -s}`, `${X+bash -s}`,
  `${X#bash -s}` and `${X/x/bash -s}` with `X` unset). On the round-10 seat's 15,937 rows, none
  goes CLEAN where `main`, the base or round 10 reports and a shell runs it, nor where round 9
  does but #2899's (158 cells, 32 rows); against round 10, 1,117 cells close (225 rows: the 657
  above, 425 that `main` reads CLEAN too, and 35 in 7 of #2905's that the default's `}` and a
  glued `$(…)` close) and 100 clear (20 rows: a default holding a Unicode or vertical space,
  which bash does not split at, 30 in 6; `${X:+…}`, `${X+…}`, `${X#…}` and `${X/x/…}` with `X`
  unset, 70 in 14). Still CLEAN, as on `main`, where rounds 6 and 7 read them whole -- the
  ruling's re-opens, 1,400 cells of the round-6 head's (305 rows) and 1,759 of the round-7
  head's (396), each row in the first of these it meets: a step that spells a reader mark (`echo
  <U+E004>` ⏎ `curl … | ${SH:-bash -s}`; 710 cells and 151 rows of round 6's, 564 and 120 of
  round 7's), a `${…}` spanning a line (`-o ${D:-tool` ⏎ `}`, `${X:-bash` ⏎ `-s}`; 500 and 108,
  676 and 154), a dup of a `<>` descriptor onto fd 0 (`sh 3<> tool <&3`; 15 and 3 of round 6's),
  a function body on its header's line (`f() { ${RUN:-sh tool}; }`; 16 and 4 each) or a command
  word after a leading redirect (`2>/dev/null ${X:-bash -s} <<'EOF'`; 45 and 9 each; #2907), a
  `for` list or a `case` subject (h21, h22; 10 and 2 each), an assignment `NAME=` whose value
  reaches, before a blank or `;`, a `${` holding a blank or newline ahead of its first `}`
  (`CMD=${CMD:-sh tool}; $CMD`, `F=${D:-"tool" x}` ⏎ `sh $F`; 20 and 4, 349 and 78), a `${…}`
  holding a blank inside double quotes on one line, or a default opening with `"` (`> ${D:-tool
  }` ⏎ `sh "${D:-tool }"`; 21 and 9, 27 and 11), and every other row: an operand or destination
  whose default holds a blank (`sh ${F:-tool }`; 63 and 15, 72 and 18). Open on `main` too, and
  left to their own fix: a nested default (`${X:-${Y:-bash} -s}`), a braced partial word
  (`${X:-bash -s}{,}`), `coproc` (#2894), a pipe into a compound command (#2896), a dup of a
  `<>` descriptor onto fd 0 in the same command (`sh 3<> tool <&3`) or read by a path (`sh
  /dev/fd/3 3<> tool`) and a group's redirect (`{ curl …; } 3<> tool >&3`), filed as #2881; the
  write side of `<>` (`curl … 0<> tool >&0` ⏎ `sh tool`, `>&3-`, `exec {fd}<>`; #2898); an
  expansion that decides a default's command or an option (`${X:-env $E sh -c}`,
  `${X:-${Y:-/usr/bin/env} sh -c}`, `${X:-sh $F -c}`; 80 cells, 16 rows of the round-10 seat's
  -- #2905's 115 and 23, but 25 in 5 the default's `}` closed and 10 in 2 a glued `$(…)` -- and
  45, 9 of the round-11 seat's -- nn-k and nn-w of hunt 33 (`${X:-$E env curl}`), K16 of hunt 35
  (`${X:-sh -}${Y:-c}`), and F1, F2, no-fw, no-p2, no-pg and no-pn of hunt 37 (`${X:-$(echo env)
  sh -c}`) -- or 85, 17 with hunt 34's W14 and W15, a nested default (`${X:-${Y:-/usr/bin/env
  sh}}`); #2905), `${1:-env sh} tool` and `${1:-sh -c '…'}`, a positional parameter's default
  whose first word names its command by no path, read whole as a command the guard does not
  follow (20 / 4 at this head; the seat's 20 / 4 at round 11: n1-f, n1-k and n1-w of hunt 33,
  and Q10 of hunt 41), an `IFS` the step sets (10, 2), a default of blanks alone (10, 2), a
  one-word alternate (`${X:+true} sh -c '…'`, a `$` word `main` reads in front of a command it
  does not know; 5, 1), a pattern in a default's command word (`${X:-/bin/s[h] -c}`; 85, 17, and
  r1 and r3 of the round-12 seat's hunt 45, `curl … | ${X:-$HOME/bin/env /bin/s[h]}`, 10 and 2
  that rounds 9 and 10 report; #2906), and, `main`'s documented gap and #2601's price, a foreign
  interpreter's program text, its default or written out (`${X:-python3 -c} 'import os;
  os.system("curl … | sh")'`, `perl -e`, `node -e`; 184, 37), as a fetch inside `python3 -c`
  needs another language entirely; and a whole default read where the step sets its name, whose
  value bash runs instead (`RUN='sh tool'` ⏎ `${RUN:-bash -s}`, as `main` reads `${RUN:-bash}`
  since #2337; #2899) -- its wrappers' half rounds 6 to 9 reported, the step's values reading
  their whole word, and round 10 reads it as `main` does: 45 cells in 9 rows of my own (`RUN='sh
  tool'` ⏎ `${RUN:-/usr/bin/env true}`, `env -S true`, `timeout 9 true`, `python3 -V`, and
  `RUN='sh -s'` ⏎ `curl … | ${RUN:-/usr/bin/env cat}`) and 158 in 32 of the round-10 seat's --
  and a pattern taken off or replaced, `#`, `%` and `/`, whose other half is the name's own
  value (`X=sh` ⏎ `curl … | ${X#a b}`, `${X%%a b}`, `${X/a b/c}` and `${X#a b} -c '…'`:
  seth1-seth4 of the round-12 seat's hunt 47, 18 cells in 4 rows that rounds 9 to 11 report and
  `main` reads CLEAN; #2899). New fail-closed over-reports against the base, none run by a shell
  (206 cells in 57 of the round-8 seat's rows -- 232 in 63 against `ca232d12` -- and 28 in 14 of
  the `N<>` rows): the continuation's -- a CRLF after `|`, `|&` ⏎ `sh` under dash, `|` ⏎ `$$ sh`
  (26 cells, 7 rows); a `<>` that bash or dash does not read as standard input -- `bash -s
  <>tool <<'EOF'` and `bash -s 0<> tool <<'EOF'` (the heredoc is the input), `source /dev/stdin
  <> tool` and `bash -s <<'EOF' <>${N:-/dev/null }` under `sh`, `sh {v}<> tool` (bash opens a
  new descriptor), `sh <> tool 0<&-` and `sh 0<> tool 0<&-`, and `sh 00<> tool` under dash (30,
  8) -- and a descriptor past 9 under dash, which opens none (`curl … 10<> tool >&10` ⏎ `sh
  tool`; 28, 14); and the whole word's (150, 42), all but two rows `main`'s own reading of the
  default written out: a default dash reads otherwise (`${X:-$'bash' -s}`, `$'-s'` and `$'-c'`,
  which dash keeps with their `$`, and `${RUN:-source ./tool}`; 20, 10), an `IFS` the step sets
  (5, 1), a name the step assigns (`RUN=cat` ⏎ `${RUN:-sh tool}`; 15, 3), `$$` in the default
  (`${X:-bash $$ -s}`; 40, 8), `sh -c "… \$0"` or a backquote in the default (20, 4), `curl … |
  ! ${SH:-bash -s}`, which no shell parses (5, 1), and an inner program behind a line that stops
  `-e` shells first (`X=1` ⏎ `bash -c '… | ${SH:-bash -s}'`; 45, 15) -- the two new beside
  `main`'s reading are `${X:-$$ bash -s} <<'EOF'` and `${X:-sh -c "echo \`id\`"} <<'EOF'`. On
  the round-9 seat's hunts 18-23, against the base, 643 cells in 161 rows, none run by a shell:
  a download fed to a whole default that names no shell (`curl … | ${V:-jq -r .}`, `${V:-less
  -R} <<< "$(curl …)"`; 245, 49), the guard's catch-all for a command word it does not follow --
  or, for `python3`, its reading of the interpreter -- where `main` reads all but `python3 -m
  json.tool` and `tar -tz` CLEAN written out; a quoted or escaped blank beside a bare one, the
  whole word read dequoted (`${X:-"" bash -s}`, `${X:-\ bash -s}`, `${X:-"bash -s" }`; 170, 40
  -- bash 3.2 runs `${X:-"" bash -s}` and `${X:-'' bash -s}`); `$'…'` and `$"…"` under dash, and
  inside a single-quoted `eval` or `bash -c` text (38, 16); `| !` at more positions (55, 11);
  `${X:?bash -s}`, which stops the shell with `X` unset (10, 2); `${X:-/bin/sh* -s}` (10, 2); a
  here-string into a wrapper's default under dash (`${X:-/usr/bin/env bash} <<< "$(curl …)"`;
  32, 16); `/usr/bin/xargs` (15, 3) and `/usr/bin/sudo`, which the harness's sudo refuses and a
  hosted runner's runs (30, 6); `>&03` and `10<>` under dash (24, 12); `sh 0<> tool 0<&-`, `sh
  00<> tool` and `sh 0<> tool 3<> /dev/null 0<&3`, a dup onto fd 0 after its read (12, 3); and
  `bash <(${X:-/usr/bin/wget -qO-} …)` under dash (2, 1). Round 10's own, against round 9, are
  21 cells in 6 of the round-9 seat's rows: `/usr/bin/sudo` (15, 3) and `bash <(…)` under dash
  (6, 3). On the round-10 seat's hunts 24-32, against the base, 126 cells in 35 rows, none run
  by a shell: a quoted or escaped blank beside a bare one (`${X:-"/usr/bin/env sh" -c}`; 56,
  13), `xargs` with no input (25, 5), `bash <(…)` under dash (22, 11), a tilde in a later word
  (`${X:-./env ~/bin/nice sh -c}`; 10, 2), a name the step sets (10, 2), `exec -a` under dash
  (2, 1) and `function f { … }` under dash with `-e` (1, 1); and against round 10, 8 cells in 4
  rows, `main`'s own reading of an array element under dash (`${X[0]:-/usr/bin/env sh -c}`),
  which dash rejects. On the round-11 seat's hunts 33-44 (its 11 rows whose reading changes from
  parse to parse aside, and S08n, which joins them: a lifted `$(…)` read as an option's letters,
  `main`'s own, #2911), against the base, 360 cells in 120 rows, none run by a shell: a default
  holding a Unicode or control character, which bash does not split at (`${X:-bash<U+00A0>-s
  x}`; 110, 22), a pattern substitution under dash, which rejects it (`${X/a/env true} sh -c
  '…'`; 96, 48), a process substitution (`${X:-env bash}<(curl …)`, glued on, which runs a
  `bash/dev/fd/63` no system has, and `${X:-env bash -s <(curl …)}` under dash, which has no
  `<(…)`; 40, 11), `${X:?env true} sh`, which stops the shell (40, 8), an array element under
  dash (`${X[0]:-/usr/bin/env sh} tool`; 28, 14), a here-string under dash (`${1:-/usr/bin/env
  bash} <<< "$(curl …)"`; 20, 10), a quoted empty word beside a blank (4, 2), a heredoc inside
  `$(…)` under dash (2, 1), and `${X:-env s}$Y`, an `IFS` the step sets, `/usr/bin/tee -a log`
  and `env -i sh` (5, 1 each); against round 10, 76 cells in 29 of those rows -- the pattern
  substitution (32, 16), a brace or glob glued after the `}` (`${X:-/usr/bin/env sh -s}{,}`,
  `}?`; 12, 3), the array element (10, 5), the process substitution (10, 2), a carriage return
  in the default (10, 2) and the here-string (2, 1) -- and against round 11, 143 cells in 70:
  the pattern substitution (96, 48), the array element (28, 14), the here-string (14, 7) and
  `${X:-env bash}<(…)` (5, 1); and on the CZ rows, against round 11, 22 cells in 10, as `main`
  reads them: a later redirection, dup or close of fd 0 that fails the check round 11 credited
  (`-c 0<> sums 0<&-`, `-c 0<> sums < /dev/null`, `-c 0<> sums 0<&4 4< self`; 18, 6), and a
  here-string or `00<>` that dash refuses or reads otherwise (4, 4). On the round-12 seat's
  rows, against round 12 -- the union's price, beside #2912's below; the #2885 round-3 kit's
  20,533 regression rows hold ten of these rows and no other -- 474 cells in 134 rows, none run
  by a shell, each a half no parent runs: the next word where the step sets the name and the
  alternate runs nothing (`X=1` ⏎ `${X:+/usr/bin/env true} sh -c '…'`, the ruling's
  `SET_RUNS_NOTHING`; `set -- 1`, `X=$(true)`, `read X < /dev/null`; 172, 38); W where nothing
  sets the name -- a positional parameter (`${1:+/usr/bin/env sh} -c '…'`, `${@+…}`, `${10:+…}`;
  77, 17), a name (`${X:+bash -s} <<'EOF'`, `main`'s reading; 55, 11) and one only bash sets
  (`${BASH:+…}` under dash; 12, 6); `$-` holding bash's options (`${-:-/usr/bin/env sh}`,
  `${-:+…}`, `${-#…}`; 52, 13); `$0` where it is not empty (`${0:+…}`, `${0=…}`; 10, 2); an
  indirection, an element or a case change under dash, which rejects it (86, 43); and a checker
  naming its list where the list fails the check under `-e` (`sha256sum -c 0<> sums 1`; 10, 4,
  which `main` reports). `SH=1` ⏎ `bash -c '"${SH:+sh}" tool'` reports again, as on `main` and
  the base (their over-report: the `-c` shell sees no `SH`), which round 8's kept test had
  cleared. The cost, measured on the forge against the base `ca232d12`: 1.04-1.07x for a
  pipeline or `||` list of unterminated `${` to 8,000 stages, where round 8 grew to 143x -- the
  scan runs only at a command word now, and ends with its stage; 0.98-1.02x for an unterminated
  `${` per line, statement, `&&`, `&`, subshell, quote or nested default and for the single
  unterminated line, where round 8 paid 1.5-7.6x; 0.04-0.12x for unterminated `echo ${x |`
  lines, one statement by the continuation; 0.98-1.07x for the closed and quoted cases and on
  rounds 3-7's shapes. At a command word the whole default is one shlex token, built a character
  at a time, which `main` pays for the double-quoted spelling of the same default (`"${X:-…}"`:
  0.21 s at 8,000 words and 8.05 s at 64,000 on `main`, the head and the base alike; #2912):
  against the base's reading, `main`'s split words, the unquoted spelling costs 1.45x at 1,000
  plain words, 1.83x at 8,000 and 6.87x at 64,000, 1.11x to 6.50x for case C's words
  (`${X:-$HOME/bin/env a0 …}`) and 1.23x at 1,000 to 1.84x at 128,000 for a glued suffix, as the
  round-11 seat measured it -- `main`'s quoted-word cost on the unquoted spelling. A default's
  words take their marks in one pass, where round 11 tested every mark of the whole word against
  each (4.6x the base at 1,000 `$(…)` words, 15.7x at 4,000; the round-11 verdict's B3), so such
  a default costs that shlex token alone -- at 16,000, 6.9x the base for `$(…)` words, 7.5x for
  backquotes, 7.2x for `<(…)`, 5.5x for the three mixed and 2.3x for a glued suffix, each within
  1.04-1.15x of `main`'s own double-quoted spelling (#2912). Both halves read no step text,
  where round 12 scanned it for the names a step sets (7.24x the base at 16,000 unclosed `x[`
  before a `${X:+…}` command word; 0.99-1.11x now), and a checker's reads on fd 0 are dropped by
  a set (round 12: 2.48x at 64,000 `0<>` on one checker; 0.59-0.69x now). The union reads a job
  again where a command word has both halves: at most twice the folds of one reading -- two, or
  four with an `Unsure` statement -- a factor that does not grow with the step (on the forge,
  interleaved, median of 3: 1.94-2.02x one reading for n words, n `$(…)` or a W of 64,000
  characters in the word; n uses of `${X:+/usr/bin/env true} sh -c 'echo'` after `X=1` cost
  3.2-3.3x the base, which reads `true` there; and on the round-12 seat's hunts 33-48, 1.30x
  round 12 and 1.76x `main` in all, and on hunts 42, 43 and 46, the ones dense in such words,
  1.58-1.74x the ranked draft's one reading (2.29-2.51x W's fold alone); the round-13 seat's n
  lines of one such word each cost 2.83-2.98x one reading from 250 to 2,000 lines, flat against
  `main`).
- **Codex model profiles move to GPT-6 (#2872).** Pinned role defaults now use `gpt-6-luna` or
  `gpt-6-sol`; set `PANOPTICON_MODEL_<ROLE>` to pin another installed model.
- **Codex headless probes reach panels without invocation-local workarounds (#2923).** The
  registered, model-neutral `setup_scan` surface probe now keeps its intentional inherited model;
  the localhost-only effective-surface probe and bundled-catalog read have a 180-second bound after
  one observed valid inspection took 64.8 seconds; and `codex exec --output-schema` is omitted for
  a published schema whose root, recursive objects, references, or composition are not strict-output
  compatible. After controller stamping, `phases.persist.write_reply` validates every returned role
  that has a published schema against its unmodified Draft-7 `role_schema(entry)` before writing.
  Consequently, a lowercase or otherwise bare tool-advisor verdict that the older acceptance check
  normalized now fails the published contract and spends a D10 retry. The 180-second bounds limit a
  slow probe, and the compatibility screen keeps an incompatible production schema off the provider
  argv, so neither can fan a rejection out across a matrix batch. The Codex disclosure separately
  reports that its successful toy proof constrains no production reply in this build.
- **X0X identifiers reject control and bidirectional code points (#2712).** The report schema now
  refuses C0 controls other than tab and line feed, DEL/C1 controls, Arabic Letter Mark, bidi
  marks, embeddings, overrides, and isolates in occurrence paths, candidate areas, and proposed
  names. The shared inert renderer now escapes those bidi controls in target-authored paths before
  report emission, with one code-point policy shared by report and prompt rendering (#2118 items
  1-2), so a hostile filename cannot suppress the X0X artifact. Honest emitter output remains
  valid, and `synthesize.py` keeps its ASCII-escaped, multi-line JSON serialization.
- **X0X candidate names and array order are reproducible (#2713).** Proposed names are now
  schema-pinned to kebab case and 60 characters, and the emitter applies that same bound. Candidate
  arrays sort by severity, domain, proposed name, and cluster key; equal-severity cluster leads use
  a stable finding fingerprint, while occurrences and CWE identifiers receive canonical orders.
  Reordering the input findings therefore leaves the emitted candidate array unchanged, and
  `generated_at` remains optional. `cwe` remains optional and is omitted when empty; the open-object
  extension contract remains explicit, with `evidence_status` undeclared until its vocabulary and
  type are standardized. A catalog-gap finding without `location.file` remains in the full findings
  report but is excluded from the occurrence-bearing X0X candidate set and written to a
  deterministic, redacted `-x0x-failures.json` sidecar with its own write-time schema. The log keeps
  duplicate ids, and an unlocated member of a mixed cluster cannot lead its located siblings,
  resolving #2090.
  Synthesize and the driver disclose the exact count and path even after child stderr flooding or a
  resume, clean runs safely remove regular or symlinked stale sidecars, and the remaining X0X is
  byte-identical to a run without the unrepresentable finding. The discard does not introduce a new
  exit status; the report gate still selects `0`, `1`, or `2`.
- **Workflow guard reads a function header in the spellings bash takes at a statement's head
  (#2664, #2608; #2785).** `f(){ curl … | sh; }` ⏎ `f`, `f ( ) { … }`, and a header after
  `then`, `do` or an opened `{` ran the pipe under bash 5.2.21, 3.2.57 and dash and read CLEAN:
  the reader knew a header only as `f()` at a statement's start, so `f(){` was one command word,
  `f ( )` a subshell, and `then f() {` the command `f` -- the body's first command on the
  header's line became that header's argument, and the call ran a function the guard had no body
  for. The splitter now reads `()` and `( )` after a name wherever bash does, ends a group's `{`
  before a header on its line as its own statement, and keeps `function NAME ()` to the name.
  Three readings move with it, each to bash's: a block nested in a one-line function's body
  inside a forked group no longer closes that body, a group's `{` before a header is the
  group's, and `function f ( )` defines `f`. 60 cells go CLEAN -> REPORT with no shell running
  the payload -- a function defined in one of the new spellings and never called, defined in a
  branch that does not run, backgrounded, after `unset -f` or redefined to `:` -- each as `main`
  already reports the `f() {` spelling, fail-closed. Still CLEAN while the shells run them
  (limits, named in the PR): a body that is a `case`, a function defined inside a function body
  or a `case` arm or a `( … )` subshell, `time f() {`, `function g { f() {`, and the names
  `a.b`, `a:b` and `1f`. Two fix rounds closed what the seats found. A negated group holding a
  header (`! { f() { CHECK; }; f; }` ⏎ USE) had its `!` stranded on the `{`, so the check read
  as gated: the `!` is now carried onto every statement the group holds, as bash runs a negated
  compound with errexit off, placed past the keywords that open the statement so `then`, `do`,
  `case` and an arm are still read first -- which also closes the own-line `! {` ⏎ `CHECK` ⏎ `}`
  form `main` missed; `! !` is read as one negation (bash XORs: fail-closed), and a
  short-circuit inside a negated group, a call in a branch that does not run or in a child, a
  call after `unset -f` and a prefix assignment are read under the `!` too (214 hunt cells and
  36 harness cells on the round-2 rows, 110 more on the round-3 families: 324 fail-closed cells
  in all). A called function's assignment (`T=/dev/null; f(){ :; T=tool; }; f; sh "$T"`) never
  reached the use, `main` reporting it only because the misread header made it the step's own
  statement; carrying the body's value out surely read past what the shells do (a `return` the
  body takes, a wrapper that runs no function, a later redefinition, a stand-in, a `declare -g`
  bash 3.2 and dash lack), so a call now adds what the body may assign as UNSURE candidates and
  keeps the caller's own (`scripts/workflow_called.py`; every definition before the call, and
  the functions the body calls, eight deep; `local` dies with the call, a subshell body reaches
  nothing (one whose first command opens with a `{` word too: `f() ( { T=x; } )`, `f() ( echo {
  ; T=x )`), and a call the step backgrounds (`f &`) carries nothing back -- a one-line `( f )`
  still does, fail-closed; `time` -- one `-p`, then one `--`, before a group, a `!`, an
  assignment or an `if` -- and `eval` (one `--`) run the function, as bash 5.2.21 reads them
  (bash 3.2.57 runs neither `time --` spelling, dash no `time` call at all: read as calls,
  fail-closed); the arm of a one-line `case` is stepped past first; a function named like a
  wrapper, `sudo() { … }; sudo x`, is the call bash makes of it, where `env f` with no `env`
  function runs none; a body's call in a list it backgrounds, `g() { f & wait; }` or `g() { f &&
  : & wait; }`, carries nothing, as at the top level; and a call site carries its bodies eight
  times a step -- `static_values` rebuilds the table at each statement that reads it, so a site
  is visited at each rebuild after it, and a memo of the carries, keyed on the state of the
  names they read or set, grew past `main` where the step assigns the words a body spells (round
  10) -- walking only the statements that may write, and every one where bash may write a name
  the step does not read (`${X:=v}`, arithmetic, `let`), copying and merging back only the names
  its bodies spell or set, and not at all where no body may write; a carry costs the statements
  it walks and the names it copies, and one costing more than 128 counts as more than one, so a
  site's carries cost 1,024 at most (round 11's walked a body's K statements eight times a site
  where the body set K names: 3.9x `main` at K = 50, 5.7x at 3,200); where a body may set any
  name (`eval`, `source`, a name taken from a value), a carry gives every other held name its
  own stand-in, as `record` does, once a walk and then to the names changed since; past a site's
  carries, each name its bodies may set holds the cap's stand-in on both sides, its word-lists
  too, so `${A[1]}` reads it, and where a body may set any name every name the table holds does,
  as the round-9 head had it -- each once a walk and then, at a later visit, those changed
  since, as the walk writes them: a statement that may set any name sets its plain names too
  (`export "$K=v" X=P` sets `X`), and a `read`, `unset` or `local` behind a wrapper (`command`,
  `nohup`, `nice`, `env`, `timeout`, `stdbuf`, `setsid`, `flock`, `xargs`) the names it names,
  as the walk's `_cleared` reads it through `shell_command.command` and takes the stand-in away
  (round 11 missed that write, and the use read the step's own value while every shell ran the
  payload: 195 cells in 53 rows of the round-11 seat's hunt, and 78 in 16 more, #2910's, that
  every tree read CLEAN: a body that may set any name with a wrapped `read` between two calls),
  so no name a carry sets escapes it; and a stand-in makes no list where the name held none,
  sharing one read-only list, so the names a walk stands in leave the collector nothing to walk;
  so a step reads within a constant factor of `main`'s time -- 1.01-1.34x on the forge, `main`
  and the head interleaved in one process a size (the round-11 seat's `seat-cost18.py`, medians
  of three, the collector on), over the round-11 seat's 20 shapes to K = 1,600 (200 where `main`
  turns cubic, 800 for `wideassigned`) but for `calls`, and on the six that grew in round 11 to
  3,200: `calls` falls from 3.88x at K = 50 to 1.12x as its carries outgrow `_WORK`; `evalwide`
  and `evalbetween` fall from 1.17-1.19x to 1.08-1.09x, `srcwide` and `srcbetween` from
  1.17-1.20x to 1.08-1.10x, and `wide` holds at 1.04-1.05x -- each within about 0.01 of flat
  from K = 800, the order of the two trees in a process moving it that much (a process's second
  run is its slower, the head's the more so: averaged over both orders `wide` reads 1.036, 1.043
  and 1.042 at 800, 1,600 and 3,200) -- at a price: past the budget a use of a name the bodies
  may set reads every download, where no shell runs one -- a call followed by more than eight
  statements that read the table (`g() { eval :; }; g`, twelve `: "$T"`, `sh "$T"`: 30 cells in
  6 rows of the round-10 seat's 3,701, MP07-MP09 and MV01, MV02 and MV06), a body that may set
  any name in a loop changing a name twelve times (`. ./env.sh`: 15 in 3, the round-9 seat's
  BU78-80), an array's whole-array use (`sh ${A[@]}`, `sh ${A[*]}`) at nine and twelve states
  (90 cells in 18 rows of the round-10 seat's, BB120-BB128 and BB136-BB144: 54 under bash, and
  36 under `sh`, which has no arrays; at eight, it reports as `main` reads the array written
  out), and under `sh`, where dash has no arrays, an array's element (68 cells in 34 rows of the
  round-9 seat's 2,903); within one read, no site in the round-8 seat's 2,667 rows is visited
  past the budget (eight visits at most, in 2 rows), and none reads otherwise than the round-10
  head reads it; at a price, round 12's, where a wrapped `read`, `unset` or `local` stands its
  names in again though a wrapper that runs no builtin leaves them alone -- under `-e`, where
  the failing wrapper stops the step (`nohup unset T`: 66 cells in 22 rows of the round-11
  seat's hunt), and under `sh` an array, which dash lacks (6 in 3) -- and where a body's carry
  costs more than 128, carried fewer than eight times a site, or never past 1,024, so every name
  it may set holds the stand-in from its first call (none of the 4,095 rows of the two seats
  reaches it: the dearest carry there costs 89); at a price too, now that a fresh carry reads
  the plain names of a statement that may set any name: under `sh`, a carry through a bashism
  dash rejects (`declare`, `typeset`, `printf -v`, `source`, an array: 60 cells in 30 rows of
  the round-10 seat's), and a `readonly` name assigned again, which bash refuses (`readonly
  "$K=v" X=P` twice: 20 in 4) -- and at a price besides: `T=P; f() { T=/dev/null; }; f; sh
  "$T"`, and #2785's `g() { T=x; }; T=P; g; sh "$T"`, are reported though no shell runs `P`, as
  are a never-run decoy in a called body (`if false; then T=P; fi`), an assignment a body makes
  only in a subshell, a pipe stage, a background job or a child shell, read as the step's own
  statement is (`( T=P )`, `( T=P; )`, `( :; T=P )`, `( T=P ) & wait`, `( T=P ) || :`, `if ( T=P
  ); then`, `( ( T=P ) )` and `( T=P ); :`, their two-line spellings with them: 85 cells in 17
  rows of the round-8 seat's 2,667; `{ T=P; } | cat`, `: | T=P`, `T=P & wait`, `{ T=P; } &
  wait`, `eval '( T=P )'`, `bash -c 'T=P'` and `sh -c 'T=P'`: 55 in 11; and a subshell body on
  its header's next line, `f()` ⏎ `( T=P )`, or after `function f()`: 10 in 2), a call after
  `unset -f f`, `bash -c f` or `export -f f; bash -c f` (15 in 3), under `sh` a body whose
  header dash rejects (`function f { …; }`, `function f () { …; }`: 29 cells in 17 rows), a call
  in a `{ …; } &` group the body backgrounds, and under `sh` a call behind `&>`, `>&`, `&>>`,
  `;&` or `;;&` (dash reads `&>` as `&` then `>`); and `eval -p f` or `eval -- -- f` reads as a
  call of `f` (the guard's `eval` reader keeps the words not led by `-` as the program) though
  bash rejects `-p` and dash runs `--` as a command. The sure carry is #2785's own PR. The value
  table's candidate cap moves with it, in the values lane, on the coordinator's rulings (#2871):
  every truncation keeps what it can beside the cap's stand-in -- a name its first eight
  candidates (`workflow_values._update`), a word's or an argv's product its first 64 (`valued`,
  `valued_argvs`), so an installer's honest OS-by-arch product written inline (`unzip
  "tool-$V-$ARCH.zip"`, 3 x 3) reads CLEAN as on `main`, where stored in a name first or walked
  by a `for` (`F="tool-$V-$ARCH.zip"; unzip "$F"`) the name holds nine and pays the name's price
  (30 cells in 6 rows of the round-8 seat's) -- and a use holding the stand-in reads as every
  download the step holds there, so it reports wherever an unverified download can reach it. A
  write of the whole value or a sure `unset` ends it; a write of word 0 (`T=y`, which bash makes
  `T[0]=y`) keeps it at the other keys; an array keeps its word-lists beside it; and the order
  kept carries no safety. `main` held the stand-in alone, which a use reads as nothing, so a
  payload anywhere among nine or more candidates now reports -- the round-4 seat's 7-arm `uname`
  and `$RUNNER_OS` dispatchers with an OVERRIDE line after them, `main`'s own x20 rows, the
  ninth candidate of #2871 (`for T in a b c d e f g h P`; seven conditional reassignments, then
  `[ -z "$NOPE" ] && T=P`): true reports, every shell running the payload; the array rows report
  under `sh` too, where dash has no arrays and runs nothing. The price, measured: a use of a
  name with nine or more candidates reports where no shell runs a download -- 26 cells in 6 rows
  of the round-6 seat's 1,823, 196 in 53 of the round-7 seat's 2,136 (`for T in a b c d e f g h
  i; do :; done; sh "$T"`) -- as does a use of a product past 64 (65 cells in 13 rows of the
  round-8 seat's hunt: PB107-PB118, PB120), and a step that spells the reserved name
  `${__panopticon_past_the_cap}` itself reads it as the stand-in (15 cells in 3 rows). Against
  the round-5 seat's 1,697 rows the head closes 1,804 cells `main` leaves CLEAN and adds 542
  fail-closed ones (177 since the round-4 head, 68 since the round-5 head, 25 since the round-6
  head); against the round-6 seat's 1,823, 2,055 and 596; against the round-7 seat's 2,136,
  2,479 and 757 (35 since the round-7 head, which this one clears of 82: the products within
  64); against the round-8 seat's 2,667, 3,282 and 1,104 (none since the round-8 head, which
  this one clears of 35: subshell bodies whose first command opens with a `{` word); against the
  round-9 seat's 2,903, 3,804 and 1,317 (83 since the round-9 head: the array stand-in's 68
  under `sh` and MP07-MP09's 15, both priced above); against the round-10 seat's 3,701, 5,229
  and 1,967 (125 since the round-10 head, the budget's price and the two above, which closes 360
  the round-10 head left CLEAN while a shell ran the payload: a name only a statement that may
  set any name sets, which its shared carry restored stale, and a body that may set any name
  past the budget); against the round-11 seat's 394 hunt rows, 273 close (its B1's 195 and
  #2910's 78) and 72 are added, round 12's price above; and none goes CLEAN where `main` reports
  and a shell runs the payload (16 cells do where none runs). A text the table would build past
  4,096 characters is still dropped, as on `main` (a limit, kept for a follow-up). Still CLEAN
  while a shell runs the payload, each as on `main`: a `case` whose header shares a one-line
  body's line (`g() { case x in x) f;; esac; }`) is not read as one; nor is a call made through
  a value (`F=f; $F`), one in a `case` behind `time`, one a loop's body makes before its own
  definition (`for …; do f; f() { … }; done`), one to a function the step names `eval` or `time`
  (`eval() { … }; eval f`, and a bare `eval`; a bare `time` is read as the call), or one a
  function makes of its own arguments (`sudo() { "$@"; }; sudo f`); an array past the cap loses
  the stand-in at its other keys where a later `T[0]=y`, `read T`, `printf -v T`, `mapfile T`,
  `unset 'T[0]'` or `( T= )` writes it, each still ending it; a body's `T=$1` holds no argument
  of its call, its `T=$(…)` and `printf -v T` no value, and a body that sets `T=P` before its
  `local T` is read as leaving `T` alone; a body whose only write is `${T:=…}` or `${T=…}`
  (#2781), or a `command`-wrapped `read T`, is read as setting nothing, within the budget and
  past it; and a check whose failure a subshell, a pipe, an `if` condition, `time` or `!` keeps
  from stopping the step (`( { f() { CHECK; }; f; } )`, `{ …; CHECK; } | cat`) still clears the
  download. And the header test at every `(` had joined and split the whole buffer before the
  match, about x4 per doubling of one `(( … ))` statement, now computed only behind a match.
  Still CLEAN as on `main` (#2928): a check in a group piped into another command inside a `bash
  -ec` or `bash -s` child, the function form among them (`bash -ec '{ f() { CHECK; }; f; } |
  cat; USE'` and its `bash -e -s` heredoc twin), which `main` since #2849 reports only by
  failing closed on the `f()` header it misreads.
- **Reviewer write safety separates the boundary from its transport (#1622).**
  `artifact_write_guard` now means reviewer-controlled artifact writes are impossible or confined.
  The static `self_write_delivery` fact is true only for Claude and Kimi, and a write-capable role
  self-writes only when that fact and a proven boundary both hold; all other cases remain
  return-persist. Current Claude/Kimi proof covers the write-tool surface. When tool policy is
  REFUTED and the operator passes `--allow-unenforced`, `unenforced-ack.json` names the remaining
  Bash-path gap. For that PROVEN-boundary case, with no flag or with tool policy UNKNOWN, no
  acknowledgement is written; the gap appears only in the `tool_policy_enforced` posture line. An
  unproven boundary (including generic) still requires `--allow-unenforced`. Codex gains no
  capability claim in this policy-only half; the family proof below adds it.
- **Codex now proves its reviewer write surface absent (#1622).**
  `codex-write-surface-absent` shares the live six-shape Codex measurement and proves
  `artifact_write_guard` only when the exact tool surfaces, Code Mode host globals/imports and MCP
  resource routes expose no reviewer-selectable write path. Codex remains return-persist, a proven
  omission needs no `--allow-unenforced`, and controller/CLI housekeeping at controller-selected
  runtime paths is explicitly outside the capability.
- **Workflow guard: the stdin and `-c` string walks read a shell's options as the shell does, and
  the guard only adds reports (#2616, #2864, #2647, #2654; #2858).** `job_defects` returns `main`'s
  findings -- a pass in which every join of the stdin and string walks answers as `main` does
  (`workflow_options.mains_answer`) -- then those of a second walk that the first pass does not
  make, so every finding `main` makes stands. The second walk skips a long option's FILE (`bash
  --rcfile /dev/null <<'EOF'` and `--init-file` ran the heredoc and read CLEAN: #2616) and reads
  bash's one-dash long words in the leading run (`bash -norc <<'EOF'`, `bash -norc -c '…'`: #2864);
  reads options on after `-s`, so `bash -s -c true <<'EOF' <check>` counts no check bash never
  reads (#2647) and dash's `sh -s -c true` reads the heredoc after the string; counts none after a
  lone `-` with a word behind it (`bash - /dev/null`: #2654), where the shell runs none of the body
  (`-n`, `-o noexec`, `-D`, `--version`, `-version`, `--pretty-print` but under `-i`) or where the
  option run holds a word that may expand (`-o $X`, a `~`, a pattern); seeks the `-c` string in
  every reading of such a word; and weighs a `$Y` after `-c` or `-c --` as a value in the option
  slot. Nothing is cleared: a body under a refused option, an exit or noexec stays reported though
  nothing runs (#2603, #2606), and so do the over-report halves of #2647 and #2654.
- **Workflow guard: what the second walk adds, and what it costs (#2858 rounds 10-11).** On the
  round-5 to round-8 seats' sets (80,514; 29,639; 18,548; 15,713 steps), their 222 direct cases and
  round 10's seat hunt (4,276 rows), the first pass gives `main`'s findings exactly and the job
  holds every one of them. Joining the walks at their inputs (round 10) was not enough: four
  consumers read less given an added reading -- `_on_stdin` and annotate's `_complete`,
  `substitution_script`, a printer-fed body read under both shells, an added `}` regrouping the
  first fold -- and 850 of the seat's rows read CLEAN where `main` reported; a union of findings
  ends that class. Against `main` the walk adds reports on 9,328 steps where a payload or an
  unverified use runs and 24,516 where nothing does, on the four sets (posture-blind step counts,
  every `shell:` setting read; a `noe` step judged on its two `{0}` settings alone gives 9,057 /
  24,515): a body only it reads 2,414 / 6,858, a check only `main` counted 2,529 / 4,605, a string
  only it reads 1,973 / 2,809, a check in a string `main` reads 1,696 / 7,752, a candidate only it
  weighs 691 / 2,447, several 25 / 45 (46 of the 222 cases; 6 of the hunt's rows, a withheld string
  read under both shells' printers). The over-reports
  are fail-closed: a word that may expand may be the FILE, `-n` or `-c` (`bash $X -c "<check>"`,
  `bash -o $X -s`), a FILE may hand its parameters on (`bash w.sh -c '…'`), a body or string whose
  check is withheld reads under both shells' printers (`bash -s -c 'echo hi' <<'EOF' echo 'sh\ttool'
  | sh`), and a long option read on past its FILE meets one that refuses or exits (`bash --rcfile
  /dev/null --version`). The cost: the job reads a step twice, so every ratio to `main` rises by
  about one and stays flat with n -- on round 10's seat shapes at 1,000 to 8,000 words, 2-3x for
  most, 3.4-3.8x for a long option's FILE, 3.5-4.4x for one-dash runs, 4.5-5.6x for `-o $X`, and
  11-16x for the two `-c --` shapes (`Y=; Z=; bash -c -- $Y $Z… 'P'`, `X=; bash -c -- $X… sh
  <<'EOF'`), which `main` reads CLEAN though bash runs the payload, every word a candidate weighed
  as `main` weighs its own; each range spans a Linux aarch64 box (its low end) and a Mac. #2855's
  pins that count a step's carries and time its reading hold each of the job's two passes on its
  own, the passes asserted to be two, where one reading was the whole. The job keys each finding
  with its step's name, so it stays linear wherever the name is one the workflow schema takes, a
  string (8,000 steps sharing one finding: 2.7x `main` on the Linux box, 3.3x on the Mac). Open,
  and this PR's own: a `name:` the schema refuses -- a list or a mapping -- is compared with the
  others under its finding, so where many share one finding the cost grows fourfold with each
  doubling (4,000 such steps: 0.14 s with list names and 0.20 s with mapping names on the Linux
  box, 0.10 s and 0.13 s on the Mac; `main` 0.005 s and 0.002 s); the guard pins in
  `tests/test_workflow_options.py` hold two things about the stdin walk's nesting. The recursive
  call: its argv is its own frame's one `command()` result, its depth and its walk are what the
  parent was entered with (an entry stack, never a frame's live locals) and the walk is the pass's
  own, at every depth to the bound of 64, and `_details`' own text binds neither `depth` nor `walk`
  and makes its one self-call with exactly `inner`, `depth + 1` and `walk`. And the verdict at
  every nesting level, at the job and in each of its two passes: a family of eight holders in
  sixteen nests behind one to five `bash -c`, `sh -c` and `eval` strings, read under every `shell:`
  setting, and one holder behind one to 64 `eval` words, read under every setting at seven depths
  (1, 8, 16, 32, 40, 63 and 64) and under the default setting alone at the other 57. The job's
  marks and the main pass's are `main`'s own on each of those rows; the walk's pass is this PR's
  reading, pinned as it reads. What is pinned is that call and those rows' verdicts: a change
  beside the call that moves none of those rows is not seen, and it can read running rows CLEAN: a
  one-line change keyed on a depth and one more dimension (an inner shell, a holder, a member, a
  run length) passes the suite, and round 20's seat built six. Open, as on `main`:
  a check counted under a refused shell where errexit is off (round 9 withheld it: 14 rows of round
  5's matrix), #2608's `-s $X` and `-c $X` rows, `-c $(…)`, #2900's one-dash long option behind a
  shell the step names through a variable (`CMD=bash; $CMD -norc <<'EOF'`), and the guard's other
  named gaps.
- **Workflow guard carries a compound command's closing output to its inner fetch (#2883).**
  A fetch whose own stdout is not redirected now inherits the first redirect or pipeline on the
  close of its enclosing `{ }`, `if`, `for`, `while`/`until` or `case`, so `> tool`,
  `>> tool` and adjacent `| tee tool` followed by `sh tool` report. An inner stdout boundary on the
  fetch itself or a disconnected closing pipeline stops the file handoff; a nested transparent
  keyword close passes the outer destination inward. An outer logging redirect does not hide an
  inner `( curl ...; ) | sh`, and an inner close before a later fetch does not hide the enclosing
  `| sh`; the inherited stage deliberately omits the close's `stdout_to_pipe` bit, preserving those
  cases. A closing `| tee tool` that still forwards stdout is represented as both a file destination
  and a stream: `bash`/`sh`/`source` consuming it through process substitution still report, while
  `tee tool > /dev/null` remains disconnected.

  On a 43-row / 387-cell matrix using bash 5.2.21, bash 3.2.57 and dash as both parent and child,
  this closes 279 executing cells / 31 rows with no REPORT-to-CLEAN flip measured on that matrix.
  Its known price there is 36 fail-closed cells / four rows: a false branch, zero-iteration loop or
  unmatched `case` arm that never fetches, and a later overwrite of `tool`. The broader seat hunt
  also records a multi-statement subshell's own redirect (11 cells / three rows), a fetch after a
  close mapped to that inner close (five / one), and `done | while ...; done > tool` (five / one).
  Bash-only `&>` parsed under dash adds 240 / 120, which main's simple-command twin also reports;
  a failing check or `sh -c` under `-e` adds seven / two.

  A round-two process-substitution matrix restores 369 running cells / 123 rows across HNE/HNT and
  18 / six on HN, while retaining the 55 / 11 compound-tee file-use closures. Its disconnected
  controls stay clean. Main's analogous simple-command gap is separate (#2921). HN also measures
  48 newly fail-closed no-run cells / 15 rows: substitution bodies consumed by `eval` or `sh -c`
  (30 / six), function/time forms under dash (four), `&>`/`>&` under dash (eight), process-
  substitution redirects under dash (four), and `source f` under dash (two); each matches main's
  simple-command behavior.

  An HNX/HNY extension restores the remaining 30 running cells / ten rows that main reports when
  `$BASH`, `"$BASH"` or `$SHELL` consumes that forwarded tee through `<( ... )` or `< <( ... )`;
  it adds no report where no parent runs against main. Pins cover a stage after the tee, redirects
  on the compound close, tee and consumer, a consumer inside a substitution, two-level compound
  nesting, and path-named executors and `tee`, so narrowing any one of those classes fails.

  Compound output depth deliberately follows keyword compounds, not lexical group markers that the
  reader also uses for array assignments. That preserves the array boundary but leaves 15 running
  cells / three mixed keyword-close/subshell rows unclaimed. Keeping the enclosing level at
  `max(before, after)` likewise avoids lending an outer destination across an inner file redirect;
  the alternate reading would close 30 running cells / six HN rows but add a no-run over-report.

  With main's #2856 reader folded via `50acb79e`, this change closes all 161 running cells / 35
  rows in #2883's numbered-descriptor source set; #2885 moves none of them. The seven `10<> tool
  >&10` rows add 14 no-run cells under dash (`sh` and `sh {0}`), as main's simple-command twins
  already do. Four pass-through-filter rows / 36 cells remain open under #2904 because
  their simple twins are open too: an inner `curl | cat` or `curl | tee`, and a closing
  `| cat > tool` or two-`tee` pipeline. The reverse output map stays 1.00–1.02x main at n = 8,000;
  one substitution holding many statements is 1.29x. Bound compound fetches now reach main's
  existing per-bound-file use scan: S3's growth rises from 8.6x to 12.1x and S5a's from 15x to 50x,
  while compound forms remain within 1.0–1.5x of their simple twins, whose scan scales about n^1.9.
  That existing scan cost is tracked by #2917 and #2436.
- **Workflow guard: what `eval`'s words and a `-c` string hand on (#2673, #2683, #2684, #2764,
  #2669, #2331).** `eval 'curl … |' 'sh'` ran the pipe and read CLEAN: `eval` joins its words before
  it runs them, and the guard read them one by one. Where a word begins or ends with an operator the
  words are now joined, with each word's lifted text kept, so a statement split across them reads as
  written (a join the reader refuses is refused on this path as on the stdin walk's, one answer);
  elsewhere they read one by one as they did. The stdin walk's own join renders a word holding a
  `$(…)` instead of dropping it -- `eval "sh $(echo -s)"` is `sh -s`, `"sh $(cat f)"` a `sh`
  handed a word that may vanish, `"$(echo 'sh')"` the shell `sh` -- so the heredoc each of them
  reads is reported; a FILE program beside a heredoc (`bash <(echo 'sh') <<'EOF'`) hands the body
  to the shell the FILE names; and a `-c` string holding a `<(…)` beside a `$(…)` is a script
  after all, the file rendered as an operand (`bash -c "sh $(echo tool) <(echo x)"` ran `tool`
  and read CLEAN). #2685 is already closed on main and pinned.
- **Workflow guard: the shell option grammar moves to `scripts/workflow_options.py` (#2331).** A
  pure move out of `scripts/workflow_programs.py`, which stood at the 700-line ceiling: the option
  letter and name tables, the refusal readers (`_refused`, `_refused_name`), `_past_options` and the
  three option-slot word readers (`_value`, `_before_operand`, `_may_spell_option`), byte for byte,
  with every name re-exported from `workflow_programs` so no importer changed. Guard answers are
  identical before and after over the 6,803 inputs the guard test families feed `job_defects` and
  `fetch_exec_defects`; no expectation moved. Sizes: 700 -> 559, and 166 for the new module.
- **`scripts/shell_reader.py` splits its command layer into `scripts/shell_command.py` (reader
  lane).** A pure move at the reader's size (699 of 700 lines): the keywords, assignment and
  function-header spellings a statement may open with, the shells and the default or optional `$`
  words that may stand for one, and the `_command_result` walk behind `command`,
  `command_as_written`, `unresolved_wrapper`, `wrapper_words`, `negated` and `conditional` now
  live in the new module, byte for byte; the reader imports every name back under its own, so no
  caller moved, and the new module imports nothing from the reader. No verdict changes: every
  `job_defects` answer the guard's test suite produces is identical before and after.
- **Child scripts keep their own failure reach when the parent shell carries on (#2423,
  #2331).** A check inside `sh -ec 'CHECK; USE'` now clears that child's later use even when the
  step has run `set +e`, starts from a no-errexit `shell:` template, or pipes the child's enclosing
  group without pipefail. The parent's refusal remains bounded to the command that runs the child,
  so a use after it is still reported; a child without its own `-e` remains reported too. Checks
  whose `-e` is suspended by an `&&`/`||` list or condition, or whose status is hidden by a later
  pipeline stage without child pipefail, also remain reported when execution reaches a later use.
- **Child-script `&&` lists keep their failure reach inside the list (#2416, #2653, #2331).** A
  failed checksum ahead of `&&` inside `sh -ec`, `eval`, or a `bash -e -s` body now certifies only
  the suffix that depends on it. A use in that skipped suffix remains gated, including one in a
  nested script; a use after the list is reported. This closes #2653's five stdin/`-c` forms.
  #2416 remains open: set 3's `v2` and `v6` rows, where the list is a called function's body, still
  read CLEAN and need their own follow-up.

  One list-scoped pass records case and group state without a process cache. Explicit braces keep
  their source positions. Because the reader retains only aggregate parenthesis counts, a hidden
  open/close pair in one stage, or a hidden opener beside leading `!` operators, is marked
  ambiguous instead of being assigned an order. A handed check keeps an existing parent `Reach` or
  a specific parent refusal; only when it has neither does the affected frame get a conservative
  refusal that names hidden parenthesis order, explicit compound negation, or a compound condition.
  That mark belongs to the innermost frame opened or enclosing the uncertain stage, so it ends
  before a sibling list; a direct check keeps main's bounded answer while it remains in the marked
  frame. No negation, condition, or function-call credit is inferred from an unplaced compound
  boundary, while a function check once again reads the enclosing negation or condition around
  every proved call in its wrapper chain. Explicit even parity such as `! ! { ...; }` keeps the
  shell's ordinary answer; the final gate contains 2,499 such CLEAN cells, 2,211 of them where main
  reports, and no measured parent runs the payload in any of them.

  The Bash `time` option skip is restored. A `coproc` after a marked or unmarked `case` arm is
  recognized, so B42's a19 family keeps its asynchronous refusal instead of exporting child-local
  reach. This is narrower than the general `coproc` gap: 250 payload-running cells in sets 21 and
  31, including function-called and `bash -ec` forms, remain CLEAN as on main (#2894). The no-digest
  refusal is applied before any context gate, and a bare function header spends its reader-hidden
  pair once when that pair is the evidence for the header. The 18 removed round-five and round-six
  test methods return with 136 original assertions; four more assertions are replaced by stronger
  step pins. Seven reason checks name the current refusal, and only the three CLEAN checks
  superseded by the accepted frame boundary are omitted. The clean-parent refusal is pinned by
  `test_b32_ambiguous_child_keeps_mains_report_when_the_parent_is_clean`;
  `test_b30_function_checks_read_the_call_sites_enclosing_context` restores all 31 round-six #2855
  call-context cells and adds direct-setting coverage for nested wrappers. The D1-D3 boundary
  controls and D8 refusal-off control fail focused tests. Focused pins also kill K2, N07, D14, S2,
  S3, the L20 asynchronous-function-gate edit, and the ME11 re-cut. Of the nested-call-chain edits,
  L15 and L24 fail pins; L14 (innermost call context only), L23 (no call collection through wrapper
  recursion), and L25 (negation refusal at the step only) pass the full suite and take back
  round-eight REPORT-side gains where main is CLEAN (F34). B1 and B8 remain with direct pins; D7,
  B10, B14, N08, N10, and S5 are removed or folded into the simpler source-order walk. The former
  N18 close-carry branch is also omitted; its removal gives N13 and four spelling variants back to
  CLEAN, matching main (five rows, F32). D9's `why is None` fold keeps 285 measured no-run cells on
  their parent-`Reach` answer and CLEAN, matching main, instead of replacing it with a structural
  refusal (F36).

  My final posture-aware Forge gate generates 936,855 candidate rows across sets 1-38. It joins
  924,755 of them to runtime truth -- the 815,744-row round-six baseline and 109,011 round-seven
  hunt rows -- while the expected 12,100 generated baseline rows remain outside the truth corpus.
  There are zero cells where fresh main REPORTs, this head is CLEAN, and a measured parent runs the
  payload. Against main, the head adds 95,390 payload-running reports, leaves 9,029 payload-running
  cells CLEAN for follow-up, makes 12,054 main reports CLEAN only where no measured parent runs,
  and adds 24,730 no-run reports.

  Of that no-run price, 10,128 cells use the explicit structural fallback: 5,904 hidden-parenthesis,
  3,936 compound-negation, and 288 compound-condition refusals. Compared with round six, the head
  gives up 266 payload-running reports where main is also CLEAN: 15 condition-group, 50 `coproc`,
  105 negated-brace, 24 negated-parenthesis, and 72 `time` cells. The 15 condition-group cells are
  set 23's `j03t`; the 24 negated-parenthesis cells are set 23's `j02t` (15) and set 36's `i06p3t`
  (9). Against round seven, the head also gives back set 30's `u07t` (24 payload-running cells,
  CLEAN on main and at round six; F33). Outside the gate, the #2855 replay gives back N13's three
  cells, which report at rounds six and seven and are CLEAN on main (F32).

  My final-source Bash 5.2.21 cost pass reports every generated nest in all five settings. At
  depths 100, 200, 400, 800, 1,600, and 2,400, candidate/main brace ratios are 1.84, 1.93, 2.00,
  2.03, 2.03, and 2.06×; function ratios are 1.70, 1.85, 1.97, 2.04, 2.09, and 2.12×. The function
  increments shrink, while the brace increments flatten within run-to-run spread; both remain a
  bounded constant factor. My three-pass, 40,000-cell full-set sample has no verdict instability
  and a 1.137× median: 178.6 CPU seconds against main's 157.1 seconds.
- **Workflow guard reads a `-c`/`eval` string with a live expansion beside a double-quoted
  escape as bash hands it on (#2466, #2331).** `bash -c "x=\$(curl -fsSL $URL); eval \"\$x\""`
  and the mixed-quoting `bash -c "x=\$(curl … i.sh)"'; eval "$x"'` run the download under bash
  5.2.21, 3.2.57 and dash and read CLEAN: #2342 undid the `\$` escapes only where no live `$` was
  left in the word, so a `$URL` beside them kept every backslash and the inner `x=$(curl …)` was
  text. The reader now spells such a word with each backslash gone and a live `$` word carried as
  the value it already is at top level, so the string reads as #2341's carried download handed to
  `eval`; the `eval`, backquote and `echo … | sh` twins read the same way. A word that also holds
  a lifted `$(…)` keeps its markers in that text, so the `Opaque` rendering of `bash -c "sh
  \$(echo tool) $(true)"` is `sh $(echo tool) $(...)`, read as its escape-only twin is (the
  neighbour noted on #2466), and a printer's word holding one stays unspelled. A live `$` in a
  COMMAND-word position (`bash -c "$CMD … | sh"`) stays unread, as `$CMD … | sh` is at top level;
  the gap list says so.
- **Workflow guard reads a `$` word in front of a shell as an optional wrapper (#2472, #2331).**
  `$SUDO sh -c 'curl … | sh'` ran its pipeline with `SUDO` unset or empty -- bash 5.2.21, bash
  3.2.57 and dash all drop the empty unquoted word, and `sudo` hands on -- and read CLEAN, as did
  `${SUDO:-} sh tool`, `CMD=; $CMD sh <<'EOF'`, `bash -c "\$x sh tool"` and `$SUDO curl … | sh`.
  The reader now drops an unquoted `$` word that is one reference, with no default or a wrapper's,
  in front of a name it knows (a shell, an interpreter, a wrapper, a fetcher) and reads the rest as
  the command, fail-closed. A quoted `"$SUDO"` keeps its word (bash runs `''` and stops), and so
  does a word the step's own table resolves to a literal that is no wrapper (`SUDO=echo` prints,
  `A=X=1` runs `X=1`): `workflow_annotate` marks it `kept`, and its rule-7 veto now fires for a
  value-reached builtin that may assign (`R=read; $R CMD`) rather than for any name outside the
  ones it reads. The price: a value set outside the step that runs nothing of what follows
  over-reports, and a checksum behind such a word is still not credited.
- **Codex read broker passes through a search-only directory (#2839).** `_open` opened every
  component from `/` read-only, so a review root under a directory that grants `--x` and not `r`
  (`drwx--x--x`, a per-tenant parent) refused every `read_file`, `search` and `list_files` -- and
  the scope binding before them -- although the kernel let the path be traversed. Directories the
  walk only passes through are now opened for search alone (`O_PATH` on Linux, `O_SEARCH` where
  CPython exposes it; macOS from 3.13), with `O_DIRECTORY | O_NOFOLLOW` kept on every step so a
  symlink component still fails, and the last component still opened to read. Without either flag
  the walk is the old read-only one and such a root still fails closed. The hard-link rule (#1642)
  is untouched.
- **Workflow guard reads a printer's `$X` and a `$CMD` through the step's values (#2468, #2600,
  #2601, #2331).** Where the step assigns a name one literal no shell expands, `echo "$X" | sh`
  weighs that text as its program (`X='curl … | sh'` reports as its literal twin), and a `$CMD`
  command word reads as the name it holds: `CMD=sh; $CMD <<'EOF'` credits its check under `sh`'s
  `-e`, `CMD=true`, `cat` or `PYTHON=python3` read as theirs. The step is marked once before
  `flattened`, the one place a value body's credit is not yet fixed; any other value -- one with a
  `$`, a backquote or a `<(` in it too -- reads as before, a quoted `'$X'` over-reports, and a
  `$(...)` or handed script inherits no mark yet. A resolved word reads as its literal twin, the
  twin's filed gaps included, so a command word is marked only where the step surely runs it, for
  a name the guard reads, and a printer's value only where its text fetches -- each only where
  every program the statement hands a shell is plain.
- **Workflow guard follows a download through the step's own values (#2425, #2489, #2331).**
  Where a use as written names no download, a name the step itself assigns a literal or an array
  literal is read through that value (`T=cuda_1.run; sh "$T"`, `declare -a a=(sh tool); "${a[@]}"`,
  a `for` header's words), and a call hands the values it sees to the function body; the use as
  written keeps main's reading. Quotes are gone to the reader, so a quoted twin over-reports, as
  does a reassignment the shell may skip; a table kept statement by statement was rejected because
  it cannot repeat the loop, condition and function-body walks of one asked per use.
- **Fail-closed workflow messages now identify guard readings (#2424, #2331).** Carried
  variables and conditional checksum rescues say when scope or status comes from a conservative
  reading. Direct carries and proven non-stopping rescues keep their existing wording; verdicts
  do not change.
- **Workflow guard now lets bound downloads own value-form stdin (#2607, #2331).**
  When `curl -o "$T"` is followed by `$T <<'EOF'`, the existing run finding now stands alone and
  the heredoc is treated as payload input, so its text cannot invent a shell stream finding or keep
  a checked download flagged. Unknown `$CMD` bodies stay fail-closed; disabling all value-body
  reads was rejected because it would hide their real `curl … | sh` executions.
- **Four Bash 3.2-only substitution-heredoc parse gaps are now explicit (#2626, #2608).** A body
  line with an apostrophe, unbalanced double quote, backquote, or bare `$(` can make Bash 3.2
  reject text Bash 5.2 accepts, but none of the measured shapes runs a payload under 3.2. The
  #2493 refusal stays limited to `)` because widening it would report parse-only differences.
- **`eval` brace alternatives bind only downloads they can name (#2624, #2608).** The
  second parse now expands bounded brace lists and numeric ranges before matching a fetched
  path, because treating every brace group as `*` misses real uses and binds excluded names;
  unbounded expansion was rejected because workflow text controls its cost.
- **Compound-command streams now reach their closing executor (#2430, #2331).** Fetches and
  carried downloads printed inside `{ }`, `( )`, `if`, loops, or `case` now bind to a shell after
  the compound's closing pipe. File redirects, disconnected input, and nonexecutors stay clean.
- **Multiline `case` headers stay visible (#2429, #2331).** A literal `in` on the line after
  its subject now reaches the statement reader, so commands in those arms remain visible to
  the workflow guard.
- **Workflow guard: a `cat` with a quoted heredoc on its stdin and an `echo` read as the step's
  shell prints it are printers too, through a substitution as well (#2467, #2476, #2478, #2487,
  #2495, #2728).** `cat <<'EOF' | sh` is read as `sh <<'EOF'` is, a `cat` with an option too (its
  body read whole: `-n` over-reports), and an EXPANDING `cat <<EOF | sh` is reported as `sh <<EOF`
  is; `echo`'s backslashes read as bash prints them (literal unless `-e`) or as `sh`/dash decode
  them, and a `printf` format's always. A shell a `-c`/`eval` string names, or a `${X:-sh}` default
  stands for, reads them both ways, as does one inside a `$(…)` in a script handed on or in a script
  a `$(…)` hands a shell (#2728); the step's own `$(…)` reads per the step's shell. A pass-through
  between the printer and the shell -- `tee` writing plain files with `-a`/`-p`/`-i`, `--append` or
  `--output-error[=MODE]` at most; a `cat` whose only operands are `-` (and one `--`) -- is read
  through (#2478); any other `tee`/`cat` spelling, or a stage that rewrites the stream (`tr`,
  `base64 -d`), leaves the program unread, reported where its words or the printer's text fetch, or
  beside a reported download. A printer inside a `$(…)` or a `<(…)` is read as the text the shell
  runs where every reading agrees on it (#2487, #2495): `eval "$(echo 'sh tool')"`,
  `sh <(echo 'sh tool')` and `bash <(cat <<'EOF' … EOF)` report the download they run, and the
  documented `eval "$(cat <<'EOF' … EOF)"` gap closes; an unquoted `$(…)` is read unsplit (`eval`
  joins bash's fields; `-c` runs the first alone, an over-report), a backquote whose text escapes
  `$`, `` ` ``, `"`, `\` or a newline, and a text the reader refuses, are not rendered, and
  the catch-all row for a word all substitution stays beside every such read. Named gaps:
  `shopt -s xpg_echo` turns bash's `echo` into a decoder, which this rule does not
  follow; a word the shell reads specially once unquoted (a quote, space, newline,
  `#`, `\`, `<`, `>`, an open `$(`) or a lifted `$(…)` word inside the unread stage's words still
  hides the fetch that follows; and a substitution's printer the readings disagree on
  (`sh -c "$(echo 'sh\ttool')"`) stays unread.
- **Pipeline uses after `case` compounds reach the workflow guard (#2610, #2608).** A
  literal `esac` now closes its case before a following redirect or pipe, so `| sh payload`
  is a real stage instead of one argv hidden in case-pattern state. Closing every `esac`
  spelling earlier was rejected because quoted and escaped forms can still be arm patterns.
- **Workflow glob matches now reach loop, positional and function values (#2585, #2331).**
  A live pattern such as `./cuda_*.run` stays tied to the download when `for`, `set --`, or a
  direct function call stores it. Literal `shift` commands reindex that value, while `$@` and
  `$*` retain it for loops and first-script uses. Quoted and nonmatching patterns, reassignment,
  step boundaries, and relative path changes retain bounded controls.
- **Nested `case` arms expose their commands to the workflow guard (#2617, #2608).** The
  reader keeps a parent arm separate from the inner `case` header, so two- and three-level
  bodies no longer hide a fetch-and-execute pipeline. Retaining the parent arm also keeps an
  inner checksum from clearing execution in the parent's sibling arm.
- **Workflow guard: value stdin inherited through `eval` or `sh -c` is read (#2599).** A quoted
  heredoc handed to an inner `$CMD` now gets shell analysis and names that word, closing a CLEAN
  `curl | sh` path; an unset `sh -c "$P"` is deliberately reported fail-closed rather than
  treating an unknown value as data.
- **Checks inside command substitutions now gate the uses beside them (#2435, #2331).**
  `x=$(CHECK && bash t.sh)` credits `CHECK` under that substitution shell's own failure reach;
  `CHECK; bash t.sh`, a plain use, and a check in a sibling substitution remain reported.
  Check discovery moved to `workflow_checks.py`, taking `workflow_guard.py` to 700 lines.
- **ANSI-C words no longer hide adjacent workflow findings (#2614, #2470).** A non-ASCII
  escape now leaves only its word unknown, so ordinary CI prose does not replace a nearby
  fetch-and-execute finding with a whole-step refusal. Backslash-newline also stays literal
  inside `$'...'`, matching both bashes instead of joining text they keep separate.
- **Workflow guard keeps stdin possible after a value-form shell option (#2605).**
  `sh $X file.sh <<'EOF'` no longer hides its body when `$X` may be `-s` or `--rcfile`;
  `X=-e` is the disclosed fail-closed cost, because always treating the bare word as a script
  file would reopen the execution defect.
- **Workflow guard: value-form consumers no longer hide streamed or redirected downloads
  (#2602).** Direct, carried and pass-through streams, plus fetched file stdin, now report under
  `$CMD`, closing a CLEAN execution path; a `$CMD` holding `cat` is deliberately reported
  fail-closed because assuming an unknown command only reads data would reopen the defect.
- **Workflow guard now reads `$` command stdin inside substitutions (#2598, #2331).**
  `x=$($CMD <<'EOF' …)` no longer hides a written `curl … | sh`: the program reader now speaks
  before the stdin hand-off only inside substitutions. Top-level wording and option-value priority
  stay unchanged; directly prioritizing the body reader was rejected because it hid louder reasons.
- **Line-only subshell rescues keep their enclosing status context (#2579, #2331).** When `(` is
  on the line before a checksum, its `|| exit` now carries through `)` into an outer `||`, so a
  swallowing branch no longer certifies later execution. Unrescued and piped diagnoses remain.
- **Workflow paths now follow a static working directory (#2427, #2331).** A literal `cd` binds
  relative fetches, checks, aliases and uses to the file they reach. Each step starts at the
  workspace; subshells and command substitutions inherit, then restore, their caller. A branched
  or dynamic `cd` stays fail-closed as an unknown directory. Known different paths remain clean.
- **Workflow guard now reads expanding heredocs under `$` command words (#2597, #2331).**
  `$CMD <<EOF` no longer hides a written `curl … | sh`; substitutions stay values in this second
  read to avoid duplicate findings. This fail-closed reading can flag non-shell bodies whose text
  resembles shell, while preserving innocent `$PYTHON`; a blanket unread warning was rejected
  because it would flag that control.
- **Workflow guard: the printer rules move to `scripts/workflow_printers.py` (#2331).** A pure move
  of `printed`, `_piped` and `_PRINTERS` out of `workflow_programs`, which re-exports them, so the
  printer follow-ups have room; the guard's answers are byte-identical before and after.
- **Workflow guard: a value in a shell's options is weighed to its first operand, or past a word
  that may re-open it (#2490, #2479, #2484, #2486).** A louder reason drops a statement's `Idle`
  one, `sh $X "$x"` names its carried download, a `-c`/`eval` string holding a `$(…)` is read
  opaque, and `sh -c "$(cat f)"`, blanks around it too, is reported unread beside a download.
- **Line-only subshell boundaries now retain their shell status (#2420, #2331).**
  The workflow reader keeps lone `(` and `)`, including `esac )`, so a following `||`, `&&`,
  pipeline or background separator reaches the gate. Subshell-local options and assignments no
  longer leak into the enclosing step's model.
- **Interpreter redirections now bind expanded paths to fetched scripts (#2426, #2331).**
  `bash < "$PWD/x.sh"` and a literal redirect after a fetch to `"$PWD/x.sh"` use the same
  last-part path binding as interpreter operands. Other basenames and non-interpreters stay clean.
- **Function checks now count only after a failure-gating call (#2421, #2331).**
  Definitions, rescued calls, and child scripts inside them no longer certify later execution;
  a plain call still credits a check whose failure stops that function and the step.
- **Conditional carriers no longer hide a failed checksum behind a later command (#2418, #2331).**
  Brace groups, subshells and functions tested by `&&` or `||` now report a check whose status a
  later command replaces. A plain function call still gates uses that occur after that call.
- **Nested conditional groups no longer inherit an earlier checksum status (#2578, #2331).**
  When a later command replaces a checksum's status before an enclosing group reaches `&&` or
  `||`, the guard reports the later use. Checks that remain the group's final status still gate.
- **Conditional checks no longer certify uses that can outlive their list (#2419, #2331).**
  A checksum behind `A &&` or `A ||` clears only paths that require the check to run. A final
  `A && CHECK` can still gate a later job step, while `A || CHECK` cannot. Literal commands get
  no special exit-status proof, keeping the rule fail-closed.
- **Checksum rescues no longer certify their own failure-only body (#2417, #2331).** A use
  inside the check's `||` branch is reported even when that branch later exits. The same
  stopping rescue still certifies uses after it, and unrelated checks retain their existing
  ordering and file-binding diagnoses.
- **Workflow guard: a stdin program is read behind `eval`/`-c`, past a value in the option slot, and
  under a `$` command word (#2500, #2485, #2473).** The quoted heredoc `eval 'bash -s'`, `sh $X` and
  `$CMD` run is caught.
  A check behind an `eval`/`-c` string counts for nothing; the body is still read. Nor does a check
  count past `$X` or under `$CMD`: one clears a download only in the body of a shell written at its
  own level, as before. Nothing else in a body behind a string, past `$X` or under `$CMD` is taken
  for the step's own either (bar one whose holder's own options read stdin, `bash -s -c 'sh'`): the
  job is read with such bodies and without them, and a defect of either reading is reported.
  `X=script.sh` over-reports; `$CMD` itself is `Idle` beside a reported fetch.
- **A checksum rescue inside a piped group is not credited without pipefail (#2630, #2608).**
  `{ CHECK || exit 1; } | cat`, its multi-line and subshell spellings, a `{ f; } | cat` call and
  a `|| return 1` twin leave only the piped stage's subshell, so without `pipefail` the pipeline
  takes the last stage's status and bash 3.2.57/5.2.21 and dash run the payload; the default and
  `shell: sh` postures now report them, while `shell: bash` (`-eo pipefail`) still clears them.
  The nested-paren spelling #2627 fixed, the `set -o pipefail` form and the no-pipe rescue keep
  their verdicts. 0 occurrences in the 11 corpora and the calibration pool.
- **Bare-subshell rescues piped onward clear only when pipefail stops the step (#2631, #2608).**
  The `( CHECK || exit 1 ) | cat` family -- the bare-`( )` sibling of the `{ ... }` forms #2582 and
  #2630 handle -- now reads CLEAN under `shell: bash` (`-eo pipefail`), where the failed group stops
  the step and no shell runs the payload, matching its brace twin; 19 such spellings (a trailer after
  the rescue, a `|| return 1`, a subshell stage, a called function body, `if`/`while` conditions) are
  covered. Where the failure is swallowed (`|| true`) or the exit masked by a command on an `&&`
  list's errexit-suspended left side, the payload still runs on bash 3.2.57/5.2.21 and the guard
  keeps reporting it -- the subshell's abort is resolved before the concurrent-stage break, and a
  `return` does not leave its subshell. The 10 named clears, the `( CHECK || exit 1 ) | cat` posture
  split, and the `{ ... } | cat` must-stays are unchanged. 0 occurrences in the corpora and the pool.
- **A use step that runs after a failed step is no longer cleared by an earlier step's check
  (#2632, #2608).** A plain `CHECK` or `CHECK || exit 1` in step a stops step a, but a later step
  whose `if:` runs after a failure -- `always()`, `failure()` or `!cancelled()` -- still runs the
  payload; the default, `bash` and `sh` now report it. `success()`, a plain expression, no `if:`,
  and a check that shares the use's own `always()` step keep their clear. 0 occurrences in the 11
  corpora and the calibration pool.
- **Workflow function gates reach proved later calls (#2586, #2331).** The guard recovers 8 of
  56 previously declined real call sites (25 to 33 of 105 scopes), including grouped calls and
  one proved wrapper. The other 48 remain fail-closed, chiefly on multi-helper steps. Distant
  piped calls retain their concurrent-use bound; posture changes, removals, redefinitions, and
  conditional calls still refuse the proof. An `||`-suppressed call is credited only when the
  gate remains the function's final status; the conservative `unset` barrier is disclosed. The
  mutually recursive function/status proof now lives in `workflow_function_calls.py`, leaving
  both proof modules room under the 700-line ceiling. A success handler after the inner
  subshell's nonzero exit invalidates each supported call form; assignment-only handlers do not
  inherit that failure. `continue-on-error` keeps the shell's posture and bounds credit after the
  proved call and before the end of its own step.
- **Tab-prefixed substitution heredoc delimiters have a regression pin (#2584, #2331).**
  A `<<-` word starting with a tab bypasses the `EOF)` terminator reading, but #2493 already
  refuses the `)` retained in its body. The pin preserves that protection because Bash 3.2
  runs the following payload where Bash 5.2 treats it as data; no new lexer rule is needed.
- **`[[ ... ]]` is one statement to the workflow reader (#2441, #2331).** The `&&`, `||`, `(`,
  `)`, `<` and `>` inside a conditional are its operators, not list separators, subshells or
  redirections, so `CHECK && [[ -f a || -f b ]] || exit 1` no longer reaches the guard as three
  statements with the `|| exit 1` rescue that ends the real list lost -- the step was refused
  where bash stops dead. `[[ $a < $b ]]` records no redirection either, and a `=~` alternation
  leaves the compound-command count balanced. Bash 3.2.57 and 5.2.21 agree on 23 probes; dash
  has no `[[`. A newline after an inner `&&` still ends the statement, as it did.
- **`shell_reader.py`'s token layer moved to `scripts/shell_tokens.py` (#2628, pure move).**
  `_Token`, `_Parse`, `derived`, `readable`, `is_marker`, `has_substitution` and `yields_words` now
  live in the new module and are imported back into the reader under their own names, so no caller
  changed; the reader goes from 683 to 599 lines, making room for #2441 and the reader half of
  #2617.
- **Substitution heredocs whose bodies contain `)` now fail closed (#2493, #2331).** Bash 3.2 may
  close the substitution there and execute later body text as code, so the lexer now names the
  ambiguity instead of accepting one reading. Selecting a parser by runner was rejected because
  the owner ruled one conservative answer for every workflow.
- **Candidate programs now expose code around substitutions (#2482, #2331).** A dynamic `-c`
  option made the guard discard an entire program word containing `$(...)`, so its visible fetch
  pipeline read clean. It now reads the outer program with the substitution opaque while the
  normal walk reads the inner script. Evaluating substitution output was rejected because that
  would invent commands from runtime values.
- **Enclosing checksum groups retain the step's pipefail state (#2582, #2331).** The workflow
  guard credits `{ ( CHECK || exit 1 ); } | cat` under `shell: bash`, where pipefail carries the
  group's failure and stops the step, while default and `sh` modes still report it.
- **Case-arm closes no longer truncate command substitutions (#2474, #2580, #2331).** The matcher
  took an unparenthesized `case` pattern's `)` for its surrounding `$()` close, so a fetched
  pipeline in the arm—including a later arm on an `EOF)` rest—escaped the substitution parse
  and read clean. It now follows nested case phases and balanced patterns, while subjects needing
  another parse fail closed by name. Treating every `)` after `case` as an arm close was rejected
  because it could hide later shell code.
- The `set`-posture reading (`seed`, `_errexit`, `_rejected`, `_takes_value`) moves from
  `scripts/workflow_gating.py` to a new `scripts/workflow_posture.py`, a pure move with re-exports,
  so the gating module has room again under the 700-line ceiling (#2620).
- **Quoted workflow globs stay literal (#2432, #2331).** The guard now uses lexer pattern
  provenance when matching fetched paths, so `sh "./cuda_*.run"` does not claim to run a
  download while unquoted and partly quoted patterns still do. Bash 3.2.57, Bash 5.2.21 and
  dash agree; 439,716 frozen corpus rows and 4,642 real jobs keep identical answers.
- **Shell quoting now has a dedicated flat module (#2615, #2608).** ANSI-C decoding and
  quote-aware heredoc and here-string word spelling moved unchanged from `shell_lex.py` to
  `shell_quote.py`, restoring lexer headroom. Further compression of the lexer's governing
  contract was rejected because a line budget must not choose which behavior stays documented.
- **Checks do not gate concurrent stages in their own pipeline (#2422, #2331).** The workflow
  guard reports a downloaded payload used by another stage of its checksum group's pipeline,
  including a checksum ahead of `&&` under every supported shell. It still credits a use after
  a failing pipefail pipeline and a use gated by `} &&`.
- **ANSI-C numeric escapes now expose shell program options (#2470, #2331).** The lexer left
  `\\xHH`, `\\nnn`, `\\uHHHH`, and `\\UHHHHHHHH` encoded, so a decoded `-c` could run a fetched
  script while the guard read the step clean. It now shares Bash's ASCII escape table across
  words, heredoc delimiters, and here-strings, and fails closed beyond ASCII. Keeping only the
  four identity escapes was rejected because it hid executable option words.
- **A `set` is read the way bash counts it (#2559, #2560, #2561, #2331).** A `set`'s option values
  now count one per `o` LETTER, as bash counts them and as the program readers already did, and a
  `-o` value that is no option NAME refuses the whole `set`, as an unknown option LETTER already
  did (#2443). So `set -oo pipefail errexit` arms errexit -- the second `o` takes `errexit`, and
  `$#` stays 0 -- and `set -o foo -e` arms nothing, where bash answers `set: foo: invalid option
  name` and changes nothing. That second one was a fail-open: the guard credited a check bash
  never armed, and passed a step that runs its download with the checksum failing. A shell's
  command line is read the same way, so `bash -c -o foo P` hands over no program; the names were
  measured as the letters were -- bash 3.2.57 and 5.2.21 for the builtin, their union with dash
  for a command line, which takes `-o stdin` where bash exits 2 -- and the measured-shells list
  is now pinned against the two shell-name lists it has to agree with (#2561). Rejected: keeping
  the per-WORD value count the #2551 docstring defended, which is what read `set -oo pipefail
  errexit` as arming nothing at all.
- **A heredoc whose substitution closes before its body is read like Bash 5.2 (#2498, #2331).**
  The lexer refused `$(cat <<EOF)` before reading the lines below it, so one generic finding
  replaced the fetch sentence in every affected step. It now files that body first and skips its
  consumed source after parsing the close-line rest; Bash 3.2's code reading remains documented
  as the standing version disagreement. Keeping the refusal was rejected because it hid the
  actionable defect without adding safety.
- **Queued heredocs after an `EOF)` close are read in Bash 5.2 order (#2497, #2331).** The
  guard used a generic refusal because one pass met the first body's same-line rest before the
  later bodies Bash reads first. The lexer now retains two source offsets, reads those bodies
  from the next line, then parses the saved rest, so body and rest payloads get specific
  findings. A second lexing pass was rejected because it would duplicate state and cost; two
  `EOF)` ends remain fail-closed because Bash reports a syntax error.
- **Nested shell-group status reaches its enclosing failure gate (#2431, #2438, #2331).** The
  workflow guard credits `( CHECK || exit 1 )` under outer errexit and follows a checksum's
  failing `&&` list through consecutive closing groups to an outer `|| exit 1`. It still reports
  `exit 0`, disabled outer errexit, and unsafe enclosing-group contexts. Bash 3.2.57,
  Bash 5.2.21 and dash agree on the target and controls.
- **An unended substitution heredoc no longer hides a later `EOF)` close (#2494, #2331).**
  After one scan reached the script's end, `_Lines` used the exact-line index for every later
  body, so it swallowed a pipeline Bash 3.2 runs between a later `B)` and exact `B` line. An
  exact line now proves and bounds that later scan, which can find the earlier `B)` while staying
  linear; resuming every unbounded scan was rejected because hostile inputs restore quadratic
  cost.
- **A substitution heredoc's `EOF)` rest is read as Bash 5.2 parses it (#2492, #2331).** Bash
  drops that rest's first `;`, so the guard missed `EOFsh -c; 'curl … | sh')` while reporting a
  `true; curl … | sh` rest whose download never runs. `_Lines` now bounds one separator-token
  omission to that logical line and command, preserving its word break; a rest beginning with `;`
  is refused because Bash 5.2 rejects it while 3.2 can run later code. A candidate before `then`
  or `do`, including across a folded `\\`-newline, is refused too: Bash keeps that required
  separator, and omitting it hid an executable compound body. An unbounded Boolean and a
  character-only omission were rejected because they hid later-line and no-space payloads.
- **Artifact diagnostics preserve the failing stage (#2571, #1816).** Findings-file and
  dispatch-plan integrity rows now distinguish oversized, unreadable and unparseable inputs.
- **A delta map that dropped a whole path turns the on-diff gate INCONCLUSIVE (#2517).** The fourth
  counter joins #2405's broken-artifact measure (owner ruling 2026-10-02). `paths_dropped` — #2169's
  count of paths whose value in the hunk map was not a list of ranges at all, so the loader drops
  the path entirely — now turns a PASS into `gate: INCONCLUSIVE` on an active delta under the
  default on-diff gate scope when gate-eligible findings exist, exactly as
  `paths_emptied_by_drops`, `ranges_dropped` and a set `payload_malformed` already did (and, as
  for those three, a FAIL or OFF run over such a map now reads NOT CERTIFIED too). The
  DIRECTION is why: a dropped path LEAVES the map, so a HIGH in that file classified off-diff, left
  the gate's source set, and the run reported a PASS it had not earned — the fail-open mirror of
  the emptied arm, which admits such findings to the gate instead. A legitimate change shape never
  produces one (the loader drops a path only for a non-list value, and no `diff_map.parse` output
  carries one), so the ruling's "never fires on a deletion-only PR" property holds; the `[]`
  remainder stays disclosed and is never gated on. Disclosure-only was rejected: the stderr line
  and both report blocks already published the count, and a note beside a green gate is not a
  refusal to certify. The exclusion pin flips to an inclusion one, the reason names the counter and
  the direction so the operator finds the same number in `meta.coverage.delta`, and a new
  end-to-end pin reads INCONCLUSIVE for a map that dropped `b.py` with a HIGH at `b.py:3`.
- **Container cleanup failures reach coverage metadata (#2556, #1817).** A failed scanner
  container stop now records the same redacted, bounded detail sent to stderr in the tools
  manifest and both human reports, while preserving the original timeout and gate outcome.
- **A download written to a `$`-spelled path binds to its literal basename at use (#2442).** The
  mirror of #2345, and a fail-open until now: that issue bound a `$`-spelled OPERAND by its last
  part (`sh "$PWD/cuda_1.run"` after `curl -o cuda_1.run`), but a `$`-spelled DESTINATION only
  through a glob, so `curl -o "$PWD/cuda_1.run"` followed by `sh cuda_1.run` — the commoner
  spelling — read CLEAN while `sh cuda_*.run` was reported. bash 3.2.57, bash 5.2.21, dash, zsh
  5.9 and ksh 93u+ all run the download through the plain name, the `./` spelling and a
  `chmod +x` before it. One predicate in `workflow_operands` (`_last_part`) now answers both
  directions for an operand and for a command word, and it takes the same fail-closed looseness
  the operand side already took: what `$PWD` expands to is not evaluated, so a same-named file
  under another directory binds too (`sh scripts/cuda_1.run`), which over-reports rather than
  reading the shell. The destination's basename must be WRITTEN — `curl -o "$PWD/$F"` still binds
  nothing by name, and a lifted `$(…)` in that basename is carried through it — and the checksum
  side stays exact: `echo "<sum>  cuda_1.run" | sha256sum -c -` does NOT credit a fetch to
  `"$PWD/cuda_1.run"`, because loosening the side that CHECKS would clear bytes nothing read.
  Half of the `PATH_DIRS` gap entry (#2308) closes with it: the `$HOME/.cargo/bin` spelling of a
  download run by its bare name is now reported, which every shell runs once the file is
  executable and that directory is on PATH. The calibration pool's 4,642 real jobs answer
  identically.
- **Bounded artifact reads share typed outcomes (#2554, #1816).** Evidence scope now uses the
  common no-follow reader; verdict loaders consistently label size, I/O, special-file, and parse
  failures, and run-artifact readers delegate limit validation to the same primitive. The 4, 8,
  and 16 MiB caps now state which source, verdict, or aggregate metadata class each one bounds.
- **The self-scan matrix gives `CI` explicit `Shell` and `Workflows` layers (#2521).** Adding
  `shell_heredoc.py` filled the 48-file leaf, so the next `.github/**` file would have replaced
  the authored `CI` cell with engine-balanced `CI_1` / `CI_2` chunks. The layers hold 9 and 39
  files, respectively, keep each test beside its code, and put `CI` behind the shared 40-file
  headroom guard. This costs one extra review cell now; waiting would make the next unrelated CI
  contributor inherit an automatic split and its unplanned test inventories.
- **Broken batch stop predicates identify their failure point (#2555, #1817).** The runner logs
  the completed entry and final predicate frame inside the existing redacted 200-character
  detail budget, then keeps yielding launched work and still honours a later stop.
- **Tolerant verdict extraction keeps small wrapped bundles (#2553, #1816).** A fixed 64 KiB
  minimum scan budget reaches JSON after shallow nested or 256-open-brace prose while the
  length-scaled caps still bound large inputs.
- **Interrupt cleanup retains child process groups (#2550, #1816).** Ctrl-C snapshots each
  validated group, waits once for the shared SIGTERM grace, and escalates before reaping any
  leader, so a resistant descendant cannot escape SIGKILL. The price: a retained leader is a
  zombie that keeps its group alive, so every interrupt now waits the full `INTERRUPT_GRACE`
  (5 s) before SIGKILL where it used to return as soon as the leader died.
- **Family PR review discloses missing agents (#2546, #1817).** Missing finders and verifier
  votes become explicit incomplete-review facts and log lines; a partly verified finding cannot
  enter the confirmed or dropped lists.
- **Kimi credential cleanup reports partial failures (#2545, #1817).** Cleanup distinguishes
  removed, absent and failed paths; retained-home and exit messages no longer claim secrets are
  gone when an unlink failed.
- **The workflow guard checks shell option letters against the shell's own table (#2443, #2444,
  #2475).** Three readings of a shell's options read the WORDS and not the letters, so each took a
  spelling the shell refuses for one it runs. A `set` carrying a letter bash's builtin lacks —
  `set -Z -e`, `set -eO foo` — was read as turning errexit back on after a `set +e`, so a checksum
  written after it was credited; bash answers `set: -Z: invalid option` with rc 2 and changes
  nothing, and bash 3.2.57 and 5.2.21 both run the download with the check failing (#2443). A
  child shell's `-O shopt` was read as the `set` builtin's `-O`, which takes no value, so
  `bash -O extglob -ec '…'` read `extglob` as the end of the options and never saw the `-ec`: the
  step was refused as running where no `-e` holds, though both bashes stop the child at the
  failing check and a `sh` that refuses `-O` runs nothing at all (#2444). And the option skip
  after `-c` (#2332) read on to the program through a word no shell takes, so
  `sh -c -K 'curl … | sh'` was FLAGGED although bash 3.2.57, bash 5.2.21, dash and bash-as-`sh`
  all exit 2 before they read the program (#2475). One table of letters answers all three, in
  `workflow_programs` (`SET_OPTIONS`, `SHELL_OPTIONS`), read there by `_past_options` and above it
  by `workflow_gating._errexit`: bash 5.2.21's `set` letters for the builtin (`-r` among them,
  and not the `i`/`I` that 5.2 refuses while surviving), and for a command line their union with
  its own `-c`, `-i`, `-l`, `-r`, `-s`, `-D`, `-O` and the `-I`/`-V` dash takes — every letter
  measured on bash 3.2.57, bash 5.2.21, dash, zsh 5.9 and ksh 93u+. On a command line the refusal
  is PER SHELL, because that measurement found zsh running twenty of the letters bash refuses and
  ksh running `-G`: `zsh -c -K 'curl … | sh'` fetches and RUNS the download under either bash as
  the step's shell, so only `sh`, `bash` and `dash` are read as refusing, while zsh, ksh, the
  unmeasured `ash` and a shell NAMED by a word rather than written (`$X -cK`, `${X:-sh} -cK`,
  whose program #2337 and #2344 report in their own words) are read ON, exactly as before. Both
  directions fail CLOSED: a `set` with an unknown letter turns NOTHING on (a `+e` in it still
  reads as off, and bash leaves errexit where it was), and an invocation with one hands over no
  program, so nothing runs and the rule is silent, which the gap list now says in the guard's own
  voice. `set` keeps its own reading, where `-O` is no option at all (the `set -O foo -e` pin is
  unchanged) and a LONG word is a refusal too, since bash's `set` has none: `set --posix -e`
  leaves errexit off and the download runs on both bashes, while `set -- "$@"` is the positional
  spelling and reads as it always did. Two spellings stay fail-closed on purpose: a letter in a
  SEPARATE word ahead of `-c` (`sh -K -c '…'`) is read on, and so is an option word that is not
  all letters: bash, dash and ksh refuse `-1`, `-I{}` and `-nw5`, but zsh RUNS `-1`, and all five
  shells run the program after `sh -c -u$X P` wherever `X` is empty.
  Over the 11 probe corpora (439,716 rows) 10 rows go FLAGGED→CLEAN, every one an option word of
  letters after `-c` handed to a shell of the measured family that refuses it — `-F`, `-g`, `-K`,
  `-fR`, `-S`, `-w`, each rc 2 on bash 3.2.57, bash 5.2.21, dash and bash-as-`sh` with nothing
  fetched and nothing run — and 4 two-step rows lose exactly the sentence of the step that went
  clean; 0 rows go CLEAN→FLAGGED and no other answer moves, in the same 14 rows before and after
  the per-shell scoping. Over the 3,200-workflow calibration pool (4,642 jobs) no job's answer
  changes, and a text census finds no job carrying a `set` letter outside the table, a refused
  option word after `-c`, or an `-O` at all.
- **Timeout cleanup retains the session group identity (#2532, #1816).** An unpolled leader that
  Darwin reports gone cannot hide its live descendants, which still receive the SIGKILL phase.
- **Verdict ingestion has bounded resources (#2531, #1816).** Advisor verdicts use a shared
  8 MiB regular-file reader, and tolerant JSON extraction bounds memory and compatibility work.
- **Runner batches name a broken outage stop predicate (#2544, #1817).** Work still continues,
  while one redacted and bounded diagnostic tells the operator the short-circuit was unavailable.
- **Scanner timeout cleanup names container-kill failures (#2543, #1817).** Missing or empty
  container ids, launch errors and nonzero kill exits are reported without replacing the timeout.
- **Image freshness lookup failures now fail monitor runs (#2542, #1817).** Push runs retain the
  warning fallback, while scheduled and manual checks return an error with the API diagnostic.
- **Family PR review bounds verifier fan-out (#2535, #1816).** Each of five finders is limited
  to 25 findings by its output schema and again before three-way verification. The result and log
  disclose truncation by dimension, bounding a run at 375 verifier calls.
- **Report chunk sizing is linear in its findings (#2534, #1816).** Each finding is serialized
  once for sizing, with exact UTF-8 envelope and separator costs tracked incrementally.
- **Evidence-scope import scans are bounded and memoized (#2533, #1816).** Each source is a
  regular file read at most once per entry and only through a 4 MiB byte cap before parsing.
- **A literal shell's dynamic program is read as unread, like a dynamic shell's (#2483).**
  `workflow_programs.scripts` hands on a shell's `-c` operand — and `eval`'s — as the script text,
  and a word that is ENTIRELY parameter expansion spells no command for `workflow_forms.flattened`
  to read, so `curl -fsSLo tool …` beside `sh -c "$P"` read CLEAN while bash 3.2.57 and 5.2.21
  both run the download once `$P` is `sh tool`; so did `bash -c "${P}"`, `eval "$P"`,
  `sh -ec "$P"` and `${X:-sh} -c "$P"`. The `$CMD -c "$P"` twin has been REPORTED since #2465's
  fix round (`candidates` hands a `$` command word's program to `unread_program`): one dynamic
  program word, two answers, decided by whether the shell happened to be spelled out.
  `dynamic_program` now reads that word wherever a shell takes one, and `unread_program` reports
  it `Idle`, kept under #2481's predicate exactly as the twin is — beside a fetch this guard
  reports, and nowhere else, so a credited download leaves it standing nowhere. `$@`, `${@}` and
  `$*` are one thing in three spellings and read alike (`set --` gives a step positionals), and a
  nest of any depth is still all expansion (`${A:-${B:-${C}}}`), since braces are counted rather
  than matched by pattern. Three spellings are NOT this rule and read as they did: a lifted
  `$(...)` marker, whose inside the guard's own walk reads (`sh -c "$(cat tool)"`), a string
  MIXING literal text with an expansion (`sh -c "echo $X"`), and a word holding text of its own
  (`sh -c "${A}x"`). The rule also speaks LAST: a value where a shell reads its options keeps
  #2344's reason, which `_weighed` makes LOUD where a word after it fetches
  (`sh $X -c "$P" 'curl … | sh'`), and this rule's droppable one would have replaced it. Where
  #2341's `carried` names the same statement louder — `x=$(curl …)` then `sh -c "$x"` — the quiet
  sentence is dropped and the carried one stands alone, the dedup `_Unprinted` already had for
  printers (one class for both now, `_Quiet`). Five readings fail CLOSED on purpose: the reader
  drops quotes, so `sh -c '$x'` is reported though bash runs nothing unless `$x` is exported;
  `eval set -- "$P"` is the getopt idiom and runs none of the value as a command, unless it holds
  a `;`, which `eval` does run; a cut (`eval "${x//$'\r'/}"`) is reported as an unread word,
  though the guard still does not follow the download through it; `curl … | sh -c "$P"` says both
  of its defects, the stream and the unread program; and `sh -c "$*"` says this rule's sentence
  beside the pattern one #2294 already gave the script inlined from it. The value gap the gap list
  keeps is untouched: `sh -c "sh $X"` runs `tool` where `$X` names it and still reads clean,
  because no word follows the value. Over the 11 probe corpora (439,716 rows) 42 rows gain the
  sentence, all of them already flagged, with 0 CLEAN→FLAGGED, 0 FLAGGED→CLEAN and no reason lost;
  over a 1,372-row grid of the shape itself 190 rows go CLEAN→FLAGGED, every one beside an
  uncredited download or a carried one, and its 70 `sh $X -c` rows read exactly as main does. Over
  the 3,200-workflow calibration pool (4,642 jobs) three jobs hand a literal shell such a word —
  mlflow `cross-version-tests.yml :: test1` and `:: test2` (`eval "$MATRIX_INSTALL"` and two
  more), vector `k8s_e2e.yml :: test-e2e-kubernetes` (`bash -c "$2"`) — and none of them fetches,
  so no job's answer changes.
- **A hand-edited non-string manifest run_id is refused at the read, not crashed on in Popen
  (#2525).** `phases/synthesize` and `phases/tools` both thread `manifest.get("run_id") or ""` into
  the child's argv unconverted, and `run_manifest.load_manifest` type-validated only `host` while
  `run_tag` slugs the id through `str()` — so a `"run_id": 7` edited into `run-manifest.json`
  survived the load, stayed truthy, and reached `subprocess.Popen` as a non-string argv member. The
  `TypeError` that raises is covered by neither `phases/child`'s `OSError` → `DriverError`
  conversion nor `driver.run`'s `except (DriverError, ValueError)`: the driver died with a
  traceback and no `status:` line at all. The loader now requires a PRESENT `run_id` to be a
  non-empty string, which covers every phase that threads it at once rather than one flag at a
  time — `phases/engine` hands each phase the dict this loader returned. A bad one is DISCARDED
  with a stderr line naming the field and the value, exactly as an unknown `host` is, and never
  raised: this same read is what `runio._run_tag` calls on every artifact path resolution, the
  `--reset` recovery path included, so an exception here would be one `--reset` could not clear
  (the failure `run_tag`'s own docstring records). The driver then takes its existing
  corrupt-manifest path — clear the derived artifacts, rebuild from the real CLI args — and ends
  with a `status:` line. An absent or null `run_id` is left alone, like an absent host: the setup
  namespace and every pre-key manifest carry none, and the consumers already read it as an
  absence. #2107's own residual assertion stays as it is, because it measures the phase handed a
  manifest dict directly; its cover is the loader's new test class.
- **Discovery uses the canonical confinement predicate (#2450, #1768).** `discovery.py` carried a
  third private `_within`, with its own cached root realpath, beside the two names that already
  alias `claim_scope.confined_to_root`. Substituting the canonical one naively would have been a
  regression and not a cleanup: it JOINS the path onto the root it resolved, and all three callers
  handed it a candidate they had already joined — so a RELATIVE repository root got double-prefixed
  (`confined_to_root("repo", "repo/x")` resolves `repo/repo/x`), and a decoy directory of that
  name, one a reviewed tree can simply commit, would have answered for an escaping symlink and
  read it as confined. Each caller now passes its repo-relative path instead: the changed-files
  listing, the git-listing `isfile` probe, and the `--scope-file`/`--scope-files` clamp. The cached
  root realpath moved DOWN with it, into `claim_scope._real_root`, so the performance property the
  private copy existed for survives the move — one `realpath` of the root per distinct root, not
  one per candidate on a whole-tree expansion. Only an ABSOLUTE root is memoized there, because a
  relative one names a different directory in every process cwd. Both shapes are now pinned, the
  working-directory decoy and the escaping symlink, in `tests/test_claim_scope.py` (the predicate)
  and `tests/test_discovery_scope.py` (the two call sites).
- **The workflow guard keeps an unread program only beside an unverified fetch (#2481, #2499).**
  Owner rulings 2026-10-01. The job-level predicate in `workflow_forms.kept` was "the job
  downloads something", so a program the guard cannot read — `$PYTHON -c '...'`, a `$CMD -c`
  candidate, a script handed to a shell inside a `$(...)` — was reported beside ANY fetch,
  including a download its `sha256sum -c` cleared and an API `curl ... | jq` that is no download
  at all. It is now reported only beside a fetch the guard itself reports: a download no checksum
  clears (the unread program is counted as the use the checksum was owed, ADDED to the uses
  `_defect` can read, so a checksum BEHIND such a program clears only the uses in front of it), a
  `curl ... | sh` stream, an unresolved transfer, or a download no file holds — `x=$(curl ...)`,
  the `carried` shape, and one a pipeline writes past the fetcher (`curl ... | cat > f`,
  `| dd of=f`, `| sponge f`, `| cat | tee t`, none of which `parse_fetch` binds a destination to;
  `workflow_forms.unbound`). Two readings are deliberate and fail closed: the report names the
  unread program and not the download that makes it one (one sentence, as before), and a download
  a variable holds keeps the reason even where only an `echo` reads it, because no file exists for
  a checksum to name. The same predicate now governs the foreign-language stdin program
  (`python3 - <<'EOF'`, `node <<'NODE'`, at the top level or inside a substitution), #2499's
  owner ruling (b), decided once for both; the EXPANDING-heredoc report is
  untouched and still loud with no fetch at all. Over the 3,200-workflow calibration pool 31 jobs
  clear and none newly fails: metabase `pr-env.yml :: deploy_pr` (`$ADMIN -c` psql beside an
  OIDC-token `curl | jq`) and 30 jobs whose heredoc program parses a `pom.xml`, YAML, HTML or
  JSON and fetches nothing.
- **`diff-hunks.json` is now bound to its `groups.json` generation (#2107).** One discovery child
  writes the hunk map and then the inventory, as two independent atomic writes, and only the
  inventory carried a run binding — so nothing compared the surface the review covered with the
  diff the gate scoped to. A probe traced every driver path and could not assemble the mixed
  pair (the pre-child clear, the hunks-before-groups write order and the per-run folder each stop
  it), but a hand-run `discovery.py` followed by a hand-run `synthesize.py` does — `--groups` is
  auto-discovered, `--diff-hunks` is not, so the operator supplies one half and inherits the
  other — and it was accepted in silence: 0 of 1 gate-eligible HIGH classified on-diff against
  the other generation's map, a green `--gate-scope on-diff` gate over a change nothing measured.
  The driver now stamps both halves with this run's `run_id`, and the loader gains an optional
  expected generation that rejects a foreign or absent stamp as the new `payload_malformed` value
  `generation-mismatch`. The refusal is REPORT-VISIBLE, not stderr-only: the synthesize phase
  hands the pair over with `--diff-hunks-run-id` even when it can already see the mismatch, so
  `meta.coverage.delta_artifact` publishes the reason instead of reading null like a run that was
  never a delta one — the gate is identical either way (no `base` survives, so the delta is
  inactive and the scope widens to whole-repo, which fails closed). `synthesize.py` defaults that
  expectation to the stamp on the `groups.json` it read, so the hand-run pair is bound too; an
  explicit `--diff-hunks-run-id` overrides it, and an unstamped inventory expects nothing, which
  keeps every direct caller and hand-written artifact reading byte for byte as before. The path
  is withheld in one case only, a manifest whose `run_id` is not a non-empty string: there is
  nothing to thread (the child cannot launch on such a manifest either way; #2525).
- **The self-scan matrix's `RepoProfiling` group has layers (#2273, #1784).** It sat AT the 48-file
  group cap, so the last two discovery policies to come out of `discovery.py` were parked in
  `Orchestration:Core` instead of claimed beside it — `dot_paths.py` (#1784) and
  `exclude_carve_out.py` (#1757). Owner-approved split into `RepoProfiling:Discovery` (24 files),
  the half that runs on every review — the file walk, the grouping of that listing against the
  matrix, the delta map, the committed-plan contract and the tests axis — and
  `RepoProfiling:Profiling` (26 files), the one-time setup and the durable profile it writes: the
  grouping engine, the surfaces/floor model, the committed-config names and trust classes, setup
  flow and proposal, and the catalog data those read. Both parks are reversed — the two modules
  are claimed by `Discovery`, beside the module they came out of and their only runtime caller —
  and `tests/test_matrix_coverage.py`'s 40-file headroom guard is now parametrised over
  `RepoProfiling` as well as `ToolAdapters`, with a second guard so a renamed group cannot make it
  vacuous. Matrix and tests only: no Python module moved.
- **The driver loop waits a bounded backoff before re-launching a failed entry (#2506, #1813).**
  Headless only: `min(2 ** streak, 8)` seconds plus up to 25% jitter before an entry whose last
  launch failed is launched again — 2 s then 4 s, since the per-entry cap of 3 parks it after
  the third — so a transient hiccup no classifier recognises no longer spends all three of its
  launches in seconds. A streak of 0 waits nothing and session mode never waits, a human
  advancing that loop. `runners/outage.py` owns the schedule, the line and the mode check, so
  `orchestrate.py` gained one call and no lines.
- **Every workflow job declares its token posture (#2247, #1784).** A fleet test rejects jobs
  whose effective `permissions:` would come from the repository default, while accepting job
  blocks and workflow-level blocks inherited by every job.
- **The shell lexer's heredoc body index moves to `scripts/shell_heredoc.py` (#2496).**
  A pure move: answers are byte-identical on the 11 corpora and the calibration pool; the lexer
  leaves its 700-line ceiling.
- **A SIGTERM to a hand-run `run_tools.py` now ends its scanner containers (#2507, #1814).**
  `__main__` runs `main` through `procgroup.sigterm_as_interrupt`, as `driver.py` has since
  #2199, so a plain `kill` raises the interrupt the teardown handles instead of ending the
  process at the default disposition and orphaning a `docker run --rm` client. The capture in
  `tools/base.py` now ends the child's tree on any interrupt mid-read, before closing the pipes.
- **A target's `exclude_paths` no longer hides the SEC surface (#1757, AGT-1355709320).** Owner
  ruling 2026-09-25: a target-authored `exclude_paths:` may not take a file the objective SEC floor
  matches out of the SEC domain. Those files are no longer pruned — they form one dedicated
  SEC-only review group, `exclude_paths_sec_carve_out`, whose coverage is pinned to `["SEC"]`; every
  other domain still honours the exclusion and the files join no other group. Disclosed in three
  places: `groups.json` and `meta.coverage.exclude_paths_sec_carve_out` carry the globs, the paths
  and the count, and discovery's stderr line carries the globs and both counts. The report block
  renders as one line in the Markdown and HTML coverage sections. Absent when nothing is
  committed, `count: 0` when globs carved nothing. `--pr` mode is identical, the tool axis is
  untouched, and the `/helm/` `/k8s/` substring half of SEC-71240568 was already fixed by #1838.
- **The security workflows' pull-or-build step can now finish its fallback build (#2509, #1818).**
  In `security.yml` and `security-fork.yml` the step ceiling equalled the 600 s pull deadline, so
  a stalled pull left the local build zero seconds; the ceiling is 25 min (pull 10 + a measured
  ~11 min build + margin), under the job's 30, and a test pins the inequality.
- **A provably broken diff-hunks artifact now turns the delta gate INCONCLUSIVE (#2405, #1783).**
  On an ACTIVE delta under `--gate-scope on-diff`, a non-zero `paths_emptied_by_drops`, a non-zero
  `ranges_dropped` or a set `payload_malformed` refuses a PASS for a run carrying gate-eligible
  findings — the map that chose the gate's scope is provably damaged. It is the
  `zero_hunk_gate_gap` posture (#2178, narrowed by #2222) over a map that still carries ranges,
  which in practice means the two drop arms: the older rule wins when both hold, and the one
  `payload_malformed` value an active delta can carry empties the map, so #2178 answers there.
  Knowingly missed: a truncated map whose paths arrived `[]`, which nothing tells apart from a
  deletion-only, binary, mode-only or same-content rename change — the rest of
  `paths_without_ranges` stays disclosed and is never gated on, and the schema descriptions now
  say exactly that.
- **An advisor's differing OCRDb code is recorded, never applied (#2101).** The schema and
  `evidence.apply_verdict` always said so; `apply_verdict_quality`, later in the live call order,
  rewrote the finding's `code` from the same value that record holds, so each step read correctly
  alone. It no longer reads the verdict's `code` at all, and the two fields that described the
  mutation are retired: the finding's `code_corrected_by` and
  `meta.coverage.ocrdb.code_corrections`. The catalog-strain signal still reads
  `provenance.advisor_code`, and the advisor prompt now asks for a second opinion rather than a
  correction. The rejection/backup policy is unchanged, and severity is still mutated only by the
  override discipline -- now measured against the PUBLISHED code's default, so a reason-less
  override reverts to the panel's code rather than to the advisor's.
- **nvd-cache.yml no longer publishes a database whose sync the deadline killed (#2508, #1818).**
  `timeout` exit statuses 124 and 137 now fail the sync step; other non-zero statuses stay
  tolerated as per-record errors and the DB is verified by the size floor as before.
- **Five flat-import fallbacks now catch `ModuleNotFoundError`, not `ImportError` (#2510, #1824).**
  `score_gate`, `host_disclosure`, `diff_map`, `model_resolver` and `safe_git` spelled the arm one
  class wider than every other fallback, so a package that resolved and then broke inside was
  retried flat instead of surfacing; `tests/test_module_identity.py` now pins the narrow class.
- **`tests/test_citations.py` no longer imports `_version` flat inside a test (#2511, #1824).**
  The module under test binds `scripts._version`; the in-test flat import built a second module
  object, the double-module hazard `tests/test_layout.py` rule 2 exists to prevent.
- **The last `0o755` chmod literal in a test is gone with its dead helper (#2389, #1777).**
  `tests/_test_helpers.argv_through_shell` had no callers after #2161 pinned an absolute
  interpreter; deleting it removes the standing bandit B103 MEDIUM the HIGH-only gate let stand.
- **Direct discovery owns its implicit delta map under the selected repository (#2102).**
  Delta runs without `--out` write `<target>/.panopticon/diff-hunks.json`, and whole-repository
  runs clean that same path. Explicit outputs still keep the map beside `--out`.
- **Tools-image pins move together: semgrep 1.178.0, filelock 4.0.3, starlette 1.7.0.** Dependabot's
  requirements-only bump (#2501) failed the closure test, which ties `ARG SEMGREP_VERSION` to the
  pinned file; both moved here and the wheel digests were regenerated by `bump_pins.py`.
- **The shell lexer reads, or refuses by name, a heredoc delivered inside a substitution (#2331).**
  The body of a heredoc in `$(...)` whose `EOF` and `)` stand on lines of their own is read (#2336).
  A heredoc in a substitution ends at an `EOF)` line, as in bash 5.2, not a later `EOF` (#2343).
- **The workflow guard reads the command and program forms its reviews found unread (#2331).**
  The command behind an `A+=x`, `a[1]=x` or `arr=(a b)` prefix is now read, as `X=1`'s is (#2348).
  The program after option words that follow `-c` is read: `sh -c -e P`, `sh -c -- P` (#2332).
  Values before a shell's program are read: `sh $X 'P'`, `sh $'-c' P`, `-eo pipefail [-]c` (#2344).
  A `$` command word that may be a shell is read: `${X:-sh} -c P`, `$CMD -c P` (#2337).
  A double-quoted `-c` or `eval` program is read as bash hands it, `\$` unescaped (#2342).
  The program an `echo` or `printf` pipes into a shell is read: `echo 'sh tool' | sh` (#2333).
- **Semgrep scans real test code despite target ignore files (#2109, #2055).** The pinned argv
  owns its ignore policy, keeps generated/package-manager exclusions, drops the four default
  test-path exclusions, and applies disclosed `exclude_paths`; live real-Git and non-Git probes
  cover both target ignore formats. The bounded 5,000-result ingest cap retains the measured
  2,274-result self-scan. For the initial baseline transition, CI rescans the exact base commit
  with the new policy, so standing test findings match while PR-added findings still gate.
- **PR worktree reuse parses Git's machine records (#2100).** Acquisition reads NUL-delimited
  porcelain paths, so spaces no longer hide a registered tree or truncate the main-worktree path
  in transport-setting remedies.
- **Golden captures reject image-mount paths (#2261, #1768).** SARIF normalization reads the
  shared scanner mount, capture reroots fixture payloads before verification, and any surviving
  fixture or probe prefix prevents the golden write (a surviving `src/` is a real directory).
- **Reports disclose tool findings that cannot be placed (#2260, #1768).** The JSON counts
  active findings by adapter, the HTML scanner context renders those counts, and the adapter
  contract accepts an empty `location.file` only beside `path_resolution: unresolved`.
- **A literal matrix entry that stops existing now reds (#2454, #1784).** The ~320
  `match:`/`tests:` entries with no glob character are checked against the tree, beside the
  allowlist guard, so a renamed file cannot leave its leaf listing dead text while the file
  itself falls back to a sibling glob; a stale `!` negation is caught the same way.
- **The legacy-only config refusal keeps its own remedy too (#2453, #1784).** A tree carrying
  only `.panopticon/groups.yml` is refused with the `migrate-config` move that fixes it, and no
  longer with "fix it or re-run `driver setup`" appended -- setup refuses that tree outright.
- **`ToolAdapters` gains a `Contract` layer (#2315, #1784).** The adapter base, SARIF
  normalization and their contract tests move out of `Integration`, which sat at the 48-file
  cap; a headroom guard now reds any `ToolAdapters` leaf above 40 before the cap does.
- **The readiness matrix row's remedy fits a refusal that names its own install (#2384, #1784).**
  A config refusal that already names its own remedy (`pip install pyyaml`) no longer has
  "fix it or re-run `driver setup`" appended, which setup could not deliver; every other
  refusal keeps it.
- **Pip-audit uses the shared path-confinement predicate (#2262, #1768).** Requirement
  candidates become absolute before the shared check, so relative target roots still reject
  escaping symlinks; the private duplicate is gone.
- **One `setup_proposal` in a driver-shaped process, at call time too (#2413, #1766).** The
  six lazy sites in `setup_flow` import it through the package inside their function bodies --
  that module has no flat mode -- and `discovery`'s lazy site keeps the guarded flat fallback
  its own flat mode needs, so the grouping engine imports it the same way and the call-time
  census keeps its three named residuals.
- **Adapter and rollback comments describe current behavior (#2190, #1784).** Brakeman's
  fallback explains that it supplies CWE citations when a capture omits `cwe_id`; the existing
  rollback prose already describes termination of registered child process groups.
- **A delta run's fixture disclosure describes the changed set (#2410, #1784).** The
  `--scope-changed` pass starts its fixture-root list empty, so `excluded.fixture_dirs` and the
  stderr line name only roots pruned from the surface the run reviewed, like every other
  disclosure on a delta run.
- **A locus-free finding is legal in the prompt and legible in the gate (#2409, #1784).** The
  domain-panel template now says a repo-wide catalog or coverage gap omits `location` instead
  of inventing a `file`, and the security gate's row prints `?` for a file it does not have,
  as the HTML and Markdown renderers already do.
- **The workflow guard credits a checksum only where its failure stops the step (#2331).**
  A top-level `set +e`, `eval`'d or not, now turns errexit off for the checks after it (#2335).
  A step's `shell:` now seeds errexit and pipefail; a piped check gates only under pipefail (#2338).
  A check ahead of `&&` now clears only what its list runs, unless the list fails the step (#2334).
  `shopt -uo` and `builtin set` turn either off too; bash's `shopt -so` turns one on (#2335, #2338).
  The guard reads `sh "$PWD/f"`, `x=$(sh f)`, `cd s; sh ../f*` and spaced `case` arms (#2345).
  `x=$(curl ...)` then `eval "$x"`, `sh -c "$x"` or `echo "$x" | sh` is now reported (#2341).
- **setup_proposal has one identity in a driver-shaped process (#2256, #1766).** Its three
  catalog imports take the guarded package-first shape its siblings use, so the flat copy every
  setup path reaches binds the same catalog modules the package side does and the import-time
  census's residual shrinks to the modules the flat `--repo-scan` entrypoint still owns.
- **One owner for the container privilege drop (#2150, #1767).** The tool runner, the fixture
  runner and the egress sidecar all splice `scanner_config.privilege_drop_flags`. The daily fixture
  lanes spell the same two flags out, keeping the ceilings exemption the workflow now states. The
  runner's private aliases are gone, so one patch of the owner reaches every launch.
- **A reconcile resume rebuilds the comment it posted (#2157, #1780).** The progress receipt
  records the repo root the scrubbed comment was built under, every body on that plan is built
  under that root, so a resume from another checkout confirms the posted comment instead of
  dead-ending on a body it could never match.
- **Delta runs are capped and disclosed like whole-repo runs (#2376, #2377, #1784).** The
  `--scope-changed` surface is bounded by `DISCOVERED_FILES_MAX`, the `discovery` block says which
  surface its numbers describe (`surface`), and both paths publish what the policy pruned by class
  (`pruned`: dot-path, excluded-dir, `.git` segment; null on the non-git walk, which counts nothing)
  with one stderr line when any count is non-zero.
- **A whole-file finding is legal end to end (#2174, #1784).** The emission envelope no longer
  requires `location` (the report schema never did), `validate_report` warns only on a missing
  `location.file` rather than on every finding without a line, and the security gate prints `?`
  for a missing line like the other renderers.
- **A non-hashable tool_name denies instead of crashing the guard (#2394, #1777).** The write
  and read guards test the tool roster inside their never-crash envelope, so a list or dict
  `tool_name` prints a deny instead of escaping `main` with a non-blocking exit; the read
  guard's envelope comment now calls its early returns permissive.
- **file_issues renders malformed sibling fields as absent (#2398, #1768).** A string
  `citations`, `occurrences` or `additional_loci` value, a non-dict locus and a non-string
  `location.file` no longer abort the filing run, and `reconcile_apply` refuses an unreadable
  source report by name through its own `refusing:` path.
- **Tell a broken rangeless path from a legitimate one (#2386, #1783).** Both delta blocks carry
  `paths_emptied_by_drops`, the subset of `paths_without_ranges` a broken artifact produced, and
  the stderr disclosure names the rangeless paths (first ten, escaped).
- **Repair the artifact-carried delta keys at the read, then pin them (#2382, #1783).** The
  diff-hunks loader reads the seven keys it copies verbatim into `meta.coverage.delta` as null
  when they carry a value of the wrong type, lists them in
  `meta.coverage.delta_artifact.keys_repaired` and on stderr, rejects an unsupported
  `schema_version` as a fourth `payload_malformed` reason, and the report schema now type-pins
  those seven keys.
- **Read the committed config once per discovery run (#2269, #1761).** Exclusion and group
  readers share per-call snapshots, so one resolver disclosure reaches the operator once.
- **Retire the dead rule-id pre-filter (#2366, #1768).** `ingest_tools._rule_id` no longer
  re-filters the fields `evidence.tool_rule_id` already reads totally, and coerces a non-string
  rule id to text before the CWE regex sees it.
- **Escape request-sourced strings that reach a terminal (#2379, #1783).** The dispatch script
  escapes any request-sourced string outside a safe charset (the checkpoint, the progress label,
  the missing-id line), and the driver loop renders its pending-id lists with `%r`.
- **Give unmatched groups a usable readiness remedy (#2268, #1761).** The failed preflight row
  now offers direct repair before the setup command that refuses an invalid committed config.
- **The stored-report path fails loud, not with a traceback (#2372, #2373, #1768).** `file_issues`
  and `evidence` read `location` / `provenance` / `evidence` through the one guarded reader each,
  so those three malformed shapes no longer abort the filing run. `reconcile.load_report` refuses
  unparseable JSON, a non-object report, `meta`, part or discarded-claims sibling and a non-list
  `meta.parts` with one reason naming the file (and the key where there is one), which both CLIs
  print before exiting 2.
- **Name integrity failures in HTML (#2265, #1761).** The NOT CERTIFIED banner renders
  every truthy certification-sinking reason from the shared integrity table.
- **The write guard fails closed when it crashes (#2391, #1777).** `main` now runs the
  interpreter check and the adjudication inside the read guard's never-crash envelope, so an
  unexpected exception becomes a deny response instead of a traceback and a non-2 exit the host
  treats as a non-blocking error -- which let the Write it exists to deny proceed.
- **Keep mixed cross-domain metadata renderable (#2266, #1761).** Summary aggregation sorts
  missing and named cell domains deterministically instead of raising before the report renders.
- **The Claude write guard runs under the driver's own interpreter, and every guard hook runs
  it isolated (#2161, #2163, #1777).** `write_guard_hook`'s registered `PreToolUse` command began
  with the bare word `python3`, and nothing resolved it: the CHILD looks that name up in ITS PATH,
  which `runners/children.py` rewrites through `executable.resolve`, dropping every entry inside
  the review root. An operator whose `python3` came from the reviewed repo's own `.venv/bin`
  therefore armed a hook the child could not start -- and a hook that cannot start fails OPEN, so
  write confinement was off with nothing said. The command now names the driver's own validated
  `sys.executable`, the binding `read_guard_hook` and the Kimi hooks already use, and `install`
  refuses before writing either file rather than arming a hook it cannot start. That refusal is
  computed on ACCESS rather than at import (#2006), because a raise inside the hook process is
  itself fail-open. `-I` now pairs with the pinned interpreter on the Kimi hooks, so a
  `sitecustomize` cannot choose code for a confinement decision (#1996), and their guard
  round-trip probe spawns the tokens of the armed command itself rather than a copy of them, so
  the evidence can no longer describe an argv the per-run config never registered (#2163).
- **Keep HTML evidence disclosures fail closed (#2195, #1774).** The coverage header counts
  the same active findings as its collapsed unverified section, and malformed evidence values
  render there without crashing.
- **Surface dropped token-ledger inputs (#2171, #1782).** Usage collection counts a present
  non-object `usage` value in its existing drop tally, and successful driver-side collection
  forwards the bounded collector disclosure to stderr.
- **A diff-hunks path with no ranges is disclosed (#2381, #1783, ARC-B8 follow-up).** A map that
  NAMES a path and gives it no range -- `{"a.py": [[1, 5]], "c.py": []}` -- classified every
  finding in `c.py` as on-diff and nothing anywhere said so: the loader drops nothing (an empty
  list is well formed), both #2169 loss counters read zero, and the two whole-map disclosures
  need `hunks_ranges: 0`, which `a.py`'s one real range denies. It is the only FAIL-OPEN shape in
  this family -- under the default `--gate-scope on-diff` those findings reach the gate's source
  set as if the diff had touched their file. A third counter now publishes it,
  `paths_without_ranges`, in `meta.coverage.delta` and `meta.coverage.delta_artifact` alike, plus
  one stderr line naming the count and the artifact. Classification is UNCHANGED on purpose:
  `diff_map.parse` emits a rangeless key for a file the diff changed without ADDING a line -- a
  pure deletion, a binary or mode-only change, a 100%-similarity rename -- and deleting a line
  can introduce a finding (a removed check), so classifying it on-diff is that module's
  documented contract. What was wrong is that a truncated or hand-edited map is
  indistinguishable from that legitimate shape; the counter is the input a later gate rule would
  need to tell the two apart.
- **Share reply publication and artifact roots (#2346, #1820).** Reply persistence uses the
  common atomic JSON writer, which cleans opened staging files after failures and leaves
  rejected paths untouched. Writers and reply placement share lexical root discovery while
  preserving their distinct symlink policies.
- **Use current OCRDb domains in synthesis test filenames (#2253, #1765).** Inert fixtures now
  use uppercase domain codes; explicit rejection fixtures retain the retired spellings they test.
- **Bind report domain enums to the runtime roster (#2347, #1821).** Contract tests cover the
  report, X0X and strain schemas, including coverage cells that exclude the domainless sentinel.
- **`driver readiness`'s gating `dependencies` row is reached for every runtime package (#2369,
  #1784).** The row names an absent `pyyaml`, `defusedxml` or `jsonschema` with its `pip install`
  before the first paid dispatch, and it printed for `jsonschema` alone. Four modules on the
  driver's own import path imported a third-party package at MODULE level: `tools/spotbugs.py`
  (`defusedxml`, reached through `scripts.tools`'s package body, which imports every adapter, which
  the host probes import) and `setup_flow.py`, `discovery.py` and `setup_proposal.py` (`yaml`). A
  checkout thinner than `pyproject.toml` therefore got a `ModuleNotFoundError` traceback out of
  `import scripts.driver` and no document at all — loud, and it named the package, but it was not
  the preflight. Each of those imports now sits inside the function that uses it, with no fallback
  and no `except ImportError:` arm, so a missing package still raises loudly from the one call that
  needs it (#2363); `ADAPTERS` stays a plain `dict`, since three test modules `mock.patch.dict` it
  and `capture_goldens.py` enumerates it. `repo_config.read_document` now REFUSES the document when
  `pyyaml` is absent rather than raising through `phases/readiness._matrix_row` and
  `setup_flow._check_groups_manifest`, both of which document that they never raise. Two guards
  pin the property. `tests/phases/test_readiness_verb.py` blocks each of the three packages in a
  child interpreter and reads the row back: exit 1, `missing` is exactly that pip name, and no
  `Traceback` on stderr. `tests/test_workflow_pins.py` asserts by AST that no module the driver's,
  `run_tools`' or `security_gate`'s import chain loads names a non-stdlib, non-local module at
  module level. It walks every statement not inside a function body — `try`/`except*`/`finally`,
  `if`, `with`, `for`, `while`, `match`, `class` — rather than enumerating shapes worth descending
  into, because a guard that knows six shapes is a guard the seventh walks past; a module-level
  `try:`/`except ImportError:` is refused not because it needs the package at import time (it does
  not) but because an except arm that rebinds the name is the fallback #2363 forbids and one that
  passes leaves the name unbound for a `NameError` at first use, while an unguarded import takes the
  row down. It selects the modules by FILE rather than by `sys.modules` name, which is how the
  fourth offender was found at all. The same file's gate-closure guard now ALSO reads those IMPORTS,
  beside the `RUNTIME_PACKAGES` proxy it keeps: every third-party module those chains import, nested
  ones included, maps through `importlib.metadata.packages_distributions()` to a distribution pinned
  in `.github/requirements-gate.txt`, and its PEP 503 normalisation is now the full `[-_.]+` fold.
  The two cover different sets and both are load-bearing — the gate's chain imports `jsonschema` and
  `defusedxml` but never `yaml`, so the proxy is the only guard keeping `pyyaml` in the closure.
- **A rejected diff-hunks artifact is disclosed in the report (#2169, #1783, ARC-B8 follow-up).**
  Three gaps the B8 disclosure left. An unreadable or non-object `diff-hunks.json` yields a payload
  with no `base`, so the review degrades to a non-delta one and `meta.coverage.delta` is null --
  the same null a run that was never passed `--diff-hunks` writes; only stderr said otherwise, and
  a `driver run` keeps a child's stderr only on failure. The loader counted a whole lost path (a
  `hunks` value that is not a list) as `ranges_dropped += 1`, the same as one malformed pair, so a
  lost file read as a lost line range -- yet every finding in that file classifies off-diff, which
  a narrowed file does not. And `meta.coverage.delta` was `{"type": ["object","null"]}` with no
  `properties`, so `tests/test_schema_parity.py`'s walk treated it as a deliberately open leaf and
  never descended: fourteen keys with no schema entry and no parity coverage, #1602 in miniature
  inside #1602's own guard. So: a sibling `meta.coverage.delta_artifact` --
  `payload_malformed`, `ranges_dropped`, `paths_dropped` -- an object whenever a `--diff-hunks`
  path was GIVEN and a read attempted, active delta or not, and null when none was, so its
  presence alone is the fact; a separate `paths_dropped` counter in the loader, in both report
  blocks, in the one stderr line and in the zero-hunk certification reason, which now names a
  loader drop as the cause instead of calling it indistinguishable from an empty change; and
  every key of both blocks pinned under `properties` with a description, with a parity test that
  the schema's pinned key set EQUALS the key set the fixture's report emits, so the open leaf
  cannot return silently. `meta.coverage.delta` itself is untouched, and its sibling's schema
  node states that contract. The seven values the block copies verbatim out of the artifact are
  described but NOT type-pinned -- a schema error is terminal (`ARTIFACT_INVALID`) and nothing
  normalizes them at the read, so pinning them would let a hand-supplied artifact end a paid-for
  run; the driver's discovery phase rewrites or removes that file, so the exposure is the direct
  `synthesize.py --diff-hunks` path rather than a `driver run`. #2169's third gap asked for the
  walk, and the pin that closes it stops at the keys this controller computes; #2382 is the
  follow-up that normalizes those seven at the read and then pins them. Still out of scope, as
  #2169 says, and now filed as #2381: a partial map naming a file with no ranges
  (`{"c.py": []}`) classifies every finding in it on-diff with no warning, a fail-open this
  change does not touch.
- **`dispatch.js` refuses an unenforced entry that names a shell, and every refusal escapes the
  entry id (#2166, #1783).** `loop_batch.refuse_misrouted` calls its two shapes "the same
  statement read from either side": an enforced entry whose agent is not the checkpoint's shell,
  and an UNENFORCED entry that names a shell at all — the phases set `agent` to null on those, so
  a name on one is a claim the run never made. B7 (#2154) taught the session-mode Workflow script
  only the first half, so `{enforced: false, agent: "panopticon-domain-panel", model: "opus"}`
  hand-copied into `args.entries` ran on `model` with no refusal and no log line. The validation
  loop now refuses it too, beside the other half and before any `agent()` call, so no entry in
  the batch launches. The same loop's refusals also interpolated `e.id` raw where
  `loop_batch.misroute_refusal` deliberately uses `%r`: the id is read out of the dispatch
  request, a file in the reviewed tree, so a control character, an ANSI escape or an embedded
  newline in it reached the operator's terminal as bytes the terminal acts on. Every refusal in
  the loop that prints an id now prints it through `JSON.stringify`. The enforced/unenforced
  dispatch branch itself is unchanged: validation now leaves it reachable only by the two shapes
  it was written for. The workflow checks SHAPES only — which shell a checkpoint may name is
  `refuse_misrouted`'s check, one level up — and `agent: ""` reads as absent on both halves of the
  JS statement, where `refuse_misrouted` treats it as a claim.
- **`--scope-changed` asks the same dot-path policy `--repo-scan` asks (#2272, #1784, ARC-F2E).**
  The delta path built its reviewed set from git-diff output, pruned fixture corpora and committed
  `exclude_paths`, and stopped -- it never asked `dot_paths.allowed`. So a tracked, CHANGED
  `.hidden/a.py`, `.venv/lib/x.py` or `.mypy_cache/b.py` -- and a changed `node_modules/c.js` in a
  target that tracks it -- was reviewable surface under `--scope-changed` while `--repo-scan` pruned
  it; #1136's comment at that caller already named this class of delta-path divergence. The branch
  now goes through the SAME `_filter_reviewable` with the SAME arguments as the whole-repo listing,
  so the one dot-path policy, `EXCLUDE_DIRS`/`EXCLUDE_DIR_GLOBS` on every ancestor segment, the
  fixture prune (#434) and the `.git`-segment drop hold under delta review too -- and so does the
  drop of a changed TRACKED symlink, which `--repo-scan` already dropped (`_is_confined_regular`
  is the shared `isfile`), so a target that tracks symlinks loses those files from a delta review.
  The instance a target hits unless it gitignores that directory: a delta run no longer reviews its
  own untracked `.panopticon/` run artifacts, which used to arrive as an `Ungrouped` cell of nothing
  but run output, with a scout checkpoint spent on it; the run now advances through the remaining
  phases instead.
  The delta path now feeds the same `pruned_fixtures` list, which stays whole-repo-scoped because
  the listing runs first and the changed set is a subset of it: a delta run's
  `excluded.fixture_dirs` equals the whole-repo prune, unlike `excluded_count`, which #1136
  re-derives from the changed set. Two divergences remain and are NOT touched here -- the delta call
  skips `_cap_discovered`, so the `discovery` block still describes the whole-repo listing on a
  delta run (#2376), and prunes are silent on both paths (#2377). A parity test pins AGREEMENT
  rather than a second copy of the policy: over one tree carrying every dot-path shape
  `dot_paths` distinguishes, plus a tracked symlink, the delta set must equal `--repo-scan`'s OWN
  output intersected with the changed set.
- **Discovery's git failure and truncation reach the report (#2271, #1784, ARC-F2E).**
  `discovery.py` records `method`, `files_seen`, `files_truncated` and `git_failure` in the
  `discovery` block of `groups.json` and prints the last two on its OWN stderr. On the driver path
  `phases/discovery.discovery_execute` runs the child through `child._run_child` -- both streams
  into bounded buffers -- and reads that stderr only when `groups.json` is MISSING, and no synth
  module, renderer or schema read the block. So on a successful `driver run` both disclosures were
  captured and dropped: a git-listing failure was a silent downgrade to a raw walk that does NOT
  honour the target's `.gitignore` ("this run's surface may be far larger than the target's own"),
  visible only to whoever hand-ran `discovery.py`. Two new `meta.integrity` keys carry them now --
  `discovery_git_failure` (the reason, else null) and `discovery_files_truncated` (an integer on
  every scan, `0` included; null = no discovery block, not measured) -- threaded from the parsed
  `groups.json` through `PlanInputs.load` on the same seam as `plan_owed` / `plan_sha256`, and
  rendered by the existing `INTEGRITY_KEYS` loop as `**Note:**` lines. THE RULING: both are
  NON-GATING, the same precedence the truncation disclosure already had, because the reviewed
  surface is a SUPERSET (git failure) or a PREFIX (truncation) of the intended one and the artifacts
  on disk are still what they claim to be, which is what this section measures. THE DISSENT,
  recorded so the owner can flip either `sinks` in one line: a surface "far larger than the target's
  own" is arguably not a run that should certify at all. Both values are isinstance-guarded at the
  publish boundary (`groups.json` is target-writable, and a bool is not an integer where `integer`
  is pinned), and the failure string is git's stderr, so it goes through `evidence_text`'s
  `inert_text` wrap like every other free-text slot. `method`, `exclude_paths` and `ungrouped_files`
  stay run artifacts in `groups.json` only; this surfaces the two that name a DEGRADED run.
- **One guarded `location` reader in `evidence.py`, so a malformed stored finding no longer aborts
  the cross-run diff (#2365, #1768, ARC-A4A).** `finding_fingerprint`, `matrix_finding_id`,
  `reconcile_key` and `_queue_tiebreak` each carried their own `finding.get("location") or {}`, and
  `reconcile.iter_records` a fifth copy. `load_report` is a plain `json.load` with no schema check,
  so a stored report holding `"location": "a.py"` reached `.get("file")` and aborted the WHOLE
  cross-run diff with `AttributeError` -- exactly the blast radius #2359 closed for `tool_evidence`,
  in an idiom that had by then recurred four times. All five sites read `evidence.location_of` now,
  which hands back the dict or `{}`, so a non-dict `location` keys precisely as an absent one does.
  `iter_records` also skips a non-dict `findings[]` entry instead of raising on it, printing one
  counted `reconcile: skipped N non-dict <key> entries` line to stderr per section, because a
  silently dropped claim is a disclosure gap; and a `findings` or `discarded_claims` section that is
  not a list reads as empty in `load_report` and in `iter_records`, and counts nothing. An AST guard
  in `tests/test_evidence.py` walks `evidence.py` and fails if `location` or `tool_evidence` appears
  as a constant anywhere outside its one reader, in any idiom -- subscript, `.get`, `.pop`,
  `.setdefault`, `in`, or a constant bound to a name -- a subscript write excepted. The honest
  limits: that guard covers `evidence.py` alone; `phases/review.py` and `security_gate.py` keep the
  idiom on adapter-constructed findings, whose `location` is always a dict an adapter built, so
  those are safe by construction, but `scripts/file_issues.py` -- the other consumer of this same
  `load_report` -- still carries it and is tracked as #2372; and one layer up, a report whose top
  level is not an object or whose `meta.parts` is not a list still aborts in `load_report` itself
  (#2373).
- **The spotbugs adapter imports `defusedxml` unconditionally; the silent stdlib fallback is gone
  (#2363, #1784, ARC-F2E).** `tools/spotbugs.py` opened with a `try`/`except ImportError` that
  rebound `ET` to `xml.etree.ElementTree`, so a declared, readiness-gated dependency -- listed in
  `pyproject.toml`'s `[project] dependencies`, pinned in `requirements-tools.txt` and gated by
  `readiness_checks.RUNTIME_PACKAGES` -- was in practice optional hardening, downgraded with no
  stderr line, no manifest row and a `nosec` that silenced the scanner along with it. The paths that
  never run readiness were the exposure: the CI gate `security_gate.py`, which imports
  `ingest_tools` and through it every adapter, and a resumed run whose `readiness.json` already
  recorded `ready: true`, both parsed an untrusted scanner report with internal-entity expansion
  enabled. The import is bare now, so a missing package fails at import naming `defusedxml` on every
  path -- readiness included, because the driver reaches the adapter package through its host
  probes, so the gating `dependencies` row is reached only for `jsonschema` until #2369 makes it
  reachable for all three; SKILL.md and the `RUNTIME_PACKAGES` comment say so rather than crediting
  the row. Only one environment had to learn the package: the tools image already ships
  `defusedxml==0.7.1`, and `.github/requirements-gate.txt` now pins it too, so the `scan`,
  `fork-scan` and adapter-integration steps that import the adapter package under
  `--require-hashes --no-deps` keep importing -- with a new `tests/test_workflow_pins.py` guard
  holding every `RUNTIME_PACKAGES` pip name to that closure. The `# nosec B314` on `ET.fromstring`
  went with the fallback, since bandit does not flag the defused call, and the adapter test that
  pinned the fallback as working now asserts the import raises instead.
- **A dropped tool member's `occurrences` and `additional_loci` move onto the surviving finding
  (#2361).** Sub-issue of #1768 (ARC-A4A), and the bug the #2353 review reproduced -- that PR's
  parity fixture had to pick two lines no agent claimed to keep the key reachable at all.
  `synth/findings.aggregate_tool_findings` deliberately parks an aggregated survivor on a locus an
  agent also flagged, so `synth/corroborate.dedupe` reinforces the pair -- and dedupe keeps the
  MORE SEVERE member, usually the agent finding, whose `_reinforce_merge` copied cvss, scenario,
  impact, remediation, references and citations but not the aggregation. So an agent flagging one
  of a rule's lines silently retired that rule's other loci and its count: nothing in the report
  said the rule had fired more than once, and `scripts/file_issues.py`, which renders both, had
  nothing to render. A new `_carry_aggregation` moves the pair, and only where the aggregated
  member actually LEAVES the report: dedupe's exactly-two tool+agent merge and its per-category
  sub-bucket drop loop (which runs whether or not the category has an agent member -- the carry
  is a property of the drop, not of corroboration) carry it, while the per-category
  representative merge does NOT -- that tool
  finding survives its own rule bucket and reaches the report, so carrying there would have two
  entries claim one pair of hits, on an entry that does not even alias the source. It carries only
  when the dropped member is tool-sourced (an agent finding can declare either key) and in the
  survivor's category (one rule's loci are not another issue's), only a well-typed non-empty locus
  list and a count above one moving as ONE unit, and only onto a survivor with no aggregation of
  its own -- which keeps it, never a sum (#2225: two artifacts at one manifest locus are two
  issues). Honest limit, unchanged here: the absorbed tool member's rule id is not disclosed
  anywhere in the report -- `_merged_ids` carries its finding id for verdict binding only and is
  stripped before the artifact is written.
- **One guarded reader for `tool_evidence`, so a malformed stored finding cannot abort `reconcile`
  through the rule id (#2359, #1768, ARC-A4A).** The low follow-up #2358 left behind: that change
  guarded the field's read in `artifact_term`, while `tool_rule_id` still read the same field --
  and its `provenance` fallback -- with `(finding.get(...) or {}).get(...)`, which raises
  `AttributeError` on a string or a list. Nothing validates a report read off disk
  (`reconcile.load_report` is a plain `json.load`) and `iter_records` fingerprints EVERY record of
  a prior run through `finding_fingerprint`, which reads the rule id, so one schema-invalid finding
  in a stored report aborted the whole cross-run diff with a traceback instead of keying as
  rule-less. `evidence._tool_evidence` is now the single reading of the field for both functions
  (`{}` for absent or malformed), the provenance fallback is guarded inline the same way, and a
  dict-valued field reads exactly as before.
- **SKILL.md's dependency list now matches the gating readiness row -- `defusedxml` was missing
  (#2323, #1784, ARC-F2E).** SKILL.md's § Dependencies named `pyyaml` and `jsonschema`, so a
  checkout that installed exactly what the doc listed failed `driver readiness`'s gating
  `dependencies` row on `defusedxml`, one of the three packages
  `readiness_checks.RUNTIME_PACKAGES` checks -- and a missing package is the one readiness failure
  a fresh checkout meets first. The paragraph now names all three and says how each is absent
  differently: `pyyaml` takes discovery down with a traceback, `jsonschema` fails closed after the
  whole review has been paid for, and `defusedxml` is caught only by the readiness row itself --
  which, being `PHASES[0]`, refuses to start the run -- because nothing in the scan would fail:
  `tools/spotbugs.py` falls back to the stdlib XML parser, which expands the internal entities
  `defusedxml` refuses, so an ingest driven outside the loop (the CI gate `security_gate.py`, which
  imports `ingest_tools` and never runs the readiness phase, or a resumed run whose
  `readiness.json` already recorded `ready: true`) parses an untrusted scanner report with the
  hardening silently gone. Golden capture also imports it, unguarded, but runs outside a review
  rather than in one. A new `tests/test_skill_md.py` case reads
  `RUNTIME_PACKAGES` and asserts the section names every pip name in it, so a package added to the
  gating row cannot skip the doc again.
- **`additional_loci` described in the report schema and walked by the parity fixture (#2353).**
  Sub-issue of #1768 (ARC-A4A), and the LOW the #2225 review left: the sibling key `occurrences`
  got a schema entry and a fixture value, `additional_loci` got neither.
  `synth/findings.aggregate_tool_findings` stamps it with the other loci one rule fired at in one
  file before collapsing them into one finding, and nothing described it, so no consumer could
  validate against it -- and #1602's parity walk stayed green because the fixture's SARIF had one
  hit per rule per file, so no finding ever carried the key. That SARIF now fires B602 twice in
  the reviewed file, at two lines no `_agentic` finding claims: an aggregated survivor sharing an
  agent's locus meets dedupe's tool+agent reinforce-merge, whose survivor is the more severe
  member (here the HIGH agentic finding), and the key would reach no artifact at all.
  `discarded_claims[]` items `$ref` the findings item schema, so the one entry covers both
  sections.
- **The `bandit`, `gitleaks` and `trivy` goldens are re-captured, and the provenance ratchet is
  empty (#2313, #1784, ARC-F2E).** Part (b) of ARC-168995033, and the half that needed docker: the
  three were captured through `panopticon-tools` with `--network none` against a SYNTHETIC corpus
  mounted at `/src` -- an `app/main.py` of textbook bandit offences, an `app/settings.py` of
  invented tokens, a fake `app/deploy_key.pem`, and a known-vulnerable node lockfile for trivy --
  so no committed golden names `/mnt/panopticon` or an operator worktree any more, and gitleaks'
  snippets are the scanner's own `REDACTED`. `tests/test_goldens_provenance.py` `PENDING` is now
  `frozenset()`; the ratchet's stale-entry half is what proved each re-capture, failing on all
  three until the entries came out. The normalization contract, the legacy-SARIF severity tests
  and the security gate's non-vendored/vendored pair all hold on the new bytes.
- **`finding_fingerprint` and `reconcile_key` carry the artifact term (#2352, #1768, ARC-A4A).**
  Follow-up to #2225: the two stages that COLLAPSE tool findings learned that one advisory against
  two artifacts at one manifest locus is two issues, but the two IDENTITY functions did not. Two
  vulnerable jars sharing one CVE at `pom.xml:1` hashed identically, so the verify queue handed the
  second one a `<fingerprint>-1` suffix and logged a collision for a pair that is two real
  vulnerabilities; `reconcile.py` recomputes both keys on both runs from today's algorithm, so a CVE
  newly matched against a second jar in run 3 was read as the FIRST jar recurring from run 2 -- a
  new vulnerability reported as a standing one. Both identities now append
  `tool_evidence.package_name` when the finding names an artifact, and one definition,
  `evidence.artifact_term`, is the only reading of that field: it serves both identities and
  replaces the inline copy each collapse stage carried (`synth/findings.aggregate_tool_findings`
  and `synth/corroborate._by_package`, behaviour unchanged). A finding naming no artifact -- every
  SARIF-path and agent finding, and one carrying an empty or non-string value -- keys byte-for-byte
  as it did before the term existed. The `--pr`/delta gate needed NO change and got none:
  `security_gate.finding_identity`'s fourth element is the whitespace-collapsed TITLE, which
  dependency-check starts with the jar name, so two artifacts were already two gate identities --
  now pinned by a test. The same one-locus shape reaches `osv-scanner`, `pip-audit`, `npm-audit`,
  `cargo-audit` and `bundler-audit`, which the one definition covers by construction.
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
- **Catalog rows for `.bandit` and two unlisted eslint spellings (#2330, #1784, ARC-G1B).** Owner
  ruling 2026-09-28 on #2274: a root dot-file no shipped catalog NAMES stays invisible BY DESIGN,
  and the remedy for a wanted one is a catalog row per spelling -- never a widened stem.
  `skill/data/commons_catalog.yml` `Config` gains `.bandit`, `.eslintrc.cjs` and `.eslintrc.yaml`,
  and `skill/scripts/dot_paths.py` `FILES` gains the same three, so this repository's own `.bandit`
  -- named by neither the catalogs nor the SEC floor, and therefore reaching no group at all -- is
  reviewable surface; with no committed `Config` group in `panopticon.yml` it is claimed by the
  Commons catalog's `Config` category, which in this repo folds into the reported `Commons` group,
  so the next self-scan carries one more file there and a reviewer may now question this repo's own
  bandit `skips=`. The ruling named `.eslintrc.mjs` too; it is not a spelling the legacy cascade
  reads (`.mjs` is flat config, already claimed as `eslint.config.mjs`), so no row. `.eslintcache`
  stays out: the family is still spelled name by name (now seven) precisely to keep generated state
  pruned.
- **The zero-hunk delta gate counts only what the gate would have judged (#1783, #2222, follow-up to
  #2178).** Owner ruling 2026-09-28: the refusal is a statement about findings the empty hunk map
  hid FROM THE GATE, so `delta.zero_hunk_population` re-applies this run's own two policies to the
  active set -- the evidence policy `verdicts._partition_gate` applies, then the `--fail-on` floor,
  which becomes `findings.severity_floor_admits` so the gate and this count have ONE spelling of it
  (`grading.gate_verdict` is now that predicate under `any()`) -- and never the delta scoping that
  empty map broke. Two runs that read INCONCLUSIVE now PASS: an empty `--changes` map whose only
  active findings sit below `--fail-on`, and one whose findings are all unverified under the default
  `confirmed_only` policy. A CONFIRMED finding at or above the floor still reads INCONCLUSIVE, an
  OFF gate is still preserved, and the `coverage_note` clause now says `gate-eligible` instead of
  `active`.
- **dependency-check locates a finding at the build manifest, not the jar (#2225, #1768,
  ARC-1020240040).** The scanner analyses ARTIFACTS, so `location.file` was
  `angus-activation-2.0.1.jar` -- a name that exists nowhere in the reviewed repository, and the
  delta/`--pr` gate, the tool-verify advisor's read grant, grading's group attribution and every
  exclude glob all resolve that against the repo root. Owner ruling: MANIFEST PROXY. The location is
  now the build manifest the scan audited, resolved `pom.xml` -> `build.gradle` ->
  `build.gradle.kts` (`BUILD_MANIFESTS`, the same tuple `is_applicable` selects on) through the
  two routes and the last resort `tools/pip_audit.py` already uses -- the manifest `invoke`
  recorded, else the first one under the root `ingest_tools` names around its parse, else
  `DEFAULT_MANIFEST` ("pom.xml") for a caller holding bytes and no tree. The jar still names the
  vulnerable artifact in `title`, `impact` and `tool_evidence.package_name`; a dependency's
  `includedBy` references are surfaced as `tool_evidence.included_by`, which is EVIDENCE ONLY and is
  never used as a location whatever the tool emits in it -- inert (`inert_text`, like every other
  target-authored string) and bounded to 16 entries with a marked cut, and described in
  `report-schema.json`. Two vulnerable artifacts that share one advisory used to collapse to ONE
  finding once they arrived at the same manifest locus, and BOTH stages that collapse tool findings
  now carry the artifact: `tool_evidence.package_name` joins the aggregate key in
  `synth/findings.aggregate_tool_findings` (which ran first and merged the pair into one
  `occurrences: 2` finding) and splits the rule bucket in `synth/corroborate.dedupe`. Findings
  naming no artifact keep their single bucket at both stages -- every SARIF-path and agent finding.
  `line_start` stays 1 and no argv byte, cwd or `-w` changed, so no real-image round is owed. The
  `PATH_DEBT` register in `tests/tools/test_normalization_contract.py` is empty again: the entry and
  the self-liquidating expiry test that owed it are gone, its meta-tests hold on the empty register.
- **The virtualenv scope leaves `run_tools.py` (#1762, #2306, ARC-2609514778; part 4).** Finding the
  virtualenvs under the target (`pyvenv.cfg` plus the SHAPE of an environment, depth-bounded and
  confined), deciding which of them a scanner's exclusion knob may be handed (the security mode, the
  name allowlist) and rendering that onto each tool's argv move to `skill/scripts/venv_scope.py`
  whole; the rows it produces are still published by `tools_manifest.write_manifest`, and
  `ingest_tools` imports its `has_venv_shape` and `VENV_MARKER` so the scan side and the ingest side
  cannot drift. `run_tools.py` goes from 1136 to 838 lines and the new module is 376, under the
  700-line ceiling; the pin STAYS in `tests/test_flat_module_ceiling.py`, lowered to 838, holding
  docker detection, language detection, selection, the argv and the CLI. No argv byte, no manifest
  row and no message changed -- `tests/test_venv_scope.py` compares the walk, both partitions and
  twenty-four argv shapes (every tool with a repeatable knob, bandit's comma-joined value, a tool
  with none; zero, one and two directories; `target` set and unset) against a golden captured before
  the move, and the patch-rule guard derives all four modules' names from their own ASTs.
- **Malformed OSV and Roslyn records disclose partial coverage (#2105).** Usable sibling
  findings remain available to reports and the security gate. Bounded diagnostics and coverage
  facts distinguish malformed records, including those without an identifiable source file,
  from valid empty results. Invalid top-level capture containers fail ingestion.
- **Separate verdict resolution stages (#2318, #1826).** Matching, evidence and gate partitions
  retain fingerprint identity, delta scope, accounting and suppressed-finding policy.
- **Separate reconciliation decisions (#2317, #1826).** Indexing, recurring matches and close
  checks retain coverage guards, reason text, collision disclosure and output ordering.
- **Share staged report publication (#2316, #1820).** Clean partial staging writes before
  propagating failures; publish report siblings before the main report.
- **A HIGH a verbatim extraction MOVES is pre-existing (moved), not new (#2309).** The pre-merge
  gate's delta pass keys on the path, so a refactor that relocated a `docker kill` call reddened the
  required `scan` check on a diff that changed no behaviour (#2305). After the exact pass, a head
  finding still counted new pairs with ONE unmatched base finding of the same tool, rule and message
  — one the base carried one more copy of than the head has here — and prints under its own
  `pre-existing (moved: …)` heading. One orphan excuses one occurrence: a second copy, or any
  occurrence the base has no orphan left for, is still new and still gates, and the pairing never
  crosses the suppression (a vendored orphan cannot excuse a first-party finding). What it
  establishes is a COUNT, not a verified move; `DEVELOPMENT.md` says what that leaves invisible. The
  strict route's verdict line is byte-identical.
- **roslyn-secguard cites the vendor's CWE for all 31 DotnetariumSCS rules (#1795).** SCS0026 is
  CWE-90 (LDAP injection), not CWE-79 (cross-site scripting, which is SCS0029); 23 of the 31
  rules shipped uncited, and SCS0041 never existed. A test now pins the table's version to the
  Dockerfile's `ARG DOTNETARIUM_SCS_VERSION` pin.
- **Per-repo configuration moved to a root `panopticon.yml` (#1681).** BREAKING for an existing
  tree: the committed matrix lives at `<repo>/panopticon.yml` (or the read-only alias
  `.panopticon.yml`) under `version: 1` with `groups:`, `exclude_paths:` and `settings:` keys, and
  `.panopticon/` now holds run artifacts only. `.panopticon/groups.yml` is no longer read by any
  phase — alone it is an error naming the remedy, beside a root config it is disclosed and ignored —
  and `.panopticon/config.json` is no longer read either, its keys having become `settings:`.
  `python3 skill/scripts/driver.py migrate-config <repo>` writes the root file from the legacy one,
  preserving committed order, refusing if a root config already exists, and leaving the old file for
  you to delete.
- **The single-stage tools image is a decision, and its split is 5.3's (#1772, #2242).** Every
  toolchain installs into one stage, so one upstream break fails the whole build; the accepted cost
  is written down in `Dockerfile` and `DEVELOPMENT.md` now, with 5.3's brief (one stage per
  toolchain, still one published image).
- **Documentation corrections where a reader looks (#2238, #2239, #2240, #2241, #2242, #2243,
  #2244, #2245).** Comments, docstrings and guide prose the code had outgrown: the `nvd-cache.yml`
  workflow ordering claim, the packaging intent in `pyproject.toml`, `integrity._plan_hash`'s
  vanished twin, what `RunResult.denials` counts per host family, why the driver re-derives
  synthesize's verify queue, what else shares synthesize's exit `2`, the `dependencies` gating row,
  the eighth evidence status, and `synthesize.py`'s "stdlib-only" claim. Two of these are pinned:
  `readiness.GATING_ROWS` against the guide's gating sentence, and
  `evidence.EVIDENCE_STATUSES`/`GATE_ELIGIBLE_DEFAULT` against the evidence chapter.
- **Parity pins for the mirrored tables, the fixture corpus and the goldens (#2234, #2235, #2236,
  #2237).** Four LOW/MEDIUM findings, one shape: a definition kept in two places with nothing
  comparing them. `sarif_utils`' hand-mirrored fixture corpus is pinned against `discovery`'s,
  value for value and predicate against predicate, so the #434 tool/agentic parity is a test and
  not a comment (ARC-1496429894). The four parallel legacy-SARIF tables -- `LEGACY_SARIF_TOOLS`,
  `TOOL_CMD`, the registered `LegacySarifAdapter` rows and `sarif_utils.PREFIX` -- are asserted
  EQUAL, as are the tool registry and the recommendable set, which closes the directions nobody
  had pinned (ARC-3428598333, ARC-1125964489). `file_issues` derives its two label tables from
  `evidence.SEV_ORDER`/`EVIDENCE_STATUSES` instead of hand-copying them, and now RAISES on an
  unknown severity or evidence status: a ninth status used to be filed as `evidence:unverified`,
  a label asserting the opposite of what happened (ARC-1576523829). `x0x_report` and
  `strain_report` share one gap predicate and one roster clamp (`ocrdb.is_fallback_code`,
  `ocrdb.clamp_domain`), so `is_fallback` is now CASE-INSENSITIVE and whitespace-stripped, and
  strain's published `domain` can no longer leave the roster enum that its own schema declares
  (ARC-101960059). A `domain` claim that is not a roster domain is still clamped to `ZZZ` and
  disclosed, never reinterpreted as the domain before its first hyphen -- `clamp_domain` validates
  a domain and `roster_domain` is the wrapper for a caller holding a code. `cross_domain` is
  decided on the RAW claims (`ocrdb.domain_claim`), not the clamped ones: two codes claiming two
  different off-roster domains are cross-domain strain, and comparing clamped values would publish
  "same domain". And `tests/test_goldens_provenance.py` refuses any file under `tests/goldens/`
  that names `/mnt/panopticon` or a `.worktrees/` path segment -- no per-file exemption; the
  directory's README was reworded so it no longer needs one -- with today's three offending goldens
  (`bandit.raw`, `gitleaks.raw`, `trivy.raw`) in a shrink-only `PENDING` set that empties when
  #2313 re-captures them against a synthetic corpus (ARC-168995033).
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
- **The capture path leaves `run_tools.py` (#1762, ARC-2609514778, ARC-3243338950; part 2 of 3).**
  One container run supervised, bounded, classified, redacted and persisted — `_capture_run` through
  `_atomic_write`: the `threading.Timer` watchdog with the `--cidfile` kill that stops the container
  and not just the CLI client, the concurrent stderr drain, the stdout spool under
  `MAX_TOOL_OUTPUT_BYTES` with its truncation marker, the exit-code classification (timeout,
  non-`(0, 1)`, empty-output fail-closed), the semgrep stderr annotator and the one redaction choke
  point — moves to `skill/scripts/tool_capture.py` whole. `_stream_and_write` moved entire rather
  than being split: the watchdog and the kill path are bound by the cidfile contract.
  `run_tools.py` goes from 1774 to 1322 lines and the new module is 524, under the 700-line
  ceiling. No argv, flag, path, byte, message or file format changed — `tests/test_tool_capture.py`
  compares the bytes written, the rows returned and the lines printed for fifteen capture shapes
  against a golden captured before the move, and the patch-rule guard now derives BOTH modules'
  names, and the `run_tools` aliases each test file really binds, instead of a fixed list.
- **The tools manifest leaves `run_tools.py` (#1762, ARC-2609514778; part 3 of 3).**
  `tools-manifest.json`'s schema -- selected/produced/missing, the `excluded_dirs` rows, the run id
  and scope, the eslint `file_coverage` read and the four posture ledgers it reads back -- moves to
  `skill/scripts/tools_manifest.py` whole, and the two ledgers whose only reader is the writer (the
  network posture and the gitleaks ignore-file posture) move with it; `run_tools` binds them back,
  and still clears and fills both where the argv is built. `run_tools.py` goes from 1322 to 1136
  lines and the new module is 265, under the 700-line ceiling. The pin STAYS in
  `tests/test_flat_module_ceiling.py`, lowered to 1136: all three extractions have now landed and
  the module is still over the ceiling, holding detection, virtualenv partitioning, selection, the
  docker argv and the CLI. No manifest key, value, order or byte changed, no argv and no message --
  `tests/test_tools_manifest.py` compares the exact bytes of seven manifests (both security modes,
  `run_id` set and unset, the eslint coverage read, an adapter refused its egress, and the
  docker-absent shape) against a golden captured before the move, and the patch-rule guard derives
  all three modules' names from their own ASTs.
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
  short. Nothing is invented — a file cannot be. #2713 replaces the count-only disclosure: each
  locus-free X0X finding is excluded from the candidate set and recorded in a deterministic,
  redacted failure sidecar while located candidates are still emitted. That sidecar is validated
  against `x0x-failure-log-schema.json`, keeps duplicate ids, and resolves #2090's silent
  mixed-cluster loss. Synthesize and the driver name the exact count and path, and a clean run
  removes a stale regular file or symlink without following it. Every agent-authored field
  in a log diagnostic is squeezed to one line, bounded with the cut MARKED, rendered inert with
  `%r`, and redacted, so one hostile finding cannot repaint the operator's terminal, forge a line
  that reads as the tool's own honest output, or publish a credential.
  `strain_report.advisor_recode_signals` — the offline catalog-MIS-FIT
  companion, which has no pipeline caller — keeps its own locus-free disclosure;
  `cross_run_signals`'s line-window join is left alone, being intrinsically file-keyed.
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

### 5.2 grouping engine, plan 1

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
- **Size policy (stage 3)** — superseded by #1681, which moved both keys out of
  `.panopticon/config.json` and under `settings:` in the root `panopticon.yml`:
  cap = `--max-per-group` > `config.json
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
- **Compatibility (5.1 -> 5.2)** — superseded by #1681: the schema below is
  unchanged, but the file moved to the root `panopticon.yml` under a `groups:`
  key, so an upgrade now runs `driver migrate-config` rather than nothing. The
  original note: the `groups.yml` schema is unchanged and a
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
