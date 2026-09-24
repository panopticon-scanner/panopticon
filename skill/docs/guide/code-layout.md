## Code layout (5.2)
`skill/scripts/synthesize.py` is a thin entry script: argparse, the run-folder resolution, the OCRDb
preflight and the write. The work lives in the `skill/scripts/synth/` package, one stage per module,
each under 700 lines — `findings` (load + normalize + the doc-severity policy + tool-finding
aggregation; `FindingSet`), `corroborate` (dedupe, cross-panel corroboration, the `prepare_*`
pipeline both passes share), `codes` (OCRDb code validation, verdict-quality scoring), `delta` (diff
hunks + on/off-diff classification; `DeltaContext`), `grading` (grades, gate, certification, health
score), `plan` (dispatch plans, tool policy mode, floor-cell audit, out-of-scope lanes,
coverage/scout/queue readers; `PlanInputs`, `ToolAxis`), `integrity` (findings-file
reconcile/mislabel/cross-domain checks, the unenforced ack, the `meta.integrity` section), `cost`
(dispatch ledger + host usage; `CostInputs`), `verdicts` (verdict resolution, verify-queue
emission), `report` (`build_report(ReportInputs)` — the orchestrator and every `meta.*` section;
`RunConfig`) and `render` (terminal summary, secret redaction, the split write). A name lives in
exactly one module and is imported by module (`import scripts.synth.report as report_mod`), never
re-exported; `synth/*` never imports the driver. Tests mirror the package:
`tests/synth/test_<module>.py` per module (shared fixtures in `tests/synth/helpers.py`),
`tests/test_synthesize.py` for `main()`/CLI wiring, and `tests/test_layout.py` enforces the import
rules and the line ratchet.

`skill/scripts/driver.py` is a thin entry script too: the CLI, the `PHASES` table, `run()` and
`main()`. Its phases live in `skill/scripts/phases/` — `runio` (run-folder paths, artifact reads and
writes, child processes, `DriverError`, review-root resolution), `engine` (`Phase`, `PhaseResult`,
`run_engine`, `emit_status`), then one module per phase: `readiness` (the pre-dispatch
scanner/environment checkpoint) with `readiness_checks` (the checks themselves: docker and the tools
image, the runtime packages, the host CLIs on PATH), `discovery`, `coverage` (the scout checkpoint,
chunk maps, per-group domains), `tools`, `review`, `verify` (the cell and backup rounds) with
`verify_tools` (the tool round: its recomputed queue, its per-finding advisor entries and the
claim-location confinement they share), `synthesize`, `validate` and `setup` (the `driver setup`
flow and `SETUP_PHASES`), with `requests` holding the dispatch-request/prompt machinery shared by
every phase that emits or clears one (`coverage`, `review`, `verify`, `synthesize`, `setup`). The
same rules apply as in `synth/`: a name lives in exactly one module, siblings are reached by module
attribute (`runio._pano(...)`) so every helper has exactly one patch target, and nothing is
re-exported. `coverage`/`requests` and `persist`/`requests` import each other (`review` and `verify`
no longer do: `review` reaches the tool round through `verify_tools`, which imports neither); that
is safe only because of the module-attribute rule, and `tests/test_layout.py` rule 6 proves every
module still imports standalone. Tests mirror the package in `tests/phases/test_<module>.py`, with
`tests/test_driver.py` keeping `run()`, the CLI and the end-to-end loops.

`skill/scripts/host_probes.py` is the host-posture registry and nothing else: `PROBE_IDS`,
`PROBE_CAPABILITY`, the id→runner table `run_probes` walks, and `capabilities_of`. The probes live
in `skill/scripts/probes/` — `common` (the driver role list, the registered-shell readers and the
shipped `registered-shell-tools` probe, the `--help` interrogation, the headless settings path, the
shadow-shell scan), then one module per family: `claude`, `codex`, `kimi`, each holding that
family's `probe_*` functions and probe-id constants, with `kimi_snapshot` holding the two readings
the kimi probes measure against (the child's `llm.tools_snapshot`, and the `config.toml` the runner
generates). The same rules apply as in `synth/` and `phases/`: a name lives in exactly one module,
siblings are reached by module attribute (`common.DRIVER_ROLES`), nothing is re-exported —
`host_probes.py` assembles its tables from the family modules rather than aliasing their names — and
no module here imports `host_probes` back. `probes/kimi.py` is the one probe module that starts a
host CLI, so it is the one that carries a `DEFAULT_RUNNER`; `tests/conftest.py`'s `LAUNCH_SEAMS`
swaps it for a refusal and `tests/test_host_launch_guard.py` finds the seam by AST walk, so a new
spawn in any module turns that test red until it has its own. Tests mirror the package in
`tests/probes/test_<module>.py`, with `tests/test_host_probes.py` keeping the registry.
