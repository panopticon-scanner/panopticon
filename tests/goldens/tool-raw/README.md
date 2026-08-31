# Captured tool output (`*.raw`)

One authentic, trimmed payload per registered adapter. `test_normalization_contract.py`
parses each of these and holds the result to the **NARF finding envelope** — the
same envelope `make_finding()` builds and the report schema accepts.

**NARF** — Normalized Analysis Result Format, serialized as `.narf.json` — is the
shape a finding takes once it is ours, whatever produced it: a static analyzer
through an adapter, a domain panel, or an advisor. SARIF is the closest analogue
and deliberately the closest name, but SARIF normalizes *analyzer* output, and a
real run is overwhelmingly *reviewer* output: gotify's report held 131 panel
findings to 1 tool finding, in one `findings[]` array with one shape. Hence
"Analysis" and not "Static Analysis" — the S would describe the minority of what
the format carries. Normalizing something into it is *narfing* it.

## Why real output, and not hand-written samples

The contract being proved is that `parse()` handles **what the tools actually
emit**. A hand-written sample proves only that `parse()` handles what its author
expected, which is the assumption that keeps failing: bandit's progress bar
corrupting its SARIF, eslint emitting a top-level array, pip-audit's ANSI
spinner, brakeman warning types with no CWE mapping. Every one of those was
found by real output and would have been missed by a tidy fixture.

Each file is genuine tool stdout, trimmed to ~3 findings with its envelope
intact, and re-parsed at capture time so a trim that broke the shape is rejected
rather than committed.

## What this does and does not prove

- **Proves the transform.** Real tool output → normalized findings, for every
  adapter in the registry, with no adapter silently uncovered.
- **Does NOT prove capability** — that the tool can read a given target at all.
  A scanner that reads zero files and exits 0 produces output that parses
  perfectly (gosec did exactly this on every Go target until #1457). Capability
  is proved separately, against deliberately vulnerable corpora, by the
  fixture-image tests in `tests/tools/test_*_integration.py`.

Keep both. Either one alone leaves a hole the other covers.

## Refreshing or adding a golden

Capture runs `skill/scripts/capture_goldens.py` inside a container, and it takes
**three passes**, because the adapters do not all tolerate the same environment.
Each pass writes into `tests/goldens/tool-raw`.

**1 — targets baked into the fixtures image** (brakeman, bundler-audit, semgrep,
spotbugs, dependency-check, roslyn-secguard, cargo-audit):

```sh
docker build -t panopticon-tools:latest .
docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .
docker run --rm \
  -v "$PWD/skill/scripts:/opt/panopticon/scripts:ro" \
  -v "$PWD/skill/scripts/capture_goldens.py:/opt/panopticon/capture_goldens.py:ro" \
  -v "$PWD/tests/goldens/tool-raw:/out" \
  panopticon-fixtures:latest python /opt/panopticon/capture_goldens.py /out
```

**2 — external targets, mounted at `/src`** (gosec, osv-scanner, eslint-security,
bandit, gitleaks, trivy). Use **`panopticon-tools`**, not the fixtures image:
the fixtures image is `WORKDIR /opt/panopticon` and runs as root, and
eslint's flat config ignores every file outside its base path, so it returns
nothing there. Add `--network none`, which is how scans really run — osv-scanner
in `--experimental-offline` mode produces **no output at all** when a network is
reachable.

```sh
docker run --rm --network none \
  -v "/path/to/target:/src:ro" \
  -v "$PWD/skill/scripts:/opt/panopticon/scripts:ro" \
  -v "$PWD/skill/scripts/capture_goldens.py:/opt/panopticon/capture_goldens.py:ro" \
  -v "$PWD/tests/goldens/tool-raw:/out" \
  panopticon-tools:latest python3 /opt/panopticon/capture_goldens.py /out <adapter>
```

**3 — the two `ONLINE_ONLY` adapters** (npm-audit, pip-audit) need a network and
a manifest with a known-vulnerable pin, so run pass 2 **without** `--network
none` against a small probe directory (a `package-lock.json` pinning
`lodash 4.17.15`, or a `requirements.txt` pinning `requests==2.19.0`). Offline
they fail by design — `filter_online` drops them in favour of osv-scanner.

Each capture re-parses its own trimmed payload before writing, so a trim that
broke the shape is rejected rather than committed. Trimming is format-aware:
JSON lists are cut to ~3 entries preferring the ones that carry findings (the
first cut of dependency-check kept 3 clean dependencies and produced a golden
that parsed to zero), XML is trimmed by dropping whole elements (slicing
spotbugs' `BugCollection` left an unclosed document), and osv-scanner is trimmed
two levels deep through `results[].packages[]`.

A new adapter with no golden fails `test_every_registered_adapter_has_a_golden`,
and a golden with no adapter fails `test_goldens_have_no_orphans`.
