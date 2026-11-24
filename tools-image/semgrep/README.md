# Pinned Semgrep rule corrections

The tools image applies five narrow corrections to the rule bundle pinned by
`SEMGREP_RULES_REF`. `corrections.json` records the expected upstream SHA-256
and corrected SHA-256 for every vendored path. `apply_corrections.py` validates
the complete batch before replacing any file, so a bundle refresh fails the
image build until a developer reviews and re-proves every affected rule.

`controls.json` stores the positive and negative examples as inert JSON.
During the image build, `verify_controls.py` materializes them under `/tmp`,
Semgrep 1.179.0 scans the five corrected vendored paths, and the verifier
requires the exact result set. This retains the seven unsafe permission modes,
three custom and eight upstream subprocess launches, five untrusted checkout
expressions, two invalid returns, and twelve JSON-derived path flows across all
six file-operation sinks. Private modes, standard subprocess result and
exception constructors, the exact pull-request base SHA, all lambda forms,
pre-parse reads, unrelated paths, and sanitized JSON-derived paths must remain
clean. The other rule in `return.yaml` remains in the result set as an
additional byte-pinned control.

When refreshing `SEMGREP_RULES_REF`, do not update source hashes just to make
the build pass. Compare each new upstream file, re-evaluate whether the local
correction is still needed, regenerate a minimal corrected file, update both
hashes, and run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest \
  tests/test_semgrep_rule_corrections.py tests/test_dockerfile.py \
  tests/test_matrix_coverage.py -q -p no:cacheprovider
docker build -t panopticon-tools:semgrep-rule-check .
```

## Path patterns (#3762)

`check_rule_paths.py` runs in the same build step, after the corrections. It reads
every rule file with the YAML loader and fails the build when a rule's
`paths.include` or `paths.exclude` holds a pattern with more than two `*` in one
path component (`**` counts as two). Semgrep matches target file names against
those patterns with wcmatch, and the wcmatch it pins (8.5.2) is polynomial in the
number of `*` (GHSA-53pm-wgxf-c6qf): a four-star pattern costs 1.7 s for one
crafted 255-byte name, where the patterns shipped today cost under 2 ms.

It fails closed. A rule file that does not parse, a file with no `rules` list, a
`paths` value that is not a mapping, or an entry that is not a string fails the
build, and the message names the file, the rule and #3762.

If a `SEMGREP_RULES_REF` refresh fails this check, do not raise the limit. Correct
or drop the rule through `corrections.json`, or wait for a Semgrep release whose
requirements admit wcmatch 11.2. The assessment behind the limit is in
`DEVELOPMENT.md`, "Advisories Semgrep's pins hold open".
