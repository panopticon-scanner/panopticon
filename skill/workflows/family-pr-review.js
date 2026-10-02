// Workflow-tool script, not a standalone ES module or CommonJS script (#2024;
// see dispatch.js's header and tests/workflows/dispatch_harness.mjs): the
// Workflow host strips the `meta` object below off the front (see the
// `export const` line a few lines down) and runs what is left as the body of
// an async function closing over `args`, `agent`, `parallel`, `phase`,
// `log`, `pipeline` -- which is why the top-level `await pipeline(...)`
// below and the top-level `return` at the end are both expected and legal
// here, and why this stays `.js`.
//
// Review a family first-class-host branch against docs/FAMILY-PR-GUARDRAILS.md
// (Panopticon #1344). Saved here so the review is a template, not an ad-hoc
// fan-out: `Workflow({ scriptPath: "skill/workflows/family-pr-review.js",
// args: { host: "codex" } })` from the repo root, on the branch under review.
// It lives beside `dispatch.js` rather than under `.claude/workflows/`: that
// directory is a Claude Code discovery surface (#1657 CL-8), and a file the
// host would load from the reviewed tree makes the target-discovery-surface
// probe refuse this repo's own claude self-scan.
//
// Shape: one finder per guardrail dimension over `git diff <base>...HEAD`
// (pipeline, no barrier), each finding then adversarially verified by three
// independent refuters; a finding survives with two "real" votes. Each finder
// is capped at 25 findings by the schema and again at the verifier boundary.
// The result carries confirmed and dropped findings plus any cap truncation.
//
// The finders and the refuters run UNCONFINED, by decision: both roles have to
// run `git diff` and `git log` and read any file in the checkout (see COMMON
// and `verifyPrompt` below), and no registered shell grants that -- the shells
// exist for the dispatch path, where `dispatch.js` binds one (`agentType`) for
// every enforced review entry, because those read a target's own text. This
// script is not that role: it is maintainer-invoked, by hand, on a first-party
// branch of this repository, so nothing target-authored reaches it on any scan
// path, and the finder has already read the diff its refuters re-read. Every
// finding STRING interpolated into a verifier prompt goes through
// `JSON.stringify` regardless (`title`, `rule`, and `file` with its line as one
// span, as `evidence` already did), so a finding's own text cannot restructure
// the prompt it lands in.
export const meta = {
  name: 'family-pr-review',
  description: 'Review a family first-class-host branch and verify up to 25 findings ' +
    'from each guardrail dimension',
  whenToUse: 'Before opening or merging a feat/1344-<host>-first-class-host PR; args: { host, base? }',
  phases: [
    { title: 'Review', detail: 'one finder per guardrail dimension over the branch diff' },
    { title: 'Verify', detail: 'three refuters per selected finding; two "real" votes to survive' },
  ],
}

const host = (args && args.host) || 'claude'
const base = (args && args.base) || 'main'
const GUARDRAILS = 'docs/FAMILY-PR-GUARDRAILS.md'
const DIFF = 'git diff ' + base + '...HEAD'
const MAX_FINDINGS_PER_DIMENSION = 25

const COMMON = 'You are reviewing the branch currently checked out, a `' + host + '` family first-class-host PR for Panopticon. ' +
  'Read ' + GUARDRAILS + ' in full first. Then inspect the change with `' + DIFF + '` and `git log ' + base + '..HEAD --format=%s`, ' +
  'reading any file you need in full. Report ONLY concrete, evidenced problems: each finding names a file and line, quotes the ' +
  'evidence, and names the guardrail section or the correctness rule it breaks. No style nits, no speculation. ' +
  'Return at most ' + MAX_FINDINGS_PER_DIMENSION + ' findings. Prioritize the most severe and ' +
  'best-evidenced. ' +
  'An empty list is a valid answer.'

const DIMENSIONS = [
  { key: 'repo-rules', prompt: COMMON + ' Dimension: section 3 "Repository" rules. Was hosts.py changed anywhere but this family\'s own row? ' +
      'Was another family\'s runner, probes, or emit branch touched? Was host-specific tool-name mapping put into the shared templates under skill/agents/? ' +
      'Is anything under .panopticon*/ or a home directory committed? Was a test or doc guard weakened to pass, rather than an expectation moved that its own comment authorised? ' +
      'Are the commit messages conventional?' },
  { key: 'suite-rules', prompt: COMMON + ' Dimension: section 3 "Suite" rules. Can any test launch the real host binary (`claude`, `codex`, `gemini`, `kimi`)? ' +
      'Does any test touch this repo\'s .panopticon/, a home directory, or the network? Is the Runner\'s launcher injectable and do loop tests patch scripts.runners.base.runner_for?' },
  { key: 'probe-rules', prompt: COMMON + ' Dimension: sections 1 and 2, the deliverable and the probe contract. For every probe the branch adds or changes: does it return (state, by, detail) ' +
      'with state in {proven, refuted, unknown}, return unknown with a reason when it cannot run, never guess, and is it able to REFUTE (is there a test that flips it to refuted)? ' +
      'Is every probe id in PROBE_IDS and PROBE_CAPABILITY and mapped on the HostSpec row? Does driver_selectable move only with the security probes? Is anything decided by host name inside phases/?' },
  { key: 'correctness', prompt: COMMON + ' Dimension: correctness of the code the diff adds or changes (Python and JavaScript). Logic errors, fail-open paths, exceptions that escape a never-raise contract, ' +
      'path handling that can leave a run folder, shell/JS that cannot run as written, stale names left behind by a rename.' },
  { key: 'docs-parity', prompt: COMMON + ' Dimension: do docs/PANOPTICON.md and its chapters under docs/guide/, skill/SKILL.md and CHANGELOG.md say what the code now does, and does every claim in the diff\'s docstrings and comments hold? ' +
      'Name any sentence that is now false, any expectation the branch moved without quoting the comment that authorised it, and any behaviour the docs promise that the code does not deliver.' },
]

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      maxItems: MAX_FINDINGS_PER_DIMENSION,
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          rule: { type: 'string', description: 'the guardrail section or correctness rule broken' },
          evidence: { type: 'string', description: 'the quoted code or text that shows it' },
        },
        required: ['title', 'file', 'severity', 'rule', 'evidence'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT = {
  type: 'object',
  properties: {
    real: { type: 'boolean' },
    reason: { type: 'string' },
  },
  required: ['real', 'reason'],
}

function verifyPrompt(f) {
  return 'You are an adversarial verifier on a `' + host + '` family PR for Panopticon. Read ' + GUARDRAILS + ' first. ' +
    'A reviewer claims: ' + JSON.stringify(f.title) + ' at ' + JSON.stringify(f.file + (f.line ? ':' + f.line : '')) + ', breaking ' + JSON.stringify(f.rule) + ', with evidence: ' +
    JSON.stringify(f.evidence) + '. Try to REFUTE it by reading the actual code on this branch (`' + DIFF + '` and the files). ' +
    'It is real only if the code as written actually has the defect and it matters; default to real=false when uncertain or when the evidence is a misreading.'
}

const findingCounts = {}
const perDimension = await pipeline(
  DIMENSIONS,
  d => agent(d.prompt, { label: 'review:' + d.key, phase: 'Review', schema: FINDINGS }),
  (found, d) => {
    const received = found && Array.isArray(found.findings) ? found.findings : []
    const selected = received.slice(0, MAX_FINDINGS_PER_DIMENSION)
    findingCounts[d.key] = {
      received: received.length,
      verified: selected.length,
      omitted: received.length - selected.length,
    }
    return parallel(selected.map(f => () =>
      parallel([0, 1, 2].map(i => () =>
        agent(verifyPrompt(f), {
          label: 'verify:' + d.key + ':' + i,
          phase: 'Verify',
          schema: VERDICT,
        })))
        .then(votes => ({ ...f, dimension: d.key, votes: votes.filter(Boolean) }))))
  },
)

const all = perDimension.filter(Boolean).flat().filter(Boolean)
const confirmed = all.filter(f => f.votes.filter(v => v.real).length >= 2)
const dropped = all.filter(f => f.votes.filter(v => v.real).length < 2)
const truncation = DIMENSIONS
  .map(d => findingCounts[d.key] && { dimension: d.key, ...findingCounts[d.key] })
  .filter(row => row && row.omitted)
const findingsOmitted = truncation.reduce((total, row) => total + row.omitted, 0)
log('family-pr-review: ' + all.length + ' verified findings, ' + confirmed.length + ' confirmed, ' +
    dropped.length + ' dropped, ' + findingsOmitted + ' omitted by the ' +
    MAX_FINDINGS_PER_DIMENSION + '-per-dimension cap')
return {
  host,
  base,
  finding_cap: MAX_FINDINGS_PER_DIMENSION,
  findings_omitted: findingsOmitted,
  truncation,
  confirmed,
  dropped,
}
