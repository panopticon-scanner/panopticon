// Review a family first-class-host branch against docs/FAMILY-PR-GUARDRAILS.md
// (Panopticon #1344). Saved here so the review is a template, not an ad-hoc
// fan-out: `Workflow({ name: "family-pr-review", args: { host: "codex" } })`
// from the repo root, on the branch under review.
//
// Shape: one finder per guardrail dimension over `git diff <base>...HEAD`
// (pipeline, no barrier), each finding then adversarially verified by three
// independent refuters; a finding survives with two "real" votes. The result
// is the confirmed list plus everything dropped, so nothing is silently lost.
export const meta = {
  name: 'family-pr-review',
  description: 'Review a family first-class-host branch against docs/FAMILY-PR-GUARDRAILS.md, then adversarially verify every finding',
  whenToUse: 'Before opening or merging a feat/1344-<host>-first-class-host PR; args: { host, base? }',
  phases: [
    { title: 'Review', detail: 'one finder per guardrail dimension over the branch diff' },
    { title: 'Verify', detail: 'three refuters per finding; two "real" votes to survive' },
  ],
}

const host = (args && args.host) || 'claude'
const base = (args && args.base) || 'main'
const GUARDRAILS = 'docs/FAMILY-PR-GUARDRAILS.md'
const DIFF = 'git diff ' + base + '...HEAD'

const COMMON = 'You are reviewing the branch currently checked out, a `' + host + '` family first-class-host PR for Panopticon. ' +
  'Read ' + GUARDRAILS + ' in full first. Then inspect the change with `' + DIFF + '` and `git log ' + base + '..HEAD --format=%s`, ' +
  'reading any file you need in full. Report ONLY concrete, evidenced problems: each finding names a file and line, quotes the ' +
  'evidence, and names the guardrail section or the correctness rule it breaks. No style nits, no speculation. ' +
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
  { key: 'docs-parity', prompt: COMMON + ' Dimension: do docs/PANOPTICON.md, skill/SKILL.md and CHANGELOG.md say what the code now does, and does every claim in the diff\'s docstrings and comments hold? ' +
      'Name any sentence that is now false, any expectation the branch moved without quoting the comment that authorised it, and any behaviour the docs promise that the code does not deliver.' },
]

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
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
    'A reviewer claims: "' + f.title + '" at ' + f.file + (f.line ? ':' + f.line : '') + ', breaking "' + f.rule + '", with evidence: ' +
    JSON.stringify(f.evidence) + '. Try to REFUTE it by reading the actual code on this branch (`' + DIFF + '` and the files). ' +
    'It is real only if the code as written actually has the defect and it matters; default to real=false when uncertain or when the evidence is a misreading.'
}

const perDimension = await pipeline(
  DIMENSIONS,
  d => agent(d.prompt, { label: 'review:' + d.key, phase: 'Review', schema: FINDINGS }),
  (found, d) => parallel(((found && found.findings) || []).map(f => () =>
    parallel([0, 1, 2].map(i => () =>
      agent(verifyPrompt(f), { label: 'verify:' + d.key + ':' + i, phase: 'Verify', schema: VERDICT })))
      .then(votes => ({ ...f, dimension: d.key, votes: votes.filter(Boolean) })))),
)

const all = perDimension.filter(Boolean).flat().filter(Boolean)
const confirmed = all.filter(f => f.votes.filter(v => v.real).length >= 2)
const dropped = all.filter(f => f.votes.filter(v => v.real).length < 2)
log('family-pr-review: ' + all.length + ' raw findings, ' + confirmed.length + ' confirmed, ' + dropped.length + ' dropped')
return { host, base, confirmed, dropped }
