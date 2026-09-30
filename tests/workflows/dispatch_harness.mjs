// #1736: a minimal, dependency-free harness that runs
// skill/workflows/dispatch.js the way the Workflow tool does -- as a body of
// top-level code closing over `args`, `agent`, `parallel`, `phase`, `log` --
// WITHOUT importing it as an ES module (it has no import target for those
// names; the Workflow host supplies them as call-scoped globals).
//
// Usage: node dispatch_harness.mjs <scriptPath> [scenarioJson]
// The scenario (argv[3], else stdin) is
//   { args: {...}, replies: { [id]: string|null }, throws: { [id]: string } }
// and the harness prints ONE JSON document to stdout:
//   { meta, calls, result, error, logs }
// `calls` is every `agent(prompt, opts)` invocation, in order; `error` is the
// thrown message when the wrapped script throws, else null; `logs` is every
// `log()` line, in order -- the operator-facing output #2379 escapes
// request-sourced text in, so a test can read what reached the terminal.
// `replies` and `throws` are keyed by the entry's RAW id, which the fake
// `agent()` reads back off the prompt's marker -- the binding the read guard
// itself keys on, and the one thing validation has already pinned to the id.
// Never off `opts.label`: that is a DISPLAY value (#2379 escapes it outside a
// safe charset), and a fixture's routing must not sit downstream of a
// rendering decision.
import fs from 'node:fs'
import vm from 'node:vm'

function splitMeta(src) {
  const marker = 'export const meta = '
  const idx = src.indexOf(marker)
  if (idx < 0) throw new Error('harness: no `export const meta = ` found')
  const braceStart = idx + marker.length
  let depth = 0, i = braceStart
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++
    else if (src[i] === '}' && --depth === 0) { i++; break }
  }
  return { metaLiteral: src.slice(braceStart, i), rest: src.slice(0, idx) + src.slice(i) }
}

const scriptPath = process.argv[2]
const scenarioArg = process.argv[3]
const scenario = JSON.parse(scenarioArg || fs.readFileSync(0, 'utf8'))
const { metaLiteral, rest } = splitMeta(fs.readFileSync(scriptPath, 'utf8'))

// `meta` and `run` are both top-level in this compiled text (not nested one
// inside the other), so the script's own trailing `return` becomes run()'s
// return while meta stays reachable via the `var` below -- `var` (unlike
// `const`/`let`) attaches to the vm context, which is what makes it visible
// to the host code after `runInContext` returns.
const wrapped = 'const meta = ' + metaLiteral + ';\n' +
  'async function run(args, agent, parallel, phase, log) {\n' + rest + '\n}\n' +
  'var __EXPORTS__ = { meta, run };\n'
const context = vm.createContext({})
new vm.Script(wrapped, { filename: scriptPath }).runInContext(context)
const { meta, run } = context.__EXPORTS__

const calls = []
const MARKER = 'panopticon-entry: '
const REQUESTED = Array.isArray(scenario.args && scenario.args.entries)
  ? scenario.args.entries : []
// Which entry's MARKER LINE does this prompt open with? The script puts
// `marker + '\n'` first and refuses any entry whose marker is not
// `MARKER + id`, so that is the id, whatever bytes it carries -- see the
// header note on why the label is not the key. Matched against the entries
// the scenario sent rather than cut at a newline, because BOTH the id and
// `prompt_file` may carry newlines of their own (the case this module exists
// for), which leaves no position in the text that means "end of the id".
// Longest match wins, so one id being another's prefix cannot go two ways.
function scenarioId(prompt) {
  const text = String(prompt)
  const hits = REQUESTED
    .filter(e => e && typeof e.id === 'string' && text.startsWith(MARKER + e.id + '\n'))
    .sort((a, b) => b.id.length - a.id.length)
  return hits.length ? hits[0].id : text.slice(MARKER.length).split('\n')[0]
}
function agent(prompt, opts) {
  calls.push({ prompt, opts })
  const id = scenarioId(prompt)
  if (scenario.throws && Object.prototype.hasOwnProperty.call(scenario.throws, id)) {
    throw new Error(scenario.throws[id])
  }
  const reply = scenario.replies ? scenario.replies[id] : undefined
  return Promise.resolve(reply === undefined ? null : reply)
}
async function parallel(thunks) {
  return Promise.all(thunks.map(async t => {
    try { return await t() } catch { return null }
  }))
}
// Real Workflow globals. `phase()` is progress-only, so it stays a no-op;
// `log()` lines are the script's operator-facing output, so they are RECORDED
// rather than dropped -- nothing could observe them before, and #2379 is about
// what they print. `calls` stays the agent-call record `{prompt, opts}` the
// pins in tests/test_workflow_dispatch_script.py read (the `opts.label` in it
// is asserted on, never keyed on).
const phase = () => {}
const logs = []
const log = (m) => { logs.push(String(m)) }

let result = null, error = null
try {
  result = await run(scenario.args, agent, parallel, phase, log)
} catch (e) {
  error = e && e.message ? e.message : String(e)
}
process.stdout.write(JSON.stringify({ meta, calls, result, error, logs }))
