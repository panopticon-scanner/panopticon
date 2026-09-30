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
// The script labels each call with `JSON.stringify(e.id)` (#2379), so no id
// reaches a terminal raw; the scenario is keyed by the RAW id, so the label is
// decoded back here. A label that is not JSON is used as it stands, which
// keeps this lookup working whichever way the script renders it.
function scenarioKey(label) {
  try { return JSON.parse(label) } catch { return label }
}
function agent(prompt, opts) {
  calls.push({ prompt, opts })
  const id = scenarioKey(opts && opts.label)
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
// pins in tests/test_workflow_dispatch_script.py read.
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
