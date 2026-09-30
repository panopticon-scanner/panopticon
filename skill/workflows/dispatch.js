// Workflow-tool script, not a standalone ES module or CommonJS script (#2024):
// the Workflow host strips the `meta` object below off the front (see the
// `export const` line a few lines down) and runs what is left as the body of
// an async function closing over `args`, `agent`, `parallel`, `phase`, `log`
// -- tests/workflows/dispatch_harness.mjs evaluates it the same way. That is
// why the file's top-level `return` is expected and legal here, and why this
// stays `.js`: neither a real ES module (top-level `return` is a SyntaxError
// there) nor a plain script parses this file whole.
//
// Panopticon session-mode dispatch on Claude Code (the Claude family PR, #1344).
//
// `driver loop --mode session` prints a `dispatch` status naming one
// checkpoint's pending entries and leaves both guards armed. This workflow is
// how a Claude Code session runs that batch -- deterministically, never with
// one-off Agent calls: one workflow subagent per entry, inside the entry's
// registered `panopticon-*` shell when the entry is `enforced` (tools and
// model host-bound), with the entry's marker line FIRST so the read guard
// binds the subagent to its entry through the workflow transcript layout
// (`<session>/subagents/workflows/<run>/agent-<id>.jsonl`), and a pointer to
// the entry's `prompt_file` second -- granted, with whatever else the builder
// granted, through the entry's `scope.reads`. Replies come back keyed by id; the
// session persists each return-persist one with `driver persist <id> --file
// <reply>` and re-runs `driver loop --mode session`. Nothing here advances the
// run: the engine's done predicates on disk are the only way forward.
//
// Invoke with the Workflow tool, from the target repo root:
//   Workflow({ scriptPath: "skill/workflows/dispatch.js",
//              args: { checkpoint: "review", entries: [ ... ] } })
// where each entry is the dispatch request's entry REDUCED to
//   { id, agent, enforced, model, marker, prompt_file, delivery, out_file }
// (read the request file the `dispatch` status names; never paste `prompt`,
// which averages 13-20 KB per entry and is exactly what `prompt_file` exists
// to keep out of the session's context). `agent` is REQUIRED whenever
// `enforced` is true -- it names the registered shell that IS the enforcement,
// so an enforced entry carrying no shell name is refused below rather than run
// as an unenforced one (#1783) -- and FORBIDDEN whenever `enforced` is false:
// the loop sets `agent` to null on an unenforced entry, so a shell name on one
// is a claim this run never made, and it is refused below too rather than run
// on `model` in silence (#2166). The two refusals are one statement read from
// either side: the same pair of SHAPES `loop_batch.refuse_misrouted` refuses
// over the request one level up -- WHICH shell a checkpoint may name is
// checked there, not here. Every refusal below that prints an id prints it
// through `JSON.stringify`, for the reason `misroute_refusal` uses `%r`: the
// id comes out of the request and reaches the operator's terminal, so a
// control character, an ANSI escape or an embedded newline in it is rendered
// as its escape sequence rather than executed by the terminal.
export const meta = {
  name: 'panopticon-dispatch',
  description: 'Run one Panopticon session-mode checkpoint: one subagent per pending entry, in its registered shell, marker line first',
  whenToUse: 'After `driver loop --mode session` prints a dispatch status; pass its pending entries (reduced, no inline prompt) as args.entries',
  phases: [{ title: 'Dispatch', detail: 'one subagent per pending entry, in parallel' }],
}

const entries = Array.isArray(args && args.entries) ? args.entries : []
if (!entries.length) {
  throw new Error('panopticon-dispatch: args.entries is empty -- pass the pending entries of the dispatch request')
}
for (const e of entries) {
  if (!e || typeof e.id !== 'string' || !e.id) {
    throw new Error('panopticon-dispatch: every entry needs a string id')
  }
  if (typeof e.marker !== 'string' || e.marker !== 'panopticon-entry: ' + e.id) {
    throw new Error('panopticon-dispatch: entry ' + JSON.stringify(e.id) + ' carries no marker line for itself; the read guard would deny it every read')
  }
  if (typeof e.prompt_file !== 'string' || !e.prompt_file) {
    throw new Error('panopticon-dispatch: entry ' + JSON.stringify(e.id) + ' has no prompt_file; the loop stamps one on every entry and grants it to the read scope')
  }
  // A request-integrity refusal, in the register of `loop_batch.misroute_refusal`
  // and raised HERE, in the validation loop, so it precedes every agent() call:
  // nothing has launched and nothing is charged. Without it such an entry fell
  // to the unenforced branch below -- no registered shell, no host-enforced tool
  // grant, no log line -- while the run's accounting still called it enforced.
  if (e.enforced && (typeof e.agent !== 'string' || !e.agent)) {
    throw new Error('panopticon-dispatch: entry ' + JSON.stringify(e.id) + ' is marked enforced but names no registered shell; agent is part of the enforcement binding -- copy it from the dispatch request rather than reducing it away')
  }
  // The mirror of the refusal above -- the same statement read from the other
  // side, the shape `loop_batch.refuse_misrouted` refuses as "unenforced but
  // names a shell". The phases set `agent` to null on every unenforced entry,
  // so a shell name on one is a claim this run never made. Without this refusal
  // such an entry fell to the `e.model` branch below and ran with no refusal and
  // no log line, on the same hand-copy path (#2166). `''` reads as absent here,
  // exactly as the dispatch branch below reads it; `refuse_misrouted`, one
  // level up, treats `""` as a claim -- that layer runs first over the request.
  if (!e.enforced && typeof e.agent === 'string' && e.agent) {
    throw new Error('panopticon-dispatch: entry ' + JSON.stringify(e.id) + ' is unenforced but names a shell ' + JSON.stringify(e.agent) + '; the loop sets agent to null on unenforced entries, so a name here is a claim this run never made -- copy the entry from the dispatch request rather than adding to it')
  }
}

phase('Dispatch')
log('panopticon-dispatch: ' + entries.length + ' pending entr' + (entries.length === 1 ? 'y' : 'ies') +
    ' at checkpoint ' + (args.checkpoint || '?'))

const results = await parallel(entries.map(e => () => {
  const opts = { label: e.id, phase: 'Dispatch' }
  // Unchanged by #2166: validation above refuses both mismatched shapes, so
  // this branch yields only the two dispatch shapes it was written for --
  // `agentType` only when enforced with a shell name, `model` otherwise (a
  // non-string `agent` on an unenforced entry still lands here, on `model`).
  if (e.enforced && e.agent) {
    opts.agentType = e.agent          // the registered shell: tools + model host-enforced
  } else if (e.model) {
    opts.model = e.model              // unenforced: the entry's model, no shell
  }
  // Marker line FIRST (the binding), the pointer second --
  // docs/guide/driver-run-loop.md, session mode. The prompt file is granted through the
  // entry's `scope.reads`, alongside whatever else the builder granted there
  // (a SEC cell's security checklist); everything else the agent may read is
  // listed inside the file.
  const prompt = e.marker + '\n' +
    'Your dispatch prompt is the file ' + e.prompt_file + ' -- Read it and follow it exactly. ' +
    'Read nothing outside the scope it lists.'
  // agent() RESOLVES to null when the user skips the subagent or it dies on
  // a terminal API error (only a thrown thunk is nulled by parallel()), so
  // a null reply is dropped here and lands in `missing` below -- never in
  // `persist` or `self_wrote` as a reply with an empty text.
  return agent(prompt, opts).then(text => (typeof text === 'string' ? {
    id: e.id,
    delivery: e.delivery || 'self_write',
    out_file: e.out_file || null,
    text,
  } : null))
}))

const replies = results.filter(Boolean)
const done = new Set(replies.map(r => r.id))
const missing = entries.map(e => e.id).filter(id => !done.has(id))
if (missing.length) {
  // No silent caps: a skipped or dead subagent is named, and the loop's
  // pending-set recomputation re-emits it on the next re-entry.
  log('panopticon-dispatch: ' + missing.length + ' entr' + (missing.length === 1 ? 'y' : 'ies') +
      ' returned nothing (skipped or died): ' + missing.join(', ') + ' -- re-run the loop and they are re-emitted')
}
return {
  checkpoint: args.checkpoint || null,
  // Pipe each of these into `driver persist <id> --file <reply>`.
  persist: replies.filter(r => r.delivery === 'return_json').map(r => ({ id: r.id, text: r.text })),
  // These wrote their own out_file under the write guard; the text is a confirmation, never findings.
  self_wrote: replies.filter(r => r.delivery !== 'return_json').map(r => ({ id: r.id, out_file: r.out_file, confirmation: r.text })),
  missing,
}
