#!/usr/bin/env python3
"""Write `<run_dir>/usage.json` from a Claude Code host's own transcripts.

The driver is a subprocess and cannot observe per-dispatch token usage, so
`meta.cost.tokens` stays null unless the HOST supplies it (#run10 D4,
docs/PANOPTICON.md "report your usage"). This is the Claude-host implementation
of that channel: it sums the usage records the host already writes to its
session transcript and its subagent transcripts, and reports them verbatim.

It is OPTIONAL and additive. Nothing in the pipeline requires it, and if no
transcript can be found it writes NOTHING and says so — an absent number stays
absent rather than becoming a fabricated zero.

What it does NOT do
-------------------
It does not estimate, model, or price anything. `total` is defined in the file
it writes (every token the API processed, cache included), and the full
per-field breakdown travels alongside so a cost model can be applied later
without re-running the scan. Note that this raw accounting does NOT reproduce
the aggregate figure Claude Code reports for a subagent in its completion
notice; that figure is computed differently and its definition is not
documented here, so it is deliberately not imitated.

Phase attribution
-----------------
A subagent is attributed by what its prompt told it to WRITE, which is the only
self-describing signal in the transcript: `scout-<g>.json` -> scout,
`findings-<g>-<d>.json` -> review, a verdict path -> verify. Anything that
matches none of them lands in `unattributed` rather than being dropped or
guessed at, so the phase buckets always re-sum to the total.

Usage:
    python3 skill/scripts/collect_usage.py --run-dir .panopticon/runs/<tag>
    python3 skill/scripts/collect_usage.py --run-dir <dir> --dry-run
"""
import argparse
import glob
import json
import os
import re
import sys

USAGE_FIELDS = ("input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens")
PHASES = ("scout", "review", "verify", "unattributed")

# #run10 B2 hands agents a `prompt_file` PATH instead of an inline prompt, so a
# real dispatch prompt names `_prompts/<entry-id>.txt` and never mentions the
# findings file at all. The entry id already encodes the phase, and it is the
# most reliable signal available -- checked before the artifact names below.
_PROMPT_ID_RE = re.compile(r"_prompts/(review|scout|verify)[-/]")
_SCOUT_RE = re.compile(r"\bscout-[^/\\\"'\s]+\.json")
_FINDINGS_RE = re.compile(r"\bfindings-[^/\\\"'\s]+\.json")
_VERDICT_RE = re.compile(r"\bverdicts?[-/][^/\\\"'\s]*\.json|/verdicts/")


def project_slug(path):
    """Claude Code's on-disk name for a project directory.

    Every character outside [A-Za-z0-9] collapses to '-', so
    `/Volumes/Mini Vault/untitled_folder/projects/panopticon` becomes
    `-Volumes-Mini-Vault-untitled-folder-projects-panopticon`.
    """
    return re.sub(r"[^A-Za-z0-9]", "-", os.path.abspath(path))


def find_controller_transcript(project_dir, home=None, since=None):
    """The session transcript that did THIS run's work, or None.

    #calibration-2: this used to return the newest `*.jsonl` by mtime. A machine
    running more than one Claude Code session in the same project has several,
    and the most-recently-TOUCHED file is not necessarily the one that ran the
    scan -- on express it selected a different session entirely, whose subagent
    directory was empty, and the collector reported 0 subagent transcripts and a
    total three orders of magnitude too small.

    With a window, pick the transcript carrying the most usage records inside
    it: that is a direct answer to "which session was working during this run",
    rather than a proxy for it. Without one, fall back to newest-by-mtime.
    """
    home = home or os.path.expanduser("~")
    d = os.path.join(home, ".claude", "projects", project_slug(project_dir))
    files = [p for p in glob.glob(os.path.join(d, "*.jsonl")) if os.path.isfile(p)]
    if not files:
        return None
    if not since:
        return max(files, key=os.path.getmtime)
    best, best_n = None, -1
    for path in files:
        _totals, n, _models = scan(path, since)
        if n > best_n:
            best, best_n = path, n
    # Every candidate was silent in the window (best_n == 0): no session did
    # this run's work here, so fall back rather than assert an arbitrary one.
    return best if best_n > 0 else max(files, key=os.path.getmtime)


def _agent_id(path):
    """The agent id a transcript filename encodes, for cross-location dedup."""
    base = re.sub(r"^agent-", "", os.path.basename(path))
    return re.sub(r"\.(jsonl|output)$", "", base)


def find_task_transcripts(controller_transcript, tasks_dir=None):
    """Every subagent transcript for the controller's session.

    Claude Code writes them in more than one place, and they OVERLAP:

      <tmp>/<slug>/<session>/tasks/<id>.output          direct Agent-tool subagents
      <project>/<session>/subagents/<id>.jsonl          the SAME agents again
      <project>/<session>/subagents/workflows/wf_*/
              agent-<id>.jsonl                          Workflow fan-out agents

    #run10: the first release looked only in `tasks/`, which misses every
    Workflow agent -- and the documented Claude-host fan-out IS a Workflow. On
    the first real target scan that silently dropped 109.4M tokens, more than
    the total it did report. Naively adding `subagents/` would have been worse:
    those are the same agents as `tasks/`, so the run would have been
    double-counted instead. Collect from all three and dedup by agent id.

    `--tasks-dir` overrides discovery entirely.
    """
    if tasks_dir:
        return sorted(p for p in glob.glob(os.path.join(tasks_dir, "*"))
                      if os.path.isfile(p))
    if not controller_transcript:
        return []
    session = os.path.splitext(os.path.basename(controller_transcript))[0]
    proj = os.path.dirname(controller_transcript)
    slug = os.path.basename(proj)
    candidates = []
    for base in glob.glob("/private/tmp/claude-*") + glob.glob("/tmp/claude-*"):
        candidates.extend(glob.glob(os.path.join(base, slug, session, "tasks", "*")))
    candidates.extend(glob.glob(os.path.join(
        proj, session, "subagents", "workflows", "*", "agent-*.jsonl")))
    candidates.extend(glob.glob(os.path.join(proj, session, "subagents", "*.jsonl")))
    seen, out = set(), []
    for cand in candidates:
        if not os.path.isfile(cand) or cand.endswith(".meta.json"):
            continue
        aid = _agent_id(cand)
        if aid in seen:
            continue
        seen.add(aid)
        out.append(cand)
    return sorted(out)


def _iter_records(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue          # a partially-flushed line is not fatal
                # A transcript line is not guaranteed to be an object: task
                # output files interleave bare scalars with records.
                if isinstance(rec, dict):
                    yield rec
    except OSError:
        return


def _zero():
    return dict.fromkeys(USAGE_FIELDS, 0)


def _add(into, usage):
    for f in USAGE_FIELDS:
        v = usage.get(f)
        if isinstance(v, int):
            into[f] += v


def dispatched_prompt(path):
    """The first user message in a subagent transcript: the dispatched prompt.

    Classification reads ONLY this. Later turns quote file contents and tool
    output, so scanning the whole transcript lets an artifact name the agent
    merely *read* decide its phase.
    """
    for rec in _iter_records(path):
        if rec.get("type") != "user":
            continue
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else msg
        return json.dumps(content)[:200000]
    return ""


def classify_transcript(path):
    """Which pipeline phase a subagent transcript belongs to.

    Keyed on the artifact the dispatched prompt named, because that is what
    identifies the dispatch; the role name is not reliably present.

    ORDER MATTERS. A verify prompt embeds the cell's findings for the advisor
    to adjudicate, so it mentions `findings-<g>-<d>.json` too -- checking
    review first would file every advisor under review and report the verify
    round as free. Verdict is the discriminating artifact, so it wins; scout is
    checked before review for the same reason.
    """
    blob = dispatched_prompt(path)
    if not blob:
        return "unattributed"
    m = _PROMPT_ID_RE.search(blob)
    if m:
        return m.group(1)
    if _VERDICT_RE.search(blob):
        return "verify"
    if _SCOUT_RE.search(blob):
        return "scout"
    if _FINDINGS_RE.search(blob):
        return "review"
    return "unattributed"


def scan(path, since=None):
    """(totals, record_count, models) for one transcript, at or after `since`."""
    totals, n, models = _zero(), 0, {}
    for rec in _iter_records(path):
        msg = rec.get("message")
        if not isinstance(msg, dict):
            continue
        usage = msg.get("usage")
        if not isinstance(usage, dict):
            continue
        if since and (rec.get("timestamp") or "") < since:
            continue
        _add(totals, usage)
        n += 1
        m = msg.get("model")
        if m:
            models[m] = models.get(m, 0) + 1
    return totals, n, models


def collect(run_dir, project_dir, transcript=None, tasks_dir=None, since=None):
    """Assemble the usage document, or None when no transcript is available."""
    controller = transcript or find_controller_transcript(project_dir, since=since)
    tasks = find_task_transcripts(controller, tasks_dir)
    if not controller and not tasks:
        return None

    by_phase = {p: _zero() for p in PHASES}
    by_source = {"controller": _zero(), "subagents": _zero()}
    models, sources, agents = {}, [], 0

    if controller:
        t, n, m = scan(controller, since)
        _add(by_source["controller"], t)
        for k, v in m.items():
            models[k] = models.get(k, 0) + v
        sources.append({"path": controller, "kind": "controller",
                        "usage_records": n})

    for p in tasks:
        t, n, m = scan(p, since)
        if not n:
            continue
        phase = classify_transcript(p)
        _add(by_phase[phase], t)
        _add(by_source["subagents"], t)
        for k, v in m.items():
            models[k] = models.get(k, 0) + v
        agents += 1
        sources.append({"path": p, "kind": "subagent", "phase": phase,
                        "usage_records": n})

    combined = _zero()
    _add(combined, by_source["controller"])
    _add(combined, by_source["subagents"])
    total = sum(combined.values())
    return {
        "schema_version": 1,
        "total": total,
        "definition": ("every token the API processed for this run, summed over "
                       "input_tokens + output_tokens + cache_creation_input_tokens "
                       "+ cache_read_input_tokens across the controller session and "
                       "all subagent transcripts. NOT a price, and not the "
                       "aggregate figure Claude Code reports per subagent."),
        "by_field": combined,
        "by_source": by_source,
        # Subagent tokens only; the controller is not attributable to one phase.
        "by_phase": {p: sum(by_phase[p].values()) for p in PHASES},
        "by_phase_fields": by_phase,
        "subagent_transcripts": agents,
        "by_model": models,
        "window_start": since,
        "sources": sources,
    }


def run_started_at(run_dir):
    """The run manifest's `created` stamp, so a shared transcript is not
    over-counted with usage that predates the scan."""
    for name in ("run-manifest.json", "manifest.json"):
        p = os.path.join(run_dir, name)
        try:
            with open(p, encoding="utf-8") as fh:
                created = json.load(fh).get("created")
        except (OSError, ValueError):
            continue
        if created:
            return created
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Write <run-dir>/usage.json from Claude Code transcripts")
    ap.add_argument("--run-dir", required=True,
                    help="the run folder holding this run's artifacts")
    ap.add_argument("--project-dir", default=".",
                    help="repo the session runs in (locates the transcript)")
    ap.add_argument("--transcript", default=None,
                    help="controller transcript .jsonl (default: auto-discover)")
    ap.add_argument("--tasks-dir", default=None,
                    help="directory of subagent transcripts (default: auto)")
    ap.add_argument("--since", default=None,
                    help="ISO timestamp floor (default: the run manifest's "
                         "`created`; pass 'none' to count the whole transcript)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the document instead of writing it")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.run_dir):
        print("collect-usage: no such run dir: %s" % args.run_dir, file=sys.stderr)
        return 2
    since = args.since
    if since is None:
        since = run_started_at(args.run_dir)
    elif since.lower() == "none":
        since = None

    doc = collect(args.run_dir, args.project_dir, args.transcript,
                  args.tasks_dir, since)
    if doc is None:
        # Deliberately not an error, and deliberately not a zero: the channel is
        # optional, and a usage.json full of zeros would be a false ledger.
        print("collect-usage: no transcript found; writing nothing "
              "(meta.cost.tokens stays null)", file=sys.stderr)
        return 1

    if args.dry_run:
        json.dump(doc, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    out = os.path.join(args.run_dir, "usage.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print("collect-usage: %s  total=%d  (%d subagent transcripts, since %s)"
          % (out, doc["total"], doc["subagent_transcripts"], since or "beginning"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
