# BursarBuddy — Reviewer-Fleet Calibration Corpus — Design

> **Goal:** Build a modern vulnerable-by-design application whose every planted vulnerability is proven by an executable exploit and whose code contains no untracked vulnerabilities, so that Panopticon's reviewer fleet can be measured — recall by difficulty, precision against decoys, evidence calibration, and scanner↔agent complementarity — rather than merely exercised.

## Context

Panopticon's existing fixtures (RailsGoat, WebGoat, AspGoat, `vulnerable-rust`) exist to prove that **scanner adapters parse real tool output**. They validate the tool layer. Nothing in the project validates the **agent layer**: no artifact measures whether the panels, lenses, and advisors actually find real vulnerabilities, or whether they invent ones that are not there.

That gap is widest exactly where the project's differentiated value is claimed. The AI-era vulnerability classes — indirect prompt injection, tool-call hijacking, LLM output trusted as control flow, PII leaking into provider requests — are **invisible to static analysis by construction**. There is no semgrep rule for "this prompt concatenates untrusted expense memos into a system message." If the agent fleet does not find these, nothing does; and today we have no way to know whether it does.

OWASP Juice Shop, the canonical target, has two problems for this purpose. It predates the entire AI-vulnerability class, and it is **contaminated**: its challenges, solutions, and walkthroughs have been crawled into every frontier model's training data, so a model "finding" a Juice Shop vulnerability cannot be distinguished from a model recalling it.

BursarBuddy is a new corpus built to close both gaps. A separate, private harness scores the fleet against a ground-truth answer key. Eventually — in Phase 5, not at the outset — Panopticon also consumes it the way it consumes RailsGoat, via a `git clone` in `Dockerfile.fixtures` and a `manifest.json` entry, so one artifact serves both adapter validation and fleet calibration.

## Success Criteria

The corpus succeeds when all of the following hold:

1. Every planted vulnerability has a **passing executable exploit** demonstrating it against a running instance.
2. Every decoy has a **passing safety proof** demonstrating the corresponding attack fails.
3. A full scanner sweep of the app produces **zero unexplained findings** — every finding maps to a key entry or an explicitly allowlisted noise entry.
4. Running Panopticon against the corpus emits a **reproducible scorecard**: recall by difficulty, precision against decoys, evidence calibration, and complementarity.
5. The score **moves** when the fleet changes. A corpus where everything or nothing is found has no discriminating power and has failed regardless of criteria 1–4.

## Constraints

- **The app repo is a measurement surface and must stay pristine.** No `// VULNERABLE:` markers, no answer-key file, no telltale naming, no test hooks — nothing greppable that distinguishes planted code from ordinary code. A reviewer that can grep for the answer is not being measured.
- **The answer key must not be readable from the review surface.** It lives in a physically separate repository. If it sat anywhere in the scanned tree, reviewer agents would read it and score a perfect game.
- **Proofs must be deterministic.** Exploits run in CI. A proof that depends on live model behavior is flaky, and a flaky proof is not a proof.
- **The audited surface grows only by one gated slice at a time.** Completeness is an inverse problem with no natural stopping rule; it is tractable only while the unaudited surface is small.
- **Realism is a requirement, not a flourish.** The vulnerabilities must read as mistakes a competent developer actually makes, because a corpus of obvious planted flags measures flag-hunting rather than review.
- **One language at a time.** The TypeScript core is completed and gated before the Python service begins.

## The Application

### Persona

A CS freshman at a Big 10 school. **Talented but naive**, and the distinction is load-bearing in the code: the app is *well-built*. Clean components, real TypeScript types, sensible file layout, unit tests for the money math. What is absent is not skill but a **threat model** — he has never once asked what happens if the person sending a request is lying to him.

This matters for measurement. If the code were merely bad, a reviewer could flag every file and score well by accident. Good code with one systematically absent axis of thinking is a far sharper instrument.

### Origin story, which is the vulnerability model

He built it in October to track his own money: dining dollars, textbooks, a work-study stipend, Venmo splits with roommates. Single user — himself. He deployed it to Vercel so he could reach it from his phone. Then his roommate wanted an account. Then someone dropped the link in the dorm GroupMe, and now roughly two hundred people use it.

**Multi-tenancy arrived after the code did and was never treated as a security boundary.** That single fact generates authentic IDOR, cross-tenant leakage, and missing-authorization findings that feel discovered rather than planted, because that is precisely how they arise in production.

### Stack

| Layer | Technology | Rationale |
|---|---|---|
| Web app | Next.js (App Router), TypeScript, Tailwind | What a freshman actually ships to Vercel in 2026 |
| ORM / DB | Prisma, Postgres | Canonical pairing; `$queryRawUnsafe` is a realistic escape hatch |
| AI service | Python, FastAPI, an LLM framework | He learned Python in intro CS and followed a tutorial |
| Provider | Deterministic fake, with optional record/replay | Reproducible proofs (see Proof Harness) |

The bolted-on Python service is a realism choice that pays a measurement dividend: it exercises both scanner families (`eslint-security`, `npm-audit`, `semgrep` on the TypeScript side; `bandit`, `pip-audit` on the Python side) and it creates a genuine cross-service trust boundary that difficulty-4 vulnerabilities can straddle.

### Feature slices

1. **Accounts & auth** — signup, sessions, password reset, and a profile carrying real PII: legal name, campus address, phone, student ID, bank account last-4.
2. **Ledger core** — accounts, transactions, categories, balances, search and filtering.
3. **Sharing & receipts** — split expenses with roommates, receipt photo upload, CSV import and export, import-from-URL.
4. **AI summarizer** — "summarize my expenses," auto-categorization, receipt OCR, and a chat assistant holding tools.

### The flagship vulnerability

Slices 3 and 4 compose into a **cross-tenant indirect prompt injection**. An attacker creates a split expense with a victim and writes an injection payload into the memo field. The victim later asks the assistant to summarize their month. The attacker's untrusted text reaches the assembled system prompt, and the assistant — holding tools such as `export_data` and `email_report` — acts on it **in the victim's session, with the victim's authority**. A second variant arrives as OCR'd text embedded in an uploaded receipt image.

No static scanner flags this. Finding it requires tracing untrusted data across a trust boundary, across two services, in two languages, into a tool-calling loop. That is the ceiling this corpus exists to measure.

### Git history as fixture

Each slice merges as a real pull request, with commit messages written in character — the AI feature lands at 2 a.m. during finals week as "ai stuff finally works!!". The history is therefore a fixture for Panopticon's `--changes` and `--pr` modes at no additional authoring cost, and `introduced_in` SHAs in the key make those modes scoreable.

## Repository Architecture

Two repositories:

| Repo | Visibility | Contents |
|---|---|---|
| `bursarbuddy` | **Public** | The application only. Pristine, unannotated. The sole artifact Panopticon clones or reviews. Issues enabled as the report-intake channel. |
| `bursarbuddy-key` | **Private** | Answer key, exploit suite, decoy registry, scoring harness, mutator, CI gates. Access granted to trusted reviewers. |

CI gates live in the private repo, which checks out the public app and runs proofs against it. Because the app accepts essentially no external code, there is no need to surface results as public status checks.

### Governance

`CONTRIBUTING.md` inverts the normal open-source reflex: **report, do not fix.** A contributor's instinct on finding SQL injection is to open a corrective PR, and that PR would damage the instrument. Branch protection and CODEOWNERS keep drive-by fixes out.

Reports arrive as GitHub issues and are triaged privately against the key, routing to one of two dispositions: already planted (key unchanged) or genuinely untracked (adopt into the key, or fix).

**Disposition is never disclosed**, because the public issue tracker would otherwise reconstruct the answer key by elimination — in a form that gets crawled. The policy:

- A bot applies a **single label**, `under investigation`, and posts a uniform acknowledgment. A second label would itself become a taxonomy of the key.
- Closing uses the **same boilerplate comment** regardless of disposition.
- **No issue references in commits or PR bodies.** GitHub auto-links `fixes #123` into a visible cross-reference that reveals disposition without a word being said.
- **Issues close on a fixed cadence, not on resolution**, so timing correlation cannot reconstruct disposition.
- **Accepted fixes land in batched periodic maintenance commits** mixed with unrelated churn, so a public diff cannot isolate which flaws were accidental — which would imply that everything similar left standing is planted.
- Contributors are credited in a periodic thanks list that does not say what they found.

### Safety posture

Publishing a working, deliberately vulnerable financial application carries real-world risk that the design must address rather than assume away. Someone will deploy it.

- **A prominent, unmissable warning** in the README, the repository description, and the app's own landing page: this application is deliberately vulnerable, is not a real accounting product, and must never be deployed on a public network or used with real data.
- **No default deployment path.** No one-click Vercel deploy button, no published container image, no live hosted demo. Running it requires deliberately bringing up `docker-compose` locally.
- **Seed data must be unmistakably synthetic.** Names, addresses, phone numbers, student IDs, and bank last-4 values are drawn from reserved or obviously fictional ranges. The corpus exercises PII *handling*; it must never contain PII.
- **Bind to localhost by default**, with any wider binding requiring an explicit opt-in flag.
- **MIT license**, matching Panopticon, with the warning restated in the license header so it travels with any fork.

### Contamination management

The app source is public and will be crawled. Secrecy of the key slows this but cannot stop it, so three structural defenses apply:

- **Canary strings.** A unique, meaningless token embedded in the corpus lets any future model be tested for memorization. Contamination cannot be prevented, but detecting it keeps the numbers honest.
- **Variant mutator.** A generator that re-parameterizes an instance — renaming symbols, relocating vulnerabilities to different routes, rewriting payloads and identifiers — with the key following the transformation automatically. Memorized specifics do not transfer to a fresh variant. Deferred to Phase 5, when real slices exist to generalize from.
- **Rounds.** New slices land periodically; the newest round is always the least-contaminated measurement surface.

## The Answer Key Contract

### Planted vulnerability entry

```yaml
- id: BB-2026-014
  title: Transaction detail route trusts the id parameter without an ownership check
  slice: ledger-core
  cwe: [CWE-639]
  owasp: "A01:2021"
  severity: HIGH
  locus:
    - file: app/api/transactions/[id]/route.ts
      lines: [18, 24]
      symbol: GET
  introduced_in: 3f2a1c9          # commit SHA — enables --changes and --pr scoring
  scanner_visible: false          # drives the complementarity metric
  expected_scanners: []           # e.g. [semgrep, eslint-security] when true
  difficulty: 2
  chains_with: [BB-2026-021]      # vulns that compose into a worse outcome
  proof: proofs/BB-2026-014.spec.ts
  narrative: >
    Any authenticated user can read any transaction by iterating sequential ids.
```

### Decoy entry

Decoys are code that **looks dangerous but is provably safe**. They are the only way to measure precision, and they carry an inverse proof.

```yaml
- id: BB-D-004
  title: Raw SQL template in the analytics endpoint
  bait_for: [CWE-89]
  locus: [{file: app/api/analytics/route.ts, lines: [31, 36]}]
  why_safe: >
    The id is validated by zod .int().positive() and coerced before interpolation;
    every non-numeric input is rejected upstream with a 400.
  proof: proofs/decoys/BB-D-004.spec.ts    # asserts the attack FAILS
```

### Difficulty scale

The scale is what turns a score into a diagnosis rather than a number.

| Level | Meaning |
|---|---|
| 1 | A scanner finds it in milliseconds — hardcoded key, known-CVE dependency |
| 2 | Single-file reading — a missing ownership check visible in the handler itself |
| 3 | Cross-file reasoning — a trust boundary violated between two modules |
| 4 | Cross-service or cross-language — the TypeScript app trusting the Python service, or the reverse |
| 5 | Semantic, requiring intent — untrusted text reaching a system prompt, or model output driving control flow |

### CI invariants

Four invariants, enforced by the private repo's CI. They are what make the key trustworthy rather than aspirational.

1. **Every key entry has a passing exploit proof.** No proof, no entry — otherwise the key asserts what it has not demonstrated.
2. **Every decoy has a passing safety proof.** A decoy that becomes genuinely exploitable fails the build and is promoted to a real entry.
3. **Every scanner finding maps to a key entry or an allowlisted noise entry.** Anything unexplained fails the build. This is the completeness ratchet, and it is what makes "no untracked vulns" operational rather than a promise.
4. **Every `locus` resolves to a real file and line.** Catches silent drift when the app is refactored.

Invariants 1 and 2 also make the proof suite a **regression suite**, which is what permits accidental bugs to be fixed safely. Planted and accidental flaws interact; a fix to one can silently neutralize another three files away. Under these invariants that becomes a red build the same afternoon rather than an undetected corruption of the instrument.

## Proof Harness

### Runtime

`docker-compose` brings up the Next.js app, a Postgres seeded with deterministic fixture data (an attacker account, a victim account, transactions, splits, receipts), the Python AI service, and a fake LLM provider. Proofs run as an **external client** against the running stack — there are no test hooks inside the app, because the app must stay pristine.

### Proving AI vulnerabilities without depending on model behavior

There is an obvious objection to proving prompt injection against a stub: if the fake model was scripted to obey the payload, the exploit proves only our own scripting.

The resolution is that **model gullibility is not the vulnerability**. Whether a given model obeys an injected instruction is a property of that model, varies by version, and is not something the application can be held responsible for. The application's vulnerability is the **absent trust boundary**.

Each AI-vulnerability proof therefore asserts two properties, both deterministic properties of the application:

1. Attacker-controlled bytes — a roommate's expense memo, OCR text from an uploaded receipt — appear **verbatim in the prompt the app assembles and sends**, in a position the app treats as trusted.
2. When the provider returns a tool call, the app **executes it with the victim's authority**: no authorization check, no confirmation, no provenance tracking on the instruction that triggered it.

Neither depends on model behavior, and both are provable against a scripted stub.

An optional **record/replay mode** against a real model can demonstrate that real models do in fact obey. That is useful evidence, but it is evidence about models rather than about the app, and it belongs in a separate report from the one grading BursarBuddy.

## Scoring Model

### The matching problem

A reviewer writes "the GET handler doesn't verify the transaction belongs to the session user"; the key says `BB-2026-014`. Deciding whether that counts as a hit is where benchmarks quietly fail. Matching is tiered:

- **Deterministic layer.** Locus overlap plus CWE-family agreement auto-matches. Handles the majority of cases and is fully reproducible.
- **Adjudication layer.** Ambiguous cases — the right bug described at the wrong line, or the right line flagged for the wrong reason — go to a judge, whose every decision is logged with its rationale.
- **Human queue.** Low-confidence adjudications go in front of a person, and each ruling is recorded into a growing golden set. That set improves the deterministic layer over time and permits the judge itself to be measured, so the scorer never becomes an unexamined oracle.

### Metrics

In rough order of what they teach:

- **Evidence calibration.** For every finding, compare Panopticon's `evidence.status` against ground truth. Do `advisor_confirmed` findings correspond to real planted vulnerabilities? Do `rejected` claims correspond to decoys? This measures precisely what the 4.0 epistemics core was built to do and currently has no validation of. **This is the headline number.**
- **Recall by difficulty**, sliced further by CWE class and feature slice. A curve rather than a number, showing where the fleet's ceiling sits.
- **Precision against decoys**, kept sound by invariant 3 — a finding matching nothing is a false positive only because we can assert nothing is there.
- **Complementarity.** Recall on `scanner_visible: true` versus `false`, split by tool layer and agent layer, and specifically whether the reinforce path fires on the overlap — a mechanism `DEVELOPMENT.md` records as having been silently dead for two versions.
- **Severity calibration.** Whether the fleet's severity assignment tracks the key's.

## Phase Plan

Ordering is driven by risk. The novel machinery is the harness, not the vulnerable code, so the harness is proven first against the smallest app that can host it.

### Phase 0 — Walking skeleton

Both repos created. The app is the thinnest runnable thing that can hold a vulnerability: signup, login, one page. `docker-compose` with a seeded Postgres. Key schema, three or four planted vulnerabilities, one decoy, their proofs, and all four CI invariants live. Scoring harness v0 runs Panopticon and emits a precision/recall figure.

**Success criterion: a number comes out — not that it is a good number.** Everything downstream is comparatively mechanical. This phase is where the design either works or does not, and that is worth discovering against four vulnerabilities rather than fifty.

### Phase 1 — Accounts & auth (TypeScript)

The full auth surface plus the PII-bearing profile. Roughly 10–14 keyed vulnerabilities and 3–4 decoys at difficulty 1–3.

### Phase 2 — Ledger core (TypeScript)

Transactions, categories, search, balances, money math. Around 12–16 vulnerabilities: SQL injection through a raw Prisma query, IDOR, mass assignment, and the decimal-versus-float bugs that make financial code its own genre. Difficulty 1–4.

### Phase 3 — Sharing & receipts (TypeScript)

Splits, receipt upload, CSV import and export, import-from-URL. About 10–14 vulnerabilities. Structurally, this phase **builds the attacker-to-victim data path** the AI flagship depends on.

### Phase 4 — AI summarizer (Python)

FastAPI service, fake provider, tool-calling loop, OCR. The cross-tenant indirect prompt injection and its receipt-image variant, plus PII-to-provider leakage, unauthenticated internal service calls, and model output driving control flow. Roughly 10–14 vulnerabilities at difficulty 3–5. This is where the project's thesis is tested.

### Phase 5 and onward — Ratchet

Mutator and canaries; additional slices (admin panel, budgets, bank sync); new rounds; and Panopticon-side integration — a `git clone` in `Dockerfile.fixtures` plus a `manifest.json` entry, so one artifact serves both adapter validation and fleet calibration.

At Phase 4 the corpus lands around **45–60 planted vulnerabilities and roughly 15 decoys** — comparable in ambition to Juice Shop's challenge count, on a far stronger evidentiary basis.

## Decomposition Note

This design is too large for a single implementation plan. It is the shared architectural reference; **each phase earns its own plan**. The implementation plan following this spec covers **Phase 0 only**.

## Open Questions

- **Judge model selection for the adjudication layer.** Using a Claude model to adjudicate Panopticon findings reintroduces a model dependency into the measurement. The golden set bounds the risk by making the judge itself measurable, but the choice of judge and how often it is re-validated is deferred to the Phase 0 plan.
- **Noise allowlist growth.** Invariant 3 permits an allowlist for irreducible scanner noise. Without discipline that allowlist becomes a place to hide real findings. Phase 0 should establish whether allowlist entries require the same review rigor as key entries.
