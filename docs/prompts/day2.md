# Guardian — Day 2 Build Prompt: Investigation, Remediation, Human Approval (Jira), Verification

> Paste this into your coding agent from the root of the Guardian repo.
> Work milestone by milestone. At the end of each milestone, stop, run the tests, and summarize what changed before starting the next.

---

## 0. Your role and first step

You are working on **Guardian**, an existing Python 3.11+ CLI for repository supply-chain security (~12.8k lines, 10 packages: `core`, `adapters`, `execution`, `analysis`, `indexing`, `knowledge`, `storage`, `reporting`, `llm`/`assistant`, `sources`). Phases 1–4 are complete. Risk scoring, reports and the interactive shell exist.

**Before writing any code:**
1. Read `docs/decisions/`, `core/models.py`, `orchestration/pipeline.py`, `execution/runner.py`, `knowledge/risk.py`, `knowledge/graph_builder.py`, `storage/` (all migrations), `llm/` and `assistant/`.
2. Write a short plan (`docs/plans/day2.md`) that maps each milestone below onto existing modules, lists the new files, and calls out anything in this prompt that conflicts with the code as it exists. If something here contradicts the codebase, the codebase's existing conventions win unless this prompt explicitly says to change them. Flag it, do not silently diverge.
3. If the `langchain-build-agent`, `fp-check` or `vulnerability-triage-brocards` skills are available, use them for the LangGraph and triage parts.

## 1. What Day 2 must demonstrate

The judges' demo request: **"Show us how Guardian takes a finding from detection to verified remediation."**

Required flow, end to end:

```
Prioritized risk → Recommended fix → Human approval (Jira) → Apply in isolated branch
→ Build & test (sandboxed) → Rescan → Before/after comparison → Verified remediation → Report + audit trail
```

Day 2 requirements to cover:

| # | Requirement | What it means for Guardian |
|---|---|---|
| 1 | Prioritize risks | Combine severity with exploitability, reachability and exposure; consider whether the dependency is used in production; separate urgent from low-priority; explainable score + confidence |
| 2 | Investigate suspicious changes | At least one **non-CVE** supply-chain risk; compare versions, manifests, lockfiles; flag suspicious install scripts, provenance gaps, integrity changes; **clearly separate verified evidence from AI inference** |
| 3 | Recommend safe remediation | Upgrade to safe version · replace/remove dependency · pin trusted version · update container base image · block component · escalate for security review. Each with expected risk reduction, compatibility impact and rollback option |
| 4 | Validate the proposed fix | Apply in a controlled branch/sandbox, build, run unit/integration tests, rescan, compare before/after SBOM, detect newly introduced vulnerabilities or dependencies |
| 5 | Verify & report | Original finding + evidence, recommended and approved action, build/test results, before/after risk, remaining or accepted risk, final confidence, audit trail |

## 2. Non-negotiable rules (extend the existing `docs/decisions/`)

Keep all five existing rules (hostile repo, unknown-not-guessed, evidence links, optional scanners → partial, works without AI). Add these as a new ADR `docs/decisions/00X-human-approved-remediation.md`:

6. **Deterministic tools establish facts; the LLM interprets and explains.** The LLM never decides whether a version is vulnerable, never invents a fix version, and never decides whether a human approved something.
7. **The LLM chooses only from enumerated candidates.** Remediation candidates (with IDs) are generated deterministically. The LLM may rank them, pick one by ID, and explain. Any output that references a non-existent candidate ID, package or version is rejected.
8. **No change is applied without a recorded human decision.** This replaces the v1 rule "no autonomous code modification": Guardian now applies changes, but only after human approval, only in an isolated git worktree on a `guardian/fix-*` branch, and never commits to or pushes the default branch.
9. **Running the repo's build/tests means running hostile code.** Build and test only inside the sandbox defined in Milestone 5. If the sandbox is unavailable, validation status is `UNVERIFIED`, never `VERIFIED`.
10. **Every AI statement is labelled as inference.** Every data model that carries AI output has `source: "verified" | "inferred"` (or equivalent), and reports render them differently.
11. **Approval input is parsed deterministically and authorized.** Jira comments/fields are untrusted text. Decisions are parsed with a strict grammar (no LLM) and accepted only from an allowlist of approver account IDs.
12. **Append-only audit trail.** Every state change of a remediation case (created, published, decided, applied, validated, verified, closed) is written to an append-only audit log with actor, timestamp and payload hash.

## 3. Milestones (build in this order — vertical slice first)

The order matters: Milestones 1–6 produce the demo path for **one** finding end to end. The seven investigator agents (Milestone 8) come after, because the demo depends on the remediation loop, not on agent count.

---

### Milestone 1 — Data models and storage

Add to `core/models.py` (Pydantic v2):

- `RemediationActionType` enum: `UPGRADE`, `PIN`, `REPLACE`, `REMOVE`, `UPDATE_BASE_IMAGE`, `BLOCK`, `ESCALATE`.
- `RemediationCandidate`: `id`, `finding_ids`, `action_type`, `component` (purl), `from_version`, `to_version | None`, `manifest_path`, `lockfile_path | None`, `fixes_finding_ids`, `semver_jump` (`patch|minor|major|unknown`), `compatibility_notes` (verified: changelog/major-bump facts only), `rollback` (exact git command / revert instructions), `expected_risk_reduction` (computed by re-scoring the finding as resolved), `evidence_ids`, `source="verified"`.
- `RemediationPlan`: `case_id`, `chosen_candidate_id`, `alternatives` (candidate IDs), `rationale` (inferred), `confidence`, `llm_provider`, `llm_model`, `source="inferred"`.
- `HumanDecision`: `case_id`, `decision` (`ACCEPT | MODIFY | DECLINE`), `modify` payload (see Milestone 4), `decline_reason` (`FALSE_POSITIVE | ACCEPTED_RISK | WONT_FIX | DUPLICATE`), `risk_acceptance_expires | None`, `justification`, `actor_id`, `actor_display`, `channel` (`jira | cli`), `jira_comment_id | None`, `decided_at`.
- `ValidationRun`: `case_id`, `branch`, `worktree_path`, `commit_sha`, `sandbox` (`docker | none`), steps (`install`, `build`, `test`) each with status/exit code/duration/log path, `tests_discovered`, `tests_passed`, `tests_failed`.
- `VerificationResult`: `case_id`, `before_scan_id`, `after_scan_id`, `target_findings_resolved`, `findings_still_present`, `new_findings`, `sbom_diff` (added/removed/changed components), `risk_before`, `risk_after`, `status` (`VERIFIED | PARTIALLY_VERIFIED | FAILED | UNVERIFIED`), `confidence`, `reasons`.
- `RemediationCase`: aggregate with `status` state machine:
  `PROPOSED → AWAITING_DECISION → (DECLINED | APPROVED | MODIFICATION_REQUESTED) → APPLYING → VALIDATING → (VERIFIED | VALIDATION_FAILED → AWAITING_DECISION) → CLOSED`.
- `AuditEvent`: `id`, `case_id`, `event`, `actor`, `at`, `payload_json`, `payload_sha256`, `prev_event_sha256` (hash chain).

Add a 4th SQLite migration: `remediation_cases`, `remediation_candidates`, `remediation_plans`, `human_decisions`, `validation_runs`, `verification_results`, `jira_links` (case_id ↔ issue key, fingerprint, last_synced_comment_id), `audit_events` (no UPDATE/DELETE paths in the repository layer).

Tests: state-machine transitions (illegal transitions raise), audit hash chain verification, migration up from a v3 database.

---

### Milestone 2 — Prioritization upgrades (Day 2 item 1)

Update `knowledge/risk.py` without changing the existing formula or the "unknown lowers confidence, not score" behaviour:

- **Exploitability (X)** — fill it from deterministic sources, not the LLM:
  - CISA Known Exploited Vulnerabilities catalog (in KEV → high X, evidence record with KEV entry).
  - FIRST EPSS score for the CVE (map probability to X; store the score and date as evidence).
  - Cache both locally with a timestamp; if offline, X stays `unknown`.
  - Network fetches go through `execution/runner` policy or a dedicated, allowlisted HTTP client with timeouts — follow whichever pattern the codebase already uses.
- **Exposure (E)** — add dependency scope: runtime vs dev/test/optional (from `devDependencies`, Poetry groups, Maven `test` scope, etc.) and direct vs transitive. If adapters do not already capture scope, add it.
- **Reachability (P)** — `verified` only when the code graph has a path from an entry point to an import/call of the affected package (and the affected symbol, when OSV provides it). Otherwise `unknown`. The LLM's opinion on reachability is stored separately as an inferred note and **does not** change P.
- Priority buckets: `CRITICAL / HIGH / MEDIUM / LOW` from score + confidence, with a one-line deterministic explanation listing each factor's value and source.

Tests: KEV hit raises priority; dev-only dependency lowers E; missing EPSS keeps X unknown and lowers confidence.

---

### Milestone 3 — Non-CVE supply-chain detection and remediation candidates (Day 2 items 2 and 3)

**3a. Suspicious-change detectors** (audit what `analysis/git_diff` already does first; add what is missing). Each produces a finding with evidence, no LLM:
- New dependency added in recent commits that is not imported anywhere (graph check).
- Typosquat candidates: name within small edit distance of a bundled list of popular package names per ecosystem (ship the list as a data file; mark as `suspected`).
- Install-time scripts: npm `preinstall/install/postinstall` (`hasInstallScript` in lockfile), `setup.py` with network/exec calls.
- Lockfile integrity anomalies: `resolved` URL pointing outside the official registry, integrity hash changed without a version change, lockfile changed without a manifest change.
- Unpinned or mutable references: Docker `FROM image:latest` / no digest, GitHub Actions not pinned to a commit SHA.

**3b. Candidate generator** (`remediation/candidates.py`), deterministic:
- `UPGRADE`: from OSV `affected[].ranges[].events[].fixed`, pick the lowest fixed version on the same major, plus the lowest overall fixed version if it crosses a major. Verify the version exists in the registry (PyPI JSON / npm registry / Maven Central) and is not yanked/deprecated. If the registry is unreachable, mark the candidate `unverified_version`.
- Transitive vulnerable deps: prefer upgrading the direct parent that pulls in a fixed version; otherwise use an override (`overrides` in npm, `resolutions` in yarn, constraints in pip/Poetry, `dependencyManagement` in Maven).
- `PIN` for unpinned/mutable refs; `UPDATE_BASE_IMAGE` with digest; `REMOVE` for unused suspicious deps; `BLOCK` (add to a Guardian policy denylist) and `ESCALATE` are always available as non-code options.
- Each candidate computes `expected_risk_reduction` by re-running `risk.py` with the targeted findings removed, and a `rollback` instruction.
- Manifest editing goes through the adapters (`adapters/*.py` get `apply_candidate(worktree, candidate)` methods). Use format-preserving edits (e.g. `tomlkit` for `pyproject.toml`); lockfile regeneration happens inside the sandbox in Milestone 5.

**3c. Remediation planner** (`remediation/planner.py`): LLM receives the finding, evidence, risk breakdown and candidate list (IDs only, no free-form patching) and returns a `RemediationPlan` via structured output. Validate the chosen ID exists. With `--no-ai`, pick deterministically: lowest semver jump that resolves all targeted findings.

Tests: OSV fixture → expected candidate versions; planner rejects a hallucinated candidate ID; `--no-ai` path produces a plan.

---

### Milestone 4 — Jira human-in-the-loop (`integrations/jira/`)

**Client** (`client.py`): thin `httpx` client for **Jira Cloud REST API v3**, basic auth with `JIRA_EMAIL` + `JIRA_API_TOKEN`. Use `/rest/api/3/search/jql` for JQL search (the old `/rest/api/3/search` endpoint has been removed from Jira Cloud). Descriptions and comments use Atlassian Document Format (ADF). Timeouts, retry with backoff on 429/5xx, never log the token.

**Config** (`.env` + `guardian.toml`):
```
JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
GUARDIAN_JIRA_ISSUE_TYPE=Bug           # or Task
GUARDIAN_APPROVERS=<accountId>,<accountId>
GUARDIAN_JIRA_MIN_PRIORITY=HIGH
GUARDIAN_JIRA_POLL_SECONDS=30
```
Make sure `execution/runner`'s environment scrubbing keeps these out of every subprocess.

**Publishing** (`publish.py`): one issue per remediation case.
- Dedup by a stable fingerprint label `guardian-fp-<sha1(repo+component+vuln_or_rule)>`; on rescan, update the existing issue instead of creating a new one.
- Summary: `[Guardian][HIGH] lodash 4.17.20 — prototype pollution (CVE-…)`.
- Description (ADF): risk score + factor breakdown with `verified`/`inferred` labels, affected component and dependency path, evidence list, recommended action + alternatives, expected risk reduction, compatibility impact, rollback, and the exact command grammar below.
- Map Guardian priority to Jira priority; labels: `guardian`, ecosystem, action type.

**Decision grammar** (`commands.py`) — parsed with a strict parser, no LLM. A comment whose first line starts with `/guardian`:
```
/guardian accept
/guardian accept candidate=<candidate_id>
/guardian modify version=<x.y.z>                    # different target version, Guardian validates it
/guardian modify action=<PIN|REMOVE|REPLACE|...> [target=<purl>]
/guardian modify branch=<branch> | commit=<sha>     # human made the change manually; Guardian validates that ref
/guardian decline reason=false_positive|accepted_risk|wont_fix|duplicate [until=YYYY-MM-DD] -- <justification>
/guardian revalidate
```
- Ignore comments by Guardian's own account and comments from accounts not in `GUARDIAN_APPROVERS` (reply once: "not authorized").
- `accepted_risk` requires `until=` and a justification.
- Invalid syntax → Guardian replies with the parse error and the grammar; state does not change.
- Optional: if the project workflow has statuses `Approved` / `Declined`, map transitions to `accept` / `decline` via config. Comments are the primary channel because they work without Jira admin rights.

**Sync** (`sync.py`): `guardian jira sync [--watch]` polls issues with the `guardian` label updated since the last sync, reads new comments after `last_synced_comment_id`, parses decisions, records `HumanDecision` + audit event, and resumes the matching LangGraph thread (Milestone 6). Polling, not webhooks, so it works on a laptop with no public URL.

**Write-back**: after each stage Guardian comments on the issue (decision acknowledged → applying → validation results → verification verdict + before/after table) and transitions the issue if configured (`Verified` → Done; `VALIDATION_FAILED` → back to review with the failure summary).

**Local fallback**: `guardian decide <case_id> accept|modify|decline ...` uses the same parser and authorization (approver = local OS user in a configured allowlist), recorded with `channel="cli"`. This keeps the demo working if Jira is down.

Tests: use `respx` (or the existing HTTP mock pattern) for every Jira call; grammar parser property tests; unauthorized approver ignored; idempotent re-sync of the same comment.

---

### Milestone 5 — Apply, sandboxed build/test, rescan, verify (Day 2 items 4 and 5)

**Apply** (`remediation/apply.py`):
- `git worktree add <guardian_home>/worktrees/<case_id> -b guardian/fix-<case_id> <scanned_commit>` via `execution/runner` (git hardening already exists — reuse it).
- Apply the candidate through the adapter; commit with a message containing case ID, finding IDs, approver and Jira key. Never touch the user's working tree, never push.
- For `modify branch=/commit=`: create the worktree from that ref instead and skip the edit step.

**Sandboxed validation** (`remediation/sandbox.py`, `remediation/validate.py`):
- Docker if available: ecosystem image (python / node / maven), **non-root**, CPU/memory/pids limits, wall-clock timeout, worktree copied in (not the user's repo mounted read-write), no host env vars, no Docker socket.
- Two phases: (1) dependency install / lockfile regeneration with network on and install scripts disabled where the ecosystem allows (`npm ci --ignore-scripts`, `pip install --no-build-isolation` only if needed — document each choice); (2) build + tests with `--network none`.
- Test discovery per adapter: `pytest`, `npm test` (only if a `test` script exists), `mvn -q test`. Record "no tests found" explicitly.
- Capture logs to files, cap size, redact secrets.
- No Docker → status `UNVERIFIED` with the reason; do **not** fall back to running tests on the host unless the user passes an explicit `--unsafe-host-validation` flag that prints a warning.

**Rescan and compare** (`remediation/verify.py`):
- Run the existing `ScanPipeline` against the worktree → `after_scan_id`.
- Diff SBOMs (added/removed/changed components by purl), diff findings (resolved, still present, newly introduced), compute risk before/after.
- Verdict:
  - `VERIFIED`: targeted findings resolved, no new HIGH/CRITICAL findings, build passed, tests ran and passed.
  - `PARTIALLY_VERIFIED`: resolved and built, but no tests found or new LOW/MEDIUM findings.
  - `FAILED`: not resolved, build/test failure, or new HIGH/CRITICAL.
  - `UNVERIFIED`: sandbox unavailable or a required scanner missing.
- Confidence derives from what actually ran (scanner coverage, test count, sandbox used).

Tests: integration test on fixture repos (see Milestone 9) — happy path VERIFIED; a candidate that breaks tests → FAILED; Docker missing → UNVERIFIED.

---

### Milestone 6 — LangGraph orchestration with durable human-in-the-loop

Two graphs in `orchestration/`:

**A. `investigation_graph` (per scan, no interrupts).** Wraps the existing pipeline steps as nodes (profile → SBOM → parallel OSV/Semgrep/git/indexing → enrichment → graph build → risk), then investigator nodes (Milestone 8), then `create_cases` which generates candidates + plans for findings at or above `GUARDIAN_JIRA_MIN_PRIORITY` and starts one remediation thread per case. Keep the existing thread-pool parallelism or move it to LangGraph fan-out, whichever is less invasive — justify the choice in the plan.

**B. `remediation_graph` (one thread per case, `thread_id = case_id`).**
```
plan → publish_jira → await_decision ──ACCEPT/MODIFY──▶ apply → validate → rescan_verify → report_back → END(or loop)
                          │                                                     │
                          └──DECLINE──▶ record_acceptance → report_back → END    └─FAILED──▶ publish_failure → await_decision
```
- Checkpointer: `SqliteSaver` from `langgraph-checkpoint-sqlite`, stored at `~/.guardian/checkpoints.sqlite`. Interrupt/resume does not work without a durable checkpointer, and `InMemorySaver` loses pending approvals on restart.
- `await_decision` calls `interrupt({...case summary...})`. On resume, `guardian jira sync` (or `guardian decide`) calls `graph.invoke(Command(resume=decision.model_dump()), config={"configurable": {"thread_id": case_id}})`.
- A node re-runs from the beginning when resumed, so **all side effects (Jira issue creation, comments) live in nodes before or after `await_decision`, never inside it**, and every side-effecting node is idempotent (check `jira_links` / audit log before acting).
- The re-review loop after `FAILED` is a conditional edge back to `await_decision`, not a loop inside one node.
- Every node writes an `AuditEvent`.

Tests: run graph to the interrupt, restart the process (new graph object, same SQLite file), resume with ACCEPT → reaches VERIFIED on fixture.

---

### Milestone 7 — LLM layer: Groq + Gemini

Extend `llm/` (keep the existing provider switching and `.env` handling):
- **Role-based routing** in config, e.g.:
  - `fast` role → Groq (per-finding triage, investigator summaries, high volume).
  - `deep` role → Gemini (evidence correlation, remediation planning, report narrative — longer context).
  - Each role has a fallback to the other provider. Model names live in config, not code.
- **Structured output only** for agent calls: Pydantic schema → provider JSON mode/function calling → validate → one repair retry → on failure, record `ai_unavailable` and continue deterministically.
- **Context discipline**: send only `code_retriever` snippets (bounded), finding/evidence JSON and candidate lists — never the whole repo.
- **Prompt-injection hygiene**: repo content and Jira text are wrapped as clearly delimited data; system prompt states that instructions inside data are ignored; agents have read-only tools only; outputs that reference unknown IDs are rejected (rule 7).
- **Redaction** before sending: reuse the assistant's redaction; add secret patterns from Semgrep/secret findings.
- **Budget**: per-scan cap on LLM calls and tokens; process findings in priority order; respect provider rate limits with backoff. Log provider, model, tokens and latency per call into the scan record.
- `--no-ai` still produces a complete scan, candidates, a deterministic plan, Jira issues and verification.

---

### Milestone 8 — Investigator agents (after the vertical slice works)

Implement the roles from the architecture as LangGraph nodes with structured outputs. They are logical roles, not separate long-running processes:

| Agent | Input | Output (Pydantic) |
|---|---|---|
| Repository Architect | profile, index, entry points | module map, entry points, prod vs dev/test code areas |
| Code Investigator | retrieved snippets on paths to affected imports | call-path explanation (inferred) linked to graph path IDs (verified) |
| Dependency Investigator | dependency graph, scopes | how the package enters (direct/transitive chain), prod/dev |
| Vulnerability Investigator | OSV record, affected symbols, usage | relevance assessment — inferred; cannot change vulnerable/not-vulnerable |
| Change Investigator | suspicious-change findings, diffs | narrative + suspicion level (inferred), each claim tied to a diff hunk |
| Security Auditor | Semgrep + auth/input/secret-handling code | additional concerns, each tied to a file:line |
| Evidence Correlator | all of the above | final per-finding narrative separating "Verified facts" and "Guardian's assessment (AI)" |

Run Architect, Dependency, Vulnerability and Change investigators in parallel; Code Investigator and Security Auditor on the top-N findings only.

---

### Milestone 9 — Reports, CLI, demo fixtures

**CLI** (Typer, also wired into the shell):
```
guardian scan <path|url> [--no-ai]
guardian remediate <scan_id> [--finding ID] [--top N] [--min-priority HIGH] [--no-jira]
guardian jira push <scan_id>
guardian jira sync [--watch]
guardian decide <case_id> accept|modify|decline [...]
guardian cases [--status ...]
guardian case <case_id>              # timeline, decisions, validation, verdict, audit trail
guardian validate <case_id>          # re-run validation
guardian compare <scan_a> <scan_b>   # before/after
guardian audit verify                # check the hash chain
guardian doctor                      # add: docker, jira auth, groq/gemini keys, checkpointer
```

**Report** (HTML/Markdown/JSON): a "Remediation" section per case with: original finding + evidence · recommended action + alternatives · human decision (who/when/channel/Jira link) · build/test results · before/after SBOM and risk · remaining or accepted risk (with expiry) · final status + confidence · audit trail. Verified facts and AI inference visually distinct.

**Demo fixtures** in `tests/fixtures/demo/` (benign — no real malicious code):
- `node-app`: a known-vulnerable direct dependency with a fixed version available, a vulnerable transitive dependency, a test suite, and a recent commit adding a lookalike-named dependency with a `postinstall` script that only echoes.
- `python-app`: a vulnerable pinned dependency imported on a route handler (reachable) and one only in dev dependencies (lower priority), with pytest tests.
- `Dockerfile` using `:latest` base image.
- A scripted demo `scripts/demo_day2.sh`: scan → remediate → Jira issue created → (approve in Jira or `guardian decide`) → sync → validation → VERIFIED → report opened.

## 4. Definition of done

- [ ] `guardian scan` + `guardian remediate` on the node fixture creates a Jira issue with score breakdown, evidence and a recommended fix.
- [ ] `/guardian accept` from an allowlisted Jira user leads, after `guardian jira sync`, to a `guardian/fix-*` worktree, sandboxed build + tests, rescan, and a VERIFIED verdict posted back to Jira.
- [ ] `/guardian modify version=…` validates the human's version; `/guardian decline reason=accepted_risk until=… -- …` records accepted risk and shows it in the report.
- [ ] A fix that breaks tests ends FAILED and returns the case to review in Jira.
- [ ] The suspicious lookalike dependency is detected without any CVE and flagged with verified evidence plus labelled AI assessment.
- [ ] Killing Guardian while a case is awaiting approval and restarting it loses nothing.
- [ ] `--no-ai` completes the whole flow.
- [ ] No Jira/LLM secret appears in logs, reports, subprocess env or LLM prompts.
- [ ] `pytest` passes; new code has unit tests; Jira and LLM calls are mocked in CI.

## 5. Out of scope for Day 2

Pushing branches or opening PRs on GitHub (optional stretch, behind a flag) · Jira webhooks · auto-merge · a web dashboard · Jira Data Center support · cross-language call tracing · continuous monitoring.
