# Day 2 plan: detection → human-approved, verified remediation

Source brief: [`docs/prompts/day2.md`](../prompts/day2.md). Baseline before Day 2: 631 tests pass,
2 e2e tests in `tests/e2e/test_cdxgen.py` fail (real cdxgen run on this machine; pre-existing).

## Conflicts with the codebase (codebase wins unless the brief says otherwise)

| # | Brief says | Codebase has | Resolution |
|---|---|---|---|
| C1 | Priority buckets `CRITICAL/HIGH/MEDIUM/LOW` | `Priority` P1–P4 with documented overrides (ADR 07) | Keep P1–P4 as the stored value. Add `Priority.label` → P1 "critical", P2 "high", P3 "medium", P4 "low" for Jira/report text. `GUARDIAN_JIRA_MIN_PRIORITY` accepts either spelling (`HIGH` == `P2`). |
| C2 | Risk fetches KEV/EPSS | `risk.py` is pure (no I/O) by design | Fetching lives in a new `knowledge/exploit_intel.py` (cached httpx client). `risk.assess(..., intel=ExploitIntel | None)` stays pure and takes the data as an argument. |
| C3 | Config in `.env` + `guardian.toml` | Only `GuardianSettings` (pydantic-settings, `.env` files, `GUARDIAN_` prefix). No TOML config exists | No `guardian.toml`. Jira settings go into `GuardianSettings`; `JIRA_*` names accepted via `AliasChoices`, like `GROQ_API_KEY` today. |
| C4 | Tests use `respx` | Tests use `httpx.MockTransport` (`test_llm_providers.py`) | Use `httpx.MockTransport`; no new test dependency. |
| C5 | ADR name `00X-...` | ADRs are `NN-topic.md` | `docs/decisions/11-human-approved-remediation.md`. |
| C6 | "Replaces the v1 rule *no autonomous code modification*" | That rule is not written anywhere; ADR 09 says the assistant has read-only tools | ADR 11 states rule 8 as a new rule and says the assistant stays read-only. |
| C7 | "Every node writes an AuditEvent"; models with state transitions | All models are `_Frozen` (`frozen=True, extra="forbid"`) | Keep frozen. `RemediationCase.transition(to)` returns a new copy and raises `IllegalTransitionError` on bad moves. |
| C8 | Dependency scope runtime vs dev | `Component.scope` is CycloneDX `required/optional/excluded`; adapters record dev deps only as names | Add `Component.dev: bool | None` and adapter-collected dev-dependency names. The SBOM normalizer sets it. Exposure keeps its ×0.5 for optional scope and applies the same factor to `dev=True`. |
| C9 | LangGraph orchestration, SqliteSaver | `langgraph` is **not installed** (only `langchain-core`) | `uv add langgraph langgraph-checkpoint-sqlite tomlkit` in M3/M6. |
| C10 | Runner allowlist | `DEFAULT_ALLOWED_TOOLS = {git, cdxgen, osv-scanner, semgrep}` | The sandbox uses its own `ExecutionPolicy` with `docker` added. Scanners keep the default policy. `npm`/`pip`/`mvn` never run on the host, except behind `--unsafe-host-validation`. |
| C11 | Agent commits fix branches | ADR 10: "The user commits and pushes; Claude does not." | Guardian (the product) commits inside its own worktree on `guardian/fix-*`. This agent does not commit to this repo. |
| C12 | `ScanPipeline` steps as LangGraph nodes | Pipeline uses a thread pool, and indexing must stay on the DB thread | **Keep the thread pool**: `investigation_graph` wraps `ScanPipeline.run` as one `scan` node, followed by `risk → investigators → create_cases`. Splitting the pipeline into nodes would break the single-thread SQLite cache and gain nothing for the demo. |
| C13 | `git worktree add` via runner | Git hardening sets `protocol.allow=never` | Worktree add is local and unaffected. The commit uses `-c user.name/user.email=Guardian` so it never depends on repo config. |

Environment note: Docker Desktop is installed but the daemon was not running at planning time.
Without it, M5 correctly yields `UNVERIFIED`; the demo needs Docker Desktop started.

## Milestone → module map

| M | Existing modules touched | New files |
|---|---|---|
| 1 | `core/models.py` (re-export only), `storage/database.py` | `core/remediation_models.py`, `storage/migrations/004_remediation.sql`, `storage/remediation.py`, `storage/audit.py` |
| 2 | `knowledge/risk.py`, `core/models.py` (`Component.dev`, `Priority.label`), `adapters/node.py`/`python.py`/`java.py` (dev names), `analysis/cyclonedx.py` | `knowledge/exploit_intel.py`, `knowledge/reachability.py` |
| 3 | `analysis/git_diff.py` (extend), `adapters/*.py` (`apply_candidate`), `core/models.py` (new `ChangeCategory` values) | `analysis/supply_chain.py`, `data/popular_packages/{npm,pypi}.txt`, `remediation/candidates.py`, `remediation/registry.py`, `remediation/planner.py` |
| 4 | `core/config.py`, `execution/policies.py` (env scrub test) | `integrations/jira/{client,adf,publish,commands,sync,authz}.py` |
| 5 | `execution/policies.py` (sandbox policy), `orchestration/pipeline.py` (reused as-is) | `remediation/{apply,sandbox,validate,verify,diff}.py` |
| 6 | `orchestration/` | `orchestration/{investigation_graph,remediation_graph,checkpoint,state}.py` |
| 7 | `llm/providers.py`, `core/config.py`, `indexing/code_retriever.py` (`redact_secrets` reuse) | `llm/routing.py`, `llm/structured.py`, `llm/budget.py`, `llm/guard.py` |
| 8 | n/a | `investigation/{models,architect,code,dependency,vulnerability,change,auditor,correlator}.py` |
| 9 | `cli/main.py`, `cli/shell.py`, `cli/doctor.py`, `reporting/*` | `cli/{remediate,jira,cases,audit,compare}.py`, `tests/fixtures/demo/{node-app,python-app}`, `scripts/demo_day2.sh` |

`core/models.py` is already 640 lines, so remediation models go in `core/remediation_models.py` and
are re-exported from `core/models.py`, which keeps the brief's import path.

## Frozen contract (shared by all subagents)

- IDs: case `rc_<12 hex>`, candidate `cand_<12 hex>` = sha1(case fingerprint + action + component + to_version). Both deterministic, so re-runs dedupe.
- Case fingerprint: `sha1(repo_root + component_purl_or_path + vuln_id_or_rule)`. The Jira label is `guardian-fp-<fingerprint[:16]>`.
- `Source = Literal["verified", "inferred"]`. Every AI-bearing model has it.
- State machine (allowed edges only):
  `PROPOSED→AWAITING_DECISION`, `AWAITING_DECISION→{DECLINED,APPROVED,MODIFICATION_REQUESTED}`,
  `{APPROVED,MODIFICATION_REQUESTED}→APPLYING`, `APPLYING→{VALIDATING,VALIDATION_FAILED}`,
  `VALIDATING→{VERIFIED,VALIDATION_FAILED}`, `VALIDATION_FAILED→AWAITING_DECISION`,
  `{VERIFIED,DECLINED}→CLOSED`.
  `APPLYING→VALIDATION_FAILED` covers a patch that cannot be applied.
- Audit: `payload_sha256 = sha256(canonical_json(payload))`. The chain hash covers
  `prev_event_sha256 + event + actor + at + payload_sha256`. The chain is global (one log), and each event also carries `case_id`. `AuditStore` exposes `append` / `list` / `verify` only, with no update or delete.
- The external facts every service needs (registry, KEV/EPSS, Jira, Docker) sit behind small injectable classes with an `httpx.Client` or `ToolRunner` parameter. Tests never touch the network.

## Scope change: Juice Shop target ([day2-scope-juice-shop.md](../prompts/day2-scope-juice-shop.md))

Order is now **M1 → M3b/M3c (npm only) → M4 → M6 graph B → M5**. M2, M3a and M8 are deferred, and so is
M7 beyond what the M3c planner needs. M2 was stopped before it changed any file. M3b/M3c and M4 run in
parallel because both depend only on M1's models, and file ownership is split.

Juice Shop specifics that shape M5:
- No lockfile (`.npmrc package-lock=false`). Before SBOM/OSV, the sandbox runs
  `npm install --package-lock-only --package-lock=true --ignore-scripts` and copies the lockfile
  out to the scan workspace, never into the user's repository.
- Validation is `npm run build:server` (`tsc`) + `npm run test:server` (`node --test` via `tsx`)
  in a prebuilt `node:24` image with dependencies preinstalled (`npm ci --ignore-scripts`). No
  postinstall, test:frontend or test:api.
- Failures confined to `test/server/rsn.unit.test.ts` are classified as
  "fix conflicts with intentional challenge code", not as a Guardian error.
- Demo cases: (1) patch/minor upgrade of a package not imported by `lib/insecurity.ts` → VERIFIED;
  (2) jsonwebtoken 0.4.0 → 4.x/9.x major upgrade → FAILED, back to review; (3) decline
  `accepted_risk` for an intentional training vulnerability.
- Jira publishing is capped at the top 5 cases with priority ≥ HIGH (P2).

## Original order and delegation

The vertical slice first: M1 → M2 → M3 → M4 → M5 → M6, then M7 → M8 → M9. Each milestone goes to a
`general-purpose` subagent with a brief carrying the frozen contract, file ownership and the
security rules. The integrator (main session) reviews, runs `uv run ruff check`, `ty` and `pytest`,
and stops for a summary after each milestone. Independent halves run in parallel where files do
not overlap: M3a detectors ∥ M3b candidates; M4 Jira ∥ M5 sandbox.

Skills: `langchain-build-agent` (M6/M7/M8: LangGraph for the deterministic workflow with
`interrupt`, direct structured-output model calls for investigators, no agent loops),
`fp-check` + `vulnerability-triage-brocards` (M8 Vulnerability/Change investigator prompts and the
verified-vs-inferred rubric).
