# 11. Human-approved remediation

## Rules
Day 2 makes Guardian propose fixes, apply them after a human approves, and verify the result.
These rules add to the five principles in the [README](README.md):

6. **Deterministic tools establish facts; the LLM interprets and explains.** The LLM never
   decides whether a version is vulnerable, never invents a fix version, and never decides
   whether a human approved something.
7. **The LLM chooses only from enumerated candidates.** Remediation candidates (with IDs) are
   generated deterministically. The LLM may rank them, pick one by ID, and explain. Any output
   that references a non-existent candidate ID, package or version is rejected.
8. **No change is applied without a recorded human decision.** This is a new rule: Guardian
   applies changes, but only after human approval, only in an isolated git worktree on a
   `guardian/fix-*` branch, and never commits to or pushes the default branch. The interactive
   assistant ([09](09-interactive-shell-and-assistant.md)) stays read-only; applying a fix is a
   workflow step, not an assistant tool.
9. **Running the repo's build/tests means running hostile code.** Build and test only inside
   the sandbox. If the sandbox is unavailable, validation is `UNVERIFIED`, never `VERIFIED`.
10. **Every AI statement is labelled as inference.** Every model that carries AI output has
    `source: "verified" | "inferred"`, and reports render the two differently.
11. **Approval input is parsed deterministically and authorized.** Jira comments and fields are
    untrusted text. Decisions are parsed with a strict grammar (no LLM) and accepted only from an
    allowlist of approver account IDs.
12. **Append-only audit trail.** Every state change of a remediation case (created, published,
    decided, applied, validated, verified, closed) is written to an append-only audit log with
    actor, timestamp and payload hash.

## What was built (milestone 1: models and storage)
- `core/remediation_models.py`, re-exported from `core/models.py`: `RemediationCandidate`
  (always `source="verified"`), `RemediationPlan` (`source="inferred"` when an LLM chose,
  `"verified"` for the deterministic `--no-ai` pick; a validator enforces the pairing),
  `HumanDecision` with `ModifyPayload`, `ValidationRun`, `VerificationResult`, `RemediationCase`
  and `AuditEvent`.
- Deterministic IDs: fingerprint = sha1(repo root, component purl/path, vuln id/rule), case
  `rc_<12 hex>`, candidate `cand_<12 hex>` over fingerprint, action, component and target
  version. A rescan finds the same case and the same candidates, so nothing duplicates.
- The case state machine is a table (`ALLOWED_TRANSITIONS`):

  ```
  PROPOSED → AWAITING_DECISION → DECLINED | APPROVED | MODIFICATION_REQUESTED
  APPROVED | MODIFICATION_REQUESTED → APPLYING → VALIDATING | VALIDATION_FAILED
  VALIDATING → VERIFIED | VALIDATION_FAILED;  VALIDATION_FAILED → AWAITING_DECISION
  VERIFIED | DECLINED → CLOSED
  ```
  There is no edge into `APPLYING` except from a decision state, which is rule 8 in code.
- Decision validators: `DECLINE` needs a reason, `accepted_risk` needs an expiry date and a
  justification, `MODIFY` needs exactly one kind of modification (candidate, version, action
  with optional target, branch or commit).
- Schema v4 (`004_remediation.sql`): cases, candidates, plans, decisions (a Jira comment ID is
  unique, so re-syncing a comment is a no-op), validation runs, verification results, Jira links
  and `audit_events`.
- `AuditStore` has `append`, `list` and `verify` only. SQLite triggers abort any `UPDATE` or
  `DELETE` on `audit_events`. `RemediationStore.create` and `update_status` write the case and
  its audit event in one transaction, so a status change without an audit entry cannot happen.

## Decisions

### Frozen models with `transition()` instead of mutable state
Every model in Guardian is frozen (`extra="forbid"`). `RemediationCase.transition(to)` returns a
new copy and raises `IllegalTransitionError` on an edge not in the table. The store reloads the
case inside the write transaction and calls `transition`, so the check cannot be bypassed by a
stale in-memory copy. Alternative: mutable models with a `status` setter. Rejected because it is
the only mutable model in the codebase and makes "who changed this, when" harder to follow.

### One global hash chain, not one chain per case
Each event stores `payload_sha256 = sha256(canonical_json(payload))` and
`event_sha256 = sha256(prev_event_sha256, case_id, event, actor, at, payload_sha256)` (fields
joined by a separator). The chain runs through every event in insertion order; each event also
carries its `case_id` for filtering. `verify()` recomputes every hash and every link.

Alternative: one chain per case. That makes per-case export easy, but deleting a whole case's
events leaves the other chains intact, so the deletion is invisible. With one chain, removing,
editing or reordering any row breaks every later link. A unique index on `prev_event_sha256`
also makes a fork (two writers appending after the same event) fail loudly.

The triggers stop accidents and casual edits. They do not stop someone with write access to the
file, who can drop them; `verify()` is what detects that. Anchoring the latest hash outside the
database (for example in the Jira issue) would detect a full rewrite of the chain; not built.

### `case_id` is not a foreign key on `audit_events`
The log must outlive what it describes, and a cascading delete from `remediation_cases` would
hit the triggers anyway.

### Lazy re-export from `core/models.py`
`core/models.py` is already large, so the models live in their own module. That module imports
`_Frozen`, `Confidence` and `Priority` from `core/models.py`, so an eager re-export at the bottom
of `models.py` would be a cycle whenever `remediation_models` is imported first. `models.py`
re-exports the names through a module `__getattr__`, with a `TYPE_CHECKING` import so type
checkers see the real types.

### Priority words over P1–P4
The brief's buckets (`CRITICAL/HIGH/MEDIUM/LOW`) map onto the existing priorities from
[07](07-risk-scoring.md) instead of replacing them: `Priority.label` gives P1 "critical" to P4
"low", and `Priority.parse` accepts either spelling (`HIGH` == `P2`).

## Remediation graph (graph B)
`orchestration/remediation_graph.py` runs one durable LangGraph thread per case
(`thread_id = case_id`), checkpointed after every step with `SqliteSaver` in
`<data_dir>/checkpoints.sqlite`:

```
plan -> publish_jira -> await_decision (interrupt)
await_decision --ACCEPT/MODIFY/REVALIDATE--> apply -> validate -> rescan_verify
await_decision --DECLINE--> record_acceptance -> report_back -> END
rescan_verify --VERIFIED--> report_back -> END (case CLOSED)
apply / validate / rescan_verify --failed--> publish_failure -> await_decision
```

- The graph is the only thing that moves a case out of `AWAITING_DECISION`. The decision
  channels (`guardian decide`, `guardian jira sync`, `guardian ui`) parse and authorize the
  decision and then call `remediation/runtime.py: submit_decision`, which records it (unless the
  channel already did) and resumes the thread. `record_decision_transition` is kept only for
  tests and back-compat; it is never combined with the graph.
- `guardian remediate` creates the cases and runs `start_cases`, which takes every open case to
  `await_decision`. An existing thread is never restarted; a refreshed case gets its Jira issue
  updated instead.
- `await_decision` has no side effects (it replays on resume). Side-effect nodes call idempotent
  services and are guarded by the case status and by `graph:<node>` audit events, so a node
  replayed after a crash does not duplicate transitions, comments or audit entries.
- Failure contract: a `GuardianError` from `apply`/`validate` is a domain failure and sends the
  case to `VALIDATION_FAILED` and back to review (attempt + 1). Any other exception is a crash:
  the checkpoint keeps the node pending and `guardian validate <case>` retries it
  (`continue_case`).
- `REVALIDATE` re-runs the last ACCEPT/MODIFY decision after a failed attempt (the case is back
  in `AWAITING_DECISION`); `guardian validate <case>` submits it.
- Nodes run on the calling thread, and `Database` connections are thread-bound, so
  `submit_decision` opens its own database and checkpointer inside the call (the UI calls it from
  a worker thread). A per-case lock serialises submits in one process; across processes the
  SQLite write lock (`BEGIN IMMEDIATE`, 30 s busy timeout) serialises writes and the audit chain
  head is read under that lock.

## Sandbox
Validation runs in Docker (`remediation/sandbox.py`). The `docker run` argument list is fixed:

```
docker run --rm --name guardian-<case>-<step> --user 1000:1000 --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 512 --memory <GUARDIAN_SANDBOX_MEMORY=4g>
  --cpus <GUARDIAN_SANDBOX_CPUS=2> --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m
  --network bridge|none --env <fixed CONTAINER_ENV only>
  --mount type=bind,src=<disposable copy>,dst=/work --workdir /work <image> <command>
```

Phase 1 (network on, install scripts off): regenerate `package-lock.json`
(`npm install --package-lock-only --ignore-scripts`), then build or reuse
`guardian-deps:<hash>` (`npm ci --ignore-scripts`). Phase 2 (`--network none`): `npm run
build:server` and `npm run test:server` for Juice Shop-like projects (`postinstall`,
`test:frontend`, `test:api` never run). The user's repository and the Docker socket are never
mounted; only a symlink-free copy of the worktree is. Each step has a wall-clock limit
(`GUARDIAN_SANDBOX_TIMEOUT_SECONDS`, default 900) after which the container is killed.
`guardian scan` uses the same sandbox to generate a missing npm lockfile into a scan workspace
(`GUARDIAN_NPM_LOCKFILE_GENERATION`, default on); without Docker it warns and the dependency scan
is partial. `GUARDIAN_UNSAFE_HOST_VALIDATION=true` runs the steps on the host instead, with a
loud warning, and caps the verdict at `PARTIALLY_VERIFIED`.

## Verdict mapping
`verify.decide_verdict` (evaluated in order) and what the graph does with it:

| Verdict | When | Case |
|---|---|---|
| `UNVERIFIED` | rescan did not run / cdxgen or OSV-Scanner did not succeed; or no sandbox | `VALIDATION_FAILED` → back to review |
| `FAILED` | a target finding still present, a new HIGH/CRITICAL finding, install/build failed, real test failures | `VALIDATION_FAILED` → back to review |
| `PARTIALLY_VERIFIED` | no build step or no tests, only lower-severity new findings, only known challenge-code test failures ("fix conflicts with intentional challenge code"), or host validation | `VALIDATION_FAILED` → back to review |
| `VERIFIED` | targets resolved, nothing new at HIGH/CRITICAL, build and tests passed in Docker | `VERIFIED` → `CLOSED` |

Only `VERIFIED` closes a case; everything else returns it to a human with the reasons.

## Jira channel
- Publishing: at most `GUARDIAN_JIRA_MAX_ISSUES` (5) open cases at or above
  `GUARDIAN_JIRA_MIN_PRIORITY` (HIGH), found again by the `guardian-fp-<fingerprint>` label.
- Decisions: `guardian jira sync [--watch]` polls comments; only `/guardian ...` commands from
  `GUARDIAN_APPROVERS` account IDs count (Guardian's own account never does), parsed by the strict
  grammar. Each comment is recorded at most once, acknowledged, then handed to the graph.
- Write-back: one comment per stage and attempt (applying, validation results, verdict, failure
  with the reasons, decline), each guarded by an audit event; optional workflow transitions via
  `GUARDIAN_JIRA_TRANSITIONS`.
- Jira is best effort: publish or comment failures are audited (`jira:publish_failed`,
  `jira:comment_failed`) and never block the remediation. `guardian decide` and `guardian ui`
  record decisions locally (approver = local OS user in `GUARDIAN_CLI_APPROVERS`).

## Known limits
- **git filter/smudge drivers.** `git worktree add` checks files out, and a repository-local
  `.git/config` (or `.gitattributes` naming a configured filter) can run filter/smudge drivers
  during that checkout. Guardian's hardening disables hooks, fsmonitor and external diff but not
  filters. The risk is low for cloned repositories, because `git clone` does not import a remote's
  config, but a local folder whose `.git/config` was written by someone else is trusted as-is.
- **Docker temp-file cleanup on Linux.** Files the container (uid 1000) creates in the bind-mounted
  copy belong to uid 1000 on the host. When the host user is not uid 1000, removing the disposable
  directory can fail and leave files in the system temp directory (macOS Docker Desktop is not
  affected).
- **Docker end-to-end is not covered by CI.** Unit and integration tests use a fake sandbox and a
  fake rescan; the real `docker run` path is exercised only by the live demo
  (`docs/demo/day2-runbook.md`).
- **Rescans are stored as scans.** Verification rescans the fix worktree with the normal
  pipeline, so each attempt adds a scan of `<data_dir>/worktrees/<case>` to `guardian history`.
  `guardian remediate latest` skips those; other commands' `latest` (`report`, `findings`,
  `jira push`) may pick one, so pass the original scan id there.
- **REVALIDATE in the web UI.** The UI accepts REVALIDATE only in `VALIDATION_FAILED`/`VERIFIED`,
  which the graph passes through immediately; use `guardian validate <case>` (or Jira) to
  re-validate after a failed attempt.

## Alternatives
- **Event sourcing (state derived only from the audit log):** strongest audit story, but every
  read replays events. A current-state table plus an audit log written in the same transaction
  gives the same guarantees for this size of data.
- **Plain concatenation for IDs and hashes:** `"/ra" + "b"` and `"/r" + "ab"` collide; joining
  fields with an ASCII unit separator avoids that.
