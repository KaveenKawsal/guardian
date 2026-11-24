# Day 2 live demo: Juice Shop, from finding to verified fix

Goal: show a vulnerable npm dependency go from **prioritized finding → recommended fix → human
decision → isolated branch → sandboxed build/test → rescan → verdict**, with every step in a
hash-chained audit log. Nothing is applied without a recorded human decision.

## 1. Prerequisites (do these before the audience arrives)

1. **Docker Desktop running**, then pull the base image (the lockfile step and validation use it):
   ```bash
   docker pull node:24-bookworm-slim
   ```
2. **A local Juice Shop git clone with history** (Guardian creates `guardian/fix-*` worktrees from
   it; it never touches your working tree):
   ```bash
   git clone https://github.com/juice-shop/juice-shop ~/Documents/juice-shop
   ```
3. **Scanners on PATH**: `cdxgen`, `osv-scanner` (required for a VERIFIED verdict), `semgrep`, `git`.
4. **`.env`** in the directory you run Guardian from (or `~/.guardian/.env`):
   ```bash
   GUARDIAN_CLI_APPROVERS=<output of `whoami`>   # who may decide via guardian decide / ui
   # Optional Jira channel:
   # JIRA_BASE_URL=https://<site>.atlassian.net
   # JIRA_EMAIL=...  JIRA_API_TOKEN=...  JIRA_PROJECT_KEY=SEC
   # GUARDIAN_APPROVERS=<jira accountId>
   ```
5. **Check everything**:
   ```bash
   uv run guardian doctor            # add --online to authenticate against Jira
   ```
   Expect `Docker sandbox ok … node:24-bookworm-slim present`, the scanners `found`, `Approvers`
   listing your user, `Checkpoints ok`.

Warm-up (strongly recommended): run steps 2–3 once before the demo. The first lockfile generation
takes about 3 minutes and the first dependency image build several more; both are cached
(`guardian-deps:<hash>` images, the npm registry cache), so the live run is much faster.

## 2. Scan

```bash
uv run guardian scan ~/Documents/juice-shop
```

Expected:
- `No npm lockfile: generating one in the Docker sandbox (npm install --package-lock-only
  --ignore-scripts); your repository is not modified.`
- Tool runs: `npm-lockfile success`, `cdxgen success`, `osv-scanner success`.
- Hundreds of npm components and a long list of vulnerabilities (jsonwebtoken 0.4.0,
  express-jwt 0.1.3, sanitize-html 1.4.2, ...).
- Warning `package-lock.json was generated in the sandbox for dependency analysis ... not written
  to the repository`.

## 3. Create cases and start the workflow

```bash
uv run guardian remediate latest --no-ai          # add --no-jira to keep Jira out of it
```

Expected: up to 5 cases (priority HIGH or above), each with `Recommended: ...`, a
`Deterministic plan` (or an `AI inference` plan without `--no-ai`), a candidates table, and the
summary `N case(s), N waiting for a decision; Jira: SEC-1, ...`. Each case's LangGraph thread is
now paused at the human decision (checkpointed in `~/.guardian/checkpoints.sqlite`, survives
restarts).

```bash
uv run guardian cases                 # all AWAITING_DECISION
uv run guardian case <ID>             # candidates, evidence, rollback, audit trail
```

## 4. The three demo cases

Pick the cases from `guardian cases`:

### Case 1: patch/minor upgrade → VERIFIED
Choose a case whose recommended candidate has a `patch` or `minor` jump and whose package is
**not** imported by `lib/insecurity.ts` (not jsonwebtoken, express-jwt or sanitize-html).

```bash
uv run guardian decide <ID1> accept
```

Expected (takes a few minutes): `Applying in an isolated worktree, then sandboxed build/test and
a rescan ...`, then `Case <ID1> is now CLOSED.`, `Verdict: VERIFIED (confidence high); risk X ->
0.0`, the reasons (targets resolved, build passed, tests passed, validated in the Docker sandbox)
and the `install` / `build` / `test` steps. Show:

```bash
uv run guardian case <ID1>            # Validation runs + Verification (before/after, SBOM diff)
git -C ~/Documents/juice-shop log --oneline guardian/fix-<ID1> -1   # Guardian's commit
git -C ~/Documents/juice-shop status   # your working tree is untouched
```

### Case 2: jsonwebtoken 0.4.0 major upgrade → FAILED, back to review

```bash
uv run guardian decide <ID2> accept            # or: modify version=9.0.0
```

Expected: `Verdict: FAILED` (the major upgrade breaks `npm run build:server` or the server tests),
`Returned to review: ...`, `Case <ID2> is now AWAITING_DECISION`. Failures only in
`test/server/rsn.unit.test.ts` are reported as "fix conflicts with intentional challenge code"
(PARTIALLY_VERIFIED), not as a Guardian error. The human can now `modify version=...`, `decline`,
or re-run with `uv run guardian validate <ID2>`.

### Case 3: intentional training vulnerability → decline with accepted risk

```bash
uv run guardian decide <ID3> decline reason=accepted_risk until=2027-06-30 -- intentional training vuln
```

Expected: `Case <ID3> is now CLOSED.` No branch, no build. `guardian case <ID3>` shows the
decision with its justification; the audit trail has `decline:recorded` with the expiry.

### Close with the audit log

```bash
uv run guardian audit verify          # ok: N audit event(s), hash chain intact.
```

## 5. Jira channel (optional)

With Jira configured, `guardian remediate` published the cases (at most 5, ≥ HIGH). In the
issue, an approver comments e.g. `/guardian accept` or `/guardian decline reason=accepted_risk
until=2027-06-30 -- intentional training vuln`. Then:

```bash
uv run guardian jira sync             # or: guardian jira sync --watch
```

Expected: `<case>: ACCEPT by <name> ...; resuming the remediation graph ...`, then the same result
block as `guardian decide`. Guardian comments on the issue: decision acknowledged, applying on
branch `guardian/fix-...`, validation results table, verification verdict (or the failure with its
reasons and how to reply).

## 6. Web UI

The local review console is the backup channel when Jira is unavailable (and a nicer screen for
the audience).

```bash
uv run guardian ui                    # --port 8765 by default, --no-open to just print the URL
```

- It binds to `127.0.0.1` only and prints a one-time URL of the form
  `http://127.0.0.1:8765/?token=<random>`; open that exact URL (the token authorizes the browser;
  without it the API answers 401).
- **`GUARDIAN_CLI_APPROVERS` must contain your OS user (`whoami`)**, or every decision gets
  HTTP 403 and nothing is recorded. The console warns at startup when your user is missing; add it
  to `.env` and restart `guardian ui`.
- Pick a case, review the recommended fix and alternatives, and Accept / Modify / Decline. The
  decision is recorded immediately (202), then the remediation graph runs on a background worker
  thread; the route map moves through Applied → Build & test → Rescan → Verified while the page
  polls. A second decision on the same case is refused while one is running.
- Re-validate after a failed attempt from the terminal (`guardian validate <ID>`) or Jira; the UI's
  revalidate action only applies to VALIDATION_FAILED/VERIFIED, which the graph passes through
  immediately.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Scan: `warning: docker daemon not reachable ...: start Docker Desktop to generate a lockfile; dependency scan will be partial` | Docker is down. Start Docker Desktop and rescan. Without it the SBOM only has the manifest's direct dependencies and few npm cases appear. |
| Scan: tool run `npm-lockfile failed (failed, exit N)` followed by npm output | Read the npm output in the warning (network/registry errors, out of memory → raise `GUARDIAN_SANDBOX_MEMORY`, slow network → raise `GUARDIAN_SANDBOX_TIMEOUT_SECONDS`). Exit 137 with no output = the container was killed (e.g. `docker rm -f` or OOM). Do not remove `guardian-*` containers while a scan or validation is running. |
| Scan status `partial`, cdxgen/osv-scanner `missing` | Install the scanner (`guardian doctor` shows the install hint). A fix can then only be `UNVERIFIED` (the rescan cannot prove the finding is gone). |
| Verdict `UNVERIFIED`: `sandbox unavailable: ...` | Docker stopped between scan and decision. Start it and `guardian validate <ID>` once the case is back in review. |
| `Case ... is not paused for a decision; run guardian validate <ID> to retry its crashed step` | A step crashed (e.g. Ctrl-C during validation). `guardian validate <ID>` resumes from the checkpoint. |
| `local user 'x' is not in GUARDIAN_CLI_APPROVERS` / UI 403 | Add your `whoami` to `GUARDIAN_CLI_APPROVERS`. |
| Jira down / 401 | Remediation is unaffected (`jira:publish_failed` / `jira:comment_failed` in the audit trail). Decide with `guardian decide` or `guardian ui`; publish later with `guardian jira push <scan-id>`. |
| `guardian report latest` / `findings latest` show a scan of `~/.guardian/worktrees/...` | Verification rescans are stored as scans. Pass the original scan id (`guardian history`). `guardian remediate latest` already skips them. |

Clean up after the demo: `git -C ~/Documents/juice-shop worktree prune`, delete
`guardian/fix-*` branches if wanted, and `docker image prune -a --filter label=guardian.deps-hash`.
