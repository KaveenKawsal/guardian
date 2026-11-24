# Day 2 scope change: OWASP Juice Shop target

Supersedes the build order in [day2.md](day2.md) where they conflict.

Day 2 target repo: OWASP Juice Shop (fork with full git history). Scope changes:
- Build in this order: M1 (cases/decisions/audit only) → M3b/M3c (npm only) → M4 → M6 graph B → M5. Defer M2, M3a, M7 beyond what M3c needs, and M8.
- Juice Shop has no lockfile (.npmrc package-lock=false). Before SBOM/OSV, generate one in the sandbox:
  npm install --package-lock-only --package-lock=true --ignore-scripts
- Validation for Juice Shop = `npm run build:server` + `npm run test:server` only, inside a prebuilt node:24 image with
  dependencies preinstalled (--ignore-scripts). Do not run postinstall, test:frontend or test:api.
- Cap Jira publishing to the top 5 cases with priority >= HIGH.
- Demo cases: (1) a patch/minor upgrade not used by lib/insecurity.ts → VERIFIED; (2) jsonwebtoken 0.4.0 major
  upgrade → expect FAILED, case returns to review; (3) decline with accepted_risk (intentional training vuln).
- rsn.unit.test.ts failures on challenge snippet files are expected; report them as "fix conflicts with
  intentional challenge code", not as a Guardian error.
