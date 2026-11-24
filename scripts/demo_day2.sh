#!/usr/bin/env bash
# Guardian Day 2 demo: scan -> (investigate) -> remediate -> human decides in the UI -> report.
#
# Usage: scripts/demo_day2.sh [JUICE_SHOP_PATH] [--no-ai]
#
# Uses a separate data directory (default ~/.guardian-demo) so rehearsals never touch your
# real Guardian data. Remove it to start over:  rm -rf ~/.guardian-demo
#
# This script never records a decision. A human approves, modifies or declines each case in
# Jira or in the review console (guardian ui); `guardian decide` is printed as a fallback.
set -euo pipefail

NO_AI=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    --no-ai) NO_AI=1 ;;
    -h|--help)
      sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*) echo "Unknown option: $arg" >&2; exit 2 ;;
    *) TARGET="$arg" ;;
  esac
done
TARGET="${TARGET:-$HOME/Documents/juice-shop}"

export GUARDIAN_DATA_DIR="${GUARDIAN_DATA_DIR:-$HOME/.guardian-demo}"
GUARDIAN="${GUARDIAN:-guardian}"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- Prerequisites ---------------------------------------------------------------------
bold "Checking prerequisites"
if ! command -v "$GUARDIAN" >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    GUARDIAN="uv run guardian"
  else
    fail "'guardian' is not on PATH. Install it (uv tool install .) or run from the repo with uv."
  fi
fi
[ -d "$TARGET" ] || fail "Juice Shop not found at $TARGET. Pass its path: $0 /path/to/juice-shop"
git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || fail "$TARGET is not a git repository. Clone it: git clone https://github.com/juice-shop/juice-shop"
command -v docker >/dev/null 2>&1 || fail "Docker is not installed: validation needs the sandbox."
docker info >/dev/null 2>&1 || fail "Docker is not running. Start Docker Desktop and try again."
note "target:   $TARGET"
note "data dir: $GUARDIAN_DATA_DIR (fresh demo data, separate from ~/.guardian)"
mkdir -p "$GUARDIAN_DATA_DIR"

# shellcheck disable=SC2086 # GUARDIAN may be "uv run guardian"
g() { $GUARDIAN "$@"; }

JIRA_ARGS=(--no-jira)
if [ -n "${GUARDIAN_JIRA_BASE_URL:-${JIRA_BASE_URL:-}}" ] && [ -n "${GUARDIAN_JIRA_API_TOKEN:-${JIRA_API_TOKEN:-}}" ]; then
  JIRA_ARGS=()
  note "Jira:     configured - cases will be published as issues"
else
  note "Jira:     not configured - decisions happen in the review console"
fi
AI_ARGS=()
if [ "$NO_AI" -eq 1 ]; then
  AI_ARGS=(--no-ai)
  note "AI:       off (--no-ai): deterministic plans, no investigators"
fi

# --- 1. Doctor -------------------------------------------------------------------------
bold "1/5 guardian doctor"
g doctor || note "doctor reported problems (see above); continuing - optional tools degrade to 'partial'."

# --- 2. Scan ---------------------------------------------------------------------------
bold "2/5 guardian scan $TARGET"
g scan "$TARGET"

# --- 3. Investigate --------------------------------------------------------------------
if [ "$NO_AI" -eq 1 ]; then
  bold "3/5 guardian investigate (skipped: --no-ai)"
else
  bold "3/5 guardian investigate latest"
  g investigate latest || note "investigation failed; the demo continues with verified facts only."
fi

# --- 4. Remediate ----------------------------------------------------------------------
bold "4/5 guardian remediate latest --top 5 --min-priority HIGH ${JIRA_ARGS[*]:-} ${AI_ARGS[*]:-}"
g remediate latest --top 5 --min-priority HIGH ${JIRA_ARGS[@]+"${JIRA_ARGS[@]}"} ${AI_ARGS[@]+"${AI_ARGS[@]}"}

bold "Cases awaiting a human decision"
g cases --status AWAITING_DECISION

cat <<'EOF'

   Guardian does not decide. Each case waits for a recorded human decision.
   If the console is unavailable, decide from a terminal instead (replace rc_... with a case id):

     guardian decide rc_... accept
     guardian decide rc_... modify version=1.2.3
     guardian decide rc_... decline reason=accepted_risk until=2027-03-31 -j "Not reachable; behind VPN"
     guardian decide rc_... revalidate

   Then:  guardian case rc_...          # timeline, validation, verdict, audit trail
          guardian report latest -f html,md,json --open
          guardian compare <before-scan> <after-scan>
          guardian audit verify
EOF

# --- 5. Review console -----------------------------------------------------------------
bold "5/5 guardian ui"
cat <<'EOF'
   In the browser:
     1. Open a case from the "Awaiting decision" list.
     2. Show the verified finding and evidence, then the AI investigation (labelled inference).
     3. Show the recommended fix, its alternatives and the expected risk reduction.
     4. Click Accept (or Modify / Decline with a reason and expiry) - this is the human step.
     5. Watch validation run in the Docker sandbox, then the rescan verdict (VERIFIED / FAILED).
     6. A FAILED fix that conflicts with Juice Shop's intentional challenge code returns to review.
   Press Ctrl+C here to stop the console, then run: guardian report latest --open
EOF
g ui
