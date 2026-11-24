# 01. Foundation: CLI, profiler, safe tool execution

## What was built
- A Typer CLI (`guardian scan`, `doctor`, `history`, ...), Pydantic models for every record
  (`core/models.py`), and a repository profiler (languages, ecosystems, manifests, lockfiles).
- A **ToolRunner** through which every external program (cdxgen, osv-scanner, semgrep, git) runs.

## ToolRunner hardening
- Allowlist of tool names; no shell; scrubbed environment (API keys never reach scanners);
  timeouts; output size caps.
- `.cmd` wrappers on Windows (npm-installed tools) reject cmd metacharacters in arguments.
- Git runs with hooks, fsmonitor, external diff drivers, pagers, credential helpers and
  non-HTTPS protocols disabled. Set both as `-c` arguments and as `GIT_CONFIG_COUNT` env vars.

## Why this approach
Guardian opens repositories the user does not control. Git hooks, `core.fsmonitor`,
`diff.external` and `.gitattributes` filters are all ways a repository can execute code when a
tool merely reads it. Treating the runner as the single choke point means one place to audit.
Pydantic models (frozen, `extra="forbid"`) catch contract drift between modules early.

## Alternatives considered
| Alternative | Why not |
|---|---|
| `subprocess.run(..., shell=True)` | Command injection via repo-controlled file names. |
| Run scanners in Docker/containers | Strongest isolation, but needs Docker on every machine; heavy for a CLI. A good future option for CI use. |
| Library bindings (e.g. GitPython only) | GitPython still shells out to git; it does not remove the hook/config risks, and adds a dependency surface. Plain `git` through the runner is easier to harden. |
| Windows-only or POSIX-only paths | The user is on Windows; CI runs both Ubuntu and Windows, so both were supported. |
| Setting `GIT_CONFIG_NOSYSTEM` | Tried, but it broke `core.autocrlf` and made the Juice Shop clone look dirty. Removed. |

## Known limits
Process-level hardening is not a sandbox. A malicious tool binary or a bug in cdxgen/Semgrep is
out of scope; Node's `--permission` model is used for cdxgen as defense in depth (see 02).
