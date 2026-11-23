# Guardian

AI-powered repository security intelligence. Guardian combines deterministic security
scanners, codebase understanding, dependency and code knowledge graphs, and specialised AI
investigators to identify, contextualise, prioritise and explain security risks.

> Status: **Phase 3 (Security detection)** complete: dependency intelligence plus known
> vulnerabilities (OSV-Scanner), insecure code patterns (Semgrep), security-relevant git
> changes, evidence records and an interactive dependency graph. Next: phase 4, codebase
> understanding with Tree-sitter.

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
uv sync
npm install -g @cyclonedx/cdxgen             # SBOM generator
winget install Google.OSVScanner             # known-vulnerability matching (or see osv.dev)
uv tool install semgrep                      # static analysis
# Every tool is optional: a missing one makes the scan "partial" instead of failing it.

uv run guardian scan ./my-project            # profile + SBOM + dependency graph, stored in ~/.guardian
uv run guardian findings                     # security findings of the latest scan, worst first
uv run guardian findings -k code -s high     # filter by kind and minimum severity
uv run guardian explain <finding-id>         # facts, evidence chain, how it enters, remediation
uv run guardian graph -o graph/              # interactive dependency graph (open graph/index.html)
uv run guardian deps                         # direct dependencies of the latest scan
uv run guardian deps --all                   # every component, with depth and declaring manifest
uv run guardian deps --why mime-db           # how a package entered the dependency tree
uv run guardian history                      # previous scans
uv run guardian profile ./my-project --json  # profile only, no storage
uv run guardian doctor                       # check external tools
```

## Development

```bash
uv run pytest                 # tests + coverage (80% minimum)
uv run ruff format src tests
uv run ruff check src tests
uv run ty check src
```

## Layout

| Package | Responsibility |
|---|---|
| `guardian.cli` | Typer commands (`scan`, `findings`, `explain`, `graph`, `deps`, `history`, `profile`, `doctor`) |
| `guardian.core` | Settings, Pydantic models, profiler, adapter registry, exceptions |
| `guardian.adapters` | Ecosystem detection: Python, Node.js, Java, containers |
| `guardian.execution` | Sandboxed external tool runner and execution policies |
| `guardian.analysis` | cdxgen SBOMs, CycloneDX parsing, OSV-Scanner, Semgrep, git change analysis |
| `guardian.knowledge` | NetworkX knowledge graph (dependencies, findings, changes) and queries |
| `guardian.indexing` | Tree-sitter symbols, imports and calls (Python, JS/TS), resolution to files and SBOM packages, entry points, incremental cache |
| `guardian.reporting` | Interactive HTML dependency graph export |
| `guardian.storage` | SQLite persistence with versioned migrations: scans, SBOMs, findings, changes |
| `guardian.orchestration` | Deterministic scan pipeline (LangGraph arrives in phase 5) |

## How direct dependencies are determined

Each SBOM records which method was used (`direct_source`):

1. `sbom`: the SBOM links its root to the direct dependencies (cdxgen does this for npm).
2. `manifest`: matched against names Guardian parsed from `pyproject.toml`,
   `requirements*.txt` and `package.json` (cdxgen omits root links for uv/Poetry projects).
3. `sbom+manifest`: the union, for polyglot repositories.
4. `graph-inference`: last resort, packages nothing else depends on; flagged with a warning
   because it misses packages that are both direct and transitive.
5. `unknown`: no dependency graph; `direct` is left null rather than guessed.

## Security model for scanning untrusted repositories

- The file walk never follows symlinks or junctions and skips vendored/build directories.
- Manifests are read with a size cap; malformed files produce warnings, not crashes.
- External tools run from an allowlist, without a shell, with a scrubbed environment
  (no API keys or cloud credentials), a timeout and bounded output.
- `git` runs with repo-local config neutralised (`core.fsmonitor`, hooks, `diff.external`,
  pager, protocols, credential helpers), so a hostile `.git/config` cannot execute code.
- cdxgen runs in secure mode with `--no-install-deps` (no package installs, so no install
  scripts) and under the Node.js permission model: read access only to the repository, its own
  install and temp; write access only to temp. The SBOM is written outside the repository.
- The git hardening is also exported as `GIT_CONFIG_*` variables to every tool, because
  scanners such as Semgrep run `git` inside the repository themselves.
- OSV-Scanner runs with `--no-resolve` (no network manifest resolution) and
  `--no-call-analysis=all` (Rust call analysis would run build scripts). It sends package
  names and versions, never source code, to api.osv.dev.
- Semgrep runs the OSS engine with metrics off and ignores the repository's `.gitignore`. A
  repository-provided `.semgrepignore` cannot be disabled, so its patterns are reported.
- Matched source text is never stored: code findings keep a hash of it, so a secret matched
  by a rule never reaches Guardian's database or reports. Author emails are never collected.
- Text from the scanned repository or from advisories is escaped before it reaches the
  terminal, and the HTML graph renders it as text only.

## Findings

Every finding has a stable id (the same issue keeps its id across scans), a severity, the tool
that established it, and evidence records:

| Kind | Source | Evidence |
|---|---|---|
| `vulnerability` | OSV-Scanner on Guardian's SBOM | advisory, tool match, declaring manifest; linked to the exact component, with the recommended fixed version |
| `code` | Semgrep | source location; the commit that last touched the lines (`git blame`) |
| `change` | git history | commit, author name, files: lockfile changed without its manifest, CI/CD or container config changed, secret-bearing files committed, security-sensitive code changed, uncommitted dependency changes |

Deterministic tools establish these facts. Phase 5 adds AI investigation of relevance,
reachability and exploitability on top.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | CLI, repository profiler, adapters, safe tool execution | Done |
| 2. Dependency intelligence | cdxgen SBOM, CycloneDX parsing, dependency graph, SQLite history | Done |
| 3. Security detection | OSV-Scanner, Semgrep, git change analysis, evidence, graph view | Done |
| 4. Codebase understanding | Tree-sitter symbols, imports, calls, entry points, code retrieval | In progress |
| 5. AI investigation | LangGraph specialist agents, evidence correlation, risk scoring | Planned |
| 6. Incremental scanning and demo | Scan comparison, JSON/HTML reports, demo scenarios | Planned |
