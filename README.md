# Guardian

AI-powered repository security intelligence. Guardian combines deterministic security
scanners, codebase understanding, dependency and code knowledge graphs, and specialised AI
investigators to identify, contextualise, prioritise and explain security risks.

> Status: **Phase 4 (Codebase understanding)** complete: dependency intelligence, known
> vulnerabilities (OSV-Scanner), insecure code patterns (Semgrep), security-relevant git
> changes, evidence records, an interactive dependency graph, and a Tree-sitter index of the
> repository's own source that puts findings in code context. Next: phase 5, AI investigation.

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
uv sync
npm install -g @cyclonedx/cdxgen             # SBOM generator
winget install Google.OSVScanner             # known-vulnerability matching (or see osv.dev)
uv tool install semgrep                      # static analysis
# Every tool is optional: a missing one makes the scan "partial" instead of failing it.

uv run guardian scan ./my-project            # profile + SBOM + dependency graph, stored in ~/.guardian
uv run guardian scan https://github.com/juice-shop/juice-shop   # clone a public HTTPS repo, then scan it
uv run guardian scan juice-shop/juice-shop --ref v17.0.0        # GitHub shorthand, branch or tag
uv run guardian scan                         # in a terminal: prompts for a URL or local path
uv run guardian findings                     # security findings of the latest scan, worst first
uv run guardian findings -k code -s high     # filter by kind and minimum severity
uv run guardian explain <finding-id>         # facts, evidence chain, how it enters, remediation
uv run guardian graph -o graph/              # interactive dependency graph (open graph/index.html)
uv run guardian deps                         # direct dependencies of the latest scan
uv run guardian deps --all                   # every component, with depth and declaring manifest
uv run guardian deps --why mime-db           # how a package entered the dependency tree
uv run guardian code                         # codebase index: files, symbols, imports, entry points
uv run guardian code --uses lodash           # where the source imports and calls a package
uv run guardian code --entry-points          # routes, servers, main guards, package entry points
uv run guardian history                      # previous scans
uv run guardian profile ./my-project --json  # profile only, no storage
uv run guardian doctor                       # check external tools
```

### AI providers (Groq or Google Gemini)

AI investigation (phase 5) uses your own API key; deterministic analysis works without one.
Copy `.env.example` to `.env` (git-ignored) or `~/.guardian/.env` (works from any directory)
and paste your keys:

```bash
GROQ_API_KEY=...      # https://console.groq.com/keys
GOOGLE_API_KEY=...    # https://aistudio.google.com/apikey (GEMINI_API_KEY also works)
```

```bash
uv run guardian ai status                    # which keys are set (masked) and the active model
uv run guardian ai models                    # live model list from the active provider
uv run guardian ai test                      # one tiny round-trip to confirm the key works
uv run guardian ai use google --model gemini-2.5-pro   # switch provider and/or model
```

Keys are never printed, stored in Guardian's database, or passed to scanner subprocesses.

Remote targets are cloned (shallow, no submodules, no hooks, symlinks checked out as plain
files, HTTPS only) into `~/.guardian/workspaces/<hash>/<repo>`; the same repository always
lands in the same directory, so `guardian history` groups its scans. The clone is kept so
`guardian explain` and `guardian code` can read files later; pass `--no-keep` to delete it
after the scan. `http://`, `ssh://`, `git@`, `file://`, `ext::` and URLs with embedded
credentials are rejected. Repositories without a lockfile (e.g. OWASP Juice Shop) give a
shallow dependency graph: generate one yourself with
`npm install --package-lock-only --ignore-scripts`; Guardian never runs package managers.

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
| `guardian.cli` | Typer commands (`scan`, `findings`, `explain`, `graph`, `deps`, `code`, `history`, `profile`, `doctor`) |
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

## Codebase understanding

Every scan indexes the repository's own source with Tree-sitter (no code is imported or
executed), alongside the security scanners:

- **What is indexed**: Python, JavaScript, TypeScript and TSX files: symbols (classes,
  functions, methods with their spans), imports (`import`/`from`, ES modules, `require`,
  dynamic imports), call sites, and entry points (`__main__` guards, `__main__.py`,
  `package.json` main/bin, `[project.scripts]`, HTTP routes, server `listen`/`run` calls).
- **Resolution**: imports resolve to repository files, the standard library / Node built-ins,
  or third-party packages matched to the exact SBOM component; calls resolve to internal
  symbols or to members of those packages (e.g. `lodash.template`).
- **Incremental**: per-file results are cached by content hash in the Guardian database, so
  rescanning a repository only re-parses changed files. Oversized, minified and unreadable
  files are skipped and counted; limits are `max_source_bytes` and `max_indexed_files`, and
  `index_source=false` disables indexing.
- **Code context on findings**: code findings name the innermost enclosing symbol
  (`guardian explain` shows `Symbol: app/api.py::UserService.login`), and vulnerability
  findings gain `code-usage` evidence: the files and lines importing the vulnerable package and
  the members called (`Imported in 2 file(s): src/a.ts:3, src/b.ts:9; calls: template (2)`),
  or that the source does not import it directly.

An indexing failure never fails the scan: it is recorded as an errored `indexer` run and the
scan is marked partial.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | CLI, repository profiler, adapters, safe tool execution | Done |
| 2. Dependency intelligence | cdxgen SBOM, CycloneDX parsing, dependency graph, SQLite history | Done |
| 3. Security detection | OSV-Scanner, Semgrep, git change analysis, evidence, graph view | Done |
| 4. Codebase understanding | Tree-sitter symbols, imports, calls, entry points, code retrieval | Done |
| 5. AI investigation | LangGraph specialist agents, evidence correlation, risk scoring | Planned |
| 6. Incremental scanning and demo | Scan comparison, JSON/HTML reports, demo scenarios | Planned |
