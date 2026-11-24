# Guardian design decisions

Each file covers one piece of work: what was built, why that approach was chosen, and which
alternatives were considered. The stack was fixed up front (Python 3.11+, Typer, Pydantic,
LangGraph, a configurable LLM, cdxgen/CycloneDX, OSV-Scanner, Semgrep, GitPython/git,
Tree-sitter, NetworkX, SQLite, Pytest). Decisions here are about *how* those pieces are used.

| # | Topic | Phase |
|---|---|---|
| [01](01-foundation-and-safe-execution.md) | Foundation: CLI, profiler, hardened tool execution | 1 |
| [02](02-dependency-intelligence.md) | SBOM, direct dependencies, dependency graph, storage | 2 |
| [03](03-security-detection.md) | OSV-Scanner, Semgrep, git change analysis, evidence | 3 |
| [04](04-codebase-understanding.md) | Tree-sitter index, call/import resolution, entry points | 4 |
| [05](05-llm-providers-and-config.md) | Groq/Gemini switching, `.env`, key handling | 4+ |
| [06](06-remote-scanning.md) | Scanning a repository URL | 4+ |
| [07](07-risk-scoring.md) | Risk formula, priorities, confidence | 5 prep |
| [08](08-review-reports.md) | HTML / Markdown / JSON reports for human review | 6 prep |
| [09](09-interactive-shell-and-assistant.md) | Claude-style shell and read-only AI assistant | 5/6 prep |
| [10](10-engineering-practices.md) | Tooling, CI, testing, subagent workflow, git hygiene | all |
| [11](11-human-approved-remediation.md) | Human-approved remediation rules, case state machine, audit log | Day 2 |

## Principles that recur

1. **Treat the scanned repository as hostile.** Its files, names, git config, advisories and
   scanner output are untrusted input. This drives the sandboxed tool runner, output escaping,
   and the AI assistant's prompt design.
2. **Unknown stays unknown.** When evidence is missing, Guardian says so instead of guessing.
   Risk factors, direct-dependency status and reachability can all be `None`.
3. **Evidence over assertions.** A finding links to the files, packages and chains that support it.
4. **Every external tool is optional.** A missing scanner makes a scan "partial", never failed.
5. **Deterministic first, AI second.** Everything that can be computed without an LLM is, so the
   AI layer works from facts and the tool still works without an API key.

## Open items

- AI investigation (phase 5) and incremental scanning / scan comparison (phase 6) are not built.
  Exploitability is therefore always "unknown" in risk scores.
- The knowledge graph keeps one edge per node pair (see [04](04-codebase-understanding.md)).
