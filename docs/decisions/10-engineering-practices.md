# 10. Engineering practices

## Tooling
- **uv** for environments and locking (`uv run`, `uv add`); **ruff** with `select=["ALL"]` and a
  short ignore list; **ty** for types; **pytest** with an 80% coverage gate (currently about 98%).
- Why: one fast toolchain, strict by default. Alternatives: pip + black + mypy (more tools to
  keep in sync), Poetry (slower, extra lockfile format).

## CI
GitHub Actions on Ubuntu and Windows, Python 3.11 and 3.12, `permissions: contents: read`,
`persist-credentials: false`. Both OSes because the tool runner has Windows-specific code paths
(`.cmd` wrappers, cp1252). Local 3.11 checks use a separate venv:
`UV_PROJECT_ENVIRONMENT=<dir> uv run --python 3.11 --locked pytest`.

## Testing approach
- Unit tests for pure logic (risk, resolution, rendering); integration tests drive the real Typer
  app; fake chat models stand in for Groq/Gemini so tests need no network or keys.
- Real runs on OWASP Juice Shop and NodeGoat catch what unit tests miss (false routes from test
  files, false dirty state, cp1252 output, retired model names).

## Subagent workflow
From phase 4, work was delegated to subagents with detailed briefs and a frozen contract
(models and function signatures) so parallel agents could not drift apart. Reason: it keeps the
main conversation's context small. Cost: each agent starts cold, so the brief must carry the
security constraints and the file ownership. The integrator then reviews, registers commands and
runs the full gate. Alternative: one agent doing everything sequentially (simpler, but context
fills up).

## Git hygiene
- `.gitignore` covers `.env`, `*.db*`, caches, editor settings, `.agents/`, `.claude/`,
  `guardian-graph/` and `guardian-reports/`.
- The user commits and pushes; Claude does not. Identity and branch (`main`) were set by the user.
- No license was chosen.

## Environment notes
- Tools were put on PATH per session through a scratch script; the user's persistent PATH was not
  modified.
- Heredocs in Git Bash collapsed backslashes, so files with backslashes were written with the
  Write/Edit tools or script files.
