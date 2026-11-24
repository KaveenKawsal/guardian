# 09. Interactive shell and AI assistant

## What was built
Running `guardian` in a terminal (or `guardian shell`) opens a prompt in the style of the
Claude CLI. Paste a folder path or repository URL to scan it; use slash commands (`/scan`,
`/findings`, `/explain`, `/deps`, `/code`, `/graph`, `/report`, `/history`, `/use`, `/model`,
`/clear`, `/doctor`, `/help`, `/exit`); ask a plain question and the assistant answers.

## Decisions

### prompt_toolkit, with an `input()` fallback
Gives history, Tab completion (including folders after `/scan`) and a status toolbar. When
stdin is not a terminal (pipes, CI), it falls back to `input()`. Alternatives: Textual (full TUI,
heavier, harder to script), `cmd`/`readline` (weak on Windows), or only subcommands (what existed
before; no conversational flow).

### Bare input is classified
An existing folder or a parsable remote target is scanned; anything else goes to the assistant.
Trade-off: convenient, but `and/or` looks like an `owner/repo` (see 06).

### Shell commands reuse the CLI functions
`/findings`, `/report` and the rest call the same code as the subcommands, so behaviour cannot
diverge. Caveat: those functions open the database from environment-based settings rather than
the shell's settings object.

### Assistant: read-only tools, bounded loop
Eight tools over the *stored* scan (findings, explain, deps, code search, file snippets, ...),
each result capped at 8 KB and secret-redacted. At most 6 rounds with 8 calls each, then one
final call without tools forces an answer. Memory is the last 6 turns (`/clear` resets).
No tool can write, run commands, or touch the network.

Why: the model reads attacker-controlled text (code, advisories). Read-only tools bound the
damage of prompt injection to a wrong answer. The system prompt states that repository content is
data, never instructions.

Alternatives: LangChain Deep Agents (more features; the brief asked for `bind_tools` with a hard
round limit, so a small manual loop was written), a ReAct framework (less control over limits),
or giving the model shell access (powerful and unsafe on untrusted code).

### Windows output encoding
A model answer containing U+202F crashed Rich on the cp1252 console. The CLI now reconfigures
stdout and stderr with `errors="replace"` at startup. Untrusted characters print as `?` instead
of crashing.

## Verified manually
Groq answered "which three findings first" on Juice Shop with correct IDs and `file:line`;
Gemini answered a usage question with line numbers; a pasted folder scanned and `/report`
wrote three files.

## Known limits
The timeout is checked between rounds; one slow provider call is bounded only by
`llm_timeout_seconds`. Text a model writes before a tool call is also streamed.
