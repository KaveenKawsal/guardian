# 05. LLM providers and configuration

## What was built
- Groq and Google Gemini through `langchain-groq` and `langchain-google-genai`.
- Settings from `~/.guardian/.env` then `./.env`; real environment variables win.
- `guardian ai status | models | test | use`, plus `/model` inside the shell.
- A git-ignored `.env` created for the user, and a committed `.env.example`.

## Decisions

### Two providers behind one small interface
Different strengths and rate limits; switching by one setting avoids lock-in. Alternatives: a
single provider (simpler, but one outage or quota ends the AI features), or LiteLLM/OpenRouter
(one gateway for everything, but an extra dependency and an intermediary seeing your code).

### Keys as `SecretStr`, never printed or stored
`ai status` shows only the last four characters. Keys are not written to SQLite and are scrubbed
from scanner subprocess environments. Provider errors are reduced to one line without the key.
Alternative: OS keychain (better at rest, but more setup; `.env` is the common convention).

### Live model listing and a connectivity test
Model names go stale fast. During testing both defaults (`llama-3.3-70b-versatile`,
`gemini-2.5-flash`) returned "model not found" for the user's account. `guardian ai models` asks
the provider what is available, and `ai test` does one tiny round trip. Defaults are now
`openai/gpt-oss-120b` (Groq) and `gemini-3.5-flash` (Google).
Alternative: hardcode a list (becomes wrong); auto-select the "best" model (surprising and
unpredictable costs).

### Files over interactive login
Plain `.env` files work in any terminal and CI, and the user asked for exactly that.

## Notes
Gemini preview models can return 503 under load; retry or switch model with
`guardian ai use google --model <name>`.
