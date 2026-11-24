# 03. Security detection

## What was built
- **OSV-Scanner** matches SBOM components to known vulnerabilities.
- **Semgrep** finds code-level issues.
- **Git change analysis** (plus blame) finds recent risky changes and links them to findings.
- A unified `Finding` model with kinds (vulnerability / code / change), severity, evidence and a
  stable fingerprint, stored in SQLite and shown by `guardian findings` and `guardian explain`.

## Decisions

### OSV-Scanner reads Guardian's own SBOM
It scans the `*.cdx.json` Guardian generated, with `--no-resolve --no-call-analysis=all`, instead
of walking the repository itself. This keeps one source of truth for components, so findings link
to the same graph nodes. Exit codes 0, 1 and 128 count as success (1 = vulnerabilities found,
128 = nothing to scan). Alternatives: `osv-scanner` on the directory (its own lockfile discovery,
different component identities); querying the OSV API directly (no extra binary, but we would
re-implement batching, version matching and offline behaviour); `pip-audit`/`npm audit` (per
ecosystem, not unified).

### Recommended fix computed by Guardian
OSV lists many fixed versions. `version_key` (tokens of rank/number/text) picks the highest
fix. A bug here ranked a pre-release above its release; fixed with 3-tuple tokens. Alternative:
trust the first listed fix (often wrong for multi-branch advisories).

### Semgrep flags and Windows handling
`--metrics=off`, `--oss-only`, `--no-git-ignore`, `PYTHONUTF8=1`, tolerant output decoding.
Metrics-off prevents code leaving the machine; OSS-only avoids needing a login. Semgrep wrote
cp1252 on Windows, so output is decoded tolerantly. A repo-supplied `.semgrepignore` could hide
findings, so it is reported as a warning rather than silently honoured. Alternatives: CodeQL
(needs build and database creation, heavy), or writing regex checks ourselves (poor coverage).

### Fingerprints hash the matched text and never store it
Stable IDs across scans without keeping potentially secret source text in the database.

### Evidence chain
Each finding records what supports it (advisory, component, file, usage). Chosen so a human can
audit *why* a finding exists. Alternative: opaque scores, which reviewers cannot challenge.

### Output escaping
Rich markup in finding titles swallowed `[advisory]`-style labels and is an injection vector for
terminal output, so all untrusted text is escaped (`rich.markup.escape` or `markup=False`).
