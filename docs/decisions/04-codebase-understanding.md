# 04. Codebase understanding

## What was built
A Tree-sitter index of Python, JavaScript, TypeScript and TSX: symbols, imports, calls, and
entry points (HTTP routes, servers, main guards, package entry points). Imports and calls are
resolved to repository files or SBOM components. The index is cached in SQLite and linked into
the knowledge graph (`DEFINES`, `IMPORTS`, `CALLS`).

## Why this matters
"This package has a CVE" is common. "This package has a CVE and your code calls it" is the
useful version. On Juice Shop, 7 of 22 vulnerable packages are actually imported.

## Decisions

### Tree-sitter (0.27, QueryCursor API)
Fast, error-tolerant parsing of broken or partial files, one API across languages. Alternatives:
Python `ast` (Python only), regex (breaks on real code), language servers or CodeQL (heavy,
need build setup), LLM-based extraction (non-deterministic, slow, prompt-injection exposure).

### Resolution to repo files and SBOM components
An `import "lodash"` is matched to the SBOM component, relative imports to files. This is what
connects code to dependencies. Limit: dynamic imports and `require` with computed names are not
resolved, so reachability is "unknown" rather than "no".

### Incremental cache keyed by `EXTRACTOR_VERSION`
Re-parse only changed files; bump the version when extraction logic changes so stale rows are not
trusted. Alternative: re-index everything each scan (simple, slow on large repos).

### Entry points exclude test files
The first run reported about 588 false HTTP routes, almost all from test files. `is_test_path`
now excludes them from call-based routes. Alternative: keep everything and filter in reports
(noise leaks into scoring).

### Indexing runs in parallel with scanners
The indexer runs on the main thread while cdxgen/OSV/Semgrep run in a pool, to cut wall time.
An indexing failure is recorded as an errored `indexer` run and the scan becomes "partial"; it
never fails the scan.

## Known limits
- Only four languages; code findings in other files (e.g. Java) get unknown reachability.
- One graph edge per node pair (see 02).
- Minified files are skipped (reported in the limitations list).
