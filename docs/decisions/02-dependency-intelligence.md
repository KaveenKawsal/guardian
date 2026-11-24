# 02. Dependency intelligence

## What was built
- cdxgen produces a CycloneDX SBOM; Guardian parses it into components and a dependency graph.
- Direct vs transitive determination, with the *source* of that answer recorded.
- A NetworkX graph (`DiGraph`) and an interactive HTML graph view.
- SQLite storage with versioned migrations (`001` initial, `002` findings, `003` code_index).

## Decisions

### cdxgen with `--no-install-deps`, secure mode, Node `--permission`
cdxgen can run package managers, and package managers run install scripts from the repository.
Guardian disables dependency installation, enables cdxgen's secure mode and starts Node with the
permission model, granting only the directories it needs (unquoted paths; wildcards and quoted
paths were rejected by Node). Alternative: let cdxgen resolve everything (richer graph, but runs
untrusted code), or write per-ecosystem parsers by hand (no external tool, but far more work and
less coverage). A consequence: repos without a lockfile (Juice Shop) give a shallow graph. The
user can generate one with `npm install --package-lock-only --ignore-scripts`; Guardian never
runs package managers.

### Direct dependency source is recorded
`DirectSource` is one of `sbom`, `manifest`, `sbom+manifest`, `graph-inference`, `unknown`.
Reason: SBOMs are inconsistent about "direct", so the answer is cross-checked with manifests, and
the report can say how sure it is. Alternative: a single boolean, which hides the uncertainty.

### NetworkX DiGraph
Simple, pure Python, supports the path queries needed ("why is this package here?"). Alternatives:
a graph database (Neo4j: operational overhead for a local tool), or plain SQL tables with
recursive CTEs (fine for paths, awkward for multi-relation knowledge graph work).
**Known limitation:** a `DiGraph` holds one edge per node pair, so two relations between the same
pair (e.g. IMPORTS and CALLS) fold together. A `MultiDiGraph` would fix this; the risk module
reads usage from the code index instead to avoid the issue (see 07).

### SQLite with explicit migrations
Zero-setup, single file, history per repository. Alternatives: JSON files (no queries, no
migrations), Postgres (needless for a local CLI). Migrations are numbered so stored scans survive
upgrades.

### Own graph viewer
A self-contained HTML file with no server, so a graph can be emailed or archived. Alternative:
Graphviz/PNG (static, unreadable at 1,600 components) or a web app (needs hosting).
