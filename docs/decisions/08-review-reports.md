# 08. Review reports for humans

## What was built
`guardian report [scan] -f html,md,json -o DIR` and `guardian scan --report` /
`--report-format`. Output files are named `guardian-report-<repo>-<scanid12>.<ext>`.

- `reporting/models.py`: the report contract (`ReportData`, `ReportFinding`, `PackageRisk`...).
- `reporting/report_data.py`: builds it from the database (risk, remediation, dependency chains,
  redacted code snippets, package roll-up, limitations).
- Renderers for HTML, Markdown and JSON.

## Decisions

### One data model, three renderers
All formats come from the same `ReportData`, so they cannot disagree. Alternative: render each
format straight from the database (duplicated logic, drift).

### HTML is one self-contained file
No server, no network calls, can be emailed or attached to a ticket. It includes filters,
factor bars (unknown shown hatched), lazy detail rendering for large reports, light/dark theme,
print stylesheet, and a phone-width layout. Alternatives: a web app (needs hosting and
authentication), PDF only (no filtering, no interaction), or a SARIF viewer (SARIF suits tools,
not human triage with verdicts).

### Verdicts and notes stored in the browser, exportable as JSON
Reviewers mark each finding (confirmed, false positive, needs review, accepted risk) with notes.
Stored in `localStorage` keyed by scan and finding, with export/import so work can be shared or
backed up. The page works without storage. Alternative: a backend database (collaboration, but
an operations burden). Typing a note on an unreviewed finding sets it to "Needs review", which was
the implementer's choice.

### Hostile content is assumed
Report text comes from scanned repositories and advisories.
- HTML: `textContent` only; only `https://` links; a Content-Security-Policy allowing just the
  page's own script (by SHA-256) and Google Fonts; embedded data is escaped for `<script>`.
- Markdown: untrusted text is single-line and backslash-escaped so links, images, HTML,
  `@mentions` and `#refs` cannot form.
- Code snippets pass through secret redaction. `--no-code` omits them entirely.
Tested in headless Chrome with hostile strings; they render as literal text.

### Markdown with checkboxes and JSON
Markdown pastes into pull requests and tickets; JSON (`schema_version` "1") feeds other tools.
SARIF export was not built; it is a reasonable future addition.

### `scan --report` uses two options
Typer 0.29's Click cannot give an option an optional value, so `--report` writes HTML and
`--report-format` selects formats.

### Reports are git-ignored
They contain code from scanned repos, so `guardian-reports/` is in `.gitignore`.

## Not verified
Print layout was not checked in a PDF viewer; phone width was checked down to 489 px.
