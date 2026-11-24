"""Render ReportData as Markdown for pull-request comments, tickets and email.

Every string in the report may come from a hostile repository, scanner or advisory feed.
Untrusted text is collapsed to one line and backslash-escaped so it cannot open links,
images, HTML, headings, tables or mentions; source code goes into fenced blocks whose
fence is longer than any backtick run inside them.
"""

import re
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath

from guardian.core.models import (
    ChangeDetails,
    CodeDetails,
    Evidence,
    Priority,
    VulnerabilityDetails,
)
from guardian.indexing.code_retriever import CodeSnippet
from guardian.reporting.models import ReportData, ReportFinding

PRIORITY_LABELS = {
    Priority.P1: "act now",
    Priority.P2: "schedule soon",
    Priority.P3: "backlog",
    Priority.P4: "informational",
}
REVIEW_CHECKLIST = "- [ ] Confirmed  - [ ] False positive  - [ ] Needs review  - [ ] Accepted risk"

# CommonMark lets any ASCII punctuation be backslash-escaped; these are the characters
# that can start inline constructs (links, images, emphasis, code, HTML, entities, tables,
# strikethrough, math, mentions, issue references) anywhere in a line. Untrusted text never
# starts a line (it always follows a prefix), so block markers like "-", "1." and "=" are
# inert. Bare URLs may still autolink, but they show their real destination.
_INLINE_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#!|~&$@])")
_WHITESPACE = re.compile(r"\s+")
_BACKTICKS = re.compile(r"`+")
_SAFE_URL = re.compile(r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "jsx",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".go": "go",
    ".rb": "ruby",
    ".sh": "bash",
}


def md_text(value: object) -> str:
    """Untrusted text as one escaped Markdown line."""
    text = _WHITESPACE.sub(" ", str(value)).strip()
    return _INLINE_SPECIAL.sub(r"\\\1", text)


def md_code(value: object, *, in_table: bool = False) -> str:
    """Untrusted text as an inline code span; GFM tables still need ``|`` escaped inside."""
    text = _WHITESPACE.sub(" ", str(value)).strip()
    if in_table:
        text = text.replace("|", "\\|")
    if not text:
        return ""
    longest = max((len(m) for m in _BACKTICKS.findall(text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_url(url: str | None) -> str:
    """An autolink for plain https URLs; anything else is shown as inert code."""
    if not url:
        return ""
    if _SAFE_URL.fullmatch(url):
        return f"<{url}>"
    return md_code(url)


def code_fence(text: str) -> str:
    longest = max((len(m) for m in _BACKTICKS.findall(text)), default=0)
    return "`" * max(3, longest + 1)


def _cell(value: object) -> str:
    return md_text(value) if value not in (None, "") else "-"


def _table(headers: list[str], rows: Iterable[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def render_markdown(report: ReportData) -> str:
    meta, summary = report.meta, report.summary
    scan = meta.scan
    out = [f"# Guardian security report: {md_text(meta.repository)}", ""]
    out += _table(
        ["Field", "Value"],
        [
            ["Repository", _cell(meta.repository)],
            ["Source", _cell(meta.source)],
            ["Scan", md_code(scan.id, in_table=True)],
            ["Status", _cell(scan.status.value)],
            ["Branch", _cell(scan.git_branch)],
            ["Commit", md_code(scan.git_commit, in_table=True) if scan.git_commit else "-"],
            ["Scanned", _cell(scan.started_at.isoformat(timespec="seconds"))],
            ["Generated", _cell(meta.generated_at.isoformat(timespec="seconds"))],
            ["Guardian", _cell(meta.guardian_version)],
            ["AI assistance", "yes" if meta.ai_used else "no"],
        ],
    )
    out += ["", f"> {md_text(summary.headline)}", ""]
    out += _summary(report)
    out += _findings(report)
    out += _appendix(report)
    return "\n".join(out).rstrip() + "\n"


def _summary(report: ReportData) -> list[str]:
    summary = report.summary
    out = ["## Summary", ""]
    out += _table(
        ["Priority", "Meaning", "Findings"],
        [
            [p.priority.value, PRIORITY_LABELS[p.priority], str(p.count)]
            for p in summary.by_priority
        ],
    )
    out.append("")
    out += _table(
        ["Severity", "Findings"], [[s.severity.value, str(s.count)] for s in summary.by_severity]
    )
    out.append("")
    facts = [
        ["Total findings", str(summary.total_findings)],
        *[[f"Kind: {md_text(k)}", str(n)] for k, n in sorted(summary.by_kind.items())],
        ["Components", str(summary.components)],
        ["Direct dependencies", str(summary.direct_dependencies)],
        ["Vulnerable packages", str(summary.vulnerable_packages)],
        ["Vulnerable packages used in code", str(summary.vulnerable_packages_used_in_code)],
        ["Files indexed", str(summary.files_indexed)],
        ["Entry points", str(summary.entry_points)],
    ]
    out += _table(["Measure", "Count"], facts)
    out.append("")
    if report.packages:
        out += ["### Vulnerable packages", ""]
        out += _table(
            ["Package", "Version", "Ecosystem", "Direct", "Used in code", "Vulns", "Worst", "Fix"],
            [
                [
                    md_text(p.package),
                    _cell(p.version),
                    _cell(p.ecosystem),
                    _tristate(p.direct),
                    _tristate(p.used_in_code),
                    str(p.vulnerability_count),
                    p.worst_severity.value,
                    _cell(p.recommended_fix),
                ]
                for p in report.packages
            ],
        )
        out.append("")
    return out


def _tristate(value: bool | None) -> str:  # noqa: FBT001
    return "unknown" if value is None else ("yes" if value else "no")


def _findings(report: ReportData) -> list[str]:
    out = ["## Findings", ""]
    shown = len(report.findings)
    if shown < report.summary.total_findings:
        out += [
            f"Showing the {shown} highest-priority of {report.summary.total_findings} findings.",
            "",
        ]
    if not report.findings:
        out += ["No findings.", ""]
    for priority in Priority:
        group = [f for f in report.findings if f.risk.priority is priority]
        if not group:
            continue
        out += [f"### {priority.value}: {PRIORITY_LABELS[priority]} ({len(group)})", ""]
        for item in group:
            out += _finding(item)
    return out


def _finding(item: ReportFinding) -> list[str]:
    finding, risk = item.finding, item.risk
    score = "n/a" if risk.score is None else f"{risk.score:.0f}/100"
    out = [
        f"#### {risk.priority.value} · {md_text(finding.title)}",
        "",
        (
            f"**Severity** {finding.severity.value} · **Risk** {score} "
            f"(confidence {risk.confidence.value}, evidence weight {risk.known_weight:.2f}) · "
            f"**Kind** {finding.kind.value} · **ID** {md_code(finding.id)}"
        ),
        "",
        f"> {md_text(risk.summary)}",
        "",
    ]
    out += _table(
        ["Factor", "Weight", "Value", "Rationale"],
        [
            [
                f.name.value,
                f"{f.weight:.2f}",
                "unknown" if f.value is None else f"{f.value:.2f}",
                _cell(f.rationale),
            ]
            for f in risk.factors
        ],
    )
    out += ["", "**What and where**", ""]
    out += [f"- {line}" for line in _what_where(item)]
    if finding.evidence:
        out += ["", "**Evidence**", ""]
        out += [f"- {_evidence(e)}" for e in finding.evidence]
    if item.introduction_paths:
        out += ["", "**Introduced through**", ""]
        out += [
            "- " + " → ".join(md_code(step) for step in path)
            for path in item.introduction_paths
            if path
        ]
    for snippet in item.code:
        out += ["", *_snippet(snippet)]
    out += [
        "",
        f"**Remediation:** {md_text(item.remediation)}",
        "",
        "**Review**",
        "",
        REVIEW_CHECKLIST,
        "",
    ]
    return out


def _labelled(pairs: Iterable[tuple[str, str | None]]) -> list[str]:
    return [f"{label}: {value}" for label, value in pairs if value]


def _joined(values: Iterable[str], render: Callable[[str], str] = md_text) -> str:
    return ", ".join(render(v) for v in values)


def _what_where(item: ReportFinding) -> list[str]:
    finding = item.finding
    location = None
    if finding.location:
        multi = finding.end_line and finding.end_line != finding.start_line
        location = md_code(finding.location + (f"-{finding.end_line}" if multi else ""))
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        specific = _vulnerability_lines(details)
    elif isinstance(details, CodeDetails):
        specific = _code_lines(details)
    else:
        specific = _change_lines(details)
    return [
        f"Tool: {md_text(finding.tool)}",
        *_labelled([("Location", location)]),
        *specific,
        *_labelled(
            [
                ("Introduced by commit", finding.introduced_by and md_code(finding.introduced_by)),
                ("Enclosing symbol", finding.symbol_id and md_code(finding.symbol_id)),
            ]
        ),
    ]


def _vulnerability_lines(details: VulnerabilityDetails) -> list[str]:
    package = f"{details.package}@{details.version}" if details.version else details.package
    fix = details.recommended_fix or ", ".join(details.fixed_versions) or "none published"
    lines = _labelled(
        [
            ("Advisory", md_code(details.vulnerability_id)),
            ("Aliases", _joined(details.aliases, md_code)),
            ("Package", f"{md_code(package)} ({_cell(details.ecosystem)})"),
            ("Summary", details.summary and md_text(details.summary)),
            ("CVSS", None if details.cvss_score is None else f"{details.cvss_score:.1f}"),
        ]
    )
    lines += [f"Vector: {md_code(v)}" for v in details.cvss_vectors]
    lines += _labelled(
        [
            ("CWE", _joined(details.cwe_ids)),
            ("Fix", md_text(fix)),
            ("Published", details.published.date().isoformat() if details.published else None),
        ]
    )
    return lines + [f"Reference: {md_url(r)}" for r in details.references]


def _code_lines(details: CodeDetails) -> list[str]:
    facts = [
        f"{name} {md_text(value)}"
        for name, value in (
            ("confidence", details.confidence),
            ("likelihood", details.likelihood),
            ("impact", details.impact),
            ("category", details.category),
        )
        if value
    ]
    lines = _labelled(
        [
            ("Rule", md_code(details.rule_id)),
            ("Message", md_text(details.message)),
            ("Rule metadata", ", ".join(facts)),
            ("CWE", _joined(details.cwe_ids)),
            ("OWASP", _joined(details.owasp)),
        ]
    )
    return lines + [f"Reference: {md_url(r)}" for r in details.references]


def _change_lines(details: ChangeDetails) -> list[str]:
    return _labelled(
        [
            ("Category", md_text(details.category.value)),
            ("Commit", md_code(details.commit) if details.commit else "uncommitted"),
            ("Author", details.author and md_text(details.author)),
            (
                "Date",
                details.authored_at.isoformat(timespec="seconds") if details.authored_at else None,
            ),
            ("Subject", details.subject and md_text(details.subject)),
            ("Paths", _joined(details.paths, md_code)),
        ]
    )


def _evidence(evidence: Evidence) -> str:
    parts = [
        f"\\[{evidence.kind.value}\\]",
        md_text(evidence.summary),
        f"\\({md_text(evidence.tool)}\\)",
    ]
    if evidence.path:
        where = f"{evidence.path}:{evidence.line}" if evidence.line else evidence.path
        parts.append(md_code(where))
    if evidence.commit:
        parts.append("commit " + md_code(evidence.commit[:12]))
    if evidence.url:
        parts.append(md_url(evidence.url))
    return " ".join(parts)


def _snippet(snippet: CodeSnippet) -> list[str]:
    lines = snippet.text.split("\n")
    width = len(str(snippet.start_line + len(lines) - 1))
    body = "\n".join(f"{snippet.start_line + i:>{width}} | {line}" for i, line in enumerate(lines))
    notes = []
    if snippet.redactions:
        notes.append(f"{snippet.redactions} secret(s) redacted")
    if snippet.truncated:
        notes.append("truncated")
    caption = f"{md_code(snippet.path)} lines {snippet.start_line}-{snippet.end_line}"
    if notes:
        caption += f" ({', '.join(notes)})"
    fence = code_fence(body)
    language = _LANG.get(PurePosixPath(snippet.path).suffix.lower(), "")
    return [caption, "", f"{fence}{language}", body, fence]


def _appendix(report: ReportData) -> list[str]:
    out: list[str] = []
    if report.entry_points:
        out += ["## Entry points", ""]
        out += _table(
            ["Kind", "Location", "Detail"],
            [
                [
                    e.kind.value,
                    md_code(f"{e.path}:{e.line}" if e.line else e.path, in_table=True),
                    _cell(e.detail),
                ]
                for e in report.entry_points
            ],
        )
        out.append("")
    if report.tool_runs:
        out += ["## Tool runs", ""]
        out += _table(
            ["Tool", "Status", "Exit code", "Duration", "Error"],
            [
                [
                    md_text(r.tool),
                    md_text(r.status),
                    "-" if r.exit_code is None else str(r.exit_code),
                    f"{r.duration_seconds:.1f}s",
                    _cell(r.error),
                ]
                for r in report.tool_runs
            ],
        )
        out.append("")
    warnings = report.meta.scan.warnings
    if report.limitations or warnings:
        out += ["## Limitations", ""]
        out += [f"- {md_text(text)}" for text in [*report.limitations, *warnings]]
        out.append("")
    out += [
        "---",
        "",
        (
            "Risk scores are a Guardian heuristic (R = 0.35 S + 0.25 E + 0.20 X + 0.10 P + 0.10 F) "
            "over known factors only; they support, not replace, human review."
        ),
    ]
    return out
