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
from guardian.core.remediation_models import (
    RemediationCandidate,
    StepStatus,
    ValidationRun,
    VerificationResult,
)
from guardian.indexing.code_retriever import CodeSnippet
from guardian.reporting.models import (
    RemediationCaseReport,
    RemediationSection,
    ReportData,
    ReportFinding,
    ReportInvestigation,
)

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
    if report.remediation is not None:
        out += _remediation(report.remediation)
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


# --- Remediation -----------------------------------------------------------------------

KNOWN_CONFLICT_NOTE = "fix conflicts with intentional challenge code"
AI_PREFIX = "AI inference:"


def _risk_value(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def risk_change(before: float | None, after: float | None) -> str:
    return f"{_risk_value(before)} → {_risk_value(after)}"


def _remediation(section: RemediationSection) -> list[str]:
    chain = section.audit_chain
    status = (
        f"intact ({chain.events} events, hash chain verified)"
        if chain.ok
        else f"BROKEN ({len(chain.problems)} problem(s) in {chain.events} events)"
    )
    out = [
        "## Remediation",
        "",
        (
            "Facts below come from deterministic tools and recorded human decisions. "
            f'Lines quoted as "{AI_PREFIX}" are AI interpretation, not verified facts.'
        ),
        "",
        f"**Audit log:** {status}",
        "",
    ]
    out += [f"- {md_text(problem)}" for problem in chain.problems[:20]]
    if chain.problems:
        out.append("")
    out += _table(
        ["Case", "Title", "Priority", "Status", "Verdict", "Risk before → after"],
        [
            [
                md_code(c.case.id, in_table=True),
                _cell(c.case.title),
                c.case.priority.value,
                c.case.status.value,
                c.verdict.value if c.verdict else "-",
                risk_change(c.risk_before, c.risk_after),
            ]
            for c in section.cases
        ],
    )
    out.append("")
    for case in section.cases:
        out += _case(case)
    return out


def _case(item: RemediationCaseReport) -> list[str]:
    case = item.case
    jira = "-"
    if case.jira_key:
        jira = md_code(case.jira_key) + (f" {md_url(item.jira_url)}" if item.jira_url else "")
    out = [
        f"### {md_code(case.id)} · {md_text(case.title)}",
        "",
        (
            f"**Priority** {case.priority.value} · **Status** {case.status.value} · "
            f"**Verdict** {item.verdict.value if item.verdict else 'none yet'} · "
            f"**Risk** {risk_change(item.risk_before, item.risk_after)} · **Jira** {jira}"
        ),
        "",
        "#### Original finding(s) (verified)",
        "",
    ]
    for finding in item.findings:
        out.append(
            f"- {md_text(finding.title)} · {finding.severity.value} · {md_code(finding.id)} "
            f"({md_text(finding.tool)})"
        )
        out += [f"  - {_evidence(e)}" for e in finding.evidence]
    out += [f"- {md_code(f)} (not stored with the loaded scans)" for f in item.missing_finding_ids]
    if not item.findings and not item.missing_finding_ids:
        out.append("- No findings recorded.")
    out.append("")
    if item.investigations:
        out += ["#### AI investigation", ""]
        for inv in item.investigations:
            out += _investigation(inv)
    out += _recommendation(item)
    out += _decisions(item)
    out += _validations(item.validations)
    out += _verifications(item.verifications)
    if item.pull_request_url:
        out += ["#### Pull request", "", f"- {md_url(item.pull_request_url)}", ""]
    out += ["#### Audit trail", ""]
    out += _table(
        ["#", "At", "Event", "Actor", "Event hash"],
        [
            [
                "-" if e.id is None else str(e.id),
                e.at.isoformat(timespec="seconds"),
                md_code(e.event, in_table=True),
                _cell(e.actor),
                md_code(e.event_sha256[:12], in_table=True),
            ]
            for e in item.audit
        ],
    )
    out.append("")
    return out


def _investigation(inv: ReportInvestigation) -> list[str]:
    via = " / ".join(md_text(v) for v in (inv.provider, inv.model) if v)
    head = f"> {AI_PREFIX} **{md_text(inv.agent_label)}** on {md_code(inv.subject_id)}"
    out = [head + (f" ({via})" if via else ""), ">"]
    for st in inv.statements:
        refs = f" (evidence: {_joined(st.evidence_refs, md_code)})" if st.evidence_refs else ""
        out.append(f"> - {AI_PREFIX} {md_text(st.label)}: {md_text(st.text)}{refs}")
    return [*out, ""]


def _candidate_row(c: RemediationCandidate) -> list[str]:
    versions = f"{_cell(c.from_version)} → {_cell(c.to_version)}"
    reduction = "-" if c.expected_risk_reduction is None else f"{c.expected_risk_reduction:.0f}"
    return [
        md_code(c.id, in_table=True),
        c.action_type.value,
        md_code(c.target_package or c.component, in_table=True),
        versions,
        c.semver_jump.value,
        reduction,
        _cell("; ".join(c.compatibility_notes)),
        md_code(c.rollback, in_table=True),
    ]


_CANDIDATE_HEADERS = [
    "Candidate",
    "Action",
    "Component",
    "Version",
    "Semver",
    "Expected risk reduction",
    "Compatibility notes",
    "Rollback",
]


def _recommendation(item: RemediationCaseReport) -> list[str]:
    out = ["#### Recommended action", ""]
    plan = item.plan
    if plan is None:
        out.append("Plan source: no plan recorded.")
    elif plan.decided_by == "llm":
        via = " / ".join(md_text(v) for v in (plan.llm_provider, plan.llm_model) if v)
        out += [
            (
                f"Plan source: AI ({via or 'model unknown'}), confidence {plan.confidence.value}. "
                "The AI chose among deterministic candidates only."
            ),
            "",
            f"> {AI_PREFIX} {md_text(plan.rationale)}",
        ]
    else:
        out.append(
            f"Plan source: deterministic (verified), confidence {plan.confidence.value}. "
            f"Rationale: {md_text(plan.rationale)}"
        )
    if plan is not None:
        out += [f"- Note: {md_text(n)}" for n in plan.notes]
    out.append("")
    if item.recommended is not None:
        out += _table(_CANDIDATE_HEADERS, [_candidate_row(item.recommended)])
        out.append("")
    if item.alternatives:
        out += ["**Alternatives**", ""]
        out += _table(_CANDIDATE_HEADERS, [_candidate_row(c) for c in item.alternatives])
        out.append("")
    return out


def _decisions(item: RemediationCaseReport) -> list[str]:
    out = ["#### Human decisions", ""]
    if not item.decisions:
        return [*out, "No human decision recorded yet; nothing was applied.", ""]
    rows = []
    for entry in item.decisions:
        d = entry.decision
        kind = d.decision.value
        if d.decline_reason:
            kind += f" ({d.decline_reason.value})"
        if d.modify:
            kind += f" ({d.modify.kind}={md_text(getattr(d.modify, d.modify.kind))})"
        jira = "-"
        if entry.jira_key:
            jira = md_code(entry.jira_key, in_table=True)
            if entry.jira_url:
                jira += " " + md_url(entry.jira_url)
        expiry = "-"
        if d.risk_acceptance_expires:
            expiry = d.risk_acceptance_expires.isoformat() + (" EXPIRED" if entry.expired else "")
        rows.append(
            [
                kind,
                f"{md_text(d.actor_display)} ({md_code(d.actor_id, in_table=True)})",
                d.decided_at.isoformat(timespec="seconds"),
                d.channel,
                jira,
                _cell(d.justification),
                expiry,
            ]
        )
    out += _table(["Decision", "Who", "When", "Channel", "Jira", "Justification", "Expiry"], rows)
    out.append("")
    risk = item.accepted_risk
    if risk is not None:
        state = "**EXPIRED** - review again" if risk.expired else "active"
        out += [
            (
                f"**Accepted risk** until {risk.expires.isoformat()} ({state}), accepted by "
                f"{md_text(risk.actor_display)}: {md_text(risk.justification or '-')}"
            ),
            "",
        ]
    return out


def _validations(runs: list[ValidationRun]) -> list[str]:
    if not runs:
        return []
    out = ["#### Validation runs", ""]
    for i, run in enumerate(runs, 1):
        tests = ""
        if run.tests_discovered is not None:
            tests = (
                f" · tests {run.tests_passed or 0} passed, {run.tests_failed or 0} failed of "
                f"{run.tests_discovered}"
            )
        out += [
            f"Run {i}: branch {md_code(run.branch)} · sandbox {run.sandbox} · "
            f"started {run.started_at.isoformat(timespec='seconds')}"
            + (f" · commit {md_code(run.commit_sha[:12])}" if run.commit_sha else "")
            + tests,
            "",
        ]
        out += _table(
            ["Step", "Status", "Exit code", "Duration", "Note"],
            [
                [
                    step.name,
                    step.status.value.upper()
                    if step.status is not StepStatus.PASSED
                    else step.status.value,
                    "-" if step.exit_code is None else str(step.exit_code),
                    f"{step.duration_seconds:.1f}s",
                    "; ".join(
                        x
                        for x in (
                            KNOWN_CONFLICT_NOTE if step.known_conflict else "",
                            md_text(step.detail) if step.detail else "",
                        )
                        if x
                    )
                    or "-",
                ]
                for step in run.steps
            ],
        )
        out.append("")
    return out


def _verifications(results: list[VerificationResult]) -> list[str]:
    if not results:
        return []
    out = ["#### Verification", ""]
    for result in results:
        diff = result.sbom_diff
        out += [
            f"**Verdict** {result.status.value} · confidence {result.confidence.value} · "
            f"risk {risk_change(result.risk_before, result.risk_after)} · rescan "
            + (md_code(result.after_scan_id[:12]) if result.after_scan_id else "none"),
            "",
        ]
        out += [f"- Reason: {md_text(r)}" for r in result.reasons]
        out += [
            f"- Findings resolved: {_joined(result.target_findings_resolved, md_code) or 'none'}",
            f"- Still present: {_joined(result.findings_still_present, md_code) or 'none'}",
            f"- New findings: {_joined(result.new_findings, md_code) or 'none'}",
            f"- SBOM added: {_joined(diff.added, md_code) or 'none'}",
            f"- SBOM removed: {_joined(diff.removed, md_code) or 'none'}",
            "- SBOM changed: "
            + (
                ", ".join(
                    f"{md_code(c.purl_base)} {_cell(c.from_version)} → {_cell(c.to_version)}"
                    for c in diff.changed
                )
                or "none"
            ),
            "",
        ]
    return out


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
