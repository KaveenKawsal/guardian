"""Render ReportData to files."""

import re
from collections.abc import Callable, Iterable
from pathlib import Path

from guardian.reporting.html_report import render_html
from guardian.reporting.json_report import render_json
from guardian.reporting.markdown_report import render_markdown
from guardian.reporting.models import ReportData, ReportFormat

RENDERERS: dict[ReportFormat, Callable[[ReportData], str]] = {
    ReportFormat.HTML: render_html,
    ReportFormat.MARKDOWN: render_markdown,
    ReportFormat.JSON: render_json,
}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_NAME = 60


def report_basename(report: ReportData) -> str:
    repo = _UNSAFE.sub("-", report.meta.repository).strip(".-")[:MAX_NAME] or "repository"
    scan_id = _UNSAFE.sub("-", report.meta.scan.id)[:12] or "scan"
    return f"guardian-report-{repo}-{scan_id}"


def write_reports(
    report: ReportData, output_dir: Path, formats: Iterable[ReportFormat]
) -> list[Path]:
    """Write one file per format into ``output_dir`` (created if needed) and return the paths.

    File names: ``guardian-report-<repo>-<scan id[:12]>.<ext>`` (repo name sanitized).
    Duplicate formats are written once; paths come back in the requested order.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    base = report_basename(report)
    paths: list[Path] = []
    for fmt in dict.fromkeys(ReportFormat(f) for f in formats):
        path = output_dir / f"{base}.{fmt.value}"
        path.write_text(RENDERERS[fmt](report), encoding="utf-8", newline="\n")
        paths.append(path)
    return paths
