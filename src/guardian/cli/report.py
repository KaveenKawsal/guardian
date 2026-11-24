"""``guardian report``: write a scan's findings as HTML, Markdown or JSON for human review."""

import webbrowser
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from guardian.cli.common import cli_errors, console, open_database
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.reporting import report_data
from guardian.reporting.models import ReportData, ReportFormat
from guardian.reporting.render import write_reports
from guardian.storage.database import Database

DEFAULT_OUTPUT = Path("guardian-reports")
DEFAULT_MAX_FINDINGS = 500
_ALIASES = {"markdown": ReportFormat.MARKDOWN, "htm": ReportFormat.HTML}


class ReportWriteError(GuardianError):
    """The report files could not be written."""


def parse_formats(values: Iterable[str] | None) -> list[ReportFormat]:
    """``['html,md', 'json']`` -> formats in order, duplicates dropped; default HTML."""
    formats: list[ReportFormat] = []
    for value in values or []:
        for raw in value.split(","):
            name = raw.strip().lower()
            if not name:
                continue
            try:
                fmt = _ALIASES.get(name) or ReportFormat(name)
            except ValueError:
                choices = ", ".join(f.value for f in ReportFormat)
                msg = f"Unknown report format {raw.strip()!r} (choose from {choices})"
                raise typer.BadParameter(msg, param_hint="'--format'") from None
            if fmt not in formats:
                formats.append(fmt)
    return formats or [ReportFormat.HTML]


def generate_reports(  # noqa: PLR0913
    db: Database,
    scan_id: str,
    settings: GuardianSettings,
    formats: list[ReportFormat],
    output: Path,
    *,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    include_code: bool = True,
) -> tuple[ReportData, list[Path]]:
    data = report_data.build_report(
        db, scan_id, settings, max_findings=max_findings, include_code=include_code
    )
    try:
        paths = write_reports(data, output, formats)
    except OSError as exc:
        msg = f"Could not write reports to {output}: {exc.strerror or exc}"
        raise ReportWriteError(msg) from exc
    return data, paths


def print_written(paths: list[Path], out: Console) -> None:
    for path in paths:
        out.print(f"Wrote [bold]{escape(str(path))}[/bold]", soft_wrap=True)


def open_in_browser(paths: list[Path], out: Console) -> None:
    page = next((p for p in paths if p.suffix == f".{ReportFormat.HTML.value}"), None)
    if page is None:
        out.print("--open needs the html format; nothing opened.")
        return
    webbrowser.open(page.resolve().as_uri())


def report(  # noqa: PLR0913, PLR0917 - one parameter per CLI option
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            help="html, md or json; repeat the option or give a comma list. Default: html.",
            show_default=False,
        ),
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Directory to write the reports to.")
    ] = DEFAULT_OUTPUT,
    no_code: Annotated[
        bool, typer.Option("--no-code", help="Leave source code snippets out of the report.")
    ] = False,
    max_findings: Annotated[
        int, typer.Option("--max-findings", min=1, help="Include at most this many findings.")
    ] = DEFAULT_MAX_FINDINGS,
    open_report: Annotated[
        bool, typer.Option("--open", help="Open the HTML report in a browser.")
    ] = False,
) -> None:
    """Write a review report: prioritized findings with evidence, code and remediation."""
    selected = parse_formats(formats)
    settings = GuardianSettings()
    with cli_errors(), open_database(settings) as db:
        resolved = db.scans.resolve(scan_id)
        data, paths = generate_reports(
            db,
            resolved,
            settings,
            selected,
            output,
            max_findings=max_findings,
            include_code=not no_code,
        )
    summary = data.summary
    shown = len(data.findings)
    extra = f" (top {shown} of {summary.total_findings})" if shown < summary.total_findings else ""
    console.print(
        f"Report for scan [bold]{escape(data.meta.scan.id[:12])}[/bold]: "
        f"{summary.total_findings} findings{extra}",
        soft_wrap=True,
    )
    print_written(paths, console)
    if open_report:
        open_in_browser(paths, console)
