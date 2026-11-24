"""``guardian investigate``: run the AI investigator agents over a stored scan (Milestone 8).

Deterministic facts are printed as they are; every model statement is labelled "AI inference".
Everything shown comes from the scanned repository or a model, so it is printed without markup.
"""

from typing import Annotated, Any

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, open_database
from guardian.core.config import GuardianSettings, env_files
from guardian.investigation.context import DEFAULT_TOP
from guardian.investigation.models import AGENT_LABELS, InvestigationRun, InvestigatorReport
from guardian.investigation.runner import DEFAULT_MAX_CALLS
from guardian.orchestration.investigation_graph import run_investigation

MAX_TEXT = 140


def verdict(report: InvestigatorReport) -> str:
    """The headline of a report: relevance, exploitability, scope or confidence."""
    a = report.assessment
    if a is None:
        return "-"
    if report.agent == "vulnerability":
        return f"relevance: {a.get('relevance')}"
    if report.agent == "code":
        flag = ", challenge code" if a.get("intentional_challenge_code") else ""
        return f"exploitability: {a.get('exploitability')}{flag}"
    if report.agent == "dependency":
        return f"scope: {a.get('scope_assessment')}"
    if report.agent == "correlator":
        return f"confidence: {a.get('confidence')}"
    return f"{len(a.get('modules', []))} modules mapped"


def headline(report: InvestigatorReport) -> str:
    a = report.assessment
    if a is None:
        return f"AI unavailable: {report.reason or 'no reason recorded'}"
    claim: Any = (
        a.get("assessment")
        or a.get("narrative")
        or a.get("threat_model")
        or a.get("how_it_enters")
        or (a.get("notes") or [None])[0]
    )
    text = claim.get("text", "") if isinstance(claim, dict) else ""
    if not text and report.agent == "architect":
        text = "; ".join(f"{m['area']}: {m['purpose']}" for m in a.get("modules", [])[:2])
    text = " ".join(text.split())
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 3] + "..."


def summary_table(run: InvestigationRun, reports: list[InvestigatorReport]) -> Table:
    table = Table(title=f"Investigation {run.id} of scan {run.scan_id[:12]} ({run.status})")
    table.add_column("Agent")
    table.add_column("Subject")
    table.add_column("Verdict (AI inference)")
    table.add_column("Provider / model")
    table.add_column("Latency", justify="right")
    table.add_column("AI inference", overflow="fold")
    for r in reports:
        model = f"{r.provider} / {r.model}" if r.provider else "-"
        latency = f"{r.latency_seconds:.1f}s" if r.latency_seconds is not None else "-"
        status = "" if r.status == "ok" else f" [{r.status}]"
        table.add_row(
            escape(AGENT_LABELS[r.agent]) + status,
            escape(r.title[:48] or r.subject_id[:12]),
            escape(verdict(r)),
            escape(model),
            latency,
            escape(headline(r)),
        )
    return table


def investigate(
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    top: Annotated[
        int, typer.Option("--top", min=1, max=100, help="Investigate the top N items per kind.")
    ] = DEFAULT_TOP,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Verified facts only; no LLM calls.")
    ] = False,
    max_calls: Annotated[
        int, typer.Option("--max-calls", min=0, max=500, help="Cap on LLM calls for this run.")
    ] = DEFAULT_MAX_CALLS,
) -> None:
    """Run the AI investigators (Architect, Dependency, Vulnerability, Code, Correlator)."""
    with cli_errors():
        settings = GuardianSettings(_env_file=env_files())
        with open_database(settings) as db:
            resolved = db.scans.resolve(scan_id)
            console.print(
                f"Investigating scan {resolved[:12]} (top {top} items per kind"
                + (", AI off)" if no_ai else f", at most {max_calls} LLM calls)"),
                highlight=False,
            )
            run, reports = run_investigation(
                db, settings, resolved, top=top, no_ai=no_ai, max_calls=max_calls
            )
    console.print(summary_table(run, reports))
    calls = run.provider_calls
    ok = sum(1 for c in calls if c.status == "ok")
    latency = sum(c.latency_seconds for c in calls)
    console.print(
        f"{len(calls)} LLM call(s), {ok} accepted, {latency:.1f}s model latency (summed over "
        "parallel calls). "
        "Verdicts and text above are AI inference; verified facts are stored with each report "
        "and shown in `guardian ui`.",
        highlight=False,
    )
    for note in run.notes:
        console.print(f"[yellow]note:[/yellow] {escape(note)}", highlight=False)
