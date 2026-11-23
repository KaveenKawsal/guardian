"""``guardian profile``: identify languages, ecosystems, CI and git state of a repository."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from guardian.core.exceptions import RepositoryNotFoundError
from guardian.core.models import RepositoryProfile
from guardian.core.profiler import RepositoryProfiler

console = Console()
err_console = Console(stderr=True)


def profile(
    path: Annotated[Path, typer.Argument(help="Repository to profile.")] = Path(),
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the profile as JSON instead of a summary.")
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Also write the JSON profile here.")
    ] = None,
) -> None:
    """Profile a repository's languages, ecosystems, CI configuration and git state."""
    try:
        result = RepositoryProfiler().profile(path)
    except RepositoryNotFoundError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    payload = result.model_dump_json(indent=2)
    if output is not None:
        output.write_text(payload + "\n", encoding="utf-8")
    if json_output:
        typer.echo(payload)
    else:
        render_profile(result)
        if output is not None:
            console.print(f"\nProfile written to [bold]{output}[/bold]")


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":  # noqa: PLR2004
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"  # pragma: no cover


def render_profile(p: RepositoryProfile, *, show_warnings: bool = True) -> None:
    console.rule(f"[bold]Guardian profile: {escape(p.name)}")
    console.print(f"Root: {p.root}", markup=False)
    console.print(f"Files: {p.total_files:,} ({_human_bytes(p.total_bytes)})")
    if p.skipped_symlinks:
        console.print(f"Skipped symlinks: {p.skipped_symlinks}")

    if p.git.is_repository:
        dirty = {True: " (uncommitted changes)", False: "", None: ""}[p.git.is_dirty]
        commit = p.git.head_commit[:12] if p.git.head_commit else "no commits"
        console.print(f"Git: {p.git.branch or 'detached HEAD'} @ {commit}{dirty}", markup=False)
    else:
        console.print(
            f"Git: not a repository{f' ({p.git.error})' if p.git.error else ''}", markup=False
        )

    if p.languages:
        table = Table(title="Languages", title_justify="left")
        table.add_column("Language")
        table.add_column("Files", justify="right")
        table.add_column("Size", justify="right")
        for lang in p.languages:
            table.add_row(lang.name, f"{lang.files:,}", _human_bytes(lang.bytes))
        console.print(table)

    if p.ecosystems:
        table = Table(title="Ecosystems", title_justify="left")
        table.add_column("Ecosystem")
        table.add_column("Tools")
        table.add_column("Manifests", justify="right")
        table.add_column("Lockfiles", justify="right")
        table.add_column("Frameworks / images")
        for eco in p.ecosystems:
            extras = [f.name for f in eco.frameworks] + eco.metadata.get("base_images", [])
            table.add_row(
                eco.ecosystem.value,
                ", ".join(eco.package_managers),
                str(len(eco.manifests)),
                str(len(eco.lockfiles)),
                escape(", ".join(extras) or "-"),
            )
        console.print(table)
    else:
        console.print("No supported ecosystems detected.")

    if p.ci:
        console.print("CI: " + ", ".join(sorted({c.provider for c in p.ci})))

    if not show_warnings:
        return
    warnings = p.warnings + [w for e in p.ecosystems for w in e.warnings]
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {escape(warning)}")
