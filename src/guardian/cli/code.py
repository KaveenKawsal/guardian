"""``guardian code``: inspect the codebase index of a scan (phase 4).

Everything shown here (paths, package names, callees, entry point details) comes from the
scanned repository, so it is printed with ``markup=False`` or escaped.
"""

import json
from collections import Counter, defaultdict
from typing import Annotated, Any

import typer
from rich.markup import escape
from rich.table import Table

from guardian.adapters.base import normalize_package_name
from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.core.models import CodeIndex, ImportTarget, ResolvedCall, ResolvedImport

TOP_PACKAGES = 10


def code(
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    uses: Annotated[
        str | None,
        typer.Option("--uses", help="Where the source imports and calls PACKAGE."),
    ] = None,
    show_entry_points: Annotated[
        bool, typer.Option("--entry-points", help="List detected entry points.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """Summarize the codebase index: files, symbols, imports, calls and entry points."""
    with cli_errors(), open_database() as db:
        resolved = db.scans.resolve(scan_id)
        index = db.code.load(resolved)
    if index is None:
        err_console.print(
            f"Scan {resolved[:12]} has no code index (no supported source files, indexing "
            "disabled, or indexing failed). Python, JavaScript and TypeScript are indexed."
        )
        raise typer.Exit(code=1)

    if uses is not None:
        _render_uses(index, uses, json_output=json_output)
    elif show_entry_points:
        _render_entry_points(index, json_output=json_output)
    elif json_output:
        typer.echo(json.dumps(code_summary(index), indent=2))
    else:
        _render_summary(index, resolved)


# --- summary ---------------------------------------------------------------------------


def code_summary(index: CodeIndex) -> dict[str, Any]:
    """Counts describing a CodeIndex (also embedded in ``guardian scan --json``)."""
    symbols = Counter(s.kind.value for f in index.files for s in f.symbols)
    return {
        "files": len(index.files),
        "files_by_language": dict(Counter(f.language.value for f in index.files).most_common()),
        "symbols": sum(symbols.values()),
        "symbols_by_kind": dict(symbols.most_common()),
        "imports": len(index.imports),
        "imports_by_target": dict(Counter(i.target.value for i in index.imports).most_common()),
        "calls": len(index.calls),
        "external_packages": top_external_packages(index, limit=None),
        "entry_points": len(index.entry_points),
        "entry_points_by_kind": dict(
            Counter(e.kind.value for e in index.entry_points).most_common()
        ),
        "skipped_files": dict(index.skipped_files),
        "parse_errors": sum(1 for f in index.files if f.has_parse_errors),
    }


def top_external_packages(index: CodeIndex, limit: int | None = TOP_PACKAGES) -> dict[str, int]:
    """External package -> number of files importing it, most imported first."""
    files: defaultdict[str, set[str]] = defaultdict(set)
    for imp in index.imports:
        if imp.target is ImportTarget.EXTERNAL and imp.package:
            files[imp.package].add(imp.path)
    ranked = sorted(files.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return {name: len(paths) for name, paths in ranked[:limit]}


def _counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{n} {k}" for k, n in counts.items()) or "none"


def _render_summary(index: CodeIndex, scan_id: str) -> None:
    summary = code_summary(index)
    console.rule(f"[bold]Code index - scan {scan_id[:12]}")
    console.print(f"Files: {summary['files']} ({_counts(summary['files_by_language'])})")
    console.print(f"Symbols: {summary['symbols']} ({_counts(summary['symbols_by_kind'])})")
    console.print(f"Imports: {summary['imports']} ({_counts(summary['imports_by_target'])})")
    console.print(f"Calls: {summary['calls']}")
    console.print(
        f"Entry points: {summary['entry_points']} ({_counts(summary['entry_points_by_kind'])})"
    )
    if summary["skipped_files"]:
        console.print(f"Skipped files: {_counts(summary['skipped_files'])}", markup=False)
    if summary["parse_errors"]:
        console.print(f"Files with parse errors: {summary['parse_errors']}")

    top = top_external_packages(index)
    if top:
        console.print("\n[bold]Most imported external packages[/bold]")
        table = Table()
        table.add_column("Package", overflow="fold")
        table.add_column("Files", justify="right")
        for name, count in top.items():
            table.add_row(escape(name), str(count))
        console.print(table)
    for warning in index.warnings:
        console.print(f"[yellow]warning:[/yellow] {escape(warning)}")
    console.print(
        "More: [bold]guardian code --uses PACKAGE[/bold], [bold]guardian code --entry-points[/bold]"
    )


# --- --uses ----------------------------------------------------------------------------


def _matches(package: str | None, wanted: str) -> bool:
    return package is not None and normalize_package_name(package) == wanted


def package_usage(
    index: CodeIndex, package: str
) -> tuple[list[ResolvedImport], list[ResolvedCall]]:
    """Imports of and calls into ``package`` (case-insensitive, PEP 503 normalized)."""
    wanted = normalize_package_name(package.strip())
    imports = sorted(
        (i for i in index.imports if _matches(i.package, wanted)), key=lambda i: (i.path, i.line)
    )
    calls = sorted(
        (c for c in index.calls if _matches(c.package, wanted)), key=lambda c: (c.path, c.line)
    )
    return imports, calls


def _render_uses(index: CodeIndex, package: str, *, json_output: bool) -> None:
    imports, calls = package_usage(index, package)
    if json_output:
        payload = {
            "package": package,
            "imports": [i.model_dump(mode="json") for i in imports],
            "calls": [c.model_dump(mode="json") for c in calls],
            "members": dict(Counter(c.member or c.callee for c in calls).most_common()),
        }
        typer.echo(json.dumps(payload, indent=2))
        return
    if not imports and not calls:
        console.print(f"The indexed source does not import or call {package}.", markup=False)
        return
    files = len({i.path for i in imports})
    console.print(f"{package}: imported in {files} file(s), {len(calls)} call(s)", markup=False)
    if imports:
        table = Table(title="Imports", title_justify="left")
        table.add_column("Location", overflow="fold")
        table.add_column("Module", overflow="fold")
        table.add_column("Style")
        table.add_column("Component", overflow="fold")
        for imp in imports:
            table.add_row(
                escape(f"{imp.path}:{imp.line}"),
                escape(imp.module),
                imp.style.value,
                escape(imp.component_ref or "-"),
            )
        console.print(table)
    if calls:
        table = Table(title="Calls", title_justify="left")
        table.add_column("Location", overflow="fold")
        table.add_column("Member", overflow="fold")
        table.add_column("Callee", overflow="fold")
        table.add_column("In", overflow="fold")
        for call in calls:
            table.add_row(
                escape(f"{call.path}:{call.line}"),
                escape(call.member or "-"),
                escape(call.callee),
                escape(call.caller_id or "(module)"),
            )
        console.print(table)


# --- --entry-points --------------------------------------------------------------------


def _render_entry_points(index: CodeIndex, *, json_output: bool) -> None:
    entries = sorted(index.entry_points, key=lambda e: (e.kind.value, e.path, e.line or 0))
    if json_output:
        typer.echo(json.dumps([e.model_dump(mode="json") for e in entries], indent=2))
        return
    if not entries:
        console.print("No entry points detected.")
        return
    table = Table(title=f"Entry points ({len(entries)})", title_justify="left")
    table.add_column("Kind")
    table.add_column("Location", overflow="fold")
    table.add_column("Detail", overflow="fold")
    table.add_column("Symbol", overflow="fold")
    for entry in entries:
        where = f"{entry.path}:{entry.line}" if entry.line else entry.path
        table.add_row(
            entry.kind.value, escape(where), escape(entry.detail), escape(entry.symbol_id or "-")
        )
    console.print(table)
