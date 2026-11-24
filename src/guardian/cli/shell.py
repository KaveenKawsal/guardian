"""``guardian`` / ``guardian shell``: an interactive session over Guardian's scan data.

Paste a folder or repository URL to scan it, use slash commands to inspect the selected scan
with the same renderers as the CLI commands, or ask a question in plain language that the
read-only assistant answers from the scan data.

Repository names, package names, finding text, tool output and model answers are untrusted:
they are escaped or printed with ``markup=False``.
"""

import difflib
import shlex
import sys
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from guardian import __version__
from guardian.assistant import Assistant, ScanToolbox
from guardian.cli import ai as ai_cli
from guardian.cli.code import code as code_command
from guardian.cli.common import console, open_database
from guardian.cli.deps import deps as deps_command
from guardian.cli.doctor import doctor as doctor_command
from guardian.cli.findings import explain as explain_command
from guardian.cli.findings import findings as findings_command
from guardian.cli.graph import graph as graph_command
from guardian.cli.history import history as history_command
from guardian.cli.scan import _clone_runner, lockfile_hints, render_scan, resolve_target
from guardian.cli.shell_input import PROMPT, LineReader, PlainReader, PromptReader
from guardian.core.config import LLM_PROVIDERS, GuardianSettings
from guardian.core.exceptions import ConfigurationError, GuardianError
from guardian.core.models import FindingKind, ScanRecord, Severity
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.llm.providers import PROVIDER_LABELS, resolve_provider
from guardian.orchestration.pipeline import ScanOutcome, ScanPipeline
from guardian.reporting.models import ReportFormat
from guardian.reporting.render import write_reports
from guardian.reporting.report_data import build_report
from guardian.sources import InvalidTargetError, LocalTarget, RemoteTarget, Target, clone
from guardian.sources import parse_target as _parse_target

REPORT_DIR = Path("guardian-reports")
GRAPH_DIR = Path("guardian-graph")
HISTORY_FILE = "shell_history"
AI_OFF = "AI off: add a key with /model or .env"


class ShellUsageError(GuardianError):
    """A slash command was called with arguments it does not accept."""


@dataclass(frozen=True)
class Command:
    usage: str
    summary: str
    handler: Callable[["GuardianShell", list[str]], None]
    needs_scan: bool = False


# --- argument helpers --------------------------------------------------------------------


def split_args(text: str) -> list[str]:
    """Split like a shell, but keep Windows backslashes; surrounding quotes are removed."""
    try:
        tokens = shlex.split(text, posix=False)
    except ValueError as exc:
        msg = f"cannot parse arguments: {exc}"
        raise ShellUsageError(msg) from None
    return [_unquote(t) for t in tokens]


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":  # noqa: PLR2004
        return token[1:-1]
    return token


def parse_options(
    tokens: list[str],
    *,
    values: dict[str, str] | None = None,
    switches: dict[str, str] | None = None,
    max_positionals: int = 1,
) -> tuple[list[str], dict[str, str | bool]]:
    """Tiny option parser: ``values`` map flags taking a value, ``switches`` boolean flags."""
    values, switches = values or {}, switches or {}
    positionals: list[str] = []
    options: dict[str, str | bool] = {}
    items = iter(tokens)
    for token in items:
        if token in values:
            value = next(items, None)
            if value is None:
                msg = f"{token} needs a value"
                raise ShellUsageError(msg)
            options[values[token]] = value
        elif token in switches:
            options[switches[token]] = True
        elif token.startswith("-") and len(token) > 1:
            msg = f"unknown option {token}"
            raise ShellUsageError(msg)
        else:
            positionals.append(token)
    if len(positionals) > max_positionals:
        msg = f"unexpected argument {positionals[max_positionals]!r}"
        raise ShellUsageError(msg)
    return positionals, options


def as_scan_target(text: str) -> Target | None:
    """The target when bare input is an existing directory or a remote repository."""
    try:
        return _parse_target(text)
    except (InvalidTargetError, OSError, ValueError):
        return None


def describe_ai(settings: GuardianSettings) -> str | None:
    """``Provider / model`` of the active provider, or None when AI is off."""
    try:
        config = resolve_provider(settings)
    except ConfigurationError:
        return None
    if config is None:
        return None
    return f"{PROVIDER_LABELS[config.provider]} / {config.model}"


# --- the shell ---------------------------------------------------------------------------


class GuardianShell:
    def __init__(
        self,
        settings: GuardianSettings | None = None,
        *,
        reader: LineReader | None = None,
        assistant: Assistant | None = None,
    ) -> None:
        self.settings = settings or ai_cli.load_settings()
        self.assistant = assistant or Assistant(self.settings)
        self.scan: ScanRecord | None = None
        self.use_workspace = reader is None and sys.stdin.isatty() and sys.stdout.isatty()
        self.reader = reader or self._default_reader()

    # Session

    @property
    def history_path(self) -> Path:
        return self.settings.data_dir / HISTORY_FILE

    def _default_reader(self) -> LineReader:
        if sys.stdin.isatty() and sys.stdout.isatty():
            summaries = {f"/{name}": c.summary for name, c in COMMANDS.items()}
            summaries["/exit"] = "Exit Guardian"
            return PromptReader(self.history_path, summaries, self.toolbar)
        return PlainReader()

    def toolbar(self) -> str:
        repo = f"{self.scan.repository_name} | scan {self.scan.id[:12]}" if self.scan else "no scan"
        context = f"{repo} | {describe_ai(self.settings) or 'AI off'}"
        context = "".join(char for char in context if char.isprintable())
        return f" {context} | Enter send · Alt+Enter newline · Ctrl+D exit "

    def run(self) -> None:
        self._select_initial_scan()
        if self.use_workspace:
            from guardian.cli.workspace import Workspace

            commands = {f"/{name}": command.summary for name, command in COMMANDS.items()}
            commands["/exit"] = "Exit Guardian"
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            Workspace(self, commands).run()
            return
        self.banner()
        while True:
            try:
                line = self.reader.read(PROMPT)
            except KeyboardInterrupt:
                continue  # Ctrl+C clears the current line
            except EOFError:
                break
            if not self.dispatch(line):
                break
        console.print("Bye.")

    def dispatch(self, line: str) -> bool:
        """Handle one line; False ends the session. Errors never escape."""
        text = line.strip()
        if not text:
            return True
        try:
            return self._handle(text)
        except KeyboardInterrupt:
            console.print("[yellow]cancelled[/yellow]")
        except typer.Exit:
            pass  # the command already printed its message
        except ShellUsageError as exc:
            console.print(f"[red]usage:[/red] {escape(str(exc))}")
        except GuardianError as exc:
            console.print(f"[red]error:[/red] {escape(str(exc))}")
        except Exception as exc:  # noqa: BLE001 - one bad command must not kill the shell
            detail = " ".join(str(exc).split())[:300]
            console.print(f"[red]error:[/red] {escape(type(exc).__name__)}: {escape(detail)}")
        return True

    def _handle(self, text: str) -> bool:
        if text.startswith("/"):
            if isinstance(as_scan_target(text), LocalTarget):  # a POSIX absolute path
                self.scan_target(text)
                return True
            name, _, rest = text[1:].partition(" ")
            return self.run_command(name.lower(), split_args(rest))
        target = as_scan_target(text)
        if target is not None:
            self.scan_target(text)
        else:
            self.ask(text)
        return True

    def run_command(self, name: str, args: list[str]) -> bool:
        if name in {"exit", "quit"}:
            return False
        command = COMMANDS.get(name)
        if command is None:
            close = difflib.get_close_matches(name, [*COMMANDS, "exit"], n=1, cutoff=0.5)
            hint = f" Did you mean /{close[0]}?" if close else " Type /help for commands."
            console.print(f"Unknown command /{escape(name)}.{hint}")
            return True
        if command.needs_scan and self.scan is None:
            console.print(
                "No scan selected: paste a folder or repository URL, or use /open latest."
            )
            return True
        command.handler(self, args)
        return True

    # Display

    def banner(self) -> None:
        if isinstance(self.reader, PromptReader):
            context = (
                f"{self.scan.repository_name} · {self._scan_line()}"
                if self.scan else "No scan selected"
            )
            body = Text()
            body.append(context + "\n")
            body.append((describe_ai(self.settings) or "AI off") + "\n", style="dim")
            body.append("\n/scan", style="bold cyan")
            body.append("  Analyze a repository     ")
            body.append("/history", style="bold cyan")
            body.append("  Open recent scans\n")
            body.append("/findings", style="bold cyan")
            body.append("  Review findings           ")
            body.append("/help", style="bold cyan")
            body.append("  Browse commands")
            console.print(Panel(body, title=f"Guardian {__version__}", title_align="left",
                                border_style="cyan", expand=False))
            return
        console.print(f"[bold cyan]Guardian[/bold cyan] {__version__}  security intelligence shell")
        if self.scan:
            console.print(
                f"Repository: [bold]{escape(self.scan.repository_name)}[/bold]  "
                + self._scan_line()
            )
        else:
            console.print("Repository: none scanned yet")
        ai = describe_ai(self.settings)
        console.print(f"AI: {escape(ai)}" if ai else f"[yellow]{escape(AI_OFF)}[/yellow]")
        console.print(
            "[dim]/help for commands. Paste a folder path or repository URL to scan it; "
            "anything else is a question for the assistant.[/dim]"
        )

    def _scan_line(self) -> str:
        assert self.scan is not None  # noqa: S101 - callers check
        when = self.scan.started_at.strftime("%Y-%m-%d %H:%M")
        return f"scan {self.scan.id[:12]} ({when} UTC, {self.scan.status.value})"

    def select(self, record: ScanRecord) -> None:
        self.scan = record
        console.print(
            f"Current scan: [bold]{escape(record.repository_name)}[/bold] {self._scan_line()}"
        )

    def _select_initial_scan(self) -> None:
        with open_database(self.settings) as db:
            for root in (str(Path.cwd().resolve()), None):
                try:
                    self.scan = db.scans.get(db.scans.resolve("latest", root))
                except GuardianError:
                    continue
                return

    # Actions

    def status(self, message: str):
        """Let the full-screen UI own progress rendering."""
        return nullcontext() if self.use_workspace else console.status(message)

    def scan_target(self, text: str, ref: str | None = None) -> None:
        settings = self.settings
        source = resolve_target(text, ref)
        if isinstance(source, RemoteTarget):
            with self.status(f"Cloning {escape(source.display)} ..."):
                path = clone(source, settings, _clone_runner(settings))
            console.print(f"Clone kept at {escape(str(path))}")
        else:
            path = source.path
        with (
            open_database(settings) as db,
            self.status(f"Scanning {escape(str(path.resolve()))} ..."),
        ):
            outcome = ScanPipeline(db, settings).run(path)
        render_scan(outcome)
        for hint in lockfile_hints(outcome.profile):
            console.print(f"[yellow]hint:[/yellow] {escape(hint)}")
        self.select(outcome.record)

    def ask(self, question: str) -> None:
        def on_token(token: str) -> None:
            console.print(token, end="", markup=False, highlight=False, soft_wrap=True)

        with open_database(self.settings) as db:
            toolbox = ScanToolbox(db, self.scan.id, self.settings) if self.scan else None
            reply = self.assistant.ask(question, toolbox, on_token)
        if reply.streamed:
            console.print()
        else:
            style = "yellow" if reply.error else None
            console.print(reply.text, markup=False, highlight=False, style=style)

    def outcome(self) -> ScanOutcome:
        """Rebuild the ScanOutcome of the current scan from storage (for /summary)."""
        assert self.scan is not None  # noqa: S101 - needs_scan guarantees it
        scan_id = self.scan.id
        with open_database(self.settings) as db:
            record = db.scans.get(scan_id)
            profile = db.scans.profile(scan_id)
            sbom = db.sboms.load(scan_id)
            found = db.findings.load(scan_id)
            changes = db.findings.changes(scan_id)
            index = db.code.load(scan_id)
        graph = DependencyGraph(
            build_knowledge_graph(profile, sbom, found, changes, code_index=index)
        )
        return ScanOutcome(record, profile, sbom, graph, found, changes, index)

    @property
    def scan_id(self) -> str:
        assert self.scan is not None  # noqa: S101 - needs_scan guarantees it
        return self.scan.id


# --- command handlers --------------------------------------------------------------------


def _cmd_help(shell: GuardianShell, args: list[str]) -> None:  # noqa: ARG001
    table = Table(title="Guardian shell", title_justify="left", show_header=False)
    table.add_column("Command", style="bold")
    table.add_column("Description")
    for command in COMMANDS.values():
        table.add_row(escape(command.usage), command.summary)
    table.add_row("/exit", "Quit (or Ctrl+D)")
    console.print(table)
    console.print(
        "Paste a folder path or repository URL to scan it. Anything else is a question "
        "for the assistant, answered from the current scan."
    )


def _cmd_scan(shell: GuardianShell, args: list[str]) -> None:
    positionals, options = parse_options(args, values={"--ref": "ref"})
    if not positionals:
        msg = "/scan <path|url> [--ref REF]"
        raise ShellUsageError(msg)
    ref = options.get("ref")
    shell.scan_target(positionals[0], ref if isinstance(ref, str) else None)


def _cmd_open(shell: GuardianShell, args: list[str]) -> None:
    positionals, _ = parse_options(args)
    identifier = positionals[0] if positionals else "latest"
    with open_database(shell.settings) as db:
        record = db.scans.get(db.scans.resolve(identifier))
    shell.select(record)


def _cmd_history(shell: GuardianShell, args: list[str]) -> None:  # noqa: ARG001
    history_command(path=None, limit=20)
    console.print("Select one with [bold]/open <scan-id>[/bold].")


def _cmd_summary(shell: GuardianShell, args: list[str]) -> None:
    parse_options(args, max_positionals=0)
    render_scan(shell.outcome())


def _cmd_findings(shell: GuardianShell, args: list[str]) -> None:
    _, options = parse_options(
        args,
        values={"-s": "severity", "--min-severity": "severity", "-k": "kind", "--kind": "kind"},
        max_positionals=0,
    )
    try:
        severity = Severity(str(options.get("severity", Severity.LOW.value)).lower())
        kind = FindingKind(str(options["kind"]).lower()) if "kind" in options else None
    except ValueError as exc:
        raise ShellUsageError(str(exc)) from None
    findings_command(shell.scan_id, min_severity=severity, kind=kind, json_output=False)


def _cmd_explain(shell: GuardianShell, args: list[str]) -> None:
    positionals, _ = parse_options(args)
    if not positionals:
        msg = "/explain <finding-id>"
        raise ShellUsageError(msg)
    explain_command(positionals[0], scan_id=shell.scan_id, json_output=False)


def _cmd_deps(shell: GuardianShell, args: list[str]) -> None:
    _, options = parse_options(
        args, values={"--why": "why"}, switches={"--all": "all"}, max_positionals=0
    )
    why = options.get("why")
    deps_command(
        shell.scan_id,
        why=why if isinstance(why, str) else None,
        show_all=bool(options.get("all")),
        json_output=False,
    )


def _cmd_code(shell: GuardianShell, args: list[str]) -> None:
    _, options = parse_options(
        args,
        values={"--uses": "uses"},
        switches={"--entry-points": "entry_points"},
        max_positionals=0,
    )
    uses = options.get("uses")
    code_command(
        shell.scan_id,
        uses=uses if isinstance(uses, str) else None,
        show_entry_points=bool(options.get("entry_points")),
        json_output=False,
    )


def _cmd_graph(shell: GuardianShell, args: list[str]) -> None:
    _, options = parse_options(
        args, values={"-o": "output", "--output": "output"}, max_positionals=0
    )
    output = Path(str(options.get("output", GRAPH_DIR)))
    graph_command(shell.scan_id, output=output, embed=True)


def _cmd_report(shell: GuardianShell, args: list[str]) -> None:
    positionals, options = parse_options(
        args, values={"-o": "output", "--output": "output"}, max_positionals=3
    )
    names = [n for token in positionals for n in token.replace(",", " ").split()]
    try:
        formats = [ReportFormat(n.lower()) for n in names] or list(ReportFormat)
    except ValueError:
        choices = ", ".join(f.value for f in ReportFormat)
        msg = f"unknown report format; choose from {choices}"
        raise ShellUsageError(msg) from None
    output = Path(str(options.get("output", REPORT_DIR)))
    with open_database(shell.settings) as db, shell.status("Building report ..."):
        report = build_report(db, shell.scan_id, shell.settings)
    paths = write_reports(report, output, list(dict.fromkeys(formats)))
    for path in paths:
        console.print(f"Wrote {escape(str(path))}")


def _cmd_model(shell: GuardianShell, args: list[str]) -> None:
    positionals, _ = parse_options(args, max_positionals=2)
    if not positionals:
        ai = describe_ai(shell.settings)
        console.print(f"AI: {escape(ai)}" if ai else escape(AI_OFF))
        console.print("Switch with [bold]/model groq|google [MODEL][/bold]; keys go in .env.")
        return
    provider = positionals[0].lower()
    if provider not in LLM_PROVIDERS:
        msg = "/model groq|google [MODEL]"
        raise ShellUsageError(msg)
    model = positionals[1] if len(positionals) > 1 else None
    ai_cli.use(ai_cli.Provider(provider), model)
    shell.settings = ai_cli.load_settings()
    shell.assistant.settings = shell.settings


def _cmd_ai(shell: GuardianShell, args: list[str]) -> None:  # noqa: ARG001
    ai_cli.status()


def _cmd_doctor(shell: GuardianShell, args: list[str]) -> None:  # noqa: ARG001
    doctor_command()


def _cmd_clear(shell: GuardianShell, args: list[str]) -> None:  # noqa: ARG001
    shell.assistant.conversation.clear()
    console.clear()
    console.print("Conversation cleared.")


COMMANDS: dict[str, Command] = {
    "help": Command("/help", "Show this help", _cmd_help),
    "scan": Command("/scan <path|url> [--ref R]", "Scan a folder or repository", _cmd_scan),
    "open": Command("/open <scan-id|latest>", "Select a previous scan", _cmd_open),
    "history": Command("/history", "List recent scans", _cmd_history),
    "summary": Command("/summary", "Summary of the current scan", _cmd_summary, needs_scan=True),
    "findings": Command(
        "/findings [-s severity] [-k kind]", "List findings", _cmd_findings, needs_scan=True
    ),
    "explain": Command("/explain <id>", "Explain one finding", _cmd_explain, needs_scan=True),
    "deps": Command(
        "/deps [--why pkg] [--all]",
        "Dependencies, or why a package is present",
        _cmd_deps,
        needs_scan=True,
    ),
    "code": Command(
        "/code [--uses pkg] [--entry-points]",
        "Code index, package usage, entry points",
        _cmd_code,
        needs_scan=True,
    ),
    "graph": Command(
        "/graph [-o dir]", "Write the interactive dependency graph", _cmd_graph, needs_scan=True
    ),
    "report": Command(
        "/report [html,md,json]",
        f"Write reports into ./{REPORT_DIR}",
        _cmd_report,
        needs_scan=True,
    ),
    "model": Command("/model [groq|google] [model]", "Show or switch the AI provider", _cmd_model),
    "ai": Command("/ai", "AI provider status", _cmd_ai),
    "doctor": Command("/doctor", "Check external analysis tools", _cmd_doctor),
    "clear": Command("/clear", "Clear the screen and the conversation", _cmd_clear),
}


def run_shell(settings: GuardianSettings | None = None, reader: LineReader | None = None) -> None:
    GuardianShell(settings, reader=reader).run()


def shell() -> None:
    """Start the interactive Guardian shell (also what plain `guardian` does in a terminal)."""
    run_shell()
