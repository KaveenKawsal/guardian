"""The interactive shell, driven by scripted input (no TTY, no network, fake chat models)."""

from pathlib import Path
from typing import Any

import pytest
from conftest import analysis
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from pydantic import Field
from typer.testing import CliRunner

from guardian.analysis.git_diff import ChangeAnalyzer
from guardian.analysis.osv import OsvScanner, parse_osv_output
from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.analysis.semgrep import SemgrepScanner
from guardian.assistant import Assistant
from guardian.cli import main as main_module
from guardian.cli import shell as shell_module
from guardian.cli.main import app
from guardian.cli.shell import GuardianShell, as_scan_target, parse_options, split_args
from guardian.cli.shell_input import PromptReader, ScriptReader, ShellCompleter
from guardian.core.config import GuardianSettings
from guardian.core.models import CodeDetails, Finding, FindingKind, Severity
from guardian.execution.results import ToolResult, ToolStatus
from guardian.sources import LocalTarget, RemoteTarget

FIXTURES = Path(__file__).parents[1] / "fixtures"
NODE_BOM = (FIXTURES / "sbom" / "node-express.cdx.json").read_bytes()
OSV_OUTPUT = (FIXTURES / "osv" / "node.osv.json").read_bytes()
GROQ_KEY = "gsk_shell_test_key_0000wxyz"
ENV_VARS = (
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GUARDIAN_GROQ_API_KEY",
    "GUARDIAN_GOOGLE_API_KEY",
    "GUARDIAN_LLM_PROVIDER",
    "GUARDIAN_LLM_MODEL",
    "GUARDIAN_GROQ_MODEL",
    "GUARDIAN_GOOGLE_MODEL",
    "GUARDIAN_AI_ENABLED",
)
CODE_REPO = {
    "package.json": '{"main": "app.js", "dependencies": {"express": "4", "lodash": "4"}}',
    "app.js": (
        "function run(a) {\n"
        "  return _.template(a);\n"
        "}\n"
        'const _ = require("lodash");\n'
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/x", run);\n'
        "app.listen(3000);\n"
    ),
}


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Isolated home, cwd and data dir; canned analyzers (as in test_cli.py)."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    home, work = tmp_path / "home", tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda _: home))
    monkeypatch.chdir(work)
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))

    def fake_generate(self, repo_root, work_dir):
        bom = work_dir / "bom.json"
        bom.write_bytes(NODE_BOM)
        result = ToolResult(tool="cdxgen", args=[], status=ToolStatus.SUCCESS, exit_code=0)
        return SbomGeneration(result=result, bom_path=bom)

    def fake_osv(self, repo_root, work_dir, sbom, raw_sbom, excluded=frozenset()):
        return analysis("osv-scanner", parse_osv_output(OSV_OUTPUT, sbom)[0])

    def fake_semgrep(self, profile, work_dir, excluded=frozenset()):
        hostile = Finding(
            id="code00000000beef",
            kind=FindingKind.CODE,
            title="[red]spoofed[/red] in app.js:2",
            severity=Severity.HIGH,
            tool="semgrep",
            path="app.js",
            start_line=2,
            details=CodeDetails(rule_id="js.[bold]x[/bold]", message="Use [link=evil]x[/link]"),
        )
        return analysis("semgrep", [hostile])

    monkeypatch.setattr(SbomGenerator, "generate", fake_generate)
    monkeypatch.setattr(OsvScanner, "scan", fake_osv)
    monkeypatch.setattr(SemgrepScanner, "scan", fake_semgrep)
    monkeypatch.setattr(
        ChangeAnalyzer, "analyze", lambda self, p: analysis("git", status="skipped")
    )
    return home / ".guardian" / ".env"


class ScriptedModel(BaseChatModel):
    responses: list[AIMessage] = Field(default_factory=list)
    prompts: list[list[Any]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.prompts.append(list(messages))
        message = self.responses.pop(0) if self.responses else AIMessage("ok")
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self


def run(lines, *, model: BaseChatModel | None = None) -> GuardianShell:
    settings = GuardianSettings()
    assistant = Assistant(settings, chat_model=model) if model else None
    shell = GuardianShell(settings, reader=ScriptReader(lines), assistant=assistant)
    shell.run()
    return shell


def flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture
def scanned(env, make_repo, capsys):
    root = make_repo(CODE_REPO)
    shell = run([str(root)])
    capsys.readouterr()
    return shell


# --- start / exit -----------------------------------------------------------------------


def test_banner_without_scan_or_ai(env, capsys):
    shell = run([])
    out = flat(capsys.readouterr().out)
    assert "Guardian 0.1.0" in out
    assert "Repository: none scanned yet" in out
    assert "AI off: add a key with /model or .env" in out
    assert "/help" in out
    assert out.endswith("Bye.")
    assert shell.scan is None
    assert shell.history_path == GuardianSettings().data_dir / "shell_history"


def test_banner_with_ai_and_latest_scan(scanned, env, capsys):
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"GROQ_API_KEY={GROQ_KEY}\n")
    shell = GuardianShell(reader=ScriptReader([]))
    shell.run()
    out = flat(capsys.readouterr().out)
    assert "Repository: repo" in out
    assert f"scan {scanned.scan.id[:12]}" in out
    assert "AI: Groq / openai/gpt-oss-120b" in out
    assert GROQ_KEY not in out
    assert "groq" in shell.toolbar().lower()
    assert scanned.scan.id[:12] in shell.toolbar()


def test_ctrl_c_and_ctrl_d(env, capsys, monkeypatch):
    def interrupted(shell, args):
        raise KeyboardInterrupt

    monkeypatch.setitem(
        shell_module.COMMANDS, "help", shell_module.Command("/help", "h", interrupted)
    )
    run([KeyboardInterrupt(), "/help", "", "/exit", "/never-reached"])
    out = capsys.readouterr().out
    assert "cancelled" in out
    assert "never-reached" not in out
    assert out.rstrip().endswith("Bye.")


def test_prompt_reader_history_and_completion(env, tmp_path):
    history = tmp_path / "data" / "shell_history"
    with create_pipe_input() as pipe:
        reader = PromptReader(
            history, {"/help": "Show help"}, lambda: "toolbar", input=pipe, output=DummyOutput()
        )
        pipe.send_text("/help\r")
        assert reader.read("guardian> ") == "/help"
        pipe.close()
        with pytest.raises(EOFError):
            reader.read("guardian> ")
    assert "/help" in history.read_text(encoding="utf-8")

    completer = ShellCompleter({"/help": "h", "/history": "x", "/scan": "s"})
    names = [c.text for c in completer.get_completions(Document("/h"), CompleteEvent())]
    assert names == ["/help", "/history"]
    (tmp_path / "work" / "projdir").mkdir()
    paths = [c.text for c in completer.get_completions(Document("/scan proj"), CompleteEvent())]
    assert any("dir" in p for p in paths)
    assert list(completer.get_completions(Document("hello"), CompleteEvent())) == []


# --- scanning ---------------------------------------------------------------------------


def test_bare_path_scans_and_selects(env, make_repo, capsys):
    root = make_repo(CODE_REPO)
    shell = run([f'"{root}"'])
    out = flat(capsys.readouterr().out)
    assert "7 components" in out
    assert "Current scan: repo" in out
    assert "[red]spoofed[/red]" in out  # hostile title printed literally
    assert shell.scan is not None
    assert shell.scan.repository_name == "repo"


def test_remote_targets_are_cloned(env, make_repo, monkeypatch, capsys):
    root = make_repo(CODE_REPO)
    cloned: list[RemoteTarget] = []

    def fake_clone(target, settings, runner):
        cloned.append(target)
        return root

    monkeypatch.setattr(shell_module, "clone", fake_clone)
    shell = run(["https://github.com/acme/app", "/scan acme/other --ref v1.2"])
    assert [t.display for t in cloned] == ["github.com/acme/app", "github.com/acme/other"]
    assert cloned[1].ref == "v1.2"
    assert "Clone kept at" in capsys.readouterr().out
    assert shell.scan is not None


def test_scan_errors_keep_shell_alive(env, tmp_path, capsys):
    run(["/scan", f"/scan {tmp_path / 'missing'}", "/scan . --ref x", "/scan . --bogus"])
    out = flat(capsys.readouterr().out)
    assert "usage: /scan <path|url>" in out
    assert "Local directory not found" in out or "Not an existing directory" in out
    assert "--ref only applies to remote repositories" in out
    assert "unknown option --bogus" in out
    assert out.endswith("Bye.")


def test_target_detection():
    assert isinstance(as_scan_target("."), LocalTarget)
    assert isinstance(as_scan_target("github.com/acme/app"), RemoteTarget)
    assert as_scan_target("which packages are vulnerable?") is None
    assert as_scan_target("hello") is None
    assert split_args(r'"C:\My Repo" --ref v1') == [r"C:\My Repo", "--ref", "v1"]
    assert parse_options(["x", "--all"], switches={"--all": "all"}) == (["x"], {"all": True})


# --- slash commands over the current scan ------------------------------------------------


def test_commands_need_a_scan(env, capsys):
    run(["/findings", "/summary", "/explain x", "/report"])
    assert capsys.readouterr().out.count("No scan selected") == 4


def test_inspection_commands(scanned, capsys, tmp_path):
    out_dir = tmp_path / "graph-out"
    run(
        [
            "/summary",
            "/findings -k code",
            "/findings -s critical",
            "/explain code0000",
            "/deps",
            "/deps --why mime-types",
            "/code",
            "/code --uses lodash",
            "/code --entry-points",
            f"/graph -o {out_dir}",
            "/history",
        ]
    )
    out = flat(capsys.readouterr().out)
    assert "1 files indexed" in out  # /summary re-renders the stored scan
    assert "code00000000beef"[:10] in out
    assert "[red]spoofed[/red]" in out
    assert "Rule: js.[bold]x[/bold]" in out
    assert "express@4.17.1" in out
    assert "express@4.17.1 -> accepts@1.3.8 -> mime-types@2.1.35" in out
    assert "Most imported external packages" in out
    assert "app.js:4" in out
    assert "GET /x" in out
    assert (out_dir / "index.html").is_file()
    assert "Select one with /open <scan-id>" in out


def test_inspection_command_errors(scanned, capsys):
    run(
        [
            "/findings -s apocalyptic",
            "/findings -k nope",
            "/explain",
            "/explain zzzz",
            "/deps --why left-pad",
            "/deps --why",
            "/code extra",
            "/summary now",
        ]
    )
    captured = capsys.readouterr()
    out = flat(captured.out + captured.err)
    assert "'apocalyptic' is not a valid Severity" in out
    assert "'nope' is not a valid FindingKind" in out
    assert "usage: /explain <finding-id>" in out
    assert "No finding matches 'zzzz'" in out
    assert "No component named 'left-pad'" in out
    assert "--why needs a value" in out
    assert "unexpected argument 'extra'" in out
    assert flat(captured.out).endswith("Bye.")


def test_open_and_history(scanned, make_repo, capsys):
    first = scanned.scan.id
    shell = run([str(make_repo(CODE_REPO)), f"/open {first[:8]}", "/open nope"])
    out = flat(capsys.readouterr().out)
    assert shell.scan.id == first
    assert "No scan matches 'nope'" in out


def test_report_command(scanned, monkeypatch, capsys, tmp_path):
    calls: list[Any] = []

    def fake_build(db, scan_id, settings):
        calls.append(scan_id)
        return "REPORT"

    def fake_write(report, output_dir, formats):
        calls.append((report, output_dir, [f.value for f in formats]))
        return [output_dir / "r.html", output_dir / "r.md"]

    monkeypatch.setattr(shell_module, "build_report", fake_build)
    monkeypatch.setattr(shell_module, "write_reports", fake_write)
    run(["/report html,md", "/report", "/report pdf"])
    out = flat(capsys.readouterr().out)
    assert calls[0] == scanned.scan.id
    assert calls[1] == ("REPORT", Path("guardian-reports"), ["html", "md"])
    assert calls[3][2] == ["html", "md", "json"]
    assert "Wrote guardian-reports" in out
    assert "unknown report format" in out


def test_report_failure_is_one_line(scanned, monkeypatch, capsys):
    def broken(db, scan_id, settings):
        raise NotImplementedError

    monkeypatch.setattr(shell_module, "build_report", broken)
    run(["/report"])
    out = capsys.readouterr().out
    assert "error: NotImplementedError" in out
    assert "Traceback" not in out


# --- AI / config commands ---------------------------------------------------------------


def test_model_ai_doctor_clear(env, capsys, monkeypatch):
    doctored: list[bool] = []
    monkeypatch.setattr(shell_module, "doctor_command", lambda: doctored.append(True))
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"GROQ_API_KEY={GROQ_KEY}\n")
    shell = run(
        ["/model", "/model google gemini-2.5-pro", "/model nope", "/ai", "/doctor", "/clear"]
    )
    out = flat(capsys.readouterr().out)
    assert "Switch with /model groq|google" in out
    assert "Active provider: Google AI (Gemini)" in out
    assert "GUARDIAN_LLM_PROVIDER=google" in env.read_text()
    assert "GUARDIAN_GOOGLE_MODEL=gemini-2.5-pro" in env.read_text()
    assert shell.settings.llm_provider == "google"
    assert shell.assistant.settings is shell.settings
    assert "usage: /model groq|google [MODEL]" in out
    assert "Guardian LLM providers" in out
    assert GROQ_KEY not in out
    assert doctored == [True]
    assert "Conversation cleared." in out


def test_unknown_command_suggestion(env, capsys):
    run(["/fidnings", "/zzzzzz"])
    out = capsys.readouterr().out
    assert "Unknown command /fidnings. Did you mean /findings?" in out
    assert "Unknown command /zzzzzz. Type /help for commands." in out


def test_help_lists_commands(env, capsys):
    run(["/help"])
    out = capsys.readouterr().out
    for name in ("/scan", "/open", "/findings", "/report", "/model", "/exit"):
        assert name in out


def test_question_answered_by_assistant(scanned, capsys):
    model = ScriptedModel(
        responses=[
            AIMessage("", tool_calls=[{"name": "list_findings", "args": {}, "id": "c1"}]),
            AIMessage("Fix [link=evil]code00000000beef[/link] at app.js:2."),
        ]
    )
    shell = run(["what should I fix first?", "/clear", "and then?"], model=model)
    out = capsys.readouterr().out
    assert "Fix [link=evil]code00000000beef[/link] at app.js:2." in out  # no markup applied
    assert len(model.prompts) == 3
    assert not any("what should I fix" in str(m.content) for m in model.prompts[-1])
    assert len(shell.assistant.conversation) == 1


def test_question_without_ai(scanned, capsys):
    run(["which dependency is vulnerable?"])
    out = flat(capsys.readouterr().out)
    assert "AI is off" in out
    assert "/findings" in out


# --- entry points -----------------------------------------------------------------------


def test_guardian_without_args(env, monkeypatch):
    cli = CliRunner()
    result = cli.invoke(app, [])
    assert result.exit_code == 2
    assert "Usage" in result.output

    started: list[bool] = []
    monkeypatch.setattr(main_module, "_interactive", lambda: True)
    monkeypatch.setattr(main_module, "run_shell", lambda: started.append(True))
    assert cli.invoke(app, []).exit_code == 0
    assert started == [True]


def test_guardian_shell_command_plain_input(env):
    result = CliRunner().invoke(app, ["shell"], input="/help\n/exit\n")
    assert result.exit_code == 0, result.output
    assert "Guardian shell" in result.output
    assert "Bye." in result.output
