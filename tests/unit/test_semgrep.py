from pathlib import Path

import pytest

from guardian.analysis.base import decode_tool_output
from guardian.analysis.semgrep import (
    SemgrepScanner,
    parse_semgrep_output,
    repository_ignore_warning,
    select_configs,
)
from guardian.core.config import GuardianSettings
from guardian.core.models import FindingKind, Severity
from guardian.core.profiler import RepositoryProfiler
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner

OUTPUT = (Path(__file__).parents[1] / "fixtures" / "semgrep" / "sample.semgrep.json").read_bytes()
SOURCES = {
    "app/server.py": "import subprocess\n\nsubprocess.check_output(cmd, shell=True)\n",
    "app/index.js": "res.send(req.query.x)\n",
    "config.txt": "api_key = 'abc123'\n",
}


def _profile(make_repo, files):
    return RepositoryProfiler(settings=GuardianSettings(_env_file=None)).profile(make_repo(files))


def test_select_configs(make_repo):
    profile = _profile(
        make_repo,
        {
            "a.py": "x=1",
            "b.ts": "let x = 1",
            "Dockerfile": "FROM python:3.12",
            ".github/workflows/ci.yml": "on: push",
        },
    )
    configs = select_configs(profile)  # language packs follow language size order
    assert set(configs) == {
        "p/python",
        "p/typescript",
        "p/dockerfile",
        "p/github-actions",
        "p/secrets",
    }
    assert configs[-1] == "p/secrets"
    assert len(configs) == len(set(configs))


def test_parse(make_repo):
    root = make_repo(SOURCES)
    findings, warnings = parse_semgrep_output(OUTPUT, root)
    by_rule = {f.details.rule_id.rsplit(".", 1)[-1]: f for f in findings}

    injection = by_rule["subprocess-injection"]
    assert injection.kind is FindingKind.CODE
    assert injection.severity is Severity.HIGH
    assert injection.path == "app/server.py"  # Windows separators normalized
    assert injection.location == "app/server.py:3"
    assert injection.details.cwe_ids == ["CWE-78"]
    assert injection.details.confidence == "HIGH"
    assert injection.details.owasp == ["A03:2021 - Injection"]

    xss = by_rule["direct-response-write"]
    assert xss.path == "app/index.js"  # leading ./ removed
    assert xss.severity is Severity.MEDIUM
    assert xss.details.cwe_ids == ["CWE-79"]  # a single string is accepted too
    assert xss.details.confidence == "MEDIUM"

    assert by_rule["generic-api-key"].severity is Severity.LOW
    assert [f.severity.rank for f in findings] == sorted(
        (f.severity.rank for f in findings), reverse=True
    )
    # Only level=error problems are surfaced; partial-parsing warnings are not.
    assert warnings == ["Semgrep reported 1 error(s): Timeout"]


def test_matched_text_is_not_stored(make_repo):
    findings, _ = parse_semgrep_output(OUTPUT, make_repo(SOURCES))
    dumped = " ".join(f.model_dump_json() for f in findings)
    assert "abc123" not in dumped
    assert "shell=True" not in dumped


def test_fingerprint_survives_moved_code_but_not_changed_code(make_repo, tmp_path):
    root = make_repo(SOURCES)
    original = {f.details.rule_id: f.id for f in parse_semgrep_output(OUTPUT, root)[0]}

    # Same code, reindented: same id.
    (root / "app/server.py").write_text(
        "import subprocess\n\nsubprocess.check_output( cmd,  shell=True )\n"
    )
    moved = {f.details.rule_id: f.id for f in parse_semgrep_output(OUTPUT, root)[0]}
    rule = "python.flask.security.injection.subprocess-injection.subprocess-injection"
    assert moved[rule] == original[rule]

    (root / "app/server.py").write_text("import subprocess\n\nsubprocess.run(other)\n")
    changed = {f.details.rule_id: f.id for f in parse_semgrep_output(OUTPUT, root)[0]}
    assert changed[rule] != original[rule]


def test_non_utf8_output_is_decoded():
    # Semgrep on Windows can write the ANSI code page (0x97 is an em dash in cp1252).
    assert decode_tool_output(b'{"m": "a \x97 b"}') == '{"m": "a � b"}'
    assert decode_tool_output("already text") == "already text"


def test_repository_ignore_warning(tmp_path):
    assert repository_ignore_warning(tmp_path) is None
    (tmp_path / ".semgrepignore").write_text("# comment\nsrc/payload/\n*.min.js\n")
    warning = repository_ignore_warning(tmp_path)
    assert warning is not None
    assert "src/payload/, *.min.js" in warning


class FakeRunner(ToolRunner):
    def __init__(self, output: bytes | None, exit_code: int = 0):
        super().__init__()
        self.output, self.exit_code = output, exit_code
        self.args: list[str] = []
        self.env: dict[str, str] = {}
        self.cwd = None

    def run(self, tool, args, *, cwd, timeout_seconds=None, env=None):
        self.args, self.env, self.cwd = list(args), dict(env or {}), cwd
        if self.output is not None:
            Path(args[args.index("--output") + 1]).write_bytes(self.output)
        status = ToolStatus.SUCCESS if self.exit_code == 0 else ToolStatus.FAILED
        return ToolResult(tool=tool, args=list(args), status=status, exit_code=self.exit_code)


def test_scanner_arguments(make_repo, tmp_path):
    profile = _profile(make_repo, SOURCES)
    runner = FakeRunner(OUTPUT)
    result = SemgrepScanner(runner).scan(profile, tmp_path, frozenset({"node_modules"}))
    assert result.tool_run.status == "success"
    assert len(result.findings) == 3
    for flag in ("--metrics=off", "--oss-only", "--no-git-ignore", "--disable-version-check"):
        assert flag in runner.args
    assert runner.args[runner.args.index("--exclude") + 1] == "node_modules"
    assert "p/secrets" in runner.args
    assert runner.env["PYTHONUTF8"] == "1"
    assert runner.env["SEMGREP_SEND_METRICS"] == "off"
    assert runner.cwd == Path(profile.root)


def test_scanner_custom_configs(make_repo, tmp_path):
    profile = _profile(make_repo, SOURCES)
    runner = FakeRunner(OUTPUT)
    SemgrepScanner(runner, configs=["rules/guardian.yml"]).scan(profile, tmp_path)
    configs = [runner.args[i + 1] for i, a in enumerate(runner.args) if a == "--config"]
    assert configs == ["rules/guardian.yml"]


def test_scanner_skips_and_failures(make_repo, tmp_path):
    empty = _profile(make_repo, {"README.md": "hi"})
    assert SemgrepScanner(FakeRunner(OUTPUT)).scan(empty, tmp_path).tool_run.status == "skipped"

    profile = _profile(make_repo, SOURCES)
    (Path(profile.root) / ".semgrepignore").write_text("app/\n")
    failed = SemgrepScanner(FakeRunner(None, exit_code=2)).scan(profile, tmp_path)
    assert failed.tool_run.status == "failed"
    assert any(".semgrepignore" in w for w in failed.warnings)

    garbage = SemgrepScanner(FakeRunner(b"{nope")).scan(profile, tmp_path)
    assert garbage.tool_run.status == "failed"


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"])
def test_new_style_severities_are_recognised(make_repo, severity):
    bom = (
        '{"results": [{"check_id": "r", "path": "a.py", "start": {"line": 1}, '
        f'"end": {{"line": 1}}, "extra": {{"severity": "{severity}"}}}}]}}'
    )
    findings, _ = parse_semgrep_output(bom, make_repo({"a.py": "x"}))
    assert findings[0].severity is not Severity.UNKNOWN
