import json
from pathlib import Path

from guardian.analysis.sbom import SbomGenerator, find_cdxgen_install, node_permission_options
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner


def _fake_install(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "npm"
    package = bin_dir / "node_modules" / "@cyclonedx" / "cdxgen"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "@cyclonedx/cdxgen"}))
    shim = bin_dir / "cdxgen.cmd"
    shim.write_text("")
    return shim


def test_find_install_from_npm_shim(tmp_path):
    shim = _fake_install(tmp_path)
    assert find_cdxgen_install(shim) == shim.parent / "node_modules" / "@cyclonedx" / "cdxgen"


def test_find_install_missing(tmp_path):
    exe = tmp_path / "cdxgen"
    exe.write_text("")
    assert find_cdxgen_install(exe) is None


def test_permission_options():
    options = node_permission_options([Path("/a"), Path("/b")], [Path("/tmp")])
    assert options is not None
    assert options.startswith("--permission ")
    assert f"--allow-fs-read={Path('/a')}" in options
    assert f"--allow-fs-write={Path('/tmp')}" in options
    assert node_permission_options([Path("/with space")], []) is None


class RecordingRunner(ToolRunner):
    def __init__(self, executable: str | None, write_bom: bool = True, status=ToolStatus.SUCCESS):
        super().__init__()
        self.executable = executable
        self.write_bom = write_bom
        self.status = status
        self.calls: list[dict] = []

    def resolve(self, tool):
        return self.executable

    def run(self, tool, args, *, cwd, timeout_seconds=None, env=None):
        self.calls.append({"tool": tool, "args": list(args), "env": dict(env or {})})
        if self.write_bom:
            Path(args[args.index("--output") + 1]).write_text("{}")
        return ToolResult(tool=tool, args=list(args), status=self.status, exit_code=0)


def test_generate_sandboxed(tmp_path):
    runner = RecordingRunner(str(_fake_install(tmp_path)))
    work = tmp_path / "work"
    work.mkdir()
    generation = SbomGenerator(runner).generate(tmp_path / "repo", work)

    call = runner.calls[0]
    assert call["args"][:3] == ["--no-install-deps", "--spec-version", "1.6"]
    assert call["args"][-1] == str(tmp_path / "repo")
    assert call["env"]["CDXGEN_SECURE_MODE"] == "true"
    assert "--permission" in call["env"]["NODE_OPTIONS"]
    assert generation.sandboxed
    assert generation.bom_path == work / "bom.json"
    assert generation.warnings == []


def test_generate_without_install_warns(tmp_path):
    exe = tmp_path / "cdxgen"
    exe.write_text("")
    runner = RecordingRunner(str(exe), write_bom=False, status=ToolStatus.FAILED)
    generation = SbomGenerator(runner).generate(tmp_path, tmp_path)
    assert not generation.sandboxed
    assert "NODE_OPTIONS" not in runner.calls[0]["env"]
    assert generation.bom_path is None
    assert "without the Node.js permission model" in generation.warnings[0]


def test_failed_run_with_output_is_flagged(tmp_path):
    runner = RecordingRunner(str(_fake_install(tmp_path)), status=ToolStatus.FAILED)
    generation = SbomGenerator(runner).generate(tmp_path / "repo", tmp_path)
    assert generation.bom_path is not None
    assert "produced an SBOM" in generation.warnings[-1]


def test_not_installed(tmp_path):
    runner = RecordingRunner(None, write_bom=False, status=ToolStatus.NOT_FOUND)
    generation = SbomGenerator(runner).generate(tmp_path, tmp_path)
    assert generation.result.status is ToolStatus.NOT_FOUND
    assert generation.warnings == []
