"""The optional npm lockfile hook in ScanPipeline (disabled by default)."""
# ruff: noqa: EM101 - inline test errors

from pathlib import Path

import pytest
from conftest import StubAnalyzer, analysis

from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import ScanStatus
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.orchestration.pipeline import NPM_LOCKFILE, ScanPipeline
from guardian.storage.database import Database

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
NODE_REPO = {
    "package.json": '{"dependencies": {"express": "4", "lodash": "4"}}',
    ".npmrc": "package-lock=false\n",
    "lib/app.js": "require('express')\n",
    "node_modules/express/index.js": "x",
}
LOCK = '{"lockfileVersion": 3, "packages": {}}'


class RecordingGenerator(SbomGenerator):
    """Canned SBOM; records which directory cdxgen would have scanned and what it contained."""

    def __init__(self):
        super().__init__(ToolRunner())
        self.roots: list[Path] = []
        self.listing: list[str] = []

    def generate(self, repo_root, work_dir):
        self.roots.append(repo_root)
        self.listing = sorted(
            p.relative_to(repo_root).as_posix() for p in repo_root.rglob("*") if p.is_file()
        )
        bom = work_dir / "bom.json"
        bom.write_bytes((FIXTURES / "node-express.cdx.json").read_bytes())
        result = ToolResult(tool="cdxgen", args=[], status=ToolStatus.SUCCESS, exit_code=0)
        return SbomGeneration(result=result, bom_path=bom)


class RecordingOsv(StubAnalyzer):
    def __init__(self):
        super().__init__(analysis("osv-scanner"))
        self.roots: list[Path] = []

    def scan(self, root, *args, **kwargs):
        self.roots.append(root)
        return super().scan(root, *args, **kwargs)


@pytest.fixture
def settings(tmp_path):
    return GuardianSettings(_env_file=None, data_dir=tmp_path / "data")


@pytest.fixture
def db(settings):
    with Database(settings.database_path) as database:
        yield database


def _pipeline(db, settings, lockfile_generator=None):
    generator, osv = RecordingGenerator(), RecordingOsv()
    pipeline = ScanPipeline(
        db,
        settings,
        sbom_generator=generator,
        osv_scanner=osv,
        semgrep_scanner=StubAnalyzer(analysis("semgrep")),
        change_analyzer=StubAnalyzer(analysis("git", status="skipped")),
        lockfile_generator=lockfile_generator,
    )
    return pipeline, generator, osv


def test_disabled_hook_changes_nothing(db, settings, make_repo):
    root = make_repo(NODE_REPO)
    pipeline, generator, osv = _pipeline(db, settings)
    outcome = pipeline.run(root)
    assert generator.roots == [root]
    assert osv.roots == [root]
    assert NPM_LOCKFILE not in {t.tool for t in outcome.record.tool_runs}
    assert outcome.record.status is ScanStatus.COMPLETED


def test_generated_lockfile_is_scanned_from_a_copy(db, settings, make_repo):
    root = make_repo(NODE_REPO)
    calls = []

    def lockfile_generator(repo, out_dir):
        calls.append(repo)
        out_dir.mkdir(parents=True)
        (out_dir / "package-lock.json").write_text(LOCK)
        return out_dir / "package-lock.json", None

    pipeline, generator, osv = _pipeline(db, settings, lockfile_generator)
    outcome = pipeline.run(root)

    assert calls == [root]
    scanned = generator.roots[0]
    assert scanned != root
    assert osv.roots == [scanned]
    assert "package-lock.json" in generator.listing
    assert "lib/app.js" in generator.listing
    assert not any(p.startswith("node_modules/") for p in generator.listing)
    assert not scanned.exists()  # the workspace is temporary
    assert not (root / "package-lock.json").exists()  # never written into the user's repo
    assert outcome.profile.root == str(root)
    runs = {t.tool: t.status for t in outcome.record.tool_runs}
    assert runs[NPM_LOCKFILE] == "success"
    assert outcome.record.status is ScanStatus.COMPLETED
    assert any("generated in the sandbox" in w for w in outcome.record.warnings)


@pytest.mark.parametrize("fail", ["warning", "raise"])
def test_failed_generation_falls_back_to_the_repository(db, settings, make_repo, fail):
    root = make_repo(NODE_REPO)

    def lockfile_generator(repo, out_dir):
        if fail == "raise":
            raise GuardianError("refused")
        return None, "npm lockfile generation skipped: sandbox unavailable: no docker"

    pipeline, generator, _ = _pipeline(db, settings, lockfile_generator)
    outcome = pipeline.run(root)
    assert generator.roots == [root]
    run = next(t for t in outcome.record.tool_runs if t.tool == NPM_LOCKFILE)
    assert run.status == "failed"
    assert outcome.record.status is ScanStatus.PARTIAL
    assert any("lockfile generation" in w for w in outcome.record.warnings)


def test_existing_lockfile_or_no_node_skips_generation(db, settings, make_repo):
    calls = []

    def lockfile_generator(repo, out_dir):
        calls.append(repo)
        return None, None

    root = make_repo({**NODE_REPO, "package-lock.json": LOCK})
    _pipeline(db, settings, lockfile_generator)[0].run(root)
    assert calls == []
