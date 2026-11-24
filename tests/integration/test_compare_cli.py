"""``guardian compare`` on two seeded scans, and the demo script's syntax."""

import json
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
import typer
from remediation_fakes import T0, profile_for, sbom_with, vuln
from typer.testing import CliRunner

from guardian.cli import common
from guardian.cli.compare import compare
from guardian.core.config import GuardianSettings
from guardian.core.models import ScanStatus, Severity
from guardian.reporting.compare import ScanComparison, compare_scans
from guardian.storage.database import Database

SCRIPT = Path(__file__).parents[2] / "scripts" / "demo_day2.sh"
ROOT = "/repos/app"

app = typer.Typer()
app.command()(compare)


@app.callback()
def _group() -> None:
    """Keep ``compare`` as a named subcommand, as in ``guardian.cli.main``."""


cli = CliRunner()


def _scan(db, scan_id, findings, sbom, minutes):
    repo_id = db.repositories.upsert(ROOT, "app")
    at = T0 + timedelta(minutes=minutes)
    db.scans.create(scan_id, repo_id, at, profile_for(ROOT))
    db.sboms.save(scan_id, sbom)
    db.findings.save(scan_id, findings, [])
    db.scans.finish(
        scan_id,
        status=ScanStatus.COMPLETED,
        finished_at=at,
        tool_runs=[],
        warnings=[],
        component_count=len(sbom.components),
        finding_count=len(findings),
    )


@pytest.fixture
def seeded(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(common.console, "width", 250)
    settings = GuardianSettings()
    settings.data_dir.mkdir(parents=True)
    with Database(settings.database_path) as db:
        _scan(
            db,
            "aaaa-before",
            [vuln("f1", "lodash"), vuln("f2", "qs", "6.0.0", Severity.CRITICAL)],
            sbom_with("pkg:npm/lodash@4.17.20", "pkg:npm/qs@6.0.0", "pkg:npm/old@1.0.0"),
            0,
        )
        _scan(
            db,
            "bbbb-after",
            [vuln("f2", "qs", "6.0.0", Severity.CRITICAL), vuln("f3", "<script>x</script>")],
            sbom_with("pkg:npm/lodash@4.17.21", "pkg:npm/qs@6.0.0", "pkg:npm/new@2.0.0"),
            5,
        )
    return settings


def test_compare_scans_model(seeded):
    with Database(seeded.database_path) as db:
        result = compare_scans(db, "aaaa-before", "bbbb-after")
    assert result.status == "mixed"
    assert [f.id for f in result.resolved] == ["f1"]
    assert [f.id for f in result.still_present] == ["f2"]
    assert [f.id for f in result.new] == ["f3"]
    assert result.sbom_diff.added == ["pkg:npm/new@2.0.0"]
    assert result.sbom_diff.removed == ["pkg:npm/old@1.0.0"]
    assert [(c.purl_base, c.from_version, c.to_version) for c in result.sbom_diff.changed] == [
        ("pkg:npm/lodash", "4.17.20", "4.17.21")
    ]
    assert result.before.findings == 2
    assert result.before.max_score is not None
    assert result.before.total_score >= result.before.max_score
    assert sum(result.after.by_priority.values()) == 2


def test_compare_cli_text_with_prefixes_and_latest(seeded):
    result = cli.invoke(app, ["compare", "aaaa", "latest"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Status: mixed" in out
    assert "1 resolved, 1 still present, 1 new" in out
    assert "SBOM changes" in out
    assert "pkg:npm/lodash" in out
    assert "4.17.21" in out
    assert "Resolved findings (1)" in out
    assert "New findings (1)" in out
    assert "<script>x</script>" in out  # printed literally, not interpreted as markup


def test_compare_cli_json(seeded):
    result = cli.invoke(app, ["compare", "aaaa", "bbbb", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    parsed = ScanComparison.model_validate(payload)
    assert parsed.status == "mixed"
    assert payload["before"]["scan"]["id"] == "aaaa-before"
    assert payload["new"][0]["severity"] == "high"


def test_compare_same_scan_is_unchanged(seeded):
    result = cli.invoke(app, ["compare", "bbbb", "bbbb"])
    assert result.exit_code == 0, result.output
    assert "Status: unchanged" in result.stdout
    assert "SBOM: no component changes." in result.stdout


def test_compare_unknown_scan_exits_2(seeded):
    result = cli.invoke(app, ["compare", "zzzz", "latest"])
    assert result.exit_code == 2
    assert "No scan matches" in result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_demo_script_syntax_and_safety():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert 'GUARDIAN_DATA_DIR="${GUARDIAN_DATA_DIR:-$HOME/.guardian-demo}"' in text
    # the script prints decide commands for a human; it never runs one itself
    assert not [line for line in text.splitlines() if line.strip().startswith("g decide")]


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_demo_script_rejects_missing_repo(tmp_path):
    result = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path / "missing")],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "GUARDIAN": "true"},
        check=False,
    )
    assert result.returncode == 1
    assert "Juice Shop not found" in result.stderr
