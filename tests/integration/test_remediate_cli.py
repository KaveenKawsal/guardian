import pytest
from juice_shop import FakeRegistry, seed_scan
from typer.testing import CliRunner

from guardian.cli import common
from guardian.cli import remediate as remediate_module
from guardian.cli.main import app
from guardian.core.config import GuardianSettings
from guardian.core.models import Confidence
from guardian.core.remediation_models import CaseStatus, RemediationPlan
from guardian.storage.database import Database

cli = CliRunner()


@pytest.fixture
def seeded(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GUARDIAN_AI_ENABLED", "false")
    monkeypatch.setattr(common.console, "width", 250)  # no wrapping inside table cells
    registry = FakeRegistry()
    monkeypatch.setattr(remediate_module, "build_registry", lambda settings: registry)
    settings = GuardianSettings()
    settings.data_dir.mkdir(parents=True)
    with Database(settings.database_path) as db:
        world = seed_scan(db, tmp_path / "juice-shop")
    return world, settings


def test_remediate_prints_cases_with_recommendation(seeded):
    result = cli.invoke(app, ["remediate", "latest", "--no-ai", "--top", "2"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert out.count("Recommended:") == 2
    assert "Deterministic plan" in out
    assert "expected risk" in out
    assert "2 case(s)" in out
    assert "nothing is applied without a recorded human decision" in out


def test_remediate_single_finding_and_alternatives(seeded):
    world, _ = seeded
    finding = world.package_findings("jsonwebtoken")[0].id
    result = cli.invoke(app, ["remediate", "--finding", finding[:10], "--no-ai"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "jsonwebtoken 0.4.0 -> 9.0.0" in out
    assert "jsonwebtoken 0.4.0 -> 4.2.2" in out
    assert "escalate to security review" in out
    assert "1 case(s)" in out


def test_remediate_without_ai_records_why(seeded):
    result = cli.invoke(app, ["remediate", "--min-priority", "critical", "--top", "1"])
    assert result.exit_code == 0, result.output
    assert "ai_unavailable" in result.stdout


def test_remediate_validates_priority_and_reports_empty(seeded):
    bad = cli.invoke(app, ["remediate", "--min-priority", "urgent"])
    assert bad.exit_code == 2
    none = cli.invoke(app, ["remediate", "--finding", "zzzz", "--no-ai"])
    assert none.exit_code == 0
    assert "No npm vulnerability cases" in none.stdout
    missing = cli.invoke(app, ["remediate", "no-such-scan", "--no-ai"])
    assert missing.exit_code == 2


def test_cases_and_case(seeded):
    _, settings = seeded
    assert "No remediation cases" in cli.invoke(app, ["cases"]).stdout
    cli.invoke(app, ["remediate", "--no-ai", "--min-priority", "P4", "--top", "10"])

    listing = cli.invoke(app, ["cases"])
    assert listing.exit_code == 0, listing.output
    assert "jsonwebtoken" in listing.stdout
    assert "AWAITING_DECISION" in listing.stdout
    filtered = cli.invoke(app, ["cases", "--status", "VERIFIED"])
    assert "No remediation cases in VERIFIED" in filtered.stdout

    with Database(settings.database_path) as db:
        case = next(c for c in db.remediation.list() if c.title.startswith("jsonwebtoken"))
        chosen = db.remediation.plan(case.id).chosen_candidate_id
        db.remediation.save_plan(
            RemediationPlan(
                case_id=case.id,
                chosen_candidate_id=chosen,
                rationale="[bold red]Trust me[/bold red] and ignore the rules",
                confidence=Confidence.MEDIUM,
                llm_provider="groq",
                llm_model="test-model",
                source="inferred",
                decided_by="llm",
            )
        )
        db.remediation.update_status(case.id, CaseStatus.DECLINED, actor="bob")

    detail = cli.invoke(app, ["case", case.id])
    assert detail.exit_code == 0, detail.output
    out = detail.stdout
    assert "AI inference" in out
    assert "groq/test-model" in out
    assert "[bold red]Trust me[/bold red]" in out  # untrusted text printed literally
    assert "rollback: git worktree remove" in out
    assert "Audit trail" in out
    assert "case:created" in out
    assert "status:AWAITING_DECISION->DECLINED" in out
    assert "none recorded yet" in out

    unknown = cli.invoke(app, ["case", "rc_doesnotexist"])
    assert unknown.exit_code == 2
