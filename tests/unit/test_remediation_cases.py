import pytest
from juice_shop import FakeRegistry, seed_scan

from guardian.core.config import GuardianSettings
from guardian.core.models import Priority
from guardian.core.remediation_models import CaseStatus, case_id_for
from guardian.remediation.cases import case_fingerprint, create_cases, select_groups
from guardian.storage.database import Database


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "guardian.db") as database:
        yield database


@pytest.fixture
def settings(tmp_path):
    return GuardianSettings(_env_file=None, data_dir=tmp_path / "home", ai_enabled=False)


@pytest.fixture
def world(db, tmp_path):
    return seed_scan(db, tmp_path / "juice-shop")


def run(db, settings, **kwargs):
    kwargs.setdefault("registry", FakeRegistry())
    kwargs.setdefault("no_ai", True)
    return create_cases(db, "scan-juice-1", settings=settings, **kwargs)


def names(cases):
    return [c.title.split(" ", 1)[0] for c in cases]


def test_creates_one_case_per_package_sorted_and_capped(db, settings, world):
    cases = run(db, settings, top=3)
    assert len(cases) == 3
    assert all(c.status is CaseStatus.AWAITING_DECISION for c in cases)
    keys = [(c.priority.value, -_max_score(world, c)) for c in cases]
    assert keys == sorted(keys)
    jwt = next(c for c in run(db, settings, top=10) if c.title.startswith("jsonwebtoken"))
    assert jwt.title == (
        "jsonwebtoken 0.4.0: 3 known vulnerabilities (CVE-2015-9235, CVE-2022-23539, "
        "CVE-2022-23540)"
    )
    assert jwt.id == case_id_for(case_fingerprint(str(world.root), "jsonwebtoken"))
    assert sorted(jwt.finding_ids) == sorted(f.id for f in world.package_findings("jsonwebtoken"))
    assert jwt.priority is Priority.P1


def _max_score(world, case):
    return max(world.assessments[i].score for i in case.finding_ids)


def test_min_priority_filters(db, settings, world):
    p1_only = run(db, settings, top=10, min_priority=Priority.P1)
    assert p1_only
    assert all(c.priority is Priority.P1 for c in p1_only)
    everything = run(db, settings, top=10, min_priority=Priority.P4)
    assert len(everything) == 7  # one per vulnerable npm package
    assert len(p1_only) < len(everything)


def test_finding_ids_select_cases_and_ignore_filters(db, settings, world):
    qs_finding = world.package_findings("qs")[0].id
    cases = run(db, settings, finding_ids=[qs_finding[:10]], min_priority=Priority.P1, top=1)
    assert names(cases) == ["qs"]
    assert run(db, settings, finding_ids=["nothing-matches"]) == []


def test_stores_candidates_plan_and_audit(db, settings, world):
    (case,) = run(db, settings, finding_ids=[world.package_findings("jsonwebtoken")[0].id])
    store = db.remediation
    candidates = store.candidates(case.id)
    plan = store.plan(case.id)
    assert plan is not None
    assert plan.chosen_candidate_id in {c.id for c in candidates}
    assert plan.decided_by == "deterministic"
    worktree_root = settings.data_dir / "worktrees"
    assert all(f"{worktree_root}/{case.id}" in c.rollback for c in candidates[:-2])
    events = [e.event for e in db.audit.list(case.id)]
    assert events == [
        "case:created",
        "candidates:generated",
        "plan:created",
        "status:PROPOSED->AWAITING_DECISION",
    ]
    assert db.audit.verify() == (True, [])


def test_idempotent_refresh_and_untouched_after_decision(db, settings, world):
    first = run(db, settings, top=10, min_priority=Priority.P4)
    second = run(db, settings, top=10, min_priority=Priority.P4)
    assert [c.id for c in first] == [c.id for c in second]
    assert len(db.remediation.list()) == 7
    target = first[0]
    events = [e.event for e in db.audit.list(target.id)]
    assert events.count("case:created") == 1
    assert events.count("case:refreshed") == 1
    assert events.count("plan:created") == 2
    assert events[-1] == "plan:created"  # refresh does not move the state again

    db.remediation.update_status(target.id, CaseStatus.APPROVED, actor="alice")
    before = len(db.audit.list(target.id))
    third = run(db, settings, top=10, min_priority=Priority.P4)
    kept = next(c for c in third if c.id == target.id)
    assert kept.status is CaseStatus.APPROVED
    assert len(db.audit.list(target.id)) == before
    assert db.audit.verify() == (True, [])


def test_ai_unavailable_is_recorded(db, settings, world):
    (case,) = run(db, settings, no_ai=False, finding_ids=[world.package_findings("marsdb")[0].id])
    plan = db.remediation.plan(case.id)
    assert plan.notes == ["ai_unavailable: no LLM provider configured"]


def test_registry_none_still_produces_cases(db, settings, world):
    (case,) = run(db, settings, registry=None, finding_ids=[world.package_findings("moment")[0].id])
    upgrades = [c for c in db.remediation.candidates(case.id) if c.to_version]
    assert upgrades
    assert all(c.version_verified is False for c in upgrades)


def test_select_groups_handles_zero_top():
    assert select_groups([], min_priority=Priority.P2, top=0, finding_ids=None) == []
