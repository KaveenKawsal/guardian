import pytest

from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    CodeIndex,
    Component,
    Confidence,
    DependencyEdge,
    DependencyScope,
    EntryPoint,
    EntryPointKind,
    FileIndex,
    Finding,
    FindingKind,
    GitInfo,
    ImportStyle,
    ImportTarget,
    Priority,
    RepositoryProfile,
    ResolvedCall,
    ResolvedImport,
    RiskFactorName,
    Sbom,
    Severity,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
    VulnerabilityDetails,
)
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import _priority, assess, language_families, package_family

PROFILE = RepositoryProfile(
    name="app", root="/nowhere/app", total_files=1, total_bytes=1, git=GitInfo(is_repository=False)
)


def _component(name, scope=DependencyScope.REQUIRED, purl_type="npm"):
    return Component(
        ref=f"pkg:{purl_type}/{name}@1.0.0",
        name=name,
        version="1.0.0",
        purl_type=purl_type,
        scope=scope,
    )


EXPRESS = _component("express")
QS = _component("qs")
DEEP = _component("deep")
DEV = _component("jest", scope=DependencyScope.OPTIONAL)
UNUSED = _component("unused")
PYLIB = _component("pyyaml", purl_type="pypi")
SBOM = Sbom(
    spec_version="1.5",
    generator="test",
    root_ref="root",
    components=[EXPRESS, QS, DEEP, DEV, UNUSED, PYLIB],
    edges=[
        DependencyEdge(source="root", target=EXPRESS.ref),
        DependencyEdge(source="root", target=DEV.ref),
        DependencyEdge(source="root", target=UNUSED.ref),
        DependencyEdge(source="root", target=PYLIB.ref),
        DependencyEdge(source=EXPRESS.ref, target=QS.ref),
        DependencyEdge(source=QS.ref, target=DEEP.ref),
    ],
)

HANDLER = Symbol(
    id="src/handler.ts::handle",
    name="handle",
    qualified_name="handle",
    kind=SymbolKind.FUNCTION,
    path="src/handler.ts",
    span=Span(start_line=1, end_line=10),
)
LONELY = Symbol(
    id="src/util.ts::lonely",
    name="lonely",
    qualified_name="lonely",
    kind=SymbolKind.FUNCTION,
    path="src/util.ts",
    span=Span(start_line=1, end_line=5),
)


def _file(path, symbols=()):
    return FileIndex(
        path=path,
        language=SourceLanguage.TYPESCRIPT,
        sha256="0" * 64,
        size=10,
        line_count=20,
        symbols=list(symbols),
    )


INDEX = CodeIndex(
    files=[
        _file("routes/x.ts"),
        _file("src/handler.ts", [HANDLER]),
        _file("src/util.ts", [LONELY]),
        _file("src/plain.ts"),
        _file("test/app.test.ts"),
    ],
    imports=[
        ResolvedImport(
            path="routes/x.ts",
            line=1,
            module="express",
            style=ImportStyle.ES,
            target=ImportTarget.EXTERNAL,
            package="express",
            component_ref=EXPRESS.ref,
        ),
        ResolvedImport(
            path="src/plain.ts",
            line=1,
            module="qs",
            style=ImportStyle.ES,
            target=ImportTarget.EXTERNAL,
            package="qs",
            component_ref=QS.ref,
        ),
        ResolvedImport(
            path="src/plain.ts",
            line=2,
            module="deep",
            style=ImportStyle.ES,
            target=ImportTarget.EXTERNAL,
            package="deep",
            component_ref=DEEP.ref,
        ),
    ],
    calls=[
        ResolvedCall(
            path="routes/x.ts",
            line=3,
            callee="express.Router",
            package="express",
            member="Router",
            component_ref=EXPRESS.ref,
        ),
        ResolvedCall(path="routes/x.ts", line=4, callee="handle", target_symbol_id=HANDLER.id),
    ],
    entry_points=[
        EntryPoint(path="routes/x.ts", line=5, kind=EntryPointKind.HTTP_ROUTE, detail="GET /x")
    ],
)


def _vuln(component, severity=Severity.HIGH, cvss=None, fix="9.9.9", fixed=("9.9.9",), **kw):
    return Finding(
        id=f"v-{component.name}-{severity}",
        kind=FindingKind.VULNERABILITY,
        title=f"vuln in {component.name}",
        severity=severity,
        tool="osv-scanner",
        component_ref=component.ref,
        details=VulnerabilityDetails(
            vulnerability_id="GHSA-1",
            package=component.name,
            version="1.0.0",
            ecosystem=kw.get("ecosystem", "npm"),
            cvss_score=cvss,
            recommended_fix=fix,
            fixed_versions=list(fixed),
        ),
    )


def _code(path, severity=Severity.HIGH, likelihood=None, symbol_id=None):
    return Finding(
        id=f"c-{path}-{symbol_id}-{likelihood}",
        kind=FindingKind.CODE,
        title=f"rule in {path}",
        severity=severity,
        tool="semgrep",
        path=path,
        start_line=2,
        symbol_id=symbol_id,
        details=CodeDetails(rule_id="js.lang.security.eval", message="m", likelihood=likelihood),
    )


def _change(category, title="change", severity=Severity.MEDIUM, commit="a" * 40):
    return Finding(
        id=f"g-{category}-{title}",
        kind=FindingKind.CHANGE,
        title=title,
        severity=severity,
        tool="git",
        details=ChangeDetails(category=category, commit=commit, paths=["f"]),
    )


def _assess(findings, *, sbom=SBOM, index=INDEX):
    graph = DependencyGraph(build_knowledge_graph(PROFILE, sbom, findings, (), code_index=index))
    return assess(findings, graph, index)


def _factors(risk):
    return {f.name: f.value for f in risk.factors}


def test_critical_called_direct_dependency_is_p1():
    (risk,) = _assess([_vuln(EXPRESS, Severity.CRITICAL, cvss=9.8)])
    values = _factors(risk)
    assert values[RiskFactorName.SEVERITY] == pytest.approx(0.98)
    assert values[RiskFactorName.EXPOSURE] == 0.8
    assert values[RiskFactorName.EXPLOITABILITY] is None
    assert values[RiskFactorName.REACHABILITY] == 1.0
    assert values[RiskFactorName.FIX] == 1.0
    assert risk.known_weight == pytest.approx(0.8)
    assert risk.confidence is Confidence.HIGH
    assert risk.priority is Priority.P1
    expected = 100 * (0.35 * 0.98 + 0.25 * 0.8 + 0.1 + 0.1) / 0.8
    assert risk.score == pytest.approx(expected, abs=0.05)
    assert "direct dependency express that the code calls" in risk.summary
    rationale = {f.name: f.rationale for f in risk.factors}
    assert rationale[RiskFactorName.REACHABILITY] == "express.Router called in routes/x.ts"
    assert "requires AI investigation" in rationale[RiskFactorName.EXPLOITABILITY]


def test_vulnerability_exposure_and_reachability_levels():
    risks = _assess(
        [
            _vuln(QS, fix=None),
            _vuln(DEEP, fix=None, fixed=()),
            _vuln(DEV),
            _vuln(UNUSED),
        ]
    )
    qs, deep, dev, unused = (_factors(r) for r in risks)
    assert qs[RiskFactorName.EXPOSURE] == 0.6
    assert qs[RiskFactorName.REACHABILITY] == 0.7  # imported, not called
    assert qs[RiskFactorName.FIX] == 0.6
    assert deep[RiskFactorName.EXPOSURE] == 0.4
    assert deep[RiskFactorName.FIX] == 0.2
    assert dev[RiskFactorName.EXPOSURE] == 0.4  # direct x0.5 for optional scope
    assert unused[RiskFactorName.REACHABILITY] == 0.2
    assert "never imports" in risks[3].summary
    assert "optional direct dependency" in risks[2].summary


def test_reachability_unknown_without_language_coverage_or_index():
    (py,) = _assess([_vuln(PYLIB, ecosystem="PyPI")])
    assert _factors(py)[RiskFactorName.REACHABILITY] is None
    (no_index,) = _assess([_vuln(EXPRESS)], index=None)
    assert _factors(no_index)[RiskFactorName.REACHABILITY] is None


def test_unlinked_vulnerability_and_unknown_severity():
    finding = _vuln(_component("ghost"), Severity.UNKNOWN, fix=None, fixed=())
    (risk,) = _assess([finding], sbom=None)
    values = _factors(risk)
    assert values[RiskFactorName.SEVERITY] is None
    assert values[RiskFactorName.EXPOSURE] is None
    assert risk.known_weight == pytest.approx(0.1)
    assert risk.confidence is Confidence.LOW
    assert risk.score == pytest.approx(20.0)
    assert risk.priority is Priority.P4


def test_code_findings():
    risks = _assess(
        [
            _code("routes/x.ts", likelihood="HIGH"),
            _code("src/handler.ts", likelihood="LOW", symbol_id=HANDLER.id),
            _code("src/util.ts", symbol_id=LONELY.id),
            _code("test/app.test.ts", likelihood="medium"),
            _code("Main.java"),
        ]
    )
    route, handler, util, test, java = (_factors(r) for r in risks)
    assert (route[RiskFactorName.EXPOSURE], route[RiskFactorName.REACHABILITY]) == (1.0, 0.9)
    assert route[RiskFactorName.EXPLOITABILITY] == 0.8
    assert handler[RiskFactorName.EXPOSURE] == 0.6
    assert handler[RiskFactorName.REACHABILITY] == 0.9  # called from the route
    assert handler[RiskFactorName.EXPLOITABILITY] == 0.2
    assert util[RiskFactorName.REACHABILITY] == 0.5
    assert util[RiskFactorName.EXPLOITABILITY] is None
    assert test[RiskFactorName.EXPOSURE] == test[RiskFactorName.REACHABILITY] == 0.1
    assert test[RiskFactorName.EXPLOITABILITY] == 0.5
    assert java[RiskFactorName.REACHABILITY] is None  # not indexed
    assert all(r[RiskFactorName.FIX] == 0.8 for r in (route, handler, util, test, java))
    assert risks[0].confidence is Confidence.HIGH
    assert risks[0].priority is Priority.P1
    assert risks[3].priority is Priority.P3
    assert "(eval) in a file with an entry point" in risks[0].summary


def test_code_reachability_unknown_without_index():
    (risk,) = _assess([_code("src/plain.ts")], index=None)
    assert _factors(risk)[RiskFactorName.REACHABILITY] is None
    assert _factors(risk)[RiskFactorName.EXPOSURE] == 0.6


def test_change_findings():
    risks = _assess(
        [
            _change(ChangeCategory.SENSITIVE_FILE, "Sensitive file .env (still present)"),
            _change(ChangeCategory.SENSITIVE_FILE, "Sensitive file .env (since removed)"),
            _change(ChangeCategory.CI_CONFIG),
            _change(ChangeCategory.LOCKFILE_ONLY),
            _change(ChangeCategory.MANIFEST, commit=None),
        ]
    )
    exposures = [_factors(r)[RiskFactorName.EXPOSURE] for r in risks]
    assert exposures == [1.0, 0.7, 0.6, 0.5, 0.2]
    assert all(_factors(r)[RiskFactorName.REACHABILITY] is None for r in risks)
    assert risks[0].confidence is Confidence.MEDIUM  # 0.35 + 0.25 + 0.1
    assert "(uncommitted)" in risks[4].summary


def test_priority_overrides():
    info, critical_imported, critical_unused = _assess(
        [
            _vuln(EXPRESS, Severity.INFO, cvss=None),
            _vuln(DEEP, Severity.CRITICAL, fix=None, fixed=()),
            _vuln(DEV, Severity.CRITICAL, fix=None, fixed=()),
        ]
    )
    assert info.priority is Priority.P4
    assert critical_imported.score < 70
    assert critical_imported.priority is Priority.P1  # P >= 0.7 overrides the score
    assert critical_unused.priority is Priority.P2


def test_score_none_is_p3():
    assert _priority(None, Severity.HIGH, None) is Priority.P3
    assert _priority(None, Severity.INFO, None) is Priority.P4


def test_priority_from_score_bands():
    risks = _assess(
        [
            _change(ChangeCategory.SENSITIVE_FILE, "x (still present)", Severity.HIGH),
            _change(ChangeCategory.CI_CONFIG, severity=Severity.MEDIUM),
            _change(ChangeCategory.MANIFEST, severity=Severity.LOW),
        ]
    )
    assert [r.priority for r in risks] == [Priority.P1, Priority.P2, Priority.P3]


def test_helpers():
    assert language_families(None) == frozenset()
    assert language_families(INDEX) == {"npm"}
    assert package_family(None, "PyPI") == "pypi"
    assert package_family(EXPRESS, None) == "npm"
    assert package_family(None, None) is None


def test_low_evidence_cannot_be_p1():
    assert _priority(90.0, Severity.HIGH, None, known_weight=0.45) is Priority.P2
    assert _priority(90.0, Severity.HIGH, None, known_weight=0.8) is Priority.P1
