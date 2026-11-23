from guardian.core.models import (
    CodeDetails,
    CodeIndex,
    Evidence,
    EvidenceKind,
    FileIndex,
    Finding,
    FindingKind,
    ImportStyle,
    ImportTarget,
    ResolvedCall,
    ResolvedImport,
    Severity,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
    VulnerabilityDetails,
)
from guardian.indexing.enrichment import NOT_IMPORTED, add_usage_evidence, attach_symbols

LODASH = "pkg:npm/lodash@4.17.20"
YAML = "pkg:pypi/pyyaml@5.3"


def _symbol(path, name, start, end, kind=SymbolKind.FUNCTION):
    return Symbol(
        id=f"{path}::{name}",
        name=name.rsplit(".", 1)[-1],
        qualified_name=name,
        kind=kind,
        path=path,
        span=Span(start_line=start, end_line=end),
    )


def _file(path, language=SourceLanguage.JAVASCRIPT, symbols=()):
    return FileIndex(
        path=path, language=language, sha256="0", size=1, line_count=99, symbols=list(symbols)
    )


def _code(path="app.py", line=5, kind=FindingKind.CODE):
    return Finding(
        id=f"c-{path}-{line}",
        kind=kind,
        title="t",
        severity=Severity.HIGH,
        tool="semgrep",
        path=path,
        start_line=line,
        details=CodeDetails(rule_id="r", message="m"),
    )


def _vuln(ref=LODASH, ecosystem="npm", evidence=()):
    return Finding(
        id=f"v-{ref}",
        kind=FindingKind.VULNERABILITY,
        title="CVE in x",
        severity=Severity.HIGH,
        tool="osv-scanner",
        component_ref=ref,
        details=VulnerabilityDetails(vulnerability_id="CVE-1", package="x", ecosystem=ecosystem),
        evidence=list(evidence),
    )


def _import(path, line, ref=LODASH, package="lodash"):
    return ResolvedImport(
        path=path,
        line=line,
        module=package,
        style=ImportStyle.ES,
        target=ImportTarget.EXTERNAL,
        package=package,
        component_ref=ref,
    )


def _call(path, line, member, ref=LODASH):
    return ResolvedCall(
        path=path,
        line=line,
        callee=f"_.{member}",
        package="lodash",
        member=member,
        component_ref=ref,
    )


# --- attach_symbols --------------------------------------------------------------------


def test_attach_symbols_picks_innermost_symbol():
    symbols = [
        _symbol("app.py", "Service", 1, 20, SymbolKind.CLASS),
        _symbol("app.py", "Service.login", 3, 10, SymbolKind.METHOD),
        _symbol("app.py", "Service.login.inner", 5, 6),
    ]
    index = CodeIndex(files=[_file("app.py", SourceLanguage.PYTHON, symbols)])
    found = attach_symbols([_code(line=5), _code(line=8), _code(line=15), _code(line=30)], index)
    assert [f.symbol_id for f in found] == [
        "app.py::Service.login.inner",
        "app.py::Service.login",
        "app.py::Service",
        None,
    ]


def test_attach_symbols_ignores_non_code_and_unlocated_findings():
    index = CodeIndex(files=[_file("app.py", symbols=[_symbol("app.py", "f", 1, 10)])])
    change = _code(kind=FindingKind.CHANGE)
    unlocated = _code().model_copy(update={"start_line": None})
    elsewhere = _code(path="missing.py")
    found = attach_symbols([change, unlocated, elsewhere, _vuln()], index)
    assert all(f.symbol_id is None for f in found)


# --- add_usage_evidence ----------------------------------------------------------------


def test_usage_evidence_lists_imports_and_calls():
    index = CodeIndex(
        files=[_file("a.ts", SourceLanguage.TYPESCRIPT), _file("b.js")],
        imports=[_import("b.js", 9), _import("a.ts", 3), _import("a.ts", 7)],
        calls=[
            _call("a.ts", 4, "template"),
            _call("b.js", 10, "merge"),
            _call("a.ts", 5, "template"),
        ],
    )
    advisory = Evidence(kind=EvidenceKind.ADVISORY, tool="osv-scanner", summary="adv")
    [finding] = add_usage_evidence([_vuln(evidence=[advisory])], index)
    assert finding.evidence[0] == advisory
    usage = finding.evidence[1]
    assert usage.kind is EvidenceKind.CODE_USAGE
    assert usage.tool == "indexer"
    assert usage.summary == "Imported in 2 file(s): a.ts:3, b.js:9; calls: template (2), merge (1)"
    assert (usage.path, usage.line) == ("a.ts", 3)


def test_usage_evidence_caps_locations_and_members():
    paths = [f"f{i}.js" for i in range(7)]
    members = ["a", "b", "c", "d", "e", "f"]
    index = CodeIndex(
        files=[_file(p) for p in paths],
        imports=[_import(p, 1) for p in paths],
        calls=[_call("f0.js", 2 + i, m) for i, m in enumerate(members)] + [_call("f1.js", 2, "f")],
    )
    [finding] = add_usage_evidence([_vuln()], index)
    summary = finding.evidence[-1].summary
    assert summary.startswith(
        "Imported in 7 file(s): f0.js:1, f1.js:1, f2.js:1, f3.js:1, f4.js:1 and 2 more; calls: "
    )
    assert summary.endswith("calls: f (2), a (1), b (1), c (1), d (1)")


def test_not_imported_component():
    index = CodeIndex(files=[_file("a.js")], imports=[_import("a.js", 1, ref="pkg:npm/other@1")])
    [finding] = add_usage_evidence([_vuln()], index)
    assert finding.evidence[-1].summary == NOT_IMPORTED
    assert finding.evidence[-1].path is None


def test_no_evidence_without_indexed_files_of_the_ecosystem():
    python_only = CodeIndex(files=[_file("app.py", SourceLanguage.PYTHON)])
    js_only = CodeIndex(files=[_file("app.js")])
    npm, pypi = _vuln(), _vuln(ref=YAML, ecosystem="PyPI")
    maven = _vuln(ref="pkg:maven/org.x/y@1", ecosystem="Maven")
    assert add_usage_evidence([npm, maven], python_only) == [npm, maven]
    assert add_usage_evidence([pypi], js_only) == [pypi]
    [enriched] = add_usage_evidence([pypi], python_only)
    assert enriched.evidence[-1].summary == NOT_IMPORTED


def test_ecosystem_falls_back_to_purl_of_component_ref():
    index = CodeIndex(files=[_file("app.py", SourceLanguage.PYTHON)])
    finding = _vuln(ref=YAML, ecosystem=None)
    [enriched] = add_usage_evidence([finding], index)
    assert enriched.evidence[-1].kind is EvidenceKind.CODE_USAGE


def test_usage_evidence_skips_other_findings():
    index = CodeIndex(files=[_file("a.js")], imports=[_import("a.js", 1)])
    no_ref = _vuln().model_copy(update={"component_ref": None})
    code = _code(path="a.js")
    assert add_usage_evidence([no_ref, code], index) == [no_ref, code]
