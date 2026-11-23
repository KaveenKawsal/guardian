import time

import pytest

from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    CodeIndex,
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
from guardian.indexing.code_retriever import (
    MAX_LINE_CHARS,
    CodeRetriever,
    redact_secrets,
    split_lines,
)

APP = """import yaml

class Service:
    def load(self, raw):
        data = yaml.load(raw)
        return data

    def dump(self):
        return yaml.dump({})

def main():
    s = Service()
    s.load("x")
    yaml.load("y")

main()
"""
YAML = "pkg:pypi/pyyaml@6.0"


def sym(qualified, start, end, kind=SymbolKind.FUNCTION, parent=None, path="app.py"):
    return Symbol(
        id=f"{path}::{qualified}",
        name=qualified.rsplit(".", 1)[-1],
        qualified_name=qualified,
        kind=kind,
        path=path,
        span=Span(start_line=start, end_line=end),
        parent_id=f"{path}::{parent}" if parent else None,
    )


SYMBOLS = [
    sym("Service", 3, 9, SymbolKind.CLASS),
    sym("Service.load", 4, 6, SymbolKind.METHOD, "Service"),
    sym("Service.dump", 8, 9, SymbolKind.METHOD, "Service"),
    sym("main", 11, 14),
]


def call(line, member, caller):
    return ResolvedCall(
        path="app.py",
        line=line,
        callee=f"yaml.{member}",
        caller_id=f"app.py::{caller}",
        package="pyyaml",
        member=member,
        component_ref=YAML,
    )


def make_index(extra_files=()):
    files = [
        FileIndex(
            path="app.py",
            language=SourceLanguage.PYTHON,
            sha256="0" * 64,
            size=len(APP),
            line_count=16,
            symbols=SYMBOLS,
        ),
        *extra_files,
    ]
    imports = [
        ResolvedImport(
            path="app.py",
            line=1,
            module="yaml",
            style=ImportStyle.IMPORT,
            target=ImportTarget.EXTERNAL,
            package="pyyaml",
            component_ref=YAML,
        )
    ]
    calls = [
        call(5, "load", "Service.load"),
        call(9, "dump", "Service.dump"),
        call(14, "load", "main"),
    ]
    return CodeIndex(files=files, imports=imports, calls=calls)


@pytest.fixture
def retriever(make_repo):
    root = make_repo({"app.py": APP, "README.md": "# hi\n"})
    return CodeRetriever(root, make_index())


def finding(kind, details, **kwargs):
    return Finding(
        id="f1", kind=kind, title="t", severity=Severity.HIGH, tool="x", details=details, **kwargs
    )


def code_finding(line, **kwargs):
    details = CodeDetails(rule_id="r", message="m")
    return finding(FindingKind.CODE, details, path="app.py", start_line=line, **kwargs)


def vuln_finding(ref=YAML):
    details = VulnerabilityDetails(vulnerability_id="CVE-1", package="pyyaml")
    return finding(FindingKind.VULNERABILITY, details, component_ref=ref)


# --- Symbols and snippets --------------------------------------------------------------


def test_enclosing_symbol_is_innermost(retriever):
    assert retriever.enclosing_symbol("app.py", 5).id == "app.py::Service.load"
    assert retriever.enclosing_symbol("app.py", 3).id == "app.py::Service"
    assert retriever.enclosing_symbol("app.py", 7).id == "app.py::Service"
    assert retriever.enclosing_symbol("app.py", 12).id == "app.py::main"
    assert retriever.enclosing_symbol("app.py", 16) is None
    assert retriever.enclosing_symbol("other.py", 1) is None


def test_snippet_clamps_to_file(retriever):
    s = retriever.snippet("app.py", 1, 1)
    assert (s.start_line, s.end_line, s.truncated) == (1, 4, False)
    assert s.text.splitlines()[0] == "import yaml"
    s = retriever.snippet("app.py", 15, 16, context=5)
    assert (s.start_line, s.end_line) == (10, 16)
    assert s.symbol_id is None
    assert retriever.snippet("app.py", 100, 100) is None


def test_snippet_truncates_and_reports_symbol(retriever):
    s = retriever.snippet("app.py", 5, 16, context=0, max_lines=3)
    assert (s.start_line, s.end_line, s.truncated) == (5, 7, True)
    assert len(s.text.split("\n")) == 3
    assert s.symbol_id == "app.py::Service.load"
    assert retriever.snippet("app.py", 5, 5, max_lines=0) is None


def test_symbol_source(retriever):
    s = retriever.symbol_source("app.py::Service")
    assert (s.start_line, s.end_line, s.symbol_id) == (3, 9, "app.py::Service")
    assert s.text.startswith("class Service:")
    short = retriever.symbol_source("app.py::Service", max_lines=2)
    assert (short.end_line, short.truncated) == (4, True)
    assert retriever.symbol_source("app.py::nope") is None


def test_crlf_bom_and_invalid_utf8(make_repo):
    root = make_repo({})
    (root / "w.py").write_bytes(b"\xef\xbb\xbfa = 1\r\nb = '\xff'\r\nc = 3\r\n")
    assert split_lines((root / "w.py").read_bytes()) == ["a = 1", "b = '�'", "c = 3"]
    s = CodeRetriever(root, CodeIndex()).snippet("w.py", 1, 3, context=0)
    assert s.text == "a = 1\nb = '�'\nc = 3"
    assert split_lines(b"") == []
    assert split_lines(b"x\n\n") == ["x", ""]


def test_long_lines_are_cut(make_repo):
    root = make_repo({"m.js": "x" * 5000 + "\n"})
    s = CodeRetriever(root, CodeIndex()).snippet("m.js", 1, 1)
    assert s.truncated
    assert len(s.text) < MAX_LINE_CHARS + 10


def test_usages(retriever):
    imports, calls = retriever.usages(YAML)
    assert [i.line for i in imports] == [1]
    assert [c.line for c in calls] == [5, 9, 14]
    assert retriever.usages("pkg:npm/other@1") == ([], [])


# --- Unsafe reads ------------------------------------------------------------------------


def test_unreadable_paths_return_none(make_repo, tmp_path):
    root = make_repo({"app.py": APP})
    outside = tmp_path / "secret.py"
    outside.write_text("token = 'x'\n", encoding="utf-8")
    retriever = CodeRetriever(root, make_index())
    assert retriever.snippet("../secret.py", 1, 1) is None
    assert retriever.snippet(str(outside), 1, 1) is None
    assert retriever.snippet("missing.py", 1, 1) is None
    small = CodeRetriever(root, make_index(), max_file_bytes=10)
    assert small.snippet("app.py", 1, 1) is None


def test_symlink_is_refused(make_repo, tmp_path):
    root = make_repo({"app.py": APP})
    outside = tmp_path / "outside.py"
    outside.write_text("print(1)\n", encoding="utf-8")
    try:
        (root / "link.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")
    assert CodeRetriever(root, CodeIndex()).snippet("link.py", 1, 1) is None


# --- Redaction ---------------------------------------------------------------------------

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"k = '''{PEM}'''\nnext", "k = '''[REDACTED]\n\n\n'''\nnext"),
        ("id = AKIAABCDEFGHIJKLMNOP;", "id = [REDACTED];"),
        ("t = ghp_" + "a" * 36, "t = [REDACTED]"),
        ("t = gho_" + "B1" * 20 + " end", "t = [REDACTED] end"),
        ("slack xoxb-1234567890-abcdefghij", "slack [REDACTED]"),
        ("auth eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM rest", "auth [REDACTED] rest"),
        ('password = "hunter2"', 'password = "[REDACTED]"'),
        ("DB_PASSWD: 'p@ss'", "DB_PASSWD: '[REDACTED]'"),
        ('{"apiKey": "abc123"}', '{"apiKey": "[REDACTED]"}'),
        ("const client_secret = 's3cr3t';", "const client_secret = '[REDACTED]';"),
        ("PRIVATE_KEY='xyz'", "PRIVATE_KEY='[REDACTED]'"),
        ('aws_credentials => "abc"', 'aws_credentials => "[REDACTED]"'),
    ],
)
def test_redacts_secrets(text, expected):
    redacted, count = redact_secrets(text)
    assert redacted == expected
    assert count == 1


@pytest.mark.parametrize(
    "text",
    [
        "token_count = 5",
        'password = ""',
        'password = "${DB_PASS}"',
        "api_key = process.env.API_KEY",
        'description = "a normal string"',
        "AKIA123",
        "ghp_short",
        "eyJ.not.ajwt",
    ],
)
def test_keeps_non_secrets(text):
    assert redact_secrets(text) == (text, 0)


def test_unterminated_pem_is_redacted_to_the_end():
    redacted, count = redact_secrets("a\n-----BEGIN PRIVATE KEY-----\nMIIE\nAAAA")
    assert redacted == "a\n[REDACTED]\n\n"
    assert count == 1


def test_snippet_inside_a_key_is_redacted(make_repo):
    root = make_repo({"k.py": f"x = 1\n{PEM}\ny = 2\npassword = 'hunter2'\n"})
    r = CodeRetriever(root, CodeIndex())
    s = r.snippet("k.py", 3, 3, context=0)  # middle of the key, BEGIN not in the window
    assert (s.text, s.redactions) == ("[REDACTED]", 1)
    whole = r.snippet("k.py", 1, 7, context=0)
    assert "MIIE" not in whole.text
    assert whole.text.split("\n")[0] == "x = 1"
    assert whole.text.split("\n")[6] == "password = '[REDACTED]'"
    assert whole.redactions == 2


def test_redaction_is_linear_on_adversarial_input():
    nasty = [
        "token" * 40_000 + "=",
        "eyJ-" * 40_000,
        "eyJaaaaa." * 40_000,
        "-----BEGIN PRIVATE KEY-----" * 5_000,
        'password = "' + "a" * 200_000,
        "ghp_" * 50_000,
    ]
    started = time.perf_counter()
    for text in nasty:
        redact_secrets(text)
    assert time.perf_counter() - started < 5


# --- for_finding -----------------------------------------------------------------------


def total_lines(snippets):
    return sum(s.end_line - s.start_line + 1 for s in snippets)


def test_code_finding_uses_enclosing_symbol(retriever):
    [s] = retriever.for_finding(code_finding(5))
    assert (s.start_line, s.end_line, s.symbol_id) == (4, 6, "app.py::Service.load")


def test_code_finding_prefers_finding_symbol_id(retriever):
    [s] = retriever.for_finding(code_finding(5, symbol_id="app.py::Service"))
    assert (s.start_line, s.end_line) == (3, 9)


def test_code_finding_window_when_symbol_too_long(retriever):
    [s] = retriever.for_finding(code_finding(5), budget_lines=2)
    assert (s.start_line, s.end_line, s.truncated) == (1, 2, True)
    [s] = retriever.for_finding(code_finding(16))  # module level: context window
    assert (s.start_line, s.end_line) == (11, 16)


def test_code_finding_without_path(retriever):
    details = CodeDetails(rule_id="r", message="m")
    assert retriever.for_finding(finding(FindingKind.CODE, details)) == []


def test_vulnerability_distinct_members_first(retriever):
    snippets = retriever.for_finding(vuln_finding())
    starts = [(s.start_line, s.end_line) for s in snippets]
    # dump@9 first (distinct members sorted), then load@5, load@14, then the import line.
    assert starts == [(6, 12), (2, 8), (11, 16), (1, 2)]
    assert snippets[0].symbol_id == "app.py::Service.dump"


def test_vulnerability_budgets(retriever):
    assert len(retriever.for_finding(vuln_finding(), max_snippets=2)) == 2
    for budget in (1, 5, 10, 15, 200):
        snippets = retriever.for_finding(vuln_finding(), budget_lines=budget)
        assert total_lines(snippets) <= budget
    assert retriever.for_finding(vuln_finding(), budget_lines=0) == []
    assert retriever.for_finding(vuln_finding(), max_snippets=0) == []
    assert retriever.for_finding(vuln_finding("pkg:npm/unused@1")) == []
    details = VulnerabilityDetails(vulnerability_id="CVE-1", package="pyyaml")
    assert retriever.for_finding(finding(FindingKind.VULNERABILITY, details)) == []


def test_change_finding_only_indexed_sources(retriever):
    details = ChangeDetails(category=ChangeCategory.SECURITY_CODE, paths=["README.md", "app.py"])
    [s] = retriever.for_finding(finding(FindingKind.CHANGE, details))
    assert (s.path, s.start_line, s.end_line) == ("app.py", 1, 16)
    [s] = retriever.for_finding(finding(FindingKind.CHANGE, details), budget_lines=4)
    assert (s.end_line, s.truncated) == (4, True)
    other = ChangeDetails(category=ChangeCategory.MANIFEST, paths=["README.md"])
    assert retriever.for_finding(finding(FindingKind.CHANGE, other)) == []


def test_budget_across_many_snippets(make_repo):
    body = "".join(f"yaml.load({i})\n" for i in range(200))
    root = make_repo({"app.py": body})
    calls = [
        ResolvedCall(path="app.py", line=i, callee="yaml.load", member="load", component_ref=YAML)
        for i in range(1, 201, 10)
    ]
    index = CodeIndex(
        files=[
            FileIndex(
                path="app.py",
                language=SourceLanguage.PYTHON,
                sha256="0" * 64,
                size=len(body),
                line_count=200,
            )
        ],
        calls=calls,
    )
    r = CodeRetriever(root, index)
    snippets = r.for_finding(vuln_finding(), max_snippets=50, budget_lines=33)
    assert total_lines(snippets) <= 33
    assert len(snippets) == 6  # 4 lines at the top, 4 windows of 7, 1 truncated to 1
    assert total_lines(snippets) == 33
    assert snippets[-1].truncated
    assert len(r.for_finding(vuln_finding(), max_snippets=3, budget_lines=1000)) == 3
