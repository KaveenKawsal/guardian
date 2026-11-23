import pytest

from guardian.core.models import SourceLanguage
from guardian.indexing.tree_sitter import EXTRACTOR_VERSION, get_parser, language_for


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("app/main.py", SourceLanguage.PYTHON),
        ("stubs/x.pyi", SourceLanguage.PYTHON),
        ("a.js", SourceLanguage.JAVASCRIPT),
        ("a.mjs", SourceLanguage.JAVASCRIPT),
        ("a.cjs", SourceLanguage.JAVASCRIPT),
        ("a.jsx", SourceLanguage.JAVASCRIPT),
        ("src/a.ts", SourceLanguage.TYPESCRIPT),
        ("a.mts", SourceLanguage.TYPESCRIPT),
        ("a.cts", SourceLanguage.TYPESCRIPT),
        ("ui/App.tsx", SourceLanguage.TSX),
        ("UPPER.PY", SourceLanguage.PYTHON),
        ("Comp.TSX", SourceLanguage.TSX),
        ("types/index.d.ts", None),
        ("x.D.TS", None),
        ("x.d.mts", None),
        ("x.d.cts", None),
        ("README.md", None),
        ("Makefile", None),
        ("archive.py.bak", None),
        (".py", None),
        ("win\\path\\x.py", SourceLanguage.PYTHON),
    ],
)
def test_language_for(path, expected):
    assert language_for(path) is expected


@pytest.mark.parametrize("language", list(SourceLanguage))
def test_get_parser_parses_each_language(language):
    parser = get_parser(language)
    tree = parser.parse(b"x = 1\n")
    assert tree.root_node is not None
    # Fresh parser each call, sharing the cached Language.
    other = get_parser(language)
    assert other is not parser
    assert other.language is parser.language


def test_tsx_parser_accepts_jsx():
    tree = get_parser(SourceLanguage.TSX).parse(b"const a = <div>{x}</div>;\n")
    assert not tree.root_node.has_error


def test_extractor_version_is_string():
    assert isinstance(EXTRACTOR_VERSION, str)
    assert EXTRACTOR_VERSION
