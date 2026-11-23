import hashlib
import os
import time
from pathlib import PurePosixPath

import pytest

from guardian.core.config import GuardianSettings
from guardian.core.models import (
    CallRef,
    Ecosystem,
    EcosystemProfile,
    EntryPointKind,
    FileIndex,
    GitInfo,
    ManifestFile,
    ManifestKind,
    RepositoryProfile,
    ResolvedCall,
    ResolvedImport,
    SourceLanguage,
)
from guardian.indexing import (
    call_graph,
    import_resolver,
    repository_indexer,
    symbol_extractor,
    tree_sitter,
)
from guardian.indexing.incremental import MemoryIndexCache
from guardian.indexing.repository_indexer import (
    RepositoryIndexer,
    has_main_guard,
    looks_minified,
    read_source,
)
from guardian.storage.database import Database

EXT = {
    ".py": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.TYPESCRIPT,
}


def _fake_language_for(path):
    return EXT.get(PurePosixPath(path).suffix)


class FakeExtractor:
    def __init__(self):
        self.calls = []
        self.fail = set()

    def __call__(self, path, source, language):
        self.calls.append(path)
        if path in self.fail:
            msg = "boom"
            raise RuntimeError(msg)
        calls = []
        if b"app.listen" in source:
            calls.append(CallRef(path=path, line=1, callee="app.listen"))
        return FileIndex(
            path=path,
            language=language,
            sha256=hashlib.sha256(source).hexdigest(),
            size=len(source),
            line_count=source.count(b"\n") + 1,
            calls=calls,
        )


@pytest.fixture
def fakes(monkeypatch):
    extractor = FakeExtractor()
    seen = {}

    def resolve_imports(files, *, repo_files, sbom, declared):
        seen["repo_files"] = set(repo_files)
        seen["declared"] = declared
        return [
            ResolvedImport(path=f.path, line=1, module="m", style="import", target="unresolved")
            for f in files
        ]

    def resolve_calls(files, imports):
        return [
            ResolvedCall(path=c.path, line=c.line, callee=c.callee) for f in files for c in f.calls
        ]

    monkeypatch.setattr(tree_sitter, "language_for", _fake_language_for)
    monkeypatch.setattr(symbol_extractor, "extract_file", extractor)
    monkeypatch.setattr(import_resolver, "resolve_imports", resolve_imports)
    monkeypatch.setattr(call_graph, "resolve_calls", resolve_calls)
    return extractor, seen


def _profile(root, ecosystems=()):
    return RepositoryProfile(
        name="r",
        root=str(root),
        total_files=0,
        total_bytes=0,
        git=GitInfo(is_repository=False),
        ecosystems=list(ecosystems),
    )


def _settings(**kw):
    return GuardianSettings(_env_file=None, **kw)


def _symlink(target, link, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks cannot be created on this system")


# --- read_source --------------------------------------------------------------------------


def test_read_source_reads_regular_files(make_repo):
    root = make_repo({"a/b.py": "x = 1"})
    assert read_source(root, "a/b.py", 100) == b"x = 1"
    assert read_source(root, "missing.py", 100) is None
    assert read_source(root, "a", 100) is None  # directory


def test_read_source_rejects_oversized(make_repo):
    root = make_repo({"big.py": "x" * 101})
    assert read_source(root, "big.py", 100) is None
    assert read_source(root, "big.py", 101) == b"x" * 101


def test_read_source_rejects_escapes(make_repo, tmp_path):
    root = make_repo({"a.py": "x"})
    (tmp_path / "secret.txt").write_text("s")
    assert read_source(root, "../secret.txt", 100) is None
    assert read_source(root, "a/../../secret.txt", 100) is None
    assert read_source(root, (tmp_path / "secret.txt").as_posix(), 100) is None
    assert read_source(root, "", 100) is None


def test_read_source_rejects_symlinked_file(make_repo, tmp_path):
    root = make_repo({"a.py": "x"})
    (tmp_path / "secret.txt").write_text("s")
    _symlink(tmp_path / "secret.txt", root / "link.py")
    _symlink(root / "a.py", root / "inner.py")
    assert read_source(root, "link.py", 100) is None
    assert read_source(root, "inner.py", 100) is None  # even when pointing inside


def test_read_source_rejects_symlinked_parent(make_repo, tmp_path):
    root = make_repo({"a.py": "x"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.py").write_text("s")
    _symlink(outside, root / "linked", directory=True)
    assert read_source(root, "linked/s.py", 100) is None


def test_read_source_rejects_junction_parent(make_repo, tmp_path):
    winapi = pytest.importorskip("_winapi")  # junctions are Windows-only, need no privilege
    root = make_repo({"a.py": "x", "real/in.py": "y"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.py").write_text("s")
    winapi.CreateJunction(str(outside), str(root / "escape"))
    winapi.CreateJunction(str(root / "real"), str(root / "alias"))
    assert read_source(root, "escape/s.py", 100) is None
    assert read_source(root, "real/in.py", 100) is not None
    if hasattr(os.path, "isjunction"):  # Python 3.12+: in-repo junctions are refused too
        assert read_source(root, "alias/in.py", 100) is None


# --- helpers ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'if __name__ == "__main__":\n    main()\n',
        "x = 1\n    if __name__=='__main__' :\n",
        "if '__main__' == __name__:\n",
        'if  __name__  ==  "__main__":  # run\n',
    ],
)
def test_main_guard_variants(text):
    assert has_main_guard(text.encode())


@pytest.mark.parametrize(
    "text",
    [
        "# if __name__ == '__main__':\n",
        "if __name__ == 'main':\n",
        "print('if __name__ == \"__main__\":')\n",
        "if __name__ != '__main__':\n",
    ],
)
def test_main_guard_negatives(text):
    assert not has_main_guard(text.encode())


def test_looks_minified():
    assert looks_minified(b"a" * 5000)
    assert not looks_minified(b"var a = 1;\n" * 500)
    assert not looks_minified(b"")


# --- indexing -----------------------------------------------------------------------------


def test_index_disabled():
    index = RepositoryIndexer(_settings(index_source=False)).index(_profile("/nowhere"), None)
    assert index.files == []
    assert index.warnings


def test_indexes_sources_and_passes_all_repo_files(make_repo, fakes):
    _, seen = fakes
    guard = "if __name__ == '__main__':\n    pass\n"
    root = make_repo(
        {
            "src/b.ts": "app.listen(3000)\n",
            "a.py": guard,
            "README.md": "# hi",
            "node_modules/x/index.js": "x",
        }
    )
    npm = EcosystemProfile(
        ecosystem=Ecosystem.NODE, adapter="npm", declared_dependencies=["express"]
    )
    index = RepositoryIndexer(_settings()).index(_profile(root, [npm]), None)
    assert [f.path for f in index.files] == ["a.py", "src/b.ts"]
    assert seen["repo_files"] == {"a.py", "src/b.ts", "README.md"}
    assert seen["declared"] == {Ecosystem.NODE: {"express"}}
    assert len(index.imports) == 2
    assert [(e.path, e.kind) for e in index.entry_points] == [
        ("a.py", EntryPointKind.MAIN_GUARD),
        ("src/b.ts", EntryPointKind.SERVER_LISTEN),
    ]
    assert index.skipped_files == {}
    assert index.warnings == []
    assert index.files[0].sha256 == hashlib.sha256((root / "a.py").read_bytes()).hexdigest()


def test_skip_reasons(make_repo, fakes):
    extractor, _ = fakes
    extractor.fail = {"bad1.py", "bad2.py"}
    root = make_repo(
        {
            "big.py": "x" * 200,
            "lib.min.js": "a",
            "a-min.js": "a",
            "app.bundle.js": "a",
            "dense.js": "a" * 99,  # one 99-char line: below the size limit, not minified
            "bad1.py": "x",
            "bad2.py": "x",
            "ok1.py": "x",
            "ok2.py": "x",
            "ok3.py": "x",
        }
    )
    settings = _settings(max_source_bytes=100, max_indexed_files=3)
    index = RepositoryIndexer(settings).index(_profile(root), None)
    assert [f.path for f in index.files] == ["dense.js", "ok1.py", "ok2.py"]
    assert index.skipped_files == {"extract-error": 2, "limit": 1, "minified": 3, "too-large": 1}
    assert any("bad1.py" in w and "bad2.py" in w for w in index.warnings)
    assert any("max_indexed_files" in w for w in index.warnings)


def test_dense_content_is_minified(make_repo, fakes):
    root = make_repo({"dense.js": "a" * 1000, "ok.js": "var a;\n"})
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    assert [f.path for f in index.files] == ["ok.js"]
    assert index.skipped_files == {"minified": 1}


def test_unreadable_files_are_counted(make_repo, fakes, monkeypatch):
    root = make_repo({"a.py": "x", "b.py": "y"})
    reader = repository_indexer._SafeReader  # noqa: SLF001
    original = reader._checked_path  # noqa: SLF001

    def deny_b(self, relative):
        return None if relative == "b.py" else original(self, relative)

    monkeypatch.setattr(reader, "_checked_path", deny_b)
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    assert [f.path for f in index.files] == ["a.py"]
    assert index.skipped_files == {"unreadable": 1}


def test_symlinked_sources_are_not_indexed(make_repo, fakes, tmp_path):
    root = make_repo({"a.py": "x"})
    (tmp_path / "outside.py").write_text("secret")
    _symlink(tmp_path / "outside.py", root / "link.py")
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    assert [f.path for f in index.files] == ["a.py"]


def test_extract_error_warning_names_at_most_five(make_repo, fakes):
    extractor, _ = fakes
    names = [f"m{i}.py" for i in range(7)]
    extractor.fail = set(names)
    root = make_repo(dict.fromkeys(names, "x"))
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    (warning,) = index.warnings
    assert "m4.py" in warning
    assert "m5.py" not in warning
    assert "2 more" in warning
    assert index.skipped_files == {"extract-error": 7}


def test_cache_hits_skip_the_extractor(make_repo, fakes):
    extractor, _ = fakes
    root = make_repo({"a.py": "x", "b.js": "y"})
    indexer = RepositoryIndexer(_settings(), cache=MemoryIndexCache())
    first = indexer.index(_profile(root), None)
    assert len(extractor.calls) == 2
    second = indexer.index(_profile(root), None)
    assert len(extractor.calls) == 2
    assert first == second
    (root / "a.py").write_text("changed")
    indexer.index(_profile(root), None)
    assert extractor.calls == ["a.py", "b.js", "a.py"]


class FlushingCache(MemoryIndexCache):
    def __init__(self, fail=False):
        super().__init__()
        self.flushes = 0
        self.fail = fail

    def flush(self):
        self.flushes += 1
        if self.fail:
            msg = "disk full"
            raise OSError(msg)


def test_cache_flush_called_once_and_failure_is_a_warning(make_repo, fakes):
    root = make_repo({"a.py": "x", "b.py": "y"})
    cache = FlushingCache()
    RepositoryIndexer(_settings(), cache=cache).index(_profile(root), None)
    assert cache.flushes == 1
    failing = FlushingCache(fail=True)
    index = RepositoryIndexer(_settings(), cache=failing).index(_profile(root), None)
    assert len(index.files) == 2
    assert any("cache" in w for w in index.warnings)


def test_sqlite_cache_with_indexer(make_repo, fakes, tmp_path):
    extractor, _ = fakes
    root = make_repo({"a.py": "x"})
    with Database(tmp_path / "g.db") as db:
        RepositoryIndexer(_settings(), cache=db.code.cache()).index(_profile(root), None)
    with Database(tmp_path / "g.db") as db:
        index = RepositoryIndexer(_settings(), cache=db.code.cache()).index(_profile(root), None)
    assert extractor.calls == ["a.py"]
    assert [f.path for f in index.files] == ["a.py"]


@pytest.mark.parametrize(
    ("module", "name"),
    [(import_resolver, "resolve_imports"), (call_graph, "resolve_calls")],
)
def test_resolver_failure_gives_partial_results(make_repo, fakes, monkeypatch, module, name):
    def boom(*args, **kwargs):
        msg = "resolver bug"
        raise ValueError(msg)

    monkeypatch.setattr(module, name, boom)
    root = make_repo({"a.py": "x", "pkg/__main__.py": "y"})
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    assert [f.path for f in index.files] == ["a.py", "pkg/__main__.py"]
    assert index.imports == []
    assert index.calls == []
    assert [e.kind for e in index.entry_points] == [EntryPointKind.DUNDER_MAIN]
    assert any("resolver bug" in w for w in index.warnings)


def test_manifest_entry_points(make_repo, fakes):
    root = make_repo(
        {
            "package.json": '{"main": "server.js"}',
            "web/package.json": '{"bin": {"cli": "cli.js"}}',
            "pyproject.toml": '[project.scripts]\ntool = "pkg:main"\n',
            "other/package.json": '{"main": "ignored.js"}',  # not a profiled manifest
            "big/package.json": '{"main": "' + "x" * (1024 * 1024) + '"}',
        }
    )
    manifests = [
        ManifestFile(path=p, ecosystem=Ecosystem.NODE, kind=ManifestKind.MANIFEST)
        for p in ("web/package.json", "big/package.json", "web/package-lock.json")
    ]
    npm = EcosystemProfile(ecosystem=Ecosystem.NODE, adapter="npm", manifests=manifests)
    index = RepositoryIndexer(_settings()).index(_profile(root, [npm]), None)
    assert [(e.path, e.detail) for e in index.entry_points] == [
        ("package.json", "main -> server.js"),
        ("pyproject.toml", "script tool -> pkg:main"),
        ("web/package.json", "bin cli -> cli.js"),
    ]


def test_many_files_index_quickly(make_repo, fakes):
    root = make_repo({f"src/d{i % 20}/f{i}.ts": "export const x = 1;\n" for i in range(1000)})
    start = time.perf_counter()
    index = RepositoryIndexer(_settings()).index(_profile(root), None)
    assert len(index.files) == 1000
    assert time.perf_counter() - start < 30


# --- integration with the real extractor and resolvers -------------------------------------


def _real_pipeline_available():
    try:
        tree_sitter.language_for("a.py")
        symbol_extractor.extract_file("a.py", b"x = 1\n", SourceLanguage.PYTHON)
        files = import_resolver.resolve_imports([], repo_files=[], sbom=None, declared={})
        call_graph.resolve_calls([], files)
    except NotImplementedError:
        return False
    return True


@pytest.mark.skipif(
    not _real_pipeline_available(), reason="extractor/resolvers not implemented yet"
)
def test_real_pipeline_on_python_and_typescript(make_repo):
    root = make_repo(
        {
            "app/__init__.py": "",
            "app/util.py": "def helper(x):\n    return x\n",
            "app/main.py": (
                "from app.util import helper\n\n\n"
                "def run():\n    return helper(1)\n\n\n"
                "if __name__ == '__main__':\n    run()\n"
            ),
            "web/server.ts": (
                "import express from 'express';\n"
                "import { check } from './auth';\n"
                "const app = express();\n"
                "app.post('/api/login', (req, res) => res.send(check(req.body)));\n"
                "app.listen(3000);\n"
            ),
            "web/auth.ts": "export function check(x: string): boolean {\n  return !!x;\n}\n",
            "web/types.d.ts": "export type T = string;\n",
        }
    )
    index = RepositoryIndexer(_settings(), cache=MemoryIndexCache()).index(_profile(root), None)
    paths = [f.path for f in index.files]
    assert paths == sorted(paths)
    assert {"app/main.py", "app/util.py", "web/server.ts", "web/auth.ts"} <= set(paths)
    assert "web/types.d.ts" not in paths
    assert any(i.path == "app/main.py" and i.target_path == "app/util.py" for i in index.imports)
    assert any(i.path == "web/server.ts" and i.target_path == "web/auth.ts" for i in index.imports)
    kinds = {(e.path, e.kind) for e in index.entry_points}
    assert ("app/main.py", EntryPointKind.MAIN_GUARD) in kinds
    assert ("web/server.ts", EntryPointKind.SERVER_LISTEN) in kinds
    assert any(
        e.kind is EntryPointKind.HTTP_ROUTE and e.detail == "POST /api/login"
        for e in index.entry_points
    )
