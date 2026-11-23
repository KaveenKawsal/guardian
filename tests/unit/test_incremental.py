from guardian.core.models import FileIndex, SourceLanguage
from guardian.indexing import tree_sitter
from guardian.indexing.incremental import IndexCache, MemoryIndexCache


def _fi(path="a.py", sha="s1", language=SourceLanguage.PYTHON):
    return FileIndex(path=path, language=language, sha256=sha, size=1, line_count=1)


def test_memory_cache_round_trip():
    cache: IndexCache = MemoryIndexCache()
    assert cache.get("a.py", "s1", SourceLanguage.PYTHON) is None
    cache.put(_fi())
    assert cache.get("a.py", "s1", SourceLanguage.PYTHON) == _fi()


def test_memory_cache_key_includes_hash_language_and_path():
    cache = MemoryIndexCache()
    cache.put(_fi())
    assert cache.get("a.py", "s2", SourceLanguage.PYTHON) is None
    assert cache.get("a.py", "s1", SourceLanguage.JAVASCRIPT) is None
    assert cache.get("b.py", "s1", SourceLanguage.PYTHON) is None


def test_memory_cache_invalidated_by_extractor_version(monkeypatch):
    cache = MemoryIndexCache()
    cache.put(_fi())
    monkeypatch.setattr(tree_sitter, "EXTRACTOR_VERSION", "999")
    assert cache.get("a.py", "s1", SourceLanguage.PYTHON) is None
