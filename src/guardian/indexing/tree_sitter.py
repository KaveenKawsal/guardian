"""Tree-sitter parser access.

Uses py-tree-sitter >= 0.25 (installed 0.27) with the per-language wheels:
``Language(tree_sitter_python.language())``, ``tree_sitter_javascript.language()``,
``tree_sitter_typescript.language_typescript()`` / ``language_tsx()``. Queries use
``tree_sitter.Query(language, src)`` + ``tree_sitter.QueryCursor(query).captures(node)``,
which returns ``dict[capture_name, list[Node]]``.
"""

from functools import cache

import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Parser

from guardian.core.models import SourceLanguage

EXTRACTOR_VERSION = "1"
"""Bump when extraction output changes, so cached FileIndex entries are invalidated."""

_EXTENSIONS: dict[str, SourceLanguage] = {
    ".py": SourceLanguage.PYTHON,
    ".pyi": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".mjs": SourceLanguage.JAVASCRIPT,
    ".cjs": SourceLanguage.JAVASCRIPT,
    ".jsx": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.TYPESCRIPT,
    ".mts": SourceLanguage.TYPESCRIPT,
    ".cts": SourceLanguage.TYPESCRIPT,
    ".tsx": SourceLanguage.TSX,
}
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")


def language_for(path: str) -> SourceLanguage | None:
    """Language by file extension (.py/.pyi, .js/.mjs/.cjs/.jsx, .ts/.mts/.cts, .tsx); else None.

    ``.d.ts`` declaration files return None (no executable code).
    """
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(_DECLARATION_SUFFIXES):
        return None
    dot = name.rfind(".")
    if dot <= 0:  # no extension, or a dotfile such as ".py"
        return None
    return _EXTENSIONS.get(name[dot:])


@cache
def _language(language: SourceLanguage) -> Language:
    if language is SourceLanguage.PYTHON:
        return Language(tree_sitter_python.language())
    if language is SourceLanguage.JAVASCRIPT:
        return Language(tree_sitter_javascript.language())
    if language is SourceLanguage.TYPESCRIPT:
        return Language(tree_sitter_typescript.language_typescript())
    return Language(tree_sitter_typescript.language_tsx())


def get_parser(language: SourceLanguage) -> Parser:
    """A Parser for ``language``. Languages are loaded once and cached; parsers are cheap."""
    return Parser(_language(language))
