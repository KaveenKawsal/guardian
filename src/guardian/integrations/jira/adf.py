"""Atlassian Document Format (ADF) builders and a bounded plain-text extractor.

Untrusted strings (package names, advisory text, Jira comments) only ever enter a document as
the ``text`` of a text node, so Jira renders them literally: no wiki markup, no HTML, no links
are interpreted. ``adf_to_text`` reads comments written by anyone with access to the issue, so
it bounds depth, node count and output size instead of trusting the structure.
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

Node = dict[str, Any]
Inline = Node | str
Mark = Literal["code", "strong", "em"]

MAX_TEXT_NODE_CHARS = 4000
MAX_DEPTH = 40
MAX_NODES = 20_000
MAX_OUTPUT_CHARS = 100_000

_END_OF_BLOCK = object()

# C0/C1 controls except tab and newline; Jira rejects some and they have no business here.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_BLOCK_TYPES = frozenset(
    {
        "paragraph",
        "heading",
        "codeBlock",
        "blockquote",
        "listItem",
        "tableRow",
        "rule",
        "panel",
        "mediaSingle",
        "mediaGroup",
        "expand",
        "nestedExpand",
        "decisionItem",
        "taskItem",
    }
)


def clean_text(value: object, limit: int = MAX_TEXT_NODE_CHARS) -> str:
    """``str(value)`` without control characters, truncated to ``limit`` characters."""
    text = _CONTROL_RE.sub("", str(value))
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --- builders -----------------------------------------------------------------------------


def doc(*content: Node | None) -> Node:
    return {"type": "doc", "version": 1, "content": [c for c in content if c is not None]}


def text(value: object, *marks: Mark) -> Node:
    """A text node. Empty text is not valid ADF, so it becomes a single space."""
    node: Node = {"type": "text", "text": clean_text(value) or " "}
    if marks:
        node["marks"] = [{"type": m} for m in marks]
    return node


def code(value: object) -> Node:
    return text(value, "code")


def strong(value: object) -> Node:
    return text(value, "strong")


def _inline(items: Iterable[Inline]) -> list[Node]:
    nodes: list[Node] = []
    for item in items:
        if isinstance(item, str):
            # Newlines inside a paragraph become hard breaks.
            for i, line in enumerate(clean_text(item).split("\n")):
                if i:
                    nodes.append({"type": "hardBreak"})
                if line:
                    nodes.append(text(line))
        else:
            nodes.append(item)
    return nodes


def paragraph(*content: Inline) -> Node:
    return {"type": "paragraph", "content": _inline(content)}


def heading(value: object, level: int = 2) -> Node:
    return {
        "type": "heading",
        "attrs": {"level": min(max(level, 1), 6)},
        "content": [text(value)],
    }


def tag(label: str) -> Node:
    """Status-like label rendered as inline code, e.g. ``[verified]``."""
    return code(f"[{label}]")


def labelled(label: str, *value: Inline) -> Node:
    """``Label: value`` paragraph with a bold label."""
    return paragraph(strong(f"{label}: "), *value)


def bullet_list(items: Sequence[Sequence[Inline] | Inline]) -> Node | None:
    """One list item per entry; an entry is a string, a node, or a sequence of inline parts.

    Returns ``None`` for an empty list (an empty bulletList is invalid ADF); ``doc`` drops it.
    """
    if not items:
        return None
    content = []
    for item in items:
        parts = [item] if isinstance(item, (str, dict)) else list(item)
        content.append({"type": "listItem", "content": [paragraph(*parts)]})
    return {"type": "bulletList", "content": content}


def code_block(value: object, language: str | None = None) -> Node:
    node: Node = {
        "type": "codeBlock",
        "content": [{"type": "text", "text": clean_text(value, 8000) or " "}],
    }
    if language:
        node["attrs"] = {"language": language}
    return node


def table(header: Sequence[str], rows: Sequence[Sequence[Inline]]) -> Node:
    def cell(kind: str, value: Inline) -> Node:
        return {"type": kind, "content": [paragraph(value)]}

    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": [
            {"type": "tableRow", "content": [cell("tableHeader", h) for h in header]},
            *({"type": "tableRow", "content": [cell("tableCell", v) for v in row]} for row in rows),
        ],
    }


# --- extraction ---------------------------------------------------------------------------


def adf_to_text(adf: object) -> str:
    """Deterministic plain text of an ADF document (or a plain string).

    Paragraph-like blocks and ``hardBreak`` end a line, code blocks keep their content,
    mentions/emoji contribute their display text, and unknown nodes contribute their children.
    Nesting deeper than ``MAX_DEPTH``, more than ``MAX_NODES`` nodes or more than
    ``MAX_OUTPUT_CHARS`` of output are cut off silently.
    """
    if isinstance(adf, str):
        return clean_text(adf, MAX_OUTPUT_CHARS)
    out: list[str] = []
    size = 0
    visited = 0
    # Explicit stack instead of recursion: hostile nesting cannot blow the Python stack.
    stack: list[tuple[object, int]] = [(adf, 0)]
    while stack and visited < MAX_NODES and size < MAX_OUTPUT_CHARS:
        node, depth = stack.pop()
        visited += 1
        if node is _END_OF_BLOCK:
            if out and not out[-1].endswith("\n"):  # nested blocks end one line, not two
                out.append("\n")
                size += 1
            continue
        if not isinstance(node, Mapping) or depth > MAX_DEPTH:
            continue
        piece = _leaf_text(node)
        if piece:
            out.append(piece)
            size += len(piece)
        kind = node.get("type")
        if kind in _BLOCK_TYPES:
            stack.append((_END_OF_BLOCK, depth))
        content = node.get("content")
        if isinstance(content, list):
            stack.extend((child, depth + 1) for child in reversed(content[:MAX_NODES]))
    result = "".join(out)[:MAX_OUTPUT_CHARS]
    lines = [line.rstrip() for line in clean_text(result, MAX_OUTPUT_CHARS).split("\n")]
    return "\n".join(lines).strip("\n")


def _leaf_text(node: Mapping[str, object]) -> str:
    kind = node.get("type")
    if kind == "text":
        value = node.get("text")
        return value if isinstance(value, str) else ""
    if kind == "hardBreak":
        return "\n"
    attrs = node.get("attrs")
    if not isinstance(attrs, Mapping):
        return ""
    if kind in {"mention", "emoji", "status", "date"}:
        for key in ("text", "shortName", "timestamp"):
            value = attrs.get(key)
            if isinstance(value, str):
                return value
    if kind in {"inlineCard", "blockCard"}:
        value = attrs.get("url")
        return value if isinstance(value, str) else ""
    return ""
