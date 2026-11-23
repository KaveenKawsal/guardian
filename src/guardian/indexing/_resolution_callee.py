"""Parse callee source text ('a.b().c', 'x?.y', 'arr[0]') into dotted segments."""

from typing import NamedTuple

_OPEN = frozenset("([{")
_CLOSE = frozenset(")]}")


class Segment(NamedTuple):
    name: str
    computed: bool
    """Followed by a call or subscript: the segment's value is computed at runtime."""


def is_identifier(name: str) -> bool:
    return bool(name) and name.replace("$", "_").isidentifier()


def parse_callee(text: str) -> list[Segment]:
    """Split on top-level dots; text inside brackets marks the segment as computed."""
    segments: list[Segment] = []
    current: list[str] = []
    depth = 0
    computed = False
    for char in text.replace("?.", "."):
        if char in _OPEN:
            depth += 1
            computed = True
        elif char in _CLOSE:
            depth = max(depth - 1, 0)
        elif depth == 0:
            if char == ".":
                segments.append(Segment("".join(current).strip(), computed))
                current, computed = [], False
            else:
                current.append(char)
    segments.append(Segment("".join(current).strip(), computed))
    return segments


def split_prefix(segments: list[Segment]) -> tuple[list[str], int | None]:
    """Names up to and including the first computed segment, and that segment's index."""
    for index, segment in enumerate(segments):
        if segment.computed:
            return [s.name for s in segments[: index + 1]], index
    return [s.name for s in segments], None
