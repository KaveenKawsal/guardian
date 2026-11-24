"""Fake chat models for the investigator tests: no network, deterministic answers."""

import re
import threading
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage

from guardian.investigation.models import (
    ArchitectAnswer,
    CodeAnswer,
    CorrelatorAnswer,
    DependencyAnswer,
    VulnerabilityAnswer,
)
from guardian.investigation.runner import ModelRoute

_REFS = re.compile(r"Valid evidence refs include: (.*?)(?: and file:line| *\.?\n|\.$)", re.DOTALL)
_AREAS = re.compile(r'"ref": "area:([^"]+)"')
_CANDIDATES = re.compile(r"Valid candidate ids: (.*?)\.\n")


def refs_in(text: str) -> list[str]:
    match = _REFS.search(text)
    if not match or match.group(1).startswith("(none)"):
        return []
    return [r.strip() for r in match.group(1).split(",") if r.strip()]


def good_answer(schema: type, text: str) -> Any:
    """A valid answer citing the first listed ref."""
    refs = [r for r in refs_in(text) if not r.startswith("area:")] or refs_in(text)
    ref = refs[:1]
    claim = {"text": "Grounded claim.", "evidence_refs": ref}
    if schema is ArchitectAnswer:
        areas = _AREAS.findall(text)
        return ArchitectAnswer.model_validate(
            {
                "modules": [
                    {"area": a, "purpose": f"Purpose of {a}", "kind": "prod", "evidence_refs": []}
                    for a in areas
                ],
                "key_entry_points": [claim] if ref else [],
                "notes": [],
            }
        )
    if schema is DependencyAnswer:
        return DependencyAnswer.model_validate(
            {
                "how_it_enters": claim,
                "scope_assessment": "prod",
                "scope_reasons": [claim],
                "blast_radius": claim,
            }
        )
    if schema is VulnerabilityAnswer:
        return VulnerabilityAnswer.model_validate(
            {
                "relevance": "possible",
                "threat_model": claim,
                "reasons": [claim],
                "prerequisites": [claim],
                "open_questions": ["Is the route exposed?"],
            }
        )
    if schema is CodeAnswer:
        return CodeAnswer.model_validate(
            {
                "exploitability": "likely",
                "narrative": claim,
                "input_path": [claim],
                "counter_evidence": [],
                "intentional_challenge_code": False,
            }
        )
    if schema is CorrelatorAnswer:
        return CorrelatorAnswer.model_validate(
            {"assessment": claim, "confidence": "medium", "recommendation": "Review it."}
        )
    raise AssertionError(schema)


Responder = Callable[[type, str, int], Any]


class FakeChat:
    """Stands in for ``BaseChatModel``; ``with_structured_output`` binds the schema."""

    def __init__(self, responder: Responder | None = None) -> None:
        self.responder = responder or (lambda schema, text, n: good_answer(schema, text))
        self.prompts: list[tuple[type, list[Any]]] = []
        self.lock = threading.Lock()

    def with_structured_output(self, schema: type, **kwargs: Any) -> "_Bound":
        return _Bound(self, schema, include_raw=bool(kwargs.get("include_raw")))


class _Bound:
    def __init__(self, chat: FakeChat, schema: type, *, include_raw: bool) -> None:
        self.chat, self.schema, self.include_raw = chat, schema, include_raw

    def invoke(self, messages: list[Any]) -> Any:
        with self.chat.lock:
            self.chat.prompts.append((self.schema, list(messages)))
            n = sum(1 for s, _ in self.chat.prompts if s is self.schema)
        text = "\n".join(str(m.content) for m in messages)
        result = self.chat.responder(self.schema, text, n)
        if isinstance(result, Exception):
            raise result
        if self.include_raw:
            raw = AIMessage(
                "{}", usage_metadata={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}
            )
            return {"raw": raw, "parsed": result, "parsing_error": None}
        return result


def routes(chat: FakeChat | None = None, deep: FakeChat | None = None) -> dict:
    fast = chat or FakeChat()
    return {
        "fast": [ModelRoute("groq", "fake-fast", fast)],
        "deep": [ModelRoute("google", "fake-deep", deep or fast)],
    }
