"""Validate a model answer against the agent's input (rule 7).

Unknown evidence refs are stripped; a claim left with no valid ref is dropped. When a required
claim loses all of its refs, or a correlator names an unknown candidate, the whole answer is
rejected so the caller can ask for one repair.
"""

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

from guardian.investigation.context import AgentInput
from guardian.investigation.models import (
    ANSWER_MODELS,
    ASSESSMENT_MODELS,
    ArchitectAnswer,
    Claim,
    CodeAnswer,
    CorrelatorAnswer,
    DependencyAnswer,
    VulnerabilityAnswer,
)

MAX_TEXT = 1200


class AnswerRejectedError(ValueError):
    """The answer is malformed or rests on evidence that is not in the input."""


@dataclass(slots=True)
class Cleaned:
    assessment: dict[str, Any]
    dropped_refs: list[str] = field(default_factory=list)
    dropped_claims: int = 0


@dataclass(slots=True)
class _Stats:
    dropped_refs: list[str] = field(default_factory=list)
    dropped_claims: int = 0


def parse_answer(agent: str, raw: object) -> BaseModel:
    """Accept the parsed model, a dict, or the ``include_raw=True`` shape."""
    if isinstance(raw, dict) and "parsed" in raw and "raw" in raw:
        if raw.get("parsed") is None:
            error = raw.get("parsing_error")
            msg = f"malformed answer: {str(error)[:200] if error else 'no structured output'}"
            raise AnswerRejectedError(msg)
        raw = raw["parsed"]
    model = ANSWER_MODELS[agent]
    if isinstance(raw, BaseModel):
        raw = raw.model_dump(mode="json")
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()))
        msg = f"malformed answer: {where} {first.get('msg', exc)}".strip()
        raise AnswerRejectedError(msg) from None


def _text(value: str) -> str:
    value = " ".join(value.split())
    return value[:MAX_TEXT]


def _claim(claim: Claim | None, inp: AgentInput, stats: _Stats) -> dict[str, Any] | None:
    if claim is None or not claim.text.strip():
        return None
    kept: list[str] = []
    for ref in claim.evidence_refs:
        canonical = inp.refs.canonical(ref)
        if canonical is None:
            stats.dropped_refs.append(str(ref)[:120])
        elif canonical not in kept:
            kept.append(canonical)
    if not kept:
        stats.dropped_claims += 1
        return None
    return {"text": _text(claim.text), "evidence_refs": kept}


def _claims(claims: list[Claim], inp: AgentInput, stats: _Stats) -> list[dict[str, Any]]:
    out = [_claim(c, inp, stats) for c in claims[:8]]
    return [c for c in out if c is not None]


def _required(claim: Claim, name: str, inp: AgentInput, stats: _Stats) -> dict[str, Any]:
    cleaned = _claim(claim, inp, stats)
    if cleaned is None:
        msg = f"{name} cites no evidence ref from the input (refs given: {claim.evidence_refs[:5]})"
        raise AnswerRejectedError(msg)
    return cleaned


def clean(agent: str, raw: object, inp: AgentInput) -> Cleaned:
    answer = parse_answer(agent, raw)
    stats = _Stats()
    body: dict[str, Any]
    if isinstance(answer, ArchitectAnswer):
        areas = {r[5:] for r in inp.refs.exact if r.startswith("area:")}
        modules = []
        for m in answer.modules[:40]:
            name = m.area.strip().removeprefix("area:")
            if name not in areas:
                stats.dropped_refs.append(m.area[:120])
                stats.dropped_claims += 1
                continue
            refs = [c for c in (inp.refs.canonical(r) for r in m.evidence_refs) if c]
            modules.append(
                {
                    "area": name,
                    "purpose": _text(m.purpose),
                    "kind": m.kind,
                    "evidence_refs": list(dict.fromkeys([f"area:{name}", *refs])),
                }
            )
        if not modules:
            msg = "no module refers to a listed area"
            raise AnswerRejectedError(msg)
        body = {
            "modules": modules,
            "key_entry_points": _claims(answer.key_entry_points, inp, stats),
            "notes": _claims(answer.notes, inp, stats),
        }
    elif isinstance(answer, DependencyAnswer):
        body = {
            "how_it_enters": _required(answer.how_it_enters, "how_it_enters", inp, stats),
            "scope_assessment": answer.scope_assessment,
            "scope_reasons": _claims(answer.scope_reasons, inp, stats),
            "blast_radius": _required(answer.blast_radius, "blast_radius", inp, stats),
        }
    elif isinstance(answer, VulnerabilityAnswer):
        reasons = _claims(answer.reasons, inp, stats)
        if answer.relevance != "unknown" and not reasons:
            msg = f"relevance {answer.relevance!r} needs at least one reason with a valid ref"
            raise AnswerRejectedError(msg)
        body = {
            "relevance": answer.relevance,
            "threat_model": _required(answer.threat_model, "threat_model", inp, stats),
            "reasons": reasons,
            "prerequisites": _claims(answer.prerequisites, inp, stats),
            "open_questions": [_text(q) for q in answer.open_questions[:6] if q.strip()],
        }
    elif isinstance(answer, CodeAnswer):
        body = {
            "exploitability": answer.exploitability,
            "narrative": _required(answer.narrative, "narrative", inp, stats),
            "input_path": _claims(answer.input_path, inp, stats),
            "counter_evidence": _claims(answer.counter_evidence, inp, stats),
            "intentional_challenge_code": answer.intentional_challenge_code,
            "intentional_reason": _claim(answer.intentional_reason, inp, stats),
        }
    elif isinstance(answer, CorrelatorAnswer):
        candidate = answer.recommended_candidate_id
        if candidate is not None and candidate.strip().lower() in {"", "null", "none"}:
            candidate = None
        if candidate is not None and candidate not in inp.candidate_ids:
            valid = ", ".join(inp.candidate_ids) or "none (use null)"
            msg = f"unknown candidate id {candidate[:80]!r}; valid: {valid}"
            raise AnswerRejectedError(msg)
        body = {
            "assessment": _required(answer.assessment, "assessment", inp, stats),
            "confidence": answer.confidence.value,
            "recommendation": _text(answer.recommendation) if answer.recommendation else None,
            "recommended_candidate_id": candidate,
        }
    else:  # pragma: no cover - ANSWER_MODELS is closed
        msg = f"unknown agent {agent}"
        raise AnswerRejectedError(msg)
    assessment = ASSESSMENT_MODELS[agent].model_validate(body).model_dump(mode="json")
    return Cleaned(assessment, stats.dropped_refs[:20], stats.dropped_claims)
