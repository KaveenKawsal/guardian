"""Run one investigator: route to a provider, call with structured output, validate, repair once,
or fall back to a deterministic ``ai_unavailable`` report.

Thread-safe: the graph calls :meth:`AgentRunner.run` from parallel branches. The budget is
reserved up front in priority order (:meth:`Budget.reserve`), so which items get AI output does
not depend on thread scheduling; repair attempts use what is left. Rate-limit handling (pacing,
key rotation, provider fallback, one cool-down wait) lives in :mod:`guardian.llm.resilient` and
is part of one logical call: it never consumes another budget slot.
"""

import json
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel

from guardian.core.config import GuardianSettings
from guardian.investigation.context import AgentInput
from guardian.investigation.models import (
    AGENT_ROLES,
    ANSWER_MODELS,
    CallRecord,
    InvestigatorReport,
    Role,
)
from guardian.investigation.prompts import build_messages
from guardian.investigation.validate import AnswerRejectedError, clean
from guardian.llm.keys import load_key_settings
from guardian.llm.providers import ProviderConfig, build_chat_model
from guardian.llm.resilient import (
    Attempt,
    LLMUnavailableError,
    ProviderPool,
    Sleep,
    build_pool,
    invoke_structured,
    provider_chain,
)

DEFAULT_MAX_CALLS = 40
DEFAULT_MAX_INPUT_CHARS = 600_000

__all__ = [
    "DEFAULT_MAX_CALLS",
    "AgentRunner",
    "Budget",
    "ModelRoute",
    "Routes",
    "Sleep",
    "build_routes",
    "role_providers",
]


@dataclass(frozen=True, slots=True)
class ModelRoute:
    provider: str
    model: str
    chat: BaseChatModel
    method: str | None = None
    """``with_structured_output`` method; Groq uses ``json_schema`` because with function
    calling gpt-oss sometimes calls tools that do not exist."""
    pool: ProviderPool | None = None
    """Keys, pacing and cool-downs; a one-key pool around ``chat`` when not given."""

    def __post_init__(self) -> None:
        if self.pool is None:
            pool = ProviderPool.single(self.provider, self.model, self.chat, self.method)
            object.__setattr__(self, "pool", pool)

    @property
    def key_pool(self) -> ProviderPool:
        if self.pool is None:  # pragma: no cover - set in __post_init__
            msg = "route without a key pool"
            raise RuntimeError(msg)
        return self.pool


Routes = dict[Role, list[ModelRoute]]


def role_providers(settings: GuardianSettings) -> dict[Role, list[ProviderConfig]]:
    """``fast`` = the active provider (Groq in practice), ``deep`` = Google when it has a key;
    each role falls back to the other provider. Model names come from settings."""
    keyed = provider_chain(settings)
    google = next((c for c in keyed if c.provider == "google"), None)
    fast = keyed
    deep = [google, *(c for c in keyed if c is not google)] if google is not None else keyed
    return {"fast": fast, "deep": deep}


def build_routes(settings: GuardianSettings) -> tuple[Routes, list[str]]:
    """Chat models per role and notes about unusable keys. Each provider gets one pool (its
    primary key plus ``<PROVIDER>_API_KEY_BACKUP_<n>`` keys) shared by both roles."""
    notes: list[str] = []
    built: dict[str, ModelRoute | None] = {}
    routes: Routes = {"fast": [], "deep": []}
    chain = role_providers(settings)
    keys = load_key_settings() if any(chain.values()) else None
    for role, configs in chain.items():
        for config in configs:
            if config.provider not in built:
                method = "json_schema" if config.provider == "groq" else None
                result = build_pool(
                    config, settings, build=build_chat_model, keys=keys, method=method
                )
                notes.extend(
                    f"{config.label}: {error}"
                    if index == 0
                    else f"{config.label} key #{index}: {error}"
                    for index, error in result.errors
                )
                pool = result.pool
                built[config.provider] = (
                    None
                    if pool is None
                    else ModelRoute(config.provider, config.model, pool.slots[0].chat, method, pool)
                )
            route = built[config.provider]
            if route is not None:
                routes[role].append(route)
    return routes, notes


class Budget:
    """Caps on LLM calls and prompt characters for one run."""

    def __init__(
        self, max_calls: int = DEFAULT_MAX_CALLS, max_input_chars: int = DEFAULT_MAX_INPUT_CHARS
    ) -> None:
        self.max_calls = max(0, max_calls)
        self.max_input_chars = max_input_chars
        self._lock = threading.Lock()
        self._reserved: set[tuple[str, str]] = set()
        self._spent_reserved: set[tuple[str, str]] = set()
        self.calls = 0
        self.chars = 0

    def reserve(self, order: Sequence[tuple[str, str]]) -> None:
        """Give the first ``max_calls`` planned calls a slot each, in priority order."""
        with self._lock:
            self._reserved = set(list(dict.fromkeys(order))[: self.max_calls])

    def is_reserved(self, key: tuple[str, str]) -> bool:
        return key in self._reserved

    def take(self, key: tuple[str, str], chars: int) -> str | None:
        """Account for one call; returns the reason it is refused, or None."""
        with self._lock:
            if self.chars + chars > self.max_input_chars:
                return "input character budget exhausted"
            first = key in self._reserved and key not in self._spent_reserved
            unreserved_left = (
                self.max_calls - len(self._reserved) - (self.calls - len(self._spent_reserved))
            )
            if not first and unreserved_left <= 0:
                return "LLM call budget exhausted"
            if first:
                self._spent_reserved.add(key)
            self.calls += 1
            self.chars += chars
            return None


def _usage(raw: object) -> tuple[int | None, int | None]:
    message = raw.get("raw") if isinstance(raw, dict) else None
    usage = getattr(message, "usage_metadata", None)
    if isinstance(usage, dict):
        return usage.get("input_tokens"), usage.get("output_tokens")
    return None, None


def _dump(raw: object) -> str:
    if isinstance(raw, dict) and "parsed" in raw:
        raw = raw.get("parsed")
    if isinstance(raw, BaseModel):
        raw = raw.model_dump(mode="json")
    return json.dumps(raw, default=str)[:2000]


@dataclass
class AgentRunner:
    routes: Routes | None
    budget: Budget = field(default_factory=Budget)
    sleep: Sleep = time.sleep
    unavailable_reason: str = "AI disabled (--no-ai)"
    calls: list[CallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _record(self, call: CallRecord) -> None:
        with self._lock:
            self.calls.append(call)

    def fallback(self, inp: AgentInput, reason: str) -> InvestigatorReport:
        return InvestigatorReport(
            agent=inp.agent,
            subject_kind=inp.subject_kind,
            subject_id=inp.subject_id,
            title=inp.title,
            status="ai_unavailable",
            source="verified",
            verified_facts=inp.facts,
            reason=reason[:500],
            finding_ids=inp.finding_ids,
        )

    def _sleep(self, seconds: float) -> None:
        self.sleep(seconds)  # looked up per call: the graph may replace ``sleep`` after init

    def _record_failures(
        self, inp: AgentInput, attempt: int, chars: int, attempts: Sequence[Attempt]
    ) -> None:
        """One trace record per failed request (key rotation, provider fallback)."""
        for failed in attempts:
            limited = failed.status in {"rate_limited", "quota_exhausted"}
            self._record(
                CallRecord(
                    agent=inp.agent,
                    subject_id=inp.subject_id,
                    role=AGENT_ROLES[inp.agent],
                    provider=failed.provider,
                    model=failed.model,
                    key_index=failed.key_index,
                    attempt=attempt,
                    input_chars=chars,
                    latency_seconds=failed.latency_seconds,
                    status="rate_limited" if limited else "error",
                    error=(failed.error or failed.status)[:300],
                )
            )

    def run(  # noqa: PLR0911 - each early exit is a distinct fallback reason
        self, inp: AgentInput, extra: dict[str, Any] | None = None
    ) -> InvestigatorReport:
        """One investigator item. Budget: one slot per *logical* call (the answer and at most
        one repair); key rotation, provider fallback and rate-limit waits inside
        :func:`invoke_structured` do not consume extra slots."""
        role = AGENT_ROLES[inp.agent]
        routes = (self.routes or {}).get(role, [])
        if self.routes is None:
            return self.fallback(inp, self.unavailable_reason)
        if not routes:
            return self.fallback(inp, "no LLM provider configured")
        key = (inp.agent, inp.subject_id)
        if not self.budget.is_reserved(key):
            return self.fallback(inp, "LLM call budget exhausted before this item")
        messages = list(build_messages(inp, extra))
        pools = [route.key_pool for route in routes]
        error = ""
        for attempt in (1, 2):
            chars = sum(len(str(m.content)) for m in messages)
            refused = self.budget.take(key, chars)
            if refused is not None:
                return self.fallback(
                    inp, refused if not error else f"{refused}; last error: {error}"
                )
            try:
                outcome = invoke_structured(
                    pools, ANSWER_MODELS[inp.agent], messages, sleep=self._sleep, include_raw=True
                )
            except LLMUnavailableError as exc:
                self._record_failures(inp, attempt, chars, exc.attempts)
                reason = str(exc) if not error else f"{exc}; earlier rejection: {error}"
                return self.fallback(inp, reason)
            self._record_failures(inp, attempt, chars, outcome.failed_attempts)
            call = CallRecord(
                agent=inp.agent,
                subject_id=inp.subject_id,
                role=role,
                provider=outcome.provider,
                model=outcome.model,
                key_index=outcome.key_index,
                attempt=attempt,
                input_chars=chars,
                latency_seconds=outcome.latency_seconds,
            )
            call.input_tokens, call.output_tokens = _usage(outcome.value)
            try:
                cleaned = clean(inp.agent, outcome.value, inp)
            except AnswerRejectedError as exc:
                error = str(exc)
                call.status, call.error = "rejected", error[:300]
                self._record(call)
                messages = [
                    *messages,
                    AIMessage(_dump(outcome.value)),
                    HumanMessage(
                        f"Your answer was rejected: {error}. Answer again with the same schema. "
                        "Cite only refs that appear in the data block."
                    ),
                ]
                continue
            self._record(call)
            return InvestigatorReport(
                agent=inp.agent,
                subject_kind=inp.subject_kind,
                subject_id=inp.subject_id,
                title=inp.title,
                status="repaired" if attempt > 1 else "ok",
                source="inferred",
                verified_facts=inp.facts,
                assessment=cleaned.assessment,
                dropped_refs=cleaned.dropped_refs,
                dropped_claims=cleaned.dropped_claims,
                provider=outcome.provider,
                model=outcome.model,
                latency_seconds=call.latency_seconds,
                finding_ids=inp.finding_ids,
                reason=f"repaired after: {error}"[:500] if attempt > 1 else None,
            )
        return self.fallback(inp, f"answer rejected twice: {error}"[:500])
