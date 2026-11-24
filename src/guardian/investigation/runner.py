"""Run one investigator: route to a provider, call with structured output, validate, repair once,
or fall back to a deterministic ``ai_unavailable`` report.

Thread-safe: the graph calls :meth:`AgentRunner.run` from parallel branches. The budget is
reserved up front in priority order (:meth:`Budget.reserve`), so which items get AI output does
not depend on thread scheduling; repair attempts and provider fallbacks use what is left.
"""

import json
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.runnables import Runnable
from pydantic import BaseModel

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import ConfigurationError
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
from guardian.llm.providers import (
    ProviderConfig,
    api_key_for,
    build_chat_model,
    resolve_provider,
    safe_error_message,
)
from guardian.remediation.planner import rate_limit_delay

DEFAULT_MAX_CALLS = 40
DEFAULT_MAX_INPUT_CHARS = 600_000
RATE_LIMIT_RETRIES = 2

Sleep = Callable[[float], None]


@dataclass(frozen=True, slots=True)
class ModelRoute:
    provider: str
    model: str
    chat: BaseChatModel
    method: str | None = None
    """``with_structured_output`` method; Groq uses ``json_schema`` because with function
    calling gpt-oss sometimes calls tools that do not exist."""


Routes = dict[Role, list[ModelRoute]]


def _config_for(settings: GuardianSettings, provider: str) -> ProviderConfig | None:
    if provider not in {"groq", "google"} or api_key_for(settings, provider) is None:
        return None
    try:
        return resolve_provider(settings, provider=provider)
    except ConfigurationError:
        return None


def role_providers(settings: GuardianSettings) -> dict[Role, list[ProviderConfig]]:
    """``fast`` = the active provider (Groq in practice), ``deep`` = Google when it has a key;
    each role falls back to the other provider. Model names come from settings."""
    if not settings.ai_enabled:
        return {"fast": [], "deep": []}
    try:
        active = resolve_provider(settings)
    except ConfigurationError:
        active = None
    keyed = [c for c in (_config_for(settings, p) for p in ("groq", "google")) if c is not None]
    if active is not None:
        keyed = [active, *(c for c in keyed if c.provider != active.provider)]
    google = next((c for c in keyed if c.provider == "google"), None)
    fast = keyed
    deep = [google, *(c for c in keyed if c is not google)] if google is not None else keyed
    return {"fast": fast, "deep": deep}


def build_routes(settings: GuardianSettings) -> tuple[Routes, list[str]]:
    """Chat models per role (built once per provider) and notes about unusable providers."""
    notes: list[str] = []
    built: dict[str, ModelRoute | None] = {}
    routes: Routes = {"fast": [], "deep": []}
    for role, configs in role_providers(settings).items():
        for config in configs:
            if config.provider not in built:
                try:
                    chat = build_chat_model(config, settings)
                    method = "json_schema" if config.provider == "groq" else None
                    built[config.provider] = ModelRoute(config.provider, config.model, chat, method)
                except Exception as exc:  # noqa: BLE001 - SDK construction errors vary
                    notes.append(f"{config.label}: {safe_error_message(exc, config.api_key)}")
                    built[config.provider] = None
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


def _is_rate_limit(exc: BaseException) -> bool:
    return rate_limit_delay(exc) is not None


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

    def run(self, inp: AgentInput, extra: dict[str, Any] | None = None) -> InvestigatorReport:
        role = AGENT_ROLES[inp.agent]
        routes = (self.routes or {}).get(role, [])
        if self.routes is None:
            return self.fallback(inp, self.unavailable_reason)
        if not routes:
            return self.fallback(inp, "no LLM provider configured")
        key = (inp.agent, inp.subject_id)
        if not self.budget.is_reserved(key):
            return self.fallback(inp, "LLM call budget exhausted before this item")
        messages = build_messages(inp, extra)
        reasons: list[str] = []
        for route in routes:
            outcome = self._try_route(route, role, inp, list(messages), key)
            if isinstance(outcome, InvestigatorReport):
                return outcome
            reasons.append(outcome)
            if outcome.startswith(("LLM call budget", "input character budget")):
                break
        return self.fallback(inp, "; then ".join(reasons) or "no answer")

    def _invoke(self, structured: Runnable[Any, Any], messages: list[BaseMessage]) -> object:
        """Invoke; on a rate limit wait as long as the provider asks (planner's helper), at most
        ``RATE_LIMIT_RETRIES`` times."""
        for attempt in range(RATE_LIMIT_RETRIES + 1):
            try:
                return structured.invoke(messages)
            except Exception as exc:
                delay = rate_limit_delay(exc)
                if delay is None or attempt == RATE_LIMIT_RETRIES:
                    raise
                self.sleep(delay)
        msg = "unreachable"  # pragma: no cover
        raise RuntimeError(msg)  # pragma: no cover

    def _try_route(
        self,
        route: ModelRoute,
        role: Role,
        inp: AgentInput,
        messages: list[BaseMessage],
        key: tuple[str, str],
    ) -> InvestigatorReport | str:
        try:
            options: dict[str, Any] = {"include_raw": True}
            if route.method is not None:
                options["method"] = route.method
            structured = route.chat.with_structured_output(ANSWER_MODELS[inp.agent], **options)
        except (NotImplementedError, AttributeError, ValueError, TypeError) as exc:
            return f"{route.provider}: structured output unsupported ({exc})"[:300]
        error = ""
        for attempt in (1, 2):
            chars = sum(len(str(m.content)) for m in messages)
            refused = self.budget.take(key, chars)
            if refused is not None:
                return refused if not error else f"{refused}; last error: {error}"
            call = CallRecord(
                agent=inp.agent,
                subject_id=inp.subject_id,
                role=role,
                provider=route.provider,
                model=route.model,
                attempt=attempt,
                input_chars=chars,
            )
            started = time.perf_counter()
            raw: object = None
            try:
                raw = self._invoke(structured, messages)
                call.input_tokens, call.output_tokens = _usage(raw)
                cleaned = clean(inp.agent, raw, inp)
            except AnswerRejectedError as exc:
                error = str(exc)
                call.status, call.error = "rejected", error[:300]
                call.latency_seconds = round(time.perf_counter() - started, 3)
                self._record(call)
                messages = [
                    *messages,
                    AIMessage(_dump(raw)),
                    HumanMessage(
                        f"Your answer was rejected: {error}. Answer again with the same schema. "
                        "Cite only refs that appear in the data block."
                    ),
                ]
                continue
            except Exception as exc:  # noqa: BLE001 - provider SDKs raise many unrelated types
                error = safe_error_message(exc)
                call.status = "rate_limited" if _is_rate_limit(exc) else "error"
                call.error = error[:300]
                call.latency_seconds = round(time.perf_counter() - started, 3)
                self._record(call)
                return f"{route.provider}: {error}"
            call.latency_seconds = round(time.perf_counter() - started, 3)
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
                provider=route.provider,
                model=route.model,
                latency_seconds=call.latency_seconds,
                finding_ids=inp.finding_ids,
                reason=f"repaired after: {error}"[:500] if attempt > 1 else None,
            )
        return f"answer rejected twice: {error}"[:500]
