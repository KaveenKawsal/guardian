"""Rate-limit resilient structured-output calls: pacing, key rotation and provider fallback.

Free-tier limits are small (Groq: 8,000 tokens/minute per *organization*; Gemini: a few requests
per minute and a daily quota), so one investigation or remediation run easily hits them.
:func:`invoke_structured` makes one *logical* call and handles the provider side:

1. **Pacing** - before each request the provider's token bucket (tokens and requests per minute,
   prompt size estimated as chars/4) is charged; when it is empty the call waits instead of
   provoking a 429.
2. **Key rotation** - a 429 cools the key down for the provider's retry-after period and the
   next key of the pool is tried; a daily quota (``RESOURCE_EXHAUSTED`` per day, Groq TPD/RPD)
   or a rejected key takes the key out for the run.
3. **Provider fallback** - a 503/overload (which affects every key) or a pool whose keys are all
   cooling moves on to the next provider in the caller's routing order.
4. **One wait** - when every route is cooling, wait for the shortest cool-down (capped) once,
   then give up with :class:`LLMUnavailableError`; the caller records ``ai_unavailable``.

State (cool-downs, buckets) is process-wide per key fingerprint and provider and guarded by one
lock, so the planner and parallel investigators share it. Sleeping happens outside the lock.
Keys never appear in logs, attempts or errors: attempts carry the pool index only.
"""

import hashlib
import logging
import math
import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage
from pydantic import SecretStr

from guardian.core.config import LLM_PROVIDERS, GuardianSettings, LLMProvider
from guardian.core.exceptions import ConfigurationError
from guardian.llm.keys import (
    KeySettings,
    key_pool_entries,
    load_key_settings,
    requests_per_minute,
    tokens_per_minute,
)
from guardian.llm.providers import (
    HTTP_FORBIDDEN,
    HTTP_UNAUTHORIZED,
    PROVIDER_LABELS,
    LLMProviderError,
    ProviderConfig,
    api_key_for,
    resolve_provider,
    safe_error_message,
)

logger = logging.getLogger(__name__)

Sleep = Callable[[float], None]
Clock = Callable[[], float]
FailureKind = Literal[
    "rate_limited", "quota_exhausted", "overloaded", "rejected_key", "unsupported", "error"
]
AttemptStatus = Literal[
    "ok", "rate_limited", "quota_exhausted", "overloaded", "rejected_key", "unsupported", "error"
]

HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVICE_UNAVAILABLE = 503
HTTP_OVERLOADED = 529
MAX_RATE_LIMIT_WAIT_SECONDS = 60.0
DEFAULT_RATE_LIMIT_WAIT_SECONDS = 20.0
DEFAULT_OVERLOAD_COOLDOWN_SECONDS = 15.0
EXHAUSTED_COOLDOWN_SECONDS = 3600.0
""""Out for the run"; expires eventually so a long-lived process (the UI server) recovers."""
RETRY_BUFFER_SECONDS = 1.0
CHARS_PER_TOKEN = 4
OUTPUT_TOKEN_ALLOWANCE = 1000
"""Providers count the completion against the per-minute limit as well."""
SECONDS_PER_MINUTE = 60.0
_LABELS: dict[str, str] = {str(k): v for k, v in PROVIDER_LABELS.items()}

_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
_RETRY_IN = re.compile(
    r"(?:try again|retry) in\s+((?:\d+(?:\.\d+)?(?:ms|h|m|s)\s*)+)", re.IGNORECASE
)
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")
_RETRY_DELAY = re.compile(r"retry_?delay\W+(?:seconds\W+)?(\d+(?:\.\d+)?)", re.IGNORECASE)
_RETRY_AFTER = re.compile(r"retry-after\W+(\d+(?:\.\d+)?)", re.IGNORECASE)
_DAILY = re.compile(r"per[ _-]?day|\btpd\b|\brpd\b|daily|limit:\s*0\b", re.IGNORECASE)
_ORG = re.compile(r"organization\W+(org_[A-Za-z0-9]+)")
_STATUS_429 = re.compile(r"\b429\b")
_STATUS_OVERLOADED = re.compile(r"\b(?:503|529)\b|UNAVAILABLE")
_AUTH_MARKERS = (
    "invalid api key",
    "invalid_api_key",
    "api key not valid",
    "api_key_invalid",
    "unauthorized",
)
_RATE_MARKERS = ("rate limit", "resource_exhausted", "too many requests", "quota")
_OVERLOAD_MARKERS = ("overloaded", "high demand", "service unavailable", "temporarily unavailable")


class LLMUnavailableError(LLMProviderError):
    """Every route failed (or is cooling down) for one logical call."""

    def __init__(self, reason: str, attempts: Sequence["Attempt"] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.attempts = list(attempts)


# --- error classification ------------------------------------------------------------------


def _status(exc: BaseException) -> int | None:
    for name in ("status_code", "code"):
        value = getattr(exc, name, None)
        if isinstance(value, int):
            return value
    return None


def retry_after_seconds(exc: BaseException) -> float | None:
    """The provider's requested wait: a ``Retry-After`` header or "try again in 7m12.5s"."""
    headers = getattr(getattr(exc, "response", None), "headers", None)
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter("retry-after")
        try:
            if value is not None:
                return max(0.0, float(value))
        except (TypeError, ValueError):
            pass
    text = str(exc)
    if match := _RETRY_IN.search(text):
        return sum(float(n) * _UNITS[unit] for n, unit in _DURATION_PART.findall(match.group(1)))
    for pattern in (_RETRY_DELAY, _RETRY_AFTER):
        if match := pattern.search(text):
            return float(match.group(1))
    return None


def rate_limit_delay(exc: BaseException) -> float | None:
    """Seconds to wait before retrying a rate-limited call, or None if it is not a rate limit."""
    lowered = str(exc).lower()
    if (
        _status(exc) != HTTP_TOO_MANY_REQUESTS
        and "rate limit" not in lowered
        and "ratelimit" not in type(exc).__name__.lower()
    ):
        return None
    parsed = retry_after_seconds(exc)
    delay = parsed + RETRY_BUFFER_SECONDS if parsed is not None else DEFAULT_RATE_LIMIT_WAIT_SECONDS
    return min(delay, MAX_RATE_LIMIT_WAIT_SECONDS)


@dataclass(frozen=True, slots=True)
class Failure:
    kind: FailureKind
    cooldown_seconds: float = 0.0
    organization: str | None = None


def classify_failure(exc: BaseException) -> Failure:
    """Map a provider exception to what the resilient caller should do about it."""
    status = _status(exc)
    text = str(exc)
    lowered = text.lower()
    name = type(exc).__name__.lower()
    if status in {HTTP_UNAUTHORIZED, HTTP_FORBIDDEN} or any(m in lowered for m in _AUTH_MARKERS):
        return Failure("rejected_key", EXHAUSTED_COOLDOWN_SECONDS)
    parsed = retry_after_seconds(exc)
    if (
        status == HTTP_TOO_MANY_REQUESTS
        or "ratelimit" in name
        or "resourceexhausted" in name
        or any(m in lowered for m in _RATE_MARKERS)
        or _STATUS_429.search(text)
    ):
        org = match.group(1) if (match := _ORG.search(text)) else None
        if _DAILY.search(text):
            return Failure("quota_exhausted", EXHAUSTED_COOLDOWN_SECONDS, org)
        delay = parsed + RETRY_BUFFER_SECONDS if parsed is not None else None
        return Failure("rate_limited", delay or DEFAULT_RATE_LIMIT_WAIT_SECONDS, org)
    if (
        status in {HTTP_SERVICE_UNAVAILABLE, HTTP_OVERLOADED}
        or any(m in lowered for m in _OVERLOAD_MARKERS)
        or _STATUS_OVERLOADED.search(text)
    ):
        return Failure("overloaded", parsed or DEFAULT_OVERLOAD_COOLDOWN_SECONDS)
    return Failure("error")


def estimate_tokens(messages: Sequence[BaseMessage]) -> int:
    """Rough prompt size (chars/4) plus an allowance for the answer."""
    chars = sum(len(str(m.content)) for m in messages)
    return chars // CHARS_PER_TOKEN + OUTPUT_TOKEN_ALLOWANCE


# --- shared state --------------------------------------------------------------------------


@dataclass
class KeyState:
    cooldown_until: float = 0.0
    exhausted: bool = False
    organization: str | None = None


class TokenBucket:
    """Refills ``per_minute`` units per minute up to ``per_minute``; may go into debt so that
    concurrent callers queue behind each other instead of all waiting the same short time."""

    def __init__(self, per_minute: float, now: float) -> None:
        self.capacity = float(per_minute)
        self.level = float(per_minute)
        self.updated = now

    def configure(self, per_minute: float) -> None:
        if per_minute != self.capacity:
            self.capacity = float(per_minute)
            self.level = min(self.level, self.capacity)

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.level = min(self.capacity, self.level + elapsed * self.capacity / SECONDS_PER_MINUTE)
        self.updated = now

    def reserve(self, amount: float, now: float) -> float:
        """Charge ``amount``; returns the seconds to wait until the charge is covered."""
        self._refill(now)
        self.level -= min(amount, self.capacity)
        return 0.0 if self.level >= 0 else -self.level * SECONDS_PER_MINUTE / self.capacity

    def refund(self, amount: float, now: float) -> None:
        self._refill(now)
        self.level = min(self.capacity, self.level + min(amount, self.capacity))


@dataclass(frozen=True, slots=True)
class Pacing:
    tokens_per_minute: int
    requests_per_minute: int


class LimitRegistry:
    """Cool-downs per key and pacing buckets per provider, shared by every call in a process."""

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self.clock = clock
        self.lock = threading.RLock()
        self._keys: dict[str, KeyState] = {}
        self._buckets: dict[str, tuple[TokenBucket, TokenBucket]] = {}

    def key_state(self, fingerprint: str | None) -> KeyState:
        if fingerprint is None:
            return KeyState()
        with self.lock:
            return self._keys.setdefault(fingerprint, KeyState())

    def buckets(self, provider: str, pacing: Pacing) -> tuple[TokenBucket, TokenBucket]:
        with self.lock:
            pair = self._buckets.get(provider)
            if pair is None:
                now = self.clock()
                pair = (
                    TokenBucket(pacing.tokens_per_minute, now),
                    TokenBucket(pacing.requests_per_minute, now),
                )
                self._buckets[provider] = pair
            else:
                pair[0].configure(pacing.tokens_per_minute)
                pair[1].configure(pacing.requests_per_minute)
            return pair

    def reset(self) -> None:
        with self.lock:
            self._keys.clear()
            self._buckets.clear()


LIMITS = LimitRegistry()
"""Process-wide state: the planner and the investigators share one view of each key."""


def key_fingerprint(provider: str, secret: SecretStr) -> str:
    """Stable, non-reversible id for a key's shared state (never logged)."""
    digest = hashlib.sha256(f"{provider}:{secret.get_secret_value()}".encode())
    return digest.hexdigest()[:16]


@dataclass(eq=False)
class KeySlot:
    index: int
    chat: BaseChatModel
    state: KeyState = field(default_factory=KeyState)
    secret: SecretStr | None = field(default=None, repr=False)


@dataclass(eq=False)
class ProviderPool:
    """One provider/model with its keys (index 0 = primary) and pacing."""

    provider: str
    model: str
    slots: list[KeySlot]
    method: str | None = None
    pacing: Pacing | None = None
    limits: LimitRegistry = field(default_factory=LimitRegistry)
    max_wait_seconds: float = MAX_RATE_LIMIT_WAIT_SECONDS

    @classmethod
    def single(
        cls, provider: str, model: str, chat: BaseChatModel, method: str | None = None
    ) -> "ProviderPool":
        """A one-key pool around an existing chat model (no pacing, private state)."""
        return cls(provider, model, [KeySlot(0, chat)], method)

    @property
    def label(self) -> str:
        return _LABELS.get(self.provider, self.provider) or "model"

    @property
    def secrets(self) -> list[SecretStr]:
        return [s.secret for s in self.slots if s.secret is not None]

    def acquire(self) -> KeySlot | None:
        """First key that is neither cooling down nor out for the run."""
        with self.limits.lock:
            now = self.limits.clock()
            return next(
                (s for s in self.slots if not s.state.exhausted and s.state.cooldown_until <= now),
                None,
            )

    def pace(self, tokens: int) -> float:
        if self.pacing is None:
            return 0.0
        with self.limits.lock:
            token_bucket, request_bucket = self.limits.buckets(self.provider, self.pacing)
            now = self.limits.clock()
            return max(token_bucket.reserve(tokens, now), request_bucket.reserve(1, now))

    def refund(self, tokens: int) -> None:
        """A rejected request (429/503) did not consume the provider's budget."""
        if self.pacing is None:
            return
        with self.limits.lock:
            token_bucket, request_bucket = self.limits.buckets(self.provider, self.pacing)
            now = self.limits.clock()
            token_bucket.refund(tokens, now)
            request_bucket.refund(1, now)

    def cool(self, slot: KeySlot, seconds: float) -> None:
        with self.limits.lock:
            until = self.limits.clock() + seconds
            slot.state.cooldown_until = max(slot.state.cooldown_until, until)

    def cool_all(self, seconds: float) -> None:
        for slot in self.slots:
            self.cool(slot, seconds)

    def exhaust(self, slot: KeySlot) -> None:
        with self.limits.lock:
            slot.state.exhausted = True
            slot.state.cooldown_until = self.limits.clock() + EXHAUSTED_COOLDOWN_SECONDS

    def release(self, slot: KeySlot) -> None:
        """After waiting out its cool-down, let ``slot`` be tried again."""
        with self.limits.lock:
            slot.state.cooldown_until = 0.0

    def shortest_cooldown(self) -> tuple[float, KeySlot] | None:
        with self.limits.lock:
            now = self.limits.clock()
            waiting = [
                (s.state.cooldown_until - now, s) for s in self.slots if not s.state.exhausted
            ]
        return min(waiting, key=lambda item: item[0]) if waiting else None

    def note_organization(self, slot: KeySlot, organization: str | None) -> None:
        """Warn once when two keys turn out to share a Groq organization (and so its limit)."""
        if organization is None:
            return
        with self.limits.lock:
            known = slot.state.organization
            slot.state.organization = organization
            shared = [
                s.index
                for s in self.slots
                if s is not slot and s.state.organization == organization
            ]
        if shared and known is None:
            logger.warning(
                "%s keys #%s and #%d belong to the same organization, so they share one "
                "rate limit; only keys from different accounts add capacity",
                self.label,
                ", #".join(str(i) for i in shared),
                slot.index,
            )

    def scrub(self, text: str) -> str:
        for secret in self.secrets:
            raw = secret.get_secret_value()
            if raw:
                text = text.replace(raw, "***")
        return text


# --- the call ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Attempt:
    """One request to one key (for the run trace; the key appears as its pool index only)."""

    provider: str
    model: str
    key_index: int
    status: AttemptStatus
    error: str | None = None
    latency_seconds: float = 0.0
    waited_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class CallOutcome:
    value: Any
    provider: str
    model: str
    key_index: int
    latency_seconds: float
    attempts: list[Attempt]

    @property
    def failed_attempts(self) -> list[Attempt]:
        return [a for a in self.attempts if a.status != "ok"]


@dataclass
class _CallState:
    tokens: int
    attempts: list[Attempt] = field(default_factory=list)
    errors: dict[int, str] = field(default_factory=dict)
    broken: set[int] = field(default_factory=set)


def _ceil_ms(seconds: float) -> float:
    return math.ceil(max(0.0, seconds) * 1000) / 1000


def _try_pool(  # noqa: PLR0913 - the call's inputs plus its running state
    position: int,
    pool: ProviderPool,
    schema: type,
    messages: Sequence[BaseMessage],
    state: _CallState,
    *,
    sleep: Sleep,
    options: dict[str, Any],
) -> CallOutcome | None:
    while (slot := pool.acquire()) is not None:
        waited = pool.pace(state.tokens)
        if waited > 0:
            waited = _ceil_ms(waited)
            logger.info("%s: pacing, waiting %.1fs for the per-minute budget", pool.label, waited)
            sleep(waited)
        started = time.perf_counter()
        try:
            runnable = slot.chat.with_structured_output(schema, **options)
        except (NotImplementedError, AttributeError, ValueError, TypeError) as exc:
            pool.refund(state.tokens)
            message = pool.scrub(f"structured output unsupported ({exc})")[:300]
            state.attempts.append(
                Attempt(pool.provider, pool.model, slot.index, "unsupported", message)
            )
            state.errors[position] = message
            state.broken.add(position)
            return None
        try:
            value = runnable.invoke(list(messages))
        except Exception as exc:  # noqa: BLE001 - provider SDKs raise many unrelated types
            latency = round(time.perf_counter() - started, 3)
            failure = classify_failure(exc)
            message = pool.scrub(safe_error_message(exc, slot.secret))
            state.attempts.append(
                Attempt(
                    pool.provider, pool.model, slot.index, failure.kind, message, latency, waited
                )
            )
            state.errors[position] = message
            if _handle_failure(pool, slot, failure, state):
                continue
            if failure.kind != "overloaded":
                state.broken.add(position)  # not retryable: skip this provider for this call
            return None
        latency = round(time.perf_counter() - started, 3)
        state.attempts.append(
            Attempt(pool.provider, pool.model, slot.index, "ok", None, latency, waited)
        )
        return CallOutcome(value, pool.provider, pool.model, slot.index, latency, state.attempts)
    return None


def _handle_failure(pool: ProviderPool, slot: KeySlot, failure: Failure, state: _CallState) -> bool:
    """Update the shared state; True when the next key of the same pool should be tried."""
    if failure.kind != "error":
        pool.refund(state.tokens)
    if failure.kind == "rate_limited":
        pool.cool(slot, failure.cooldown_seconds)
        pool.note_organization(slot, failure.organization)
        logger.warning(
            "%s key #%d rate limited; cooling down %.1fs and trying the next key",
            pool.label,
            slot.index,
            failure.cooldown_seconds,
        )
        return True
    if failure.kind in {"quota_exhausted", "rejected_key"}:
        pool.exhaust(slot)
        logger.warning(
            "%s key #%d %s; not using it again in this run",
            pool.label,
            slot.index,
            "is out of quota" if failure.kind == "quota_exhausted" else "was rejected",
        )
        return True
    if failure.kind == "overloaded":
        pool.cool_all(failure.cooldown_seconds)
        logger.warning(
            "%s is overloaded; cooling down %.1fs and trying the next provider",
            pool.label,
            failure.cooldown_seconds,
        )
    return False


def _reason(pools: Sequence[ProviderPool], state: _CallState) -> str:
    parts: list[str] = []
    for position, pool in enumerate(pools):
        error = state.errors.get(position)
        if error is None:
            exhausted = all(s.state.exhausted for s in pool.slots)
            error = (
                f"all {len(pool.slots)} key(s) out of quota for this run"
                if exhausted
                else f"all {len(pool.slots)} key(s) cooling down after rate limits"
            )
        parts.append(f"{pool.provider}: {error}" if pool.provider else error)
    return "; then ".join(parts) or "no LLM provider configured"


def invoke_structured(  # noqa: PLR0913 - one logical call and its knobs
    pools: Sequence[ProviderPool],
    schema: type,
    messages: Sequence[BaseMessage],
    *,
    sleep: Sleep = time.sleep,
    include_raw: bool = False,
    use_method: bool = True,
    max_waits: int = 1,
) -> CallOutcome:
    """One logical structured-output call across ``pools`` (in routing order).

    Raises :class:`LLMUnavailableError` when no route answers; its ``attempts`` list every
    request made (for the run trace). Callers count the whole call once toward their budget.
    """
    state = _CallState(tokens=estimate_tokens(messages))
    waits_left = max_waits
    while True:
        for position, pool in enumerate(pools):
            if position in state.broken:
                continue
            options: dict[str, Any] = {"include_raw": True} if include_raw else {}
            if use_method and pool.method is not None:
                options["method"] = pool.method
            outcome = _try_pool(
                position, pool, schema, messages, state, sleep=sleep, options=options
            )
            if outcome is not None:
                return outcome
        cooling: list[tuple[float, ProviderPool, KeySlot]] = []
        for position, pool in enumerate(pools):
            shortest = None if position in state.broken else pool.shortest_cooldown()
            if shortest is not None:
                cooling.append((shortest[0], pool, shortest[1]))
        if not cooling or waits_left <= 0:
            raise LLMUnavailableError(_reason(pools, state), state.attempts)
        remaining, pool, slot = min(cooling, key=lambda item: item[0])
        wait = _ceil_ms(min(remaining, pool.max_wait_seconds))
        logger.info(
            "every route is cooling down; waiting %.1fs for %s key #%d",
            wait,
            pool.label,
            slot.index,
        )
        sleep(wait)
        pool.release(slot)
        waits_left -= 1


# --- building pools from settings ----------------------------------------------------------


def config_for(settings: GuardianSettings, provider: LLMProvider) -> ProviderConfig | None:
    """The provider's config when it has a key; ``None`` otherwise."""
    if api_key_for(settings, provider) is None:
        return None
    try:
        return resolve_provider(settings, provider=provider)
    except ConfigurationError:
        return None


def provider_chain(settings: GuardianSettings) -> list[ProviderConfig]:
    """The active provider first, then every other provider that has a key."""
    if not settings.ai_enabled:
        return []
    try:
        active = resolve_provider(settings)
    except ConfigurationError:
        active = None
    keyed = [c for c in (config_for(settings, p) for p in LLM_PROVIDERS) if c is not None]
    if active is not None:
        keyed = [active, *(c for c in keyed if c.provider != active.provider)]
    return keyed


BuildChat = Callable[[ProviderConfig, GuardianSettings], BaseChatModel]


@dataclass
class PoolBuild:
    pool: ProviderPool | None
    errors: list[tuple[int, str]] = field(default_factory=list)
    """``(key index, key-free message)`` for keys whose client could not be built."""


def build_pool(  # noqa: PLR0913 - config, settings and the injectable pieces
    config: ProviderConfig,
    settings: GuardianSettings,
    *,
    build: BuildChat,
    keys: KeySettings | None = None,
    method: str | None = None,
    limits: LimitRegistry = LIMITS,
) -> PoolBuild:
    """A pool with one chat model per key (primary, then ``<PROVIDER>_API_KEY_BACKUP_<n>``)."""
    extra = keys if keys is not None else load_key_settings()
    result = PoolBuild(None)
    slots: list[KeySlot] = []
    for entry in key_pool_entries(settings, config.provider, extra):
        try:
            chat = build(replace(config, api_key=entry.secret), settings)
        except Exception as exc:  # noqa: BLE001 - SDK construction errors vary
            result.errors.append((entry.index, safe_error_message(exc, entry.secret)))
            continue
        state = limits.key_state(key_fingerprint(config.provider, entry.secret))
        slots.append(KeySlot(entry.index, chat, state, entry.secret))
    if slots:
        result.pool = ProviderPool(
            config.provider,
            config.model,
            slots,
            method,
            Pacing(
                tokens_per_minute(extra, config.provider),
                requests_per_minute(extra, config.provider),
            ),
            limits,
            extra.llm_max_wait_seconds,
        )
        if len(slots) > 1:
            logger.info("%s: %d keys in the pool", config.label, len(slots))
    return result
