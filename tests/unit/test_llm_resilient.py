"""Rate-limit resilience: key pools, pacing, rotation, provider fallback, budget, secrecy.

Fake chat models only; time is a fake clock advanced by the fake sleep (no real waiting).
"""

import logging
import threading

import pytest
from investigation import FakeChat, good_answer
from investigation_world import SCAN_ID, seed_ai_scan
from juice_shop import FakeRegistry, build_world
from langchain_core.messages import HumanMessage
from pydantic import BaseModel, SecretStr

import guardian.remediation.planner as planner_module
from guardian.core.config import GuardianSettings
from guardian.investigation.context import build_plan, load_context
from guardian.investigation.runner import AgentRunner, Budget, ModelRoute, build_routes
from guardian.llm import resilient
from guardian.llm.keys import LLMKeySettings, key_pool, key_pool_entries
from guardian.llm.resilient import (
    KeySlot,
    LimitRegistry,
    LLMUnavailableError,
    Pacing,
    ProviderPool,
    build_pool,
    classify_failure,
    estimate_tokens,
    invoke_structured,
    rate_limit_delay,
    retry_after_seconds,
)
from guardian.remediation.candidates import generate_candidates
from guardian.storage.database import Database

GROQ = "gsk_primary_secret_0000aaaa"
GROQ_B1 = "gsk_backup1_secret_0000bbbb"
GROQ_B2 = "gsk_backup2_secret_0000cccc"
GOOGLE = "AIza_primary_secret_0000dddd"


class Answer(BaseModel):
    text: str


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []
        self.lock = threading.Lock()

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.slept.append(seconds)
            self.now += seconds


class Status(Exception):  # noqa: N818 - mimics SDK errors carrying an HTTP status
    def __init__(self, text: str, status: int | None = None) -> None:
        super().__init__(text)
        self.status_code = status


class Scripted:
    """A chat model per key: answers from a script (exception instances are raised)."""

    def __init__(self, *script: object, default: object = None) -> None:
        self.script = list(script)
        self.default = default
        self.calls = 0
        self.kwargs: list[dict] = []

    def with_structured_output(self, schema, **kwargs):
        self.kwargs.append(kwargs)
        return self

    def invoke(self, messages):
        self.calls += 1
        item = self.script.pop(0) if self.script else self.default
        if item is None:
            item = Answer(text="ok")
        if isinstance(item, Exception):
            raise item
        return item


def pool(provider, *chats, limits, pacing=None, secrets=None):
    secrets = secrets or [None] * len(chats)
    slots = [
        KeySlot(i, chat, limits.key_state(f"{provider}-{i}" if secrets[i] else None), secrets[i])
        for i, chat in enumerate(chats)
    ]
    return ProviderPool(provider, f"{provider}-model", slots, pacing=pacing, limits=limits)


MESSAGES = [HumanMessage("x" * 400)]
TPM_429 = (
    "Error code: 429 - Rate limit reached for model `openai/gpt-oss-120b` in organization "
    "`org_01abc` service tier `on_demand` on tokens per minute (TPM): Limit 8000, Used 7000, "
    "Requested 2500. Please try again in 9.5s."
)


# --- keys -------------------------------------------------------------------------------------


def test_key_pool_primary_then_backups_deduplicated(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY_BACKUP_1", GROQ_B1)
    monkeypatch.setenv("GUARDIAN_GROQ_API_KEY_BACKUP_3", GROQ_B2)
    monkeypatch.setenv("GROQ_API_KEY_BACKUP_2", GROQ)  # duplicate of the primary
    monkeypatch.setenv("GOOGLE_API_KEY_BACKUP_1", "   ")  # blank = unset
    keys = LLMKeySettings(_env_file=None)
    settings = GuardianSettings(_env_file=None, groq_api_key=SecretStr(GROQ))
    assert [k.get_secret_value() for k in key_pool(settings, "groq", keys)] == [
        GROQ,
        GROQ_B1,
        GROQ_B2,
    ]
    entries = key_pool_entries(settings, "groq", keys)
    assert [(e.index, e.env_var, e.masked) for e in entries] == [
        (0, "GROQ_API_KEY", "...aaaa"),
        (1, "GROQ_API_KEY_BACKUP_1", "...bbbb"),
        (2, "GROQ_API_KEY_BACKUP_3", "...cccc"),
    ]
    assert key_pool(settings, "google", keys) == []
    for text in (repr(keys), repr(entries), str(keys.model_dump())):
        assert GROQ_B1 not in text
        assert GROQ_B2 not in text


def test_key_settings_read_env_files_and_pacing(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        f"GOOGLE_API_KEY_BACKUP_2={GOOGLE}\nGUARDIAN_GROQ_TOKENS_PER_MINUTE=5000\n"
        "GUARDIAN_LLM_MAX_WAIT_SECONDS=30\n"
    )
    keys = LLMKeySettings(_env_file=(env,))
    assert keys.groq_tokens_per_minute == 5000
    assert keys.llm_max_wait_seconds == 30
    settings = GuardianSettings(_env_file=None)
    assert [e.env_var for e in key_pool_entries(settings, "google", keys)] == [
        "GOOGLE_API_KEY_BACKUP_2"
    ]


# --- classification -----------------------------------------------------------------------


class _Response:
    headers = {"retry-after": "12"}  # noqa: RUF012


class _WithHeaders(Exception):  # noqa: N818
    status_code = 429
    response = _Response()


@pytest.mark.parametrize(
    ("exc", "kind", "cooldown"),
    [
        (Status(TPM_429, 429), "rate_limited", 10.5),
        (RuntimeError("Rate limit reached. Please try again in 7m12.5s."), "rate_limited", 433.5),
        (
            RuntimeError("429 RESOURCE_EXHAUSTED. quota exceeded. Please retry in 23.2s."),
            "rate_limited",
            24.2,
        ),
        (
            RuntimeError(
                "429 RESOURCE_EXHAUSTED quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier"
            ),
            "quota_exhausted",
            resilient.EXHAUSTED_COOLDOWN_SECONDS,
        ),
        (
            Status("Rate limit reached on tokens per day (TPD): Limit 200000", 429),
            "quota_exhausted",
            resilient.EXHAUSTED_COOLDOWN_SECONDS,
        ),
        (
            RuntimeError("503 UNAVAILABLE. This model is currently experiencing high demand."),
            "overloaded",
            resilient.DEFAULT_OVERLOAD_COOLDOWN_SECONDS,
        ),
        (Status("Invalid API Key", 401), "rejected_key", resilient.EXHAUSTED_COOLDOWN_SECONDS),
        (RuntimeError("rate limit"), "rate_limited", resilient.DEFAULT_RATE_LIMIT_WAIT_SECONDS),
        (_WithHeaders("too many"), "rate_limited", 13.0),
        (RuntimeError("boom"), "error", 0.0),
    ],
)
def test_classify_failure(exc, kind, cooldown):
    failure = classify_failure(exc)
    assert failure.kind == kind
    assert failure.cooldown_seconds == pytest.approx(cooldown)


def test_retry_after_formats_and_planner_export():
    assert retry_after_seconds(RuntimeError("retryDelay': '41s'")) == 41
    assert retry_after_seconds(RuntimeError("Retry-After: 5")) == 5
    assert retry_after_seconds(RuntimeError("try again in 250ms")) == pytest.approx(0.25)
    assert retry_after_seconds(RuntimeError("nothing")) is None
    assert classify_failure(Status(TPM_429, 429)).organization == "org_01abc"
    assert planner_module.rate_limit_delay is rate_limit_delay
    assert rate_limit_delay(RuntimeError("Rate limit: try again in 1m2s")) == 60.0


# --- rotation, cool-down, fallback, give-up ---------------------------------------------------


def test_rate_limit_rotates_to_next_key_and_cools_down():
    clock = Clock()
    limits = LimitRegistry(clock)
    k0, k1 = Scripted(Status(TPM_429, 429)), Scripted()
    groq = pool("groq", k0, k1, limits=limits)
    outcome = invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    assert (outcome.provider, outcome.key_index) == ("groq", 1)
    assert [(a.key_index, a.status) for a in outcome.attempts] == [(0, "rate_limited"), (1, "ok")]
    assert clock.slept == []  # rotation, not waiting
    # key 0 is still cooling: the next call goes straight to key 1
    assert invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep).key_index == 1
    assert k0.calls == 1
    clock.now += 11  # retry-after 9.5s + 1s buffer has passed
    assert invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep).key_index == 0


def test_daily_quota_takes_key_out_for_the_run():
    clock = Clock()
    limits = LimitRegistry(clock)
    k0 = Scripted(RuntimeError("429 RESOURCE_EXHAUSTED: GenerateRequestsPerDay limit reached"))
    k1 = Scripted(default=Answer(text="b1"))
    google = pool("google", k0, k1, limits=limits)
    assert invoke_structured([google], Answer, MESSAGES, sleep=clock.sleep).key_index == 1
    clock.now += 600
    assert invoke_structured([google], Answer, MESSAGES, sleep=clock.sleep).key_index == 1
    assert k0.calls == 1


def test_overload_falls_back_to_other_provider_and_skips_it_while_cooling():
    clock = Clock()
    limits = LimitRegistry(clock)
    gemini = Scripted(RuntimeError("503 UNAVAILABLE: high demand"))
    gemini_b = Scripted()
    groq_chat = Scripted(default=Answer(text="groq"))
    google = pool("google", gemini, gemini_b, limits=limits)
    groq = pool("groq", groq_chat, limits=limits)
    outcome = invoke_structured([google, groq], Answer, MESSAGES, sleep=clock.sleep)
    assert outcome.provider == "groq"
    assert gemini_b.calls == 0  # overload affects every key of the provider
    assert [a.status for a in outcome.attempts] == ["overloaded", "ok"]
    invoke_structured([google, groq], Answer, MESSAGES, sleep=clock.sleep)
    assert gemini.calls == 1  # still cooling: not asked again
    assert clock.slept == []


def test_generic_error_moves_on_without_retrying_that_provider():
    clock = Clock()
    limits = LimitRegistry(clock)
    broken = Scripted(default=RuntimeError("boom"))
    groq = pool("groq", broken, limits=limits)
    google = pool("google", Scripted(Status(TPM_429, 429), Status(TPM_429, 429)), limits=limits)
    with pytest.raises(LLMUnavailableError) as info:
        invoke_structured([groq, google], Answer, MESSAGES, sleep=clock.sleep)
    assert broken.calls == 1  # not retried after the wait
    assert "groq: RuntimeError: boom; then google: Status:" in info.value.reason
    assert clock.slept == [10.5]


def test_waits_shortest_cooldown_once_then_succeeds():
    clock = Clock()
    limits = LimitRegistry(clock)
    groq = pool(
        "groq",
        Scripted(Status("Rate limit. Please try again in 30s", 429)),
        Scripted(Status("Rate limit. Please try again in 4s", 429)),
        limits=limits,
    )
    outcome = invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    assert clock.slept == [5.0]  # key 1 frees up first
    assert outcome.key_index == 1
    assert [a.status for a in outcome.attempts] == ["rate_limited", "rate_limited", "ok"]


def test_gives_up_after_one_capped_wait():
    clock = Clock()
    limits = LimitRegistry(clock)
    limited = Status("Rate limit. Please try again in 500s", 429)
    groq = pool("groq", Scripted(limited, limited), limits=limits)
    groq.max_wait_seconds = 60.0
    with pytest.raises(LLMUnavailableError) as info:
        invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    assert clock.slept == [60.0]
    assert len(info.value.attempts) == 2
    # nothing is tried while every key is cooling; the reason says so
    clock.now += 1
    with pytest.raises(LLMUnavailableError, match="cooling down"):
        invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep, max_waits=0)


def test_exhausted_pool_reason_and_rejected_key():
    clock = Clock()
    limits = LimitRegistry(clock)
    groq = pool("groq", Scripted(Status("Invalid API Key", 401)), limits=limits)
    with pytest.raises(LLMUnavailableError, match="API key rejected"):
        invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    with pytest.raises(LLMUnavailableError, match="out of quota for this run"):
        invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    assert clock.slept == []


def test_unsupported_structured_output_and_method_option():
    class NoStructured:
        def with_structured_output(self, schema, **kwargs):
            msg = "nope"
            raise NotImplementedError(msg)

    clock = Clock()
    limits = LimitRegistry(clock)
    good = Scripted()
    google = ProviderPool("google", "m", [KeySlot(0, good)], method="json_schema", limits=limits)
    outcome = invoke_structured(
        [pool("groq", NoStructured(), limits=limits), google],
        Answer,
        MESSAGES,
        sleep=clock.sleep,
        include_raw=True,
    )
    assert outcome.provider == "google"
    assert outcome.attempts[0].status == "unsupported"
    assert good.kwargs == [{"include_raw": True, "method": "json_schema"}]


# --- pacing ----------------------------------------------------------------------------------


def test_estimate_tokens():
    assert estimate_tokens([HumanMessage("x" * 4000)]) == 1000 + resilient.OUTPUT_TOKEN_ALLOWANCE


def test_pacing_waits_instead_of_429():
    clock = Clock()
    limits = LimitRegistry(clock)
    groq = pool("groq", Scripted(default=Answer(text="x")), limits=limits, pacing=Pacing(4000, 100))
    messages = [HumanMessage("x" * 4000)]  # 2000 tokens with the answer allowance
    for _ in range(4):
        invoke_structured([groq], Answer, messages, sleep=clock.sleep)
    # a full bucket covers two calls; then each call waits for 2000 tokens (30s at 4000/min)
    assert clock.slept == [pytest.approx(30.0), pytest.approx(30.0)]


def test_pacing_requests_per_minute_and_refund_on_429():
    clock = Clock()
    limits = LimitRegistry(clock)
    pacing = Pacing(1_000_000, 2)
    chat = Scripted(Status(TPM_429, 429), default=Answer(text="x"))
    google = pool("google", chat, Scripted(), limits=limits, pacing=pacing)
    invoke_structured([google], Answer, MESSAGES, sleep=clock.sleep)
    invoke_structured([google], Answer, MESSAGES, sleep=clock.sleep)
    assert clock.slept == []  # the 429'd request was refunded, so two requests fit
    invoke_structured([google], Answer, MESSAGES, sleep=clock.sleep)
    assert clock.slept == [pytest.approx(30.0)]


def test_two_threads_queue_on_the_shared_bucket():
    clock = Clock()
    limits = LimitRegistry(clock)
    pacing = Pacing(2000, 100)
    barrier = threading.Barrier(2)

    class Slow(Scripted):
        def invoke(self, messages):
            return Answer(text="x")

    groq_a = pool("groq", Slow(), limits=limits, pacing=pacing)
    groq_b = pool("groq", Slow(), limits=limits, pacing=pacing)  # same provider: same bucket
    results = []

    def work(p):
        barrier.wait()
        results.append(invoke_structured([p], Answer, MESSAGES, sleep=clock.sleep))

    threads = [threading.Thread(target=work, args=(p,)) for p in (groq_a, groq_b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 2
    # 1100 tokens each against 2000/min: the second caller waits for the 200 it is short
    assert clock.slept == [pytest.approx(6.0)]


def test_two_threads_rotate_keys_consistently():
    clock = Clock()
    limits = LimitRegistry(clock)
    gate = threading.Barrier(2)

    class Limited(Scripted):
        def invoke(self, messages):
            gate.wait(timeout=5)
            raise Status(TPM_429, 429)

    k0, k1 = Limited(), Scripted(default=Answer(text="x"))
    groq = pool("groq", k0, k1, limits=limits)
    results = []

    def work():
        results.append(invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep))

    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [r.key_index for r in results] == [1, 1]
    assert k1.calls == 2
    assert clock.slept == []


# --- secrecy ---------------------------------------------------------------------------------


def test_secrets_never_in_logs_errors_or_trace(caplog):
    caplog.set_level(logging.DEBUG)
    clock = Clock()
    limits = LimitRegistry(clock)
    leaky = Status(f"{TPM_429} (key {GROQ})", 429)
    leaky_b = Status(f"Rate limit. Please try again in 2s. key={GROQ_B1}", 429)
    groq = pool(
        "groq",
        Scripted(leaky, leaky),
        Scripted(leaky_b, leaky_b),
        limits=limits,
        secrets=[SecretStr(GROQ), SecretStr(GROQ_B1)],
    )
    with pytest.raises(LLMUnavailableError) as info:
        invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    texts = [caplog.text, str(info.value), repr(info.value.attempts), repr(groq)]
    for text in texts:
        assert GROQ not in text
        assert GROQ_B1 not in text
    assert "key #0 rate limited" in caplog.text


def test_same_organization_is_logged(caplog):
    caplog.set_level(logging.WARNING)
    clock = Clock()
    limits = LimitRegistry(clock)
    groq = pool(
        "groq",
        Scripted(Status(TPM_429, 429)),
        Scripted(Status(TPM_429, 429)),
        Scripted(),
        limits=limits,
    )
    invoke_structured([groq], Answer, MESSAGES, sleep=clock.sleep)
    assert "keys #0 and #1 belong to the same organization" in caplog.text


# --- wiring: build_pool, runner budget, planner ----------------------------------------------


def _keyed_settings(tmp_path, **extra):
    return GuardianSettings(
        _env_file=None,
        data_dir=tmp_path / "data",
        llm_provider="groq",
        groq_api_key=SecretStr(GROQ),
        **extra,
    )


def test_build_pool_shares_state_per_key_across_builds(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY_BACKUP_1", GROQ_B1)
    keys = LLMKeySettings(_env_file=None)
    settings = _keyed_settings(tmp_path)
    config = resilient.config_for(settings, "groq")
    assert config is not None
    built_with = []

    def build(cfg, s):
        built_with.append(cfg.api_key.get_secret_value())
        return Scripted()

    first = build_pool(config, settings, build=build, keys=keys).pool
    assert first is not None
    assert built_with == [GROQ, GROQ_B1]
    assert first.pacing == Pacing(7000, 25)
    first.cool(first.slots[0], 30)
    second = build_pool(config, settings, build=build, keys=keys).pool
    assert second is not None
    assert second.acquire() is second.slots[1]  # the cool-down survived the rebuild

    def broken(cfg, s):
        raise RuntimeError("bad " + cfg.api_key.get_secret_value())

    failed = build_pool(config, settings, build=broken, keys=keys)
    assert failed.pool is None
    assert [i for i, _ in failed.errors] == [0, 1]
    assert all(GROQ not in e and GROQ_B1 not in e for _, e in failed.errors)


def test_build_routes_pools_backup_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY_BACKUP_1", GROQ_B1)
    monkeypatch.setattr("guardian.investigation.runner.build_chat_model", lambda cfg, s: Scripted())
    routes, notes = build_routes(_keyed_settings(tmp_path))
    assert notes == []
    route = routes["fast"][0]
    assert [s.index for s in route.key_pool.slots] == [0, 1]
    assert route.key_pool is routes["deep"][0].key_pool  # one pool per provider
    assert route.method == "json_schema"


@pytest.fixture
def investigation_plan(tmp_path):
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path / "data", ai_enabled=True)
    with Database(settings.database_path) as db:
        seed_ai_scan(db, tmp_path / "juice-shop")
        yield build_plan(load_context(db, SCAN_ID, settings), top=10)


def test_runner_rotation_counts_once_and_records_key_index(investigation_plan, caplog):
    caplog.set_level(logging.DEBUG)
    plan = investigation_plan
    limits = LimitRegistry(Clock())
    k0 = FakeChat(lambda schema, text, n: Status(f"{TPM_429} {GROQ}", 429))
    k1 = FakeChat()
    groq = ProviderPool(
        "groq",
        "fake",
        [KeySlot(0, k0, secret=SecretStr(GROQ)), KeySlot(1, k1, secret=SecretStr(GROQ_B1))],
        limits=limits,
    )
    budget = Budget(len(plan.call_order()))
    budget.reserve(plan.call_order())
    route = ModelRoute("groq", "fake", k0, pool=groq)
    runner = AgentRunner({"fast": [route], "deep": [route]}, budget, sleep=lambda _s: None)
    report = runner.run(plan.input_for("code", "code-login"))
    assert report.status == "ok"
    assert budget.calls == 1
    assert [(c.key_index, c.status) for c in runner.calls] == [(0, "rate_limited"), (1, "ok")]
    dumped = repr(runner.calls) + caplog.text + report.model_dump_json()
    assert GROQ not in dumped
    assert GROQ_B1 not in dumped


def test_runner_gives_up_with_ai_unavailable(investigation_plan):
    plan = investigation_plan
    clock = Clock()
    limited = FakeChat(lambda schema, text, n: Status(TPM_429, 429))
    route = ModelRoute(
        "groq", "fake", limited, pool=pool("groq", limited, limits=LimitRegistry(clock))
    )
    budget = Budget(len(plan.call_order()))
    budget.reserve(plan.call_order())
    runner = AgentRunner({"fast": [route], "deep": [route]}, budget, sleep=clock.sleep)
    report = runner.run(plan.input_for("code", "code-login"))
    assert report.status == "ai_unavailable"
    assert "groq:" in report.reason
    assert budget.calls == 1
    assert clock.slept == [10.5]
    assert [c.status for c in runner.calls] == ["rate_limited", "rate_limited"]


def test_runner_repair_after_rotation(investigation_plan):
    plan = investigation_plan
    calls = {"n": 0}

    def responder(schema, text, n):
        calls["n"] += 1
        if calls["n"] == 1:
            return Status(TPM_429, 429)
        if calls["n"] == 2:
            return {"exploitability": "nope"}
        return good_answer(schema, text)

    chat = FakeChat(responder)
    groq = pool("groq", chat, chat, limits=LimitRegistry(Clock()))
    budget = Budget(len(plan.call_order()) + 1)
    budget.reserve(plan.call_order())
    route = ModelRoute("groq", "fake", chat, pool=groq)
    runner = AgentRunner({"fast": [route], "deep": [route]}, budget)
    report = runner.run(plan.input_for("code", "code-login"))
    assert report.status == "repaired"
    assert budget.calls == 2  # answer + repair; the 429 cost nothing
    assert [c.status for c in runner.calls] == ["rate_limited", "rejected", "ok"]


def test_make_plan_rotates_to_backup_key(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY_BACKUP_1", GROQ_B1)
    world = build_world(tmp_path / "juice-shop")
    case = world.case("jsonwebtoken")
    found = world.package_findings("jsonwebtoken")
    cands = generate_candidates(
        case,
        found,
        world.sbom,
        world.graph,
        world.index,
        world.assessments,
        FakeRegistry(),
        world.root,
    )
    by_key = {
        GROQ: Scripted(Status(TPM_429, 429)),
        GROQ_B1: Scripted(
            default=planner_module.PlanChoice(
                chosen_candidate_id=cands[0].id, rationale="Pick it.", confidence="high"
            )
        ),
    }
    monkeypatch.setattr(
        planner_module, "build_chat_model", lambda cfg, s: by_key[cfg.api_key.get_secret_value()]
    )
    slept = []
    monkeypatch.setattr(planner_module, "_sleep", slept.append)
    settings = _keyed_settings(tmp_path)
    plan = planner_module.make_plan(
        case, found, world.assessments, cands, settings=settings, no_ai=False
    )
    assert plan.decided_by == "llm"
    assert plan.llm_provider == "groq"
    assert plan.notes == ["answered by groq key #1 after groq rate_limited"]
    assert slept == []
    # the primary is still cooling for the next case: no second request to it
    planner_module.make_plan(case, found, world.assessments, cands, settings=settings, no_ai=False)
    assert by_key[GROQ].calls == 1
    assert all(GROQ not in n and GROQ_B1 not in n for n in plan.notes)


def test_make_plan_falls_back_to_other_provider(tmp_path, monkeypatch):
    world = build_world(tmp_path / "juice-shop")
    case = world.case("jsonwebtoken")
    found = world.package_findings("jsonwebtoken")
    cands = generate_candidates(
        case,
        found,
        world.sbom,
        world.graph,
        world.index,
        world.assessments,
        FakeRegistry(),
        world.root,
    )
    answer = planner_module.PlanChoice(
        chosen_candidate_id=cands[0].id, rationale="Pick it.", confidence="medium"
    )
    by_provider = {
        "groq": Scripted(default=RuntimeError("503 Service Unavailable")),
        "google": Scripted(default=answer),
    }
    monkeypatch.setattr(
        planner_module, "build_chat_model", lambda cfg, s: by_provider[cfg.provider]
    )
    settings = _keyed_settings(tmp_path, google_api_key=SecretStr(GOOGLE))
    plan = planner_module.make_plan(
        case, found, world.assessments, cands, settings=settings, no_ai=False
    )
    assert plan.llm_provider == "google"
    assert plan.notes == ["answered by google key #0 after groq overloaded"]
