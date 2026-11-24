"""Investigation graph (Milestone 8): the AI investigators as an explicit LangGraph workflow.

```
load_scan --Send--> architect                      (one per scan)
          --Send--> dependency, vulnerability       (one each per npm case / vulnerable package)
          --Send--> code                            (one per top-N Semgrep finding)
all of them --> gather --Send--> correlate          (one per item)
correlate --> persist --> END
```

Each investigator is a direct structured-output model call (no tool loop): the inputs are already
bounded and fixed, so an agent loop would only add ways to wander. No interrupts: the human step
is the remediation graph's ``await_decision``; investigators only explain.

Threading: LangGraph runs a superstep's tasks in parallel threads. Nothing here touches SQLite
from those branches: the scan is loaded into an :class:`InvestigationPlan` on the calling thread
before the graph starts, and ``persist`` opens its own connection (sqlite connections are
thread-bound) and writes the run and every report in one transaction.
"""

import contextlib
import operator
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypeAlias, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Send

from guardian.core.config import GuardianSettings
from guardian.investigation.context import (
    DEFAULT_TOP,
    InvestigationPlan,
    WorkItem,
    build_plan,
    correlator_input,
    load_context,
)
from guardian.investigation.models import (
    InvestigationRun,
    InvestigatorReport,
    TraceEvent,
)
from guardian.investigation.runner import (
    DEFAULT_MAX_CALLS,
    AgentRunner,
    Budget,
    Routes,
    Sleep,
    build_routes,
)
from guardian.storage.database import Database

InvestigationGraph: TypeAlias = CompiledStateGraph[Any, Any, Any, Any]
EventSink = Callable[[TraceEvent], None]
DEFAULT_CONCURRENCY = 2
"""Parallel model calls; free-tier provider rate limits punish wider fan-out with 429s."""
Persist = Callable[[InvestigationRun, list[InvestigatorReport]], None]


class InvestigationState(TypedDict, total=False):
    reports: Annotated[list[InvestigatorReport], operator.add]
    trace: Annotated[list[TraceEvent], operator.add]
    item: WorkItem
    """Only in a Send payload: the item a per-item branch works on."""
    item_reports: list[InvestigatorReport]
    """Only in the correlate Send payload."""
    run: InvestigationRun


def _now() -> datetime:
    return datetime.now(UTC)


def new_run_id() -> str:
    return f"ir_{secrets.token_hex(6)}"


class _Tracer:
    def __init__(self, sink: EventSink | None) -> None:
        self.sink = sink
        self._lock = threading.Lock()

    def event(self, node: str, event: str, **fields: Any) -> TraceEvent:  # noqa: ANN401
        ev = TraceEvent(node=node, event=event, at=_now(), **fields)  # ty: ignore[invalid-argument-type]
        if self.sink is not None:
            # A failing progress display must not break the run.
            with self._lock, contextlib.suppress(Exception):
                self.sink(ev)
        return ev


def build_investigation_graph(  # noqa: C901, PLR0913 - node closures over one plan
    plan: InvestigationPlan,
    runner: AgentRunner,
    *,
    run_id: str,
    persist: Persist,
    on_event: EventSink | None = None,
    notes: list[str] | None = None,
) -> InvestigationGraph:
    tracer = _Tracer(on_event)
    started_at = _now()

    def load_scan(state: InvestigationState) -> dict[str, Any]:  # noqa: ARG001
        start = tracer.event("load_scan", "started")
        detail = (
            f"{len(plan.context.findings)} findings; "
            f"{sum(1 for i in plan.items if i.kind == 'dependency')} dependency items, "
            f"{sum(1 for i in plan.items if i.kind == 'code')} code findings selected"
        )
        return {"trace": [start, tracer.event("load_scan", "finished", detail=detail)]}

    def fan_out(state: InvestigationState) -> list[Send]:  # noqa: ARG001
        sends = [Send("architect", {})]
        for item in plan.items:
            sends.extend(Send(agent, {"item": item}) for agent in item.agents)
        return sends

    def agent_node(agent: str) -> Callable[[InvestigationState], dict[str, Any]]:
        def node(state: InvestigationState) -> dict[str, Any]:
            item = state.get("item")
            inp = plan.architect if item is None else plan.input_for(agent, item.subject_id)
            start = tracer.event(agent, "started", agent=agent, subject_id=inp.subject_id)
            report = runner.run(inp)
            done = tracer.event(
                agent,
                "finished",
                agent=agent,
                subject_id=inp.subject_id,
                status=report.status,
                detail=report.reason,
            )
            return {"reports": [report], "trace": [start, done]}

        node.__name__ = agent
        return node

    def gather(state: InvestigationState) -> dict[str, Any]:
        reports = state.get("reports", [])
        detail = f"{len(reports)} investigator reports"
        return {"trace": [tracer.event("gather", "finished", detail=detail)]}

    def to_correlate(state: InvestigationState) -> list[Send] | str:
        if not plan.items:
            return "persist"
        reports = state.get("reports", [])
        return [
            Send(
                "correlate",
                {
                    "item": item,
                    "item_reports": [r for r in reports if r.subject_id == item.subject_id],
                },
            )
            for item in plan.items
        ]

    def correlate(state: InvestigationState) -> dict[str, Any]:
        item = state["item"]
        inp = correlator_input(plan, item, state.get("item_reports", []))
        start = tracer.event("correlate", "started", agent="correlator", subject_id=item.subject_id)
        report = runner.run(inp)
        done = tracer.event(
            "correlate",
            "finished",
            agent="correlator",
            subject_id=item.subject_id,
            status=report.status,
            detail=report.reason,
        )
        return {"reports": [report], "trace": [start, done]}

    def persist_node(state: InvestigationState) -> dict[str, Any]:
        reports = state.get("reports", [])
        statuses = {r.status for r in reports}
        ai_used = runner.routes is not None
        status = "completed" if not ai_used or statuses <= {"ok", "repaired"} else "partial"
        if ai_used and reports and statuses == {"ai_unavailable"}:
            status = "partial"
        done = tracer.event("persist", "finished", detail=f"{len(reports)} reports stored")
        run = InvestigationRun(
            id=run_id,
            scan_id=plan.context.scan_id,
            started_at=started_at,
            finished_at=_now(),
            status=status,
            ai_enabled=ai_used,
            max_calls=runner.budget.max_calls,
            provider_calls=list(runner.calls),
            trace=[*state.get("trace", []), done],
            notes=list(notes or []),
        )
        persist(run, reports)
        return {"run": run, "trace": [done]}

    graph = StateGraph(InvestigationState)  # ty: ignore[invalid-argument-type]
    graph.add_node("load_scan", load_scan)
    for agent in ("architect", "dependency", "vulnerability", "code"):
        graph.add_node(agent, agent_node(agent))  # ty: ignore[invalid-argument-type]
        graph.add_edge(agent, "gather")
    graph.add_node("gather", gather)
    graph.add_node("correlate", correlate)
    graph.add_node("persist", persist_node)
    graph.add_edge(START, "load_scan")
    graph.add_conditional_edges(
        "load_scan", fan_out, ["architect", "dependency", "vulnerability", "code"]
    )
    graph.add_conditional_edges("gather", to_correlate, ["correlate", "persist"])
    graph.add_edge("correlate", "persist")
    graph.add_edge("persist", END)
    return graph.compile()


def database_persist(path: Path) -> Persist:
    """Write on a connection opened by the persisting thread itself."""

    def persist(run: InvestigationRun, reports: list[InvestigatorReport]) -> None:
        with Database(path) as db:
            db.investigations.save_run(run, reports)

    return persist


def run_investigation(  # noqa: PLR0913 - switches plus test injection points
    db: Database,
    settings: GuardianSettings,
    scan_id: str,
    *,
    top: int = DEFAULT_TOP,
    no_ai: bool = False,
    max_calls: int = DEFAULT_MAX_CALLS,
    routes: Routes | None = None,
    on_event: EventSink | None = None,
    sleep: Sleep | None = None,
    persist: Persist | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> tuple[InvestigationRun, list[InvestigatorReport]]:
    """Load the scan (calling thread), run the graph, persist once; returns the stored run."""
    plan = build_plan(load_context(db, scan_id, settings), top=top)
    notes: list[str] = []
    if no_ai:
        chosen: Routes | None = None
        reason = "AI disabled (--no-ai)"
    elif routes is not None:
        chosen, reason = routes, "no LLM provider configured"
    elif not settings.ai_enabled:
        chosen, reason = None, "AI disabled (GUARDIAN_AI_ENABLED=false)"
    else:
        chosen, notes = build_routes(settings)
        reason = "no LLM provider configured"
        if not chosen["fast"] and not chosen["deep"]:
            chosen = None
    budget = Budget(max_calls)
    budget.reserve(plan.call_order())
    runner = AgentRunner(chosen, budget, unavailable_reason=reason)
    if sleep is not None:
        runner.sleep = sleep
    graph = build_investigation_graph(
        plan,
        runner,
        run_id=new_run_id(),
        persist=persist or database_persist(db.path),
        on_event=on_event,
        notes=[*notes, *([reason] if chosen is None else [])],
    )
    result = graph.invoke(
        {"reports": [], "trace": []}, config={"max_concurrency": max(1, concurrency)}
    )
    return result["run"], list(result["reports"])
