"""Load one stored scan and turn it into bounded, redacted agent inputs.

Everything here runs on the calling thread before the graph starts (SQLite connections and the
code retriever's file cache are not shared with parallel branches). The output is a
:class:`InvestigationPlan`: the work items in priority order plus one :class:`AgentInput` per
(agent, subject), each carrying

* ``facts``: verified facts copied from deterministic tool output (shown as "Verified facts"),
* ``data``: the JSON the model sees inside a ``<data>`` block (bounded, secrets redacted),
* ``refs``: the only evidence IDs the model may cite (rule 7).
"""

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.models import (
    CodeDetails,
    CodeIndex,
    Component,
    EntryPoint,
    Finding,
    FindingKind,
    RepositoryProfile,
    RiskAssessment,
    Sbom,
    ScanRecord,
    VulnerabilityDetails,
)
from guardian.core.remediation_models import RemediationCandidate, RemediationCase
from guardian.indexing.code_retriever import CodeRetriever, CodeSnippet
from guardian.indexing.entry_points import is_test_path
from guardian.investigation.models import (
    AgentName,
    AreaKind,
    Fact,
    InvestigatorReport,
    SubjectKind,
)
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.storage.database import Database

DEFAULT_TOP = 10
MAX_ENTRY_POINTS = 15
MAX_AREAS = 20
MAX_PATHS = 5
MAX_SITES = 8
MAX_SNIPPETS = 2
MAX_SNIPPET_LINES = 40
MAX_SUMMARY_CHARS = 600
MAX_CALLERS = 8

FIXTURE_MARKERS = frozenset({"codefixes"})
"""Directories of intentional challenge snippets (OWASP Juice Shop's data/static/codefixes)."""
TEST_FIXTURE_DIRS = frozenset({"fixtures", "__fixtures__", "testdata", "__mocks__"})
DEV_DIRS = frozenset(
    {".github", ".gitlab", ".circleci", ".devcontainer", ".vscode", "scripts", "tools", "docs"}
)
_DEV_FILE = re.compile(
    r"^(gruntfile|gulpfile|webpack\.[\w.]*|rollup\.[\w.]*|vite\.[\w.]*|karma\.conf|"
    r"protractor\.conf|jest\.config|cypress\.config|eslint[\w.]*|\.eslintrc[\w.]*)",
    re.IGNORECASE,
)
_LINE_REF = re.compile(r"^(?P<path>[^\s:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")


# --- Verified path classification --------------------------------------------------------


def classify_path(path: str) -> AreaKind:
    """Deterministic, path-only classification (the *verified* side of the module map)."""
    parts = PurePosixPath(path).parts
    lowered = [p.lower() for p in parts]
    if any(p in FIXTURE_MARKERS for p in lowered[:-1]):
        return "challenge-fixture"
    if is_test_path(path) or any(p in TEST_FIXTURE_DIRS for p in lowered[:-1]):
        return "test"
    if (lowered and lowered[0] in DEV_DIRS) or (
        len(parts) == 1 and _DEV_FILE.match(parts[0]) is not None
    ):
        return "dev"
    return "prod"


def area_of(path: str) -> str:
    """Top-level directory, or the path up to a challenge-fixture marker directory."""
    parts = PurePosixPath(path).parts
    for i, part in enumerate(parts[:-1]):
        if part.lower() in FIXTURE_MARKERS:
            return "/".join(parts[: i + 1])
    return parts[0] if len(parts) > 1 else "(root files)"


# --- Evidence references -----------------------------------------------------------------


@dataclass(slots=True)
class RefSet:
    """The evidence IDs an agent may cite. ``path:line`` refs are also accepted when the line
    falls inside a snippet the agent was given."""

    exact: set[str] = field(default_factory=set)
    ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict)

    def add(self, *refs: str | None) -> None:
        self.exact.update(r for r in refs if r)

    def add_range(self, path: str, start: int, end: int) -> None:
        self.ranges.setdefault(path, []).append((start, end))
        self.exact.add(f"{path}:{start}-{end}")

    def merge(self, other: "RefSet") -> None:
        self.exact |= other.exact
        for path, spans in other.ranges.items():
            self.ranges.setdefault(path, []).extend(spans)

    def canonical(self, ref: object) -> str | None:  # noqa: PLR0911 - one return per rule
        """The accepted spelling of ``ref``, or None when it is not in the input."""
        if not isinstance(ref, str):
            return None
        text = ref.strip().strip("`'\"").strip()
        if not text or len(text) > 300:  # noqa: PLR2004
            return None
        if text in self.exact:
            return text
        lowered = {r.lower(): r for r in self.exact}
        if text.lower() in lowered:
            return lowered[text.lower()]
        if " " in text:  # "lib/x.ts:54 sign": a ref followed by a label
            return self.canonical(text.split(" ", 1)[0])
        match = _LINE_REF.match(text)
        if match is None:
            return None
        path, start = match["path"], int(match["start"])
        end = int(match["end"]) if match["end"] else start
        for lo, hi in self.ranges.get(path, ()):
            if lo <= start <= end <= hi:
                return f"{path}:{start}" if start == end else f"{path}:{start}-{end}"
        return None

    def sample(self, limit: int = 60) -> list[str]:
        return sorted(self.exact)[:limit]


# --- Inputs and work items ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WorkItem:
    """One subject the per-item investigators look at, in priority order."""

    kind: str  # "dependency" (npm vulnerability case/finding) or "code" (Semgrep finding)
    subject_kind: SubjectKind
    subject_id: str
    title: str
    score: float
    finding_ids: tuple[str, ...]
    component_ref: str | None = None
    candidate_ids: tuple[str, ...] = ()

    @property
    def agents(self) -> tuple[AgentName, ...]:
        if self.kind == "dependency":
            return ("dependency", "vulnerability")
        return ("code",)


@dataclass(slots=True)
class AgentInput:
    agent: AgentName
    subject_kind: SubjectKind
    subject_id: str
    title: str
    facts: list[Fact]
    data: dict[str, Any]
    refs: RefSet
    finding_ids: list[str] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanContext:
    record: ScanRecord
    profile: RepositoryProfile
    findings: list[Finding]
    sbom: Sbom | None
    index: CodeIndex | None
    graph: DependencyGraph
    assessments: dict[str, RiskAssessment]
    cases: list[RemediationCase]
    candidates: dict[str, list[RemediationCandidate]]
    retriever: CodeRetriever | None

    @property
    def scan_id(self) -> str:
        return self.record.id

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def score(self, finding_id: str) -> float:
        assessment = self.assessments.get(finding_id)
        return assessment.score if assessment is not None and assessment.score is not None else 0.0


@dataclass(slots=True)
class InvestigationPlan:
    context: ScanContext
    architect: AgentInput
    items: list[WorkItem]
    inputs: dict[tuple[str, str], AgentInput]
    """(agent, subject_id) -> input, for the per-item agents (not the correlator)."""

    def input_for(self, agent: str, subject_id: str) -> AgentInput:
        return self.inputs[(agent, subject_id)]

    def call_order(self) -> list[tuple[str, str]]:
        """Every planned LLM call in priority order: the architect, then per item its
        investigators followed by its correlator. The budget is reserved in this order."""
        order: list[tuple[str, str]] = [("architect", self.architect.subject_id)]
        for item in self.items:
            order.extend((agent, item.subject_id) for agent in item.agents)
            order.append(("correlator", item.subject_id))
        return order


# --- Loading -----------------------------------------------------------------------------


def load_context(db: Database, scan_id: str, settings: GuardianSettings) -> ScanContext:
    record = db.scans.get(scan_id)
    profile = db.scans.profile(scan_id)
    findings = db.findings.load(scan_id)
    sbom = db.sboms.load(scan_id)
    index = db.code.load(scan_id)
    graph = DependencyGraph(
        build_knowledge_graph(
            profile, sbom, findings, db.findings.changes(scan_id), code_index=index
        )
    )
    assessments = {a.finding_id: a for a in assess(findings, graph, index)}
    cases = [c for c in db.remediation.list() if c.scan_id == scan_id]
    candidates = {c.id: db.remediation.candidates(c.id) for c in cases}
    root = Path(record.repository_root)
    retriever = (
        CodeRetriever(root, index, max_file_bytes=settings.max_source_bytes)
        if index is not None and root.is_dir()
        else None
    )
    return ScanContext(
        record, profile, findings, sbom, index, graph, assessments, cases, candidates, retriever
    )


def build_plan(context: ScanContext, *, top: int = DEFAULT_TOP) -> InvestigationPlan:
    items = [*dependency_items(context, top), *code_items(context, top)]
    inputs: dict[tuple[str, str], AgentInput] = {}
    for item in items:
        if item.kind == "dependency":
            inputs[("dependency", item.subject_id)] = dependency_input(context, item)
            inputs[("vulnerability", item.subject_id)] = vulnerability_input(context, item)
        else:
            inputs[("code", item.subject_id)] = code_input(context, item)
    return InvestigationPlan(context, architect_input(context), items, inputs)


def dependency_items(context: ScanContext, top: int) -> list[WorkItem]:
    """Remediation cases of the scan; without cases, vulnerable components (top N by risk)."""
    items: list[WorkItem] = []
    if context.cases:
        for case in context.cases:
            found = [f for f in (context.finding(i) for i in case.finding_ids) if f is not None]
            if not found:
                continue
            items.append(
                WorkItem(
                    kind="dependency",
                    subject_kind="case",
                    subject_id=case.id,
                    title=case.title,
                    score=max(context.score(f.id) for f in found),
                    finding_ids=tuple(f.id for f in found),
                    component_ref=next((f.component_ref for f in found if f.component_ref), None),
                    candidate_ids=tuple(c.id for c in context.candidates.get(case.id, [])),
                )
            )
    else:
        by_component: dict[str, list[Finding]] = {}
        for f in context.findings:
            if f.kind is FindingKind.VULNERABILITY and f.component_ref:
                by_component.setdefault(f.component_ref, []).append(f)
        for ref, found in by_component.items():
            found.sort(key=lambda f: (-context.score(f.id), -f.severity.rank, f.id))
            details = found[0].details
            name = details.package if isinstance(details, VulnerabilityDetails) else ref
            version = details.version if isinstance(details, VulnerabilityDetails) else None
            items.append(
                WorkItem(
                    kind="dependency",
                    subject_kind="finding",
                    subject_id=found[0].id,
                    title=f"{name} {version or ''}".strip() + f" ({len(found)} advisories)",
                    score=context.score(found[0].id),
                    finding_ids=tuple(f.id for f in found),
                    component_ref=ref,
                )
            )
    items.sort(key=lambda i: (-i.score, i.subject_id))
    return items[:top]


def code_items(context: ScanContext, top: int) -> list[WorkItem]:
    code = [f for f in context.findings if f.kind is FindingKind.CODE]
    code.sort(key=lambda f: (-context.score(f.id), -f.severity.rank, f.path or "", f.id))
    return [
        WorkItem(
            kind="code",
            subject_kind="finding",
            subject_id=f.id,
            title=f.title,
            score=context.score(f.id),
            finding_ids=(f.id,),
        )
        for f in code[:top]
    ]


# --- Helpers -----------------------------------------------------------------------------


def _clip(text: str | None, limit: int = MAX_SUMMARY_CHARS) -> str | None:
    if text is None:
        return None
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def _at(path: str, line: int | None) -> str:
    return f"{path}:{line}" if line else path


def entry_ref(entry: EntryPoint) -> str:
    return _at(entry.path, entry.line)


def _snippet_json(snippets: Iterable[CodeSnippet], refs: RefSet) -> list[dict[str, Any]]:
    out = []
    for s in snippets:
        refs.add_range(s.path, s.start_line, s.end_line)
        out.append(
            {
                "ref": f"{s.path}:{s.start_line}-{s.end_line}",
                "first_line": s.start_line,
                "symbol_id": s.symbol_id,
                "truncated": s.truncated,
                "code": s.text,
            }
        )
    return out


def _risk_facts(context: ScanContext, finding_ids: Sequence[str]) -> list[Fact]:
    facts = []
    for fid in finding_ids:
        a = context.assessments.get(fid)
        if a is not None:
            score = f"{a.score:.1f}" if a.score is not None else "unknown"
            facts.append(
                Fact(label="Risk", value=f"{a.priority.value}, score {score}: {a.summary}", ref=fid)
            )
    return facts


def _entry_points(context: ScanContext, paths: Iterable[str]) -> list[EntryPoint]:
    if context.index is None:
        return []
    wanted = set(paths)
    return [e for e in context.index.entry_points if e.path in wanted]


# --- Repository Architect ----------------------------------------------------------------


def architect_input(context: ScanContext) -> AgentInput:
    profile, index = context.profile, context.index
    refs = RefSet()
    facts: list[Fact] = []
    files = [f.path for f in index.files] if index is not None else []
    areas: dict[str, Counter[str]] = {}
    for path in files:
        areas.setdefault(area_of(path), Counter())[classify_path(path)] += 1
    area_rows = []
    for name, kinds in sorted(areas.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))[
        :MAX_AREAS
    ]:
        verified_kind = kinds.most_common(1)[0][0]
        refs.add(f"area:{name}")
        sample = sorted(p for p in files if area_of(p) == name)[:4]
        refs.add(*sample)
        area_rows.append(
            {
                "ref": f"area:{name}",
                "files": sum(kinds.values()),
                "path_classification": verified_kind,
                "by_kind": dict(kinds),
                "sample_files": sample,
            }
        )
        facts.append(
            Fact(
                label=f"Area {name}",
                value=f"{sum(kinds.values())} indexed files; path rule says {verified_kind}",
                ref=f"area:{name}",
            )
        )
    entries = sorted(
        index.entry_points if index is not None else [],
        key=lambda e: (is_test_path(e.path), e.kind.value != "http-route", e.path, e.line or 0),
    )[:MAX_ENTRY_POINTS]
    for e in entries:
        refs.add(entry_ref(e))
    prod = sum(1 for p in files if classify_path(p) == "prod")
    tests = sum(1 for p in files if classify_path(p) == "test")
    languages = [f"{lang.name} ({lang.files} files)" for lang in profile.languages[:8]]
    ecosystems = [e.ecosystem.value for e in profile.ecosystems]
    frameworks = sorted({f.name for e in profile.ecosystems for f in e.frameworks})
    facts[:0] = [
        Fact(label="Repository", value=profile.name, ref=None),
        Fact(label="Languages", value=", ".join(languages) or "none detected"),
        Fact(label="Ecosystems", value=", ".join(ecosystems) or "none detected"),
        Fact(
            label="Indexed files",
            value=f"{len(files)} ({prod} production, {tests} test by path rule)",
        ),
        Fact(
            label="Entry points",
            value=str(len(index.entry_points)) if index is not None else "no code index",
        ),
    ]
    data = {
        "repository": profile.name,
        "languages": languages,
        "ecosystems": ecosystems,
        "frameworks": frameworks,
        "ci": [c.path for c in profile.ci][:10],
        "index_stats": {
            "files": len(files),
            "symbols": sum(len(f.symbols) for f in index.files) if index is not None else 0,
            "entry_points": len(index.entry_points) if index is not None else 0,
            "production_files_by_path_rule": prod,
            "test_files_by_path_rule": tests,
        },
        "areas": area_rows,
        "entry_points": [
            {"ref": entry_ref(e), "kind": e.kind.value, "detail": _clip(e.detail, 160)}
            for e in entries
        ],
    }
    return AgentInput(
        agent="architect",
        subject_kind="scan",
        subject_id=context.scan_id,
        title=f"Repository {profile.name}",
        facts=facts,
        data=data,
        refs=refs,
    )


def area_table(index: CodeIndex | None) -> list[dict[str, Any]]:
    """Verified module map rows for the UI (no AI)."""
    files = list(index.files) if index is not None else []
    rows: dict[str, dict[str, Any]] = {}
    for f in files:
        row = rows.setdefault(
            area_of(f.path),
            {"area": area_of(f.path), "files": 0, "by_kind": Counter(), "languages": Counter()},
        )
        row["files"] += 1
        row["by_kind"][classify_path(f.path)] += 1
        row["languages"][f.language.value] += 1
    return [
        {
            "area": row["area"],
            "files": row["files"],
            "path_classification": row["by_kind"].most_common(1)[0][0],
            "by_kind": dict(row["by_kind"]),
            "languages": dict(row["languages"]),
        }
        for row in sorted(rows.values(), key=lambda r: (-r["files"], r["area"]))
    ]


# --- Dependency and Vulnerability Investigators ------------------------------------------


def _usage(
    context: ScanContext, ref: str | None
) -> tuple[list[str], list[str], list[dict[str, str]]]:
    """(importing files, import sites, call sites) for a component."""
    index = context.index
    if index is None or ref is None:
        return [], [], []
    imports = sorted({(i.path, i.line) for i in index.imports if i.component_ref == ref})
    calls = sorted(
        {(c.path, c.line, c.member or c.callee) for c in index.calls if c.component_ref == ref}
    )
    files = sorted({p for p, _ in imports})
    return (
        files,
        [_at(p, line) for p, line in imports][:MAX_SITES],
        [{"ref": _at(p, line), "calls": member} for p, line, member in calls][:MAX_SITES],
    )


def dependency_input(context: ScanContext, item: WorkItem) -> AgentInput:
    refs = RefSet()
    ref = item.component_ref
    graph = context.graph
    component = _component(graph, ref) if ref is not None else None
    paths = graph.introduction_paths(ref, limit=MAX_PATHS) if ref else []
    path_rows = []
    for n, path in enumerate(paths, start=1):
        pid = f"path-{n}"
        refs.add(pid, *(c.ref for c in path), *(c.purl for c in path))
        path_rows.append({"ref": pid, "chain": [c.display_name for c in path]})
    files, import_sites, call_sites = _usage(context, ref)
    refs.add(*files, *import_sites, *(c["ref"] for c in call_sites))
    refs.add(ref, component.purl if component else None, *item.finding_ids)
    direct = bool(paths) and len(paths[0]) == 1
    dependents = (
        [c.display_name for c in graph.dependents_of(component.ref)][:10]
        if component is not None
        else []
    )
    scope = component.scope.value if component is not None else "unknown"
    name = component.display_name if component is not None else (ref or item.title)
    entries = _entry_points(context, files)
    for e in entries:
        refs.add(entry_ref(e))
    facts = [
        Fact(label="Component", value=name, ref=ref),
        Fact(label="Declared scope", value=scope, ref=ref),
        Fact(
            label="How it enters",
            value="direct dependency"
            if direct
            else (f"transitive, depth {len(paths[0])}" if paths else "no path from the repository"),
            ref="path-1" if paths else None,
        ),
        *(
            Fact(label=f"Path {n}", value=" > ".join(c.display_name for c in path), ref=f"path-{n}")
            for n, path in enumerate(paths, start=1)
        ),
        Fact(
            label="Imported by",
            value=", ".join(files[:8]) + (" ..." if len(files) > 8 else "")  # noqa: PLR2004
            if files
            else "no indexed file imports it",
        ),
    ]
    data = {
        "component": {"ref": ref, "name": name, "declared_scope": scope, "direct": direct},
        "dependency_paths": path_rows,
        "direct_dependents": dependents,
        "importing_files": files[:MAX_SITES],
        "import_sites": import_sites,
        "call_sites": call_sites,
        "importing_files_classification": {p: classify_path(p) for p in files[:MAX_SITES]},
        "entry_points_in_importing_files": [
            {"ref": entry_ref(e), "kind": e.kind.value, "detail": _clip(e.detail, 120)}
            for e in entries[:MAX_SITES]
        ],
    }
    return AgentInput(
        agent="dependency",
        subject_kind=item.subject_kind,
        subject_id=item.subject_id,
        title=item.title,
        facts=facts,
        data=data,
        refs=refs,
        finding_ids=list(item.finding_ids),
    )


def _component(graph: DependencyGraph, ref: str) -> Component | None:
    matches = [c for c in graph.components() if c.ref == ref]
    return matches[0] if matches else None


def vulnerability_input(context: ScanContext, item: WorkItem) -> AgentInput:
    refs = RefSet()
    advisories = []
    facts: list[Fact] = []
    findings = [f for f in (context.finding(i) for i in item.finding_ids) if f is not None]
    for f in findings:
        d = f.details
        if not isinstance(d, VulnerabilityDetails):
            continue
        refs.add(f.id, d.vulnerability_id, *d.aliases)
        ranges = [
            {k: v for k, v in r.model_dump().items() if v is not None} for r in d.affected_ranges
        ][:6]
        advisories.append(
            {
                "finding_id": f.id,
                "advisory_id": d.vulnerability_id,
                "aliases": d.aliases[:6],
                "severity": f.severity.value,
                "summary": _clip(d.summary),
                "cwe_ids": d.cwe_ids,
                "package": d.package,
                "installed_version": d.version,
                "affected_ranges": ranges,
                "fixed_versions": d.fixed_versions[:6],
            }
        )
        facts.append(
            Fact(
                label=f"Advisory {d.vulnerability_id}",
                value=f"{f.severity.value}: {_clip(d.summary, 200) or f.title}; "
                f"{d.package} {d.version or '?'} is in an affected range (OSV)",
                ref=f.id,
            )
        )
        if d.fixed_versions:
            facts.append(
                Fact(label="Fixed in (OSV)", value=", ".join(d.fixed_versions[:6]), ref=f.id)
            )
    files, import_sites, call_sites = _usage(context, item.component_ref)
    refs.add(*files, *import_sites, *(c["ref"] for c in call_sites), item.component_ref)
    snippets: list[CodeSnippet] = []
    if context.retriever is not None and findings:
        snippets = context.retriever.for_finding(
            findings[0], max_snippets=MAX_SNIPPETS, budget_lines=MAX_SNIPPET_LINES
        )
    entries = _entry_points(context, files)
    for e in entries:
        refs.add(entry_ref(e))
    facts.extend(_risk_facts(context, item.finding_ids[:3]))
    facts.append(
        Fact(
            label="Usage in code",
            value=f"{len(import_sites)} import site(s), {len(call_sites)} call site(s)"
            if files
            else "not imported by indexed code",
        )
    )
    data = {
        "advisories": advisories,
        "usage": {"import_sites": import_sites, "call_sites": call_sites},
        "snippets": _snippet_json(snippets, refs),
        "entry_points_in_importing_files": [
            {"ref": entry_ref(e), "kind": e.kind.value, "detail": _clip(e.detail, 120)}
            for e in entries[:MAX_SITES]
        ],
    }
    return AgentInput(
        agent="vulnerability",
        subject_kind=item.subject_kind,
        subject_id=item.subject_id,
        title=item.title,
        facts=facts,
        data=data,
        refs=refs,
        finding_ids=list(item.finding_ids),
    )


# --- Code Investigator -------------------------------------------------------------------


def code_input(context: ScanContext, item: WorkItem) -> AgentInput:
    refs = RefSet()
    finding = context.finding(item.subject_id)
    if finding is None:  # pragma: no cover - items are built from the findings
        msg = f"finding {item.subject_id} is not in the scan"
        raise KeyError(msg)
    d = finding.details
    location = _at(finding.path or "?", finding.start_line)
    refs.add(finding.id, location, finding.path)
    if finding.path and finding.start_line:
        refs.add_range(finding.path, finding.start_line, finding.end_line or finding.start_line)
    snippets: list[CodeSnippet] = []
    enclosing = None
    callers: list[str] = []
    if context.retriever is not None:
        snippets = context.retriever.for_finding(
            finding, max_snippets=2, budget_lines=MAX_SNIPPET_LINES
        )
        if finding.path and finding.start_line:
            enclosing = context.retriever.enclosing_symbol(finding.path, finding.start_line)
    if enclosing is not None:
        refs.add(enclosing.id)
        for caller in context.graph.callers_of_symbol(enclosing.id)[:MAX_CALLERS]:
            refs.add(caller)
            callers.append(caller)
    entries = _entry_points(context, [finding.path] if finding.path else [])
    for e in entries:
        refs.add(entry_ref(e))
    path_kind = classify_path(finding.path) if finding.path else "unknown"
    rule = d.rule_id if isinstance(d, CodeDetails) else finding.tool
    facts = [
        Fact(label="Rule", value=rule, ref=finding.id),
        Fact(label="Severity", value=finding.severity.value, ref=finding.id),
        Fact(label="Location", value=location, ref=location),
        Fact(label="Path classification", value=path_kind, ref=finding.path),
    ]
    if enclosing is not None:
        facts.append(
            Fact(label="Enclosing symbol", value=enclosing.qualified_name, ref=enclosing.id)
        )
    if entries:
        facts.append(
            Fact(
                label="Entry points in this file",
                value=", ".join(f"{e.detail} ({entry_ref(e)})" for e in entries[:4]),
            )
        )
    facts.extend(_risk_facts(context, [finding.id]))
    data = {
        "finding": {
            "id": finding.id,
            "rule_id": rule,
            "message": _clip(d.message if isinstance(d, CodeDetails) else finding.title),
            "severity": finding.severity.value,
            "cwe_ids": d.cwe_ids if isinstance(d, CodeDetails) else [],
            "owasp": d.owasp if isinstance(d, CodeDetails) else [],
            "location": location,
            "path_classification": path_kind,
        },
        "snippets": _snippet_json(snippets, refs),
        "enclosing_symbol": (
            {"ref": enclosing.id, "name": enclosing.qualified_name, "kind": enclosing.kind.value}
            if enclosing is not None
            else None
        ),
        "callers": callers,
        "entry_points_in_file": [
            {"ref": entry_ref(e), "kind": e.kind.value, "detail": _clip(e.detail, 120)}
            for e in entries[:MAX_SITES]
        ],
    }
    return AgentInput(
        agent="code",
        subject_kind="finding",
        subject_id=finding.id,
        title=finding.title,
        facts=facts,
        data=data,
        refs=refs,
        finding_ids=[finding.id],
    )


# --- Evidence Correlator -----------------------------------------------------------------


def correlator_input(
    plan: InvestigationPlan, item: WorkItem, reports: Sequence[InvestigatorReport]
) -> AgentInput:
    """Verified facts are copied from the item's investigator inputs (never generated); the
    other agents' assessments are passed as inference to be weighed, not as facts."""
    refs = RefSet()
    facts: list[Fact] = []
    seen: set[tuple[str, str]] = set()
    for agent in item.agents:
        sub = plan.input_for(agent, item.subject_id)
        refs.merge(sub.refs)
        for fact in sub.facts:
            if (fact.label, fact.value) not in seen:
                seen.add((fact.label, fact.value))
                facts.append(fact)
    candidates = [
        {
            "id": c.id,
            "action": c.action_type.value,
            "component": c.component,
            "from_version": c.from_version,
            "to_version": c.to_version,
            "fixes_finding_ids": c.fixes_finding_ids,
            "semver_jump": c.semver_jump.value,
        }
        for c in plan.context.candidates.get(item.subject_id, [])
    ]
    data = {
        "verified_facts": [f.model_dump(exclude={"source"}) for f in facts],
        "investigator_assessments_ai_inference": {
            r.agent: r.assessment if r.assessment is not None else f"ai_unavailable: {r.reason}"
            for r in reports
        },
        "candidates": candidates,
    }
    return AgentInput(
        agent="correlator",
        subject_kind=item.subject_kind,
        subject_id=item.subject_id,
        title=item.title,
        facts=facts,
        data=data,
        refs=refs,
        finding_ids=list(item.finding_ids),
        candidate_ids=list(item.candidate_ids),
    )
