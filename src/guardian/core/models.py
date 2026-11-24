"""Guardian's internal data models.

Paths stored on models are repository-relative POSIX strings so that profiles serialize
identically on every platform and never leak the scanning machine's directory layout.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class Ecosystem(StrEnum):
    PYTHON = "python"
    NODE = "node"
    JAVA = "java"
    CONTAINER = "container"


class ManifestKind(StrEnum):
    MANIFEST = "manifest"
    """Declares direct dependencies (package.json, pyproject.toml, pom.xml)."""
    LOCKFILE = "lockfile"
    """Pins the resolved dependency tree (poetry.lock, package-lock.json)."""
    CONTAINER = "container"
    """Container build or composition file (Dockerfile, compose.yaml)."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ManifestFile(_Frozen):
    path: str
    ecosystem: Ecosystem
    kind: ManifestKind
    package_manager: str | None = None


class Framework(_Frozen):
    name: str
    ecosystem: Ecosystem
    evidence: str = Field(description="Repository-relative path where the framework was detected")


class EcosystemProfile(_Frozen):
    ecosystem: Ecosystem
    adapter: str
    package_managers: list[str] = Field(default_factory=list)
    manifests: list[ManifestFile] = Field(default_factory=list)
    frameworks: list[Framework] = Field(default_factory=list)
    declared_dependencies: list[str] = Field(
        default_factory=list,
        description="Normalized names of dependencies declared directly in manifests",
    )
    metadata: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Adapter-specific facts, e.g. container base images",
    )
    warnings: list[str] = Field(default_factory=list)

    @property
    def lockfiles(self) -> list[ManifestFile]:
        return [m for m in self.manifests if m.kind is ManifestKind.LOCKFILE]


class LanguageStat(_Frozen):
    name: str
    files: int
    bytes: int


class CIConfig(_Frozen):
    provider: str
    path: str


class GitInfo(_Frozen):
    is_repository: bool
    branch: str | None = None
    head_commit: str | None = None
    is_dirty: bool | None = None
    error: str | None = None


class RepositoryProfile(_Frozen):
    name: str
    root: str = Field(description="Absolute path of the profiled repository")
    profiled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_files: int
    total_bytes: int
    skipped_symlinks: int = 0
    truncated: bool = Field(
        default=False,
        description="True when the file limit was reached and the walk stopped early",
    )
    languages: list[LanguageStat] = Field(default_factory=list)
    ecosystems: list[EcosystemProfile] = Field(default_factory=list)
    ci: list[CIConfig] = Field(default_factory=list)
    git: GitInfo
    warnings: list[str] = Field(default_factory=list)

    @property
    def primary_language(self) -> str | None:
        return self.languages[0].name if self.languages else None

    def ecosystem(self, ecosystem: Ecosystem) -> EcosystemProfile | None:
        return next((e for e in self.ecosystems if e.ecosystem is ecosystem), None)

    @property
    def manifest_paths(self) -> set[str]:
        return {m.path for e in self.ecosystems for m in e.manifests}

    @property
    def declared_dependencies(self) -> dict[Ecosystem, set[str]]:
        return {e.ecosystem: set(e.declared_dependencies) for e in self.ecosystems}


# --- Dependency intelligence -----------------------------------------------------------


class DependencyScope(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    EXCLUDED = "excluded"
    UNKNOWN = "unknown"


class Component(_Frozen):
    """A software component (package) normalized from an SBOM."""

    ref: str = Field(description="Stable identifier within one SBOM (CycloneDX bom-ref)")
    name: str
    group: str | None = None
    version: str | None = None
    purl: str | None = None
    purl_type: str | None = Field(default=None, description="purl type, e.g. pypi, npm, maven")
    ecosystem: Ecosystem | None = None
    component_type: str = "library"
    scope: DependencyScope = DependencyScope.UNKNOWN
    licenses: list[str] = Field(default_factory=list)
    declared_in: list[str] = Field(
        default_factory=list, description="Repository-relative manifests declaring the component"
    )
    direct: bool | None = Field(
        default=None, description="Direct dependency of the repository; None when unknown"
    )

    @property
    def display_name(self) -> str:
        name = f"{self.group}/{self.name}" if self.group else self.name
        return f"{name}@{self.version}" if self.version else name


class DirectSource(StrEnum):
    """How Guardian determined which components are direct dependencies."""

    SBOM = "sbom"
    """The SBOM links its root component to the direct dependencies."""
    MANIFEST = "manifest"
    """Matched against dependencies Guardian parsed from the repository's manifests."""
    SBOM_AND_MANIFEST = "sbom+manifest"
    """Union of both, e.g. a polyglot repository where the SBOM links only one ecosystem."""
    GRAPH_INFERENCE = "graph-inference"
    """Components no other component depends on. Misses packages that are also transitive."""
    UNKNOWN = "unknown"


class DependencyEdge(_Frozen):
    source: str
    target: str


class Sbom(_Frozen):
    spec_version: str
    generator: str
    root_ref: str | None = None
    components: list[Component] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    direct_source: DirectSource = DirectSource.UNKNOWN
    warnings: list[str] = Field(default_factory=list)

    @property
    def direct_components(self) -> list[Component]:
        return [c for c in self.components if c.direct]


# --- Security findings and evidence ----------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Higher is more severe; UNKNOWN sorts between LOW and MEDIUM so it is not buried."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """CVSS v3/v4 qualitative rating scale."""
        if score >= 9.0:  # noqa: PLR2004
            return cls.CRITICAL
        if score >= 7.0:  # noqa: PLR2004
            return cls.HIGH
        if score >= 4.0:  # noqa: PLR2004
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.UNKNOWN: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingKind(StrEnum):
    VULNERABILITY = "vulnerability"
    """A known vulnerability in a dependency (OSV-Scanner)."""
    CODE = "code"
    """An insecure code pattern (Semgrep)."""
    CHANGE = "change"
    """A security-relevant repository change (git history)."""


class EvidenceKind(StrEnum):
    ADVISORY = "advisory"
    MANIFEST = "manifest"
    TOOL_MATCH = "tool-match"
    SOURCE_LOCATION = "source-location"
    GIT_CHANGE = "git-change"
    REPOSITORY_CONFIG = "repository-config"
    CODE_USAGE = "code-usage"
    """Where the repository's own source imports or calls into a component (phase 4)."""


class Evidence(_Frozen):
    kind: EvidenceKind
    tool: str
    summary: str
    path: str | None = None
    line: int | None = None
    commit: str | None = None
    url: str | None = None


class AffectedRange(_Frozen):
    """One OSV ``SEMVER``/``ECOSYSTEM`` affected interval for the finding's package.

    ``introduced`` is inclusive (None or "0" = since the beginning); ``fixed`` is exclusive and
    ``last_affected`` inclusive. Both None means every later version is affected.
    """

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class VulnerabilityDetails(_Frozen):
    kind: Literal[FindingKind.VULNERABILITY] = FindingKind.VULNERABILITY
    vulnerability_id: str
    summary: str | None = None
    aliases: list[str] = Field(default_factory=list)
    package: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    cvss_score: float | None = None
    cvss_vectors: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(
        default_factory=list, description="Every fixed release across all branches"
    )
    recommended_fix: str | None = Field(
        default=None, description="First fixed release in the range containing this version"
    )
    published: datetime | None = None
    references: list[str] = Field(default_factory=list)
    affected_ranges: list[AffectedRange] = Field(
        default_factory=list,
        description="OSV affected intervals for this package; empty in scans stored earlier",
    )

    @property
    def fix_available(self) -> bool:
        return bool(self.fixed_versions)


class CodeDetails(_Frozen):
    kind: Literal[FindingKind.CODE] = FindingKind.CODE
    rule_id: str
    message: str
    confidence: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    category: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ChangeCategory(StrEnum):
    LOCKFILE_ONLY = "lockfile-only-change"
    MANIFEST = "dependency-manifest-change"
    CI_CONFIG = "ci-config-change"
    CONTAINER = "container-config-change"
    SENSITIVE_FILE = "sensitive-file-committed"
    SECURITY_CODE = "security-sensitive-code-change"
    UNCOMMITTED = "uncommitted-dependency-change"


class ChangeDetails(_Frozen):
    kind: Literal[FindingKind.CHANGE] = FindingKind.CHANGE
    category: ChangeCategory
    commit: str | None = Field(default=None, description="None for uncommitted changes")
    author: str | None = None
    authored_at: datetime | None = None
    subject: str | None = None
    paths: list[str] = Field(default_factory=list)


FindingDetails = Annotated[
    VulnerabilityDetails | CodeDetails | ChangeDetails, Field(discriminator="kind")
]


class Finding(_Frozen):
    id: str = Field(description="Stable across scans for the same underlying issue")
    kind: FindingKind
    title: str
    severity: Severity
    tool: str
    component_ref: str | None = None
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    introduced_by: str | None = Field(default=None, description="Commit that introduced it")
    symbol_id: str | None = Field(
        default=None, description="Innermost indexed symbol enclosing the finding (phase 4)"
    )
    details: FindingDetails
    evidence: list[Evidence] = Field(default_factory=list)

    @property
    def location(self) -> str | None:
        if self.path is None:
            return None
        return f"{self.path}:{self.start_line}" if self.start_line else self.path


class FileChange(_Frozen):
    path: str
    status: str = Field(description="git name-status letter: A, M, D, T ...")


class ChangeRecord(_Frozen):
    commit: str
    author: str | None = None
    authored_at: datetime | None = None
    subject: str | None = None
    files: list[FileChange] = Field(default_factory=list)


# --- Risk assessment -------------------------------------------------------------------
#
# Guardian heuristic (not an industry standard): R = 0.35 S + 0.25 E + 0.20 X + 0.10 P + 0.10 F
# with each factor in [0, 1]. Unknown factors stay unknown (value None) and are excluded from
# the weighted mean instead of counting as zero; `known_weight` says how much evidence the
# score rests on.


class RiskFactorName(StrEnum):
    SEVERITY = "severity"  # S: vulnerability / rule severity
    EXPOSURE = "exposure"  # E: exposure and dependency context (direct, entry points, scope)
    EXPLOITABILITY = "exploitability"  # X: evidence of exploitability (AI investigation, phase 5)
    REACHABILITY = "reachability"  # P: potential reachability (imported / called / in a route)
    FIX = "fix"  # F: fix availability and remediation context (higher = easier to act on)


RISK_WEIGHTS: dict[RiskFactorName, float] = {
    RiskFactorName.SEVERITY: 0.35,
    RiskFactorName.EXPOSURE: 0.25,
    RiskFactorName.EXPLOITABILITY: 0.20,
    RiskFactorName.REACHABILITY: 0.10,
    RiskFactorName.FIX: 0.10,
}


class RiskFactor(_Frozen):
    name: RiskFactorName
    weight: float
    value: float | None = Field(default=None, ge=0, le=1, description="None = unknown")
    rationale: str


class Priority(StrEnum):
    P1 = "P1"  # act now
    P2 = "P2"  # schedule soon
    P3 = "P3"  # backlog
    P4 = "P4"  # informational

    @property
    def label(self) -> str:
        """Bucket word for Jira and report text: P1 critical, P2 high, P3 medium, P4 low."""
        return _PRIORITY_LABELS[self]

    @classmethod
    def parse(cls, text: str) -> "Priority":
        """Accept either spelling: ``P2``, ``p2``, ``HIGH`` or ``high`` all give P2."""
        key = text.strip().upper()
        for priority, label in _PRIORITY_LABELS.items():
            if key in {priority.value, label.upper()}:
                return priority
        msg = f"Unknown priority {text!r}; use P1-P4 or critical/high/medium/low"
        raise ValueError(msg)


_PRIORITY_LABELS = {
    Priority.P1: "critical",
    Priority.P2: "high",
    Priority.P3: "medium",
    Priority.P4: "low",
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskAssessment(_Frozen):
    finding_id: str
    score: float | None = Field(
        default=None, ge=0, le=100, description="Weighted mean of known factors x 100"
    )
    known_weight: float = Field(ge=0, le=1, description="Sum of weights of known factors")
    confidence: Confidence
    priority: Priority
    factors: list[RiskFactor]
    summary: str = Field(description="One sentence a reviewer can read, e.g. why P1")


# --- Codebase index (phase 4) ----------------------------------------------------------
#
# Paths are repository-relative POSIX strings. Lines are 1-based and inclusive. A symbol id
# is "<path>::<qualified_name>", e.g. "app/server.py::UserService.login".


class SourceLanguage(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    TSX = "tsx"


class SymbolKind(StrEnum):
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"


class Span(_Frozen):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


class Symbol(_Frozen):
    id: str
    name: str
    qualified_name: str = Field(description="Dotted path inside the file, e.g. 'Cls.method'")
    kind: SymbolKind
    path: str
    span: Span
    parent_id: str | None = Field(default=None, description="Enclosing class/function symbol")
    decorators: list[str] = Field(
        default_factory=list,
        description="Decorator/annotation source text, e.g. 'app.route(\"/x\")'",
    )
    exported: bool | None = Field(default=None, description="JS/TS export; None for Python")


class ImportStyle(StrEnum):
    IMPORT = "import"  # Python `import a.b [as c]`
    FROM = "from"  # Python `from a import b`
    ES = "es"  # JS/TS `import x from "m"`, `export ... from "m"`
    REQUIRE = "require"  # JS `require("m")`
    DYNAMIC = "dynamic"  # JS `import("m")`, Python `importlib.import_module("m")`/`__import__`


class ImportedName(_Frozen):
    name: str = Field(description="Imported member; '*' for star, 'default' for JS default")
    alias: str | None = None

    @property
    def local_name(self) -> str:
        return self.alias or self.name


class ImportRef(_Frozen):
    """One import statement exactly as written; resolution happens separately."""

    path: str
    line: int = Field(ge=1)
    module: str = Field(description="Specifier as written: 'a.b', '.models', './x', 'express'")
    style: ImportStyle
    level: int = Field(default=0, ge=0, description="Python relative-import dots")
    names: list[ImportedName] = Field(
        default_factory=list,
        description="Bound names. Empty for `import a.b` (binds 'a') or side-effect imports.",
    )
    module_alias: str | None = Field(
        default=None, description="`import a.b as c` / `import * as c` / `c = require(...)`"
    )


class CallRef(_Frozen):
    """A call site with its callee as written (e.g. 'os.system', 'self.save', 'eval')."""

    path: str
    line: int = Field(ge=1)
    callee: str = Field(description="Callee source text, whitespace-normalized, max 200 chars")
    caller_id: str | None = Field(
        default=None, description="Enclosing symbol; None at module level"
    )
    literal_args: list[str] = Field(
        default_factory=list,
        description="Values of the first 3 positional string-literal arguments (max 100 chars "
        "each), e.g. ['/api/users'] for app.get('/api/users', h); non-literals are skipped",
    )


class FileIndex(_Frozen):
    path: str
    language: SourceLanguage
    sha256: str
    size: int
    line_count: int
    symbols: list[Symbol] = Field(default_factory=list)
    imports: list[ImportRef] = Field(default_factory=list)
    calls: list[CallRef] = Field(default_factory=list)
    has_parse_errors: bool = False


class ImportTarget(StrEnum):
    INTERNAL = "internal"  # a file in this repository
    EXTERNAL = "external"  # a third-party package
    STDLIB = "stdlib"  # Python stdlib / Node built-in
    UNRESOLVED = "unresolved"


class ResolvedImport(_Frozen):
    path: str
    line: int
    module: str
    style: ImportStyle
    target: ImportTarget
    target_path: str | None = Field(default=None, description="INTERNAL: the imported file")
    package: str | None = Field(
        default=None, description="EXTERNAL/STDLIB: distribution or module name, e.g. 'pyyaml'"
    )
    component_ref: str | None = Field(default=None, description="Matching SBOM component")


class ResolvedCall(_Frozen):
    path: str
    line: int
    callee: str
    caller_id: str | None = None
    target_symbol_id: str | None = Field(default=None, description="Internal callee, if known")
    package: str | None = Field(default=None, description="External/stdlib package called into")
    member: str | None = Field(
        default=None, description="Dotted member inside the package, e.g. 'load' for yaml.load"
    )
    component_ref: str | None = None


class EntryPointKind(StrEnum):
    MAIN_GUARD = "main-guard"  # Python `if __name__ == "__main__":`
    PACKAGE_MAIN = "package-main"  # package.json "main"/"bin", pyproject [project.scripts]
    SERVER_LISTEN = "server-listen"  # app.listen(...), uvicorn.run(...), app.run(...)
    HTTP_ROUTE = "http-route"  # @app.route / @router.get / app.get("/x", ...)
    DUNDER_MAIN = "dunder-main"  # __main__.py


class EntryPoint(_Frozen):
    path: str
    line: int | None = None
    kind: EntryPointKind
    detail: str = Field(description="Human-readable, e.g. 'GET /api/users' or 'bin: guardian'")
    symbol_id: str | None = None


class CodeIndex(_Frozen):
    files: list[FileIndex] = Field(default_factory=list)
    imports: list[ResolvedImport] = Field(default_factory=list)
    calls: list[ResolvedCall] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    skipped_files: dict[str, int] = Field(
        default_factory=dict, description="Reason -> count, e.g. {'too-large': 3, 'minified': 9}"
    )
    warnings: list[str] = Field(default_factory=list)


# --- Knowledge graph -------------------------------------------------------------------


class NodeType(StrEnum):
    REPOSITORY = "repository"
    FILE = "file"
    COMPONENT = "component"
    FINDING = "finding"
    CHANGE = "change"
    SYMBOL = "symbol"


class Relation(StrEnum):
    CONTAINS = "CONTAINS"
    DEPENDS_ON = "DEPENDS_ON"
    DECLARED_IN = "DECLARED_IN"
    AFFECTED_BY = "AFFECTED_BY"
    """component -> vulnerability finding; file -> code finding."""
    INTRODUCED_BY = "INTRODUCED_BY"
    """finding -> change (commit) that last modified the flagged lines."""
    MODIFIES = "MODIFIES"
    """change -> file."""
    DEFINES = "DEFINES"
    """file -> symbol; class symbol -> method symbol."""
    IMPORTS = "IMPORTS"
    """file -> file (internal) or file -> component (third-party)."""
    CALLS = "CALLS"
    """symbol|file -> symbol (internal) or symbol|file -> component (third-party)."""


# --- Scans -----------------------------------------------------------------------------


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    """Finished, but at least one analysis step was skipped or failed."""
    FAILED = "failed"


class ToolRunSummary(_Frozen):
    tool: str
    status: str
    exit_code: int | None = None
    duration_seconds: float = 0.0
    error: str | None = None


class ScanRecord(_Frozen):
    id: str
    repository_name: str
    repository_root: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None = None
    git_branch: str | None = None
    git_commit: str | None = None
    component_count: int = 0
    finding_count: int = 0
    tool_runs: list[ToolRunSummary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# --- Remediation (Day 2) ---------------------------------------------------------------
#
# Remediation models live in `core/remediation_models.py` (which imports from this module) and
# are re-exported here lazily: an eager import at the bottom of this file would fail whenever
# `remediation_models` is imported first. Type checkers see the real names via TYPE_CHECKING.

if TYPE_CHECKING:
    from guardian.core.remediation_models import (
        ALLOWED_TRANSITIONS,  # noqa: F401
        AuditEvent,  # noqa: F401
        CaseStatus,  # noqa: F401
        ComponentChange,  # noqa: F401
        DecisionType,  # noqa: F401
        DeclineReason,  # noqa: F401
        HumanDecision,  # noqa: F401
        JiraLink,  # noqa: F401
        ModifyPayload,  # noqa: F401
        RemediationActionType,  # noqa: F401
        RemediationCandidate,  # noqa: F401
        RemediationCase,  # noqa: F401
        RemediationPlan,  # noqa: F401
        SbomDiff,  # noqa: F401
        SemverJump,  # noqa: F401
        Source,  # noqa: F401
        StepStatus,  # noqa: F401
        ValidationRun,  # noqa: F401
        ValidationStep,  # noqa: F401
        VerificationResult,  # noqa: F401
        VerificationStatus,  # noqa: F401
        candidate_id_for,  # noqa: F401
        canonical_json,  # noqa: F401
        case_id_for,  # noqa: F401
        fingerprint_for,  # noqa: F401
    )

_REMEDIATION_EXPORTS = frozenset(
    {
        "ALLOWED_TRANSITIONS",
        "AuditEvent",
        "CaseStatus",
        "ComponentChange",
        "DecisionType",
        "DeclineReason",
        "HumanDecision",
        "JiraLink",
        "ModifyPayload",
        "RemediationActionType",
        "RemediationCandidate",
        "RemediationCase",
        "RemediationPlan",
        "SbomDiff",
        "SemverJump",
        "Source",
        "StepStatus",
        "ValidationRun",
        "ValidationStep",
        "VerificationResult",
        "VerificationStatus",
        "candidate_id_for",
        "canonical_json",
        "case_id_for",
        "fingerprint_for",
    }
)


def __getattr__(name: str) -> object:
    if name in _REMEDIATION_EXPORTS:
        from guardian.core import remediation_models  # noqa: PLC0415 - avoids an import cycle

        return getattr(remediation_models, name)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
