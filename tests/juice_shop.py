"""A small, offline Juice Shop-shaped world for remediation tests.

package.json pins jsonwebtoken 0.4.0, express-jwt 0.1.3 and sanitize-html 1.4.2 exactly and uses
^/~ ranges elsewhere; qs is a transitive dependency of express; unused-lib is never imported.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.analysis.osv import parse_osv_output
from guardian.core.models import (
    CodeIndex,
    Ecosystem,
    EcosystemProfile,
    FileIndex,
    Finding,
    GitInfo,
    ImportStyle,
    ImportTarget,
    ManifestFile,
    ManifestKind,
    Priority,
    RepositoryProfile,
    ResolvedImport,
    RiskAssessment,
    Sbom,
    ScanStatus,
    SourceLanguage,
)
from guardian.core.remediation_models import RemediationCase, case_id_for
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.remediation.cases import case_fingerprint
from guardian.remediation.registry import PackageVersions, VersionMeta

FIXTURES = Path(__file__).parent / "fixtures"
OSV_OUTPUT = (FIXTURES / "osv" / "juice-shop.osv.json").read_bytes()
SBOM_BYTES = (FIXTURES / "sbom" / "juice-shop.cdx.json").read_bytes()
T0 = datetime(2026, 11, 1, tzinfo=UTC)

PACKAGE_JSON = """{
  "name": "juice-shop",
  "version": "19.0.0",
  "scripts": {
    "start": "node build/app",
    "test": "mocha test/server"
  },
  "dependencies": {
    "express": "^4.17.1",
    "express-jwt": "0.1.3",
    "jsonwebtoken": "0.4.0",
    "marsdb": "^0.6.11",
    "moment": "^2.18.0",
    "sanitize-html": "1.4.2",
    "unused-lib": "~1.0.0"
  }
}
"""


def _versions(*items: str | tuple[str, dict]) -> dict[str, VersionMeta]:
    out: dict[str, VersionMeta] = {}
    for item in items:
        if isinstance(item, tuple):
            version, meta = item
            out[version] = VersionMeta(
                deprecated=meta.get("deprecated"), dependencies=meta.get("deps", {})
            )
        else:
            out[item] = VersionMeta()
    return out


REGISTRY: dict[str, dict[str, VersionMeta]] = {
    "jsonwebtoken": _versions(
        "0.1.0",
        "0.4.0",
        "0.4.1",
        "1.0.0",
        "4.2.1",
        "4.2.2",
        "5.0.0",
        "8.5.1",
        "9.0.0",
        "9.0.1",
        "10.0.0-beta.1",
    ),
    "express-jwt": _versions(
        "0.1.3", "0.1.4", "5.3.3", ("6.0.0", {"deprecated": "Use 6.1.0"}), "6.1.0", "8.0.0"
    ),
    "sanitize-html": _versions("1.4.2", "1.4.3", "2.0.0"),
    "marsdb": _versions("0.6.11", "0.6.12", "0.7.0"),
    "moment": _versions("2.18.0", "2.18.1", "2.19.3", "2.29.4"),
    "express": _versions(
        ("4.17.1", {"deps": {"qs": "6.7.0"}}),
        ("4.17.2", {"deps": {"qs": "6.9.6"}}),
        ("4.17.3", {"deps": {"qs": "6.9.7"}}),
        ("4.18.0", {"deps": {"qs": "6.10.3"}}),
    ),
    "qs": _versions("6.7.0", "6.7.3", "6.9.6", "6.9.7", "6.10.3"),
    "unused-lib": _versions("1.0.0", "1.0.1"),
}


class FakeRegistry:
    def __init__(self, *, down: bool = False) -> None:
        self.down = down
        self.calls: list[str] = []

    def fetch(self, name: str) -> PackageVersions | None:
        self.calls.append(name)
        if self.down or name not in REGISTRY:
            return None
        return PackageVersions(name=name, versions=REGISTRY[name], fetched_at=T0)


def code_index() -> CodeIndex:
    files = [
        FileIndex(
            path=path, language=SourceLanguage.TYPESCRIPT, sha256="0" * 64, size=1, line_count=10
        )
        for path in ("lib/insecurity.ts", "server.ts")
    ]
    imports = [
        ResolvedImport(
            path=path,
            line=line,
            module=name,
            style=ImportStyle.ES,
            target=ImportTarget.EXTERNAL,
            package=name,
            component_ref=ref,
        )
        for path, line, name, ref in (
            ("lib/insecurity.ts", 1, "jsonwebtoken", "pkg:npm/jsonwebtoken@0.4.0"),
            ("lib/insecurity.ts", 2, "express-jwt", "pkg:npm/express-jwt@0.1.3"),
            ("lib/insecurity.ts", 3, "sanitize-html", "pkg:npm/sanitize-html@1.4.2"),
            ("server.ts", 1, "express", "pkg:npm/express@4.17.1"),
            ("server.ts", 2, "marsdb", "pkg:npm/marsdb@0.6.11"),
            ("server.ts", 3, "moment", "pkg:npm/moment@2.18.0"),
        )
    ]
    return CodeIndex(files=files, imports=imports)


def profile(root: Path) -> RepositoryProfile:
    eco = EcosystemProfile(
        ecosystem=Ecosystem.NODE,
        adapter="node",
        package_managers=["npm"],
        manifests=[
            ManifestFile(path="package.json", ecosystem=Ecosystem.NODE, kind=ManifestKind.MANIFEST)
        ],
    )
    return RepositoryProfile(
        name="juice-shop",
        root=str(root),
        profiled_at=T0,
        total_files=3,
        total_bytes=100,
        ecosystems=[eco],
        git=GitInfo(is_repository=True),
    )


@dataclass
class World:
    root: Path
    sbom: Sbom
    findings: list[Finding]
    graph: DependencyGraph
    index: CodeIndex
    assessments: dict[str, RiskAssessment]

    def package_findings(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.details.package == name]  # ty: ignore

    def case(self, name: str) -> RemediationCase:
        fp = case_fingerprint(str(self.root), name)
        items = self.package_findings(name)
        return RemediationCase(
            id=case_id_for(fp),
            fingerprint=fp,
            scan_id="s1",
            repository_root=str(self.root),
            finding_ids=[f.id for f in items],
            title=name,
            priority=Priority.P2,
            created_at=T0,
            updated_at=T0,
        )


def write_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(PACKAGE_JSON, encoding="utf-8")
    return root


def build_world(root: Path) -> World:
    write_repo(root)
    sbom = parse_cyclonedx(SBOM_BYTES, repo_root=root, manifests={"package.json"})
    findings, _ = parse_osv_output(OSV_OUTPUT, sbom)
    graph = DependencyGraph(build_knowledge_graph(profile(root), sbom, findings))
    index = code_index()
    assessments = {a.finding_id: a for a in assess(findings, graph, index)}
    return World(root, sbom, findings, graph, index, assessments)


def seed_scan(db, root: Path, scan_id: str = "scan-juice-1") -> World:
    """Store a completed scan of the world in ``db``."""
    world = build_world(root)
    repo_id = db.repositories.upsert(str(root), "juice-shop")
    db.scans.create(scan_id, repo_id, T0, profile(root))
    db.sboms.save(scan_id, world.sbom, SBOM_BYTES)
    db.findings.save(scan_id, world.findings, [])
    db.code.save(scan_id, world.index)
    db.scans.finish(
        scan_id,
        status=ScanStatus.COMPLETED,
        finished_at=T0,
        tool_runs=[],
        warnings=[],
        component_count=len(world.sbom.components),
        finding_count=len(world.findings),
    )
    return world


def manifest(root: Path) -> dict:
    return json.loads((root / "package.json").read_text())
