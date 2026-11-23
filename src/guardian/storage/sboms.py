"""SBOMs, components and dependency edges per scan."""

import json
import zlib
from typing import TYPE_CHECKING

from guardian.core.models import (
    Component,
    DependencyEdge,
    DependencyScope,
    DirectSource,
    Ecosystem,
    Sbom,
)

if TYPE_CHECKING:
    from guardian.storage.database import Database


class SbomStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def save(self, scan_id: str, sbom: Sbom, raw_bom: bytes | None = None) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO sboms (scan_id, spec_version, generator, root_ref, direct_source, "
                "warnings_json, raw_bom) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    sbom.spec_version,
                    sbom.generator,
                    sbom.root_ref,
                    sbom.direct_source.value,
                    json.dumps(sbom.warnings),
                    zlib.compress(raw_bom) if raw_bom is not None else None,
                ),
            )
            conn.executemany(
                "INSERT INTO components (scan_id, ref, name, grp, version, purl, purl_type, "
                "ecosystem, component_type, scope, direct, licenses_json, declared_in_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        c.ref,
                        c.name,
                        c.group,
                        c.version,
                        c.purl,
                        c.purl_type,
                        c.ecosystem.value if c.ecosystem else None,
                        c.component_type,
                        c.scope.value,
                        None if c.direct is None else int(c.direct),
                        json.dumps(c.licenses),
                        json.dumps(c.declared_in),
                    )
                    for c in sbom.components
                ],
            )
            conn.executemany(
                "INSERT INTO dependency_edges (scan_id, source, target) VALUES (?, ?, ?)",
                [(scan_id, e.source, e.target) for e in sbom.edges],
            )

    def load(self, scan_id: str) -> Sbom | None:
        conn = self.db.conn
        head = conn.execute("SELECT * FROM sboms WHERE scan_id = ?", (scan_id,)).fetchone()
        if head is None:
            return None
        components = [
            Component(
                ref=r["ref"],
                name=r["name"],
                group=r["grp"],
                version=r["version"],
                purl=r["purl"],
                purl_type=r["purl_type"],
                ecosystem=Ecosystem(r["ecosystem"]) if r["ecosystem"] else None,
                component_type=r["component_type"],
                scope=DependencyScope(r["scope"]),
                direct=None if r["direct"] is None else bool(r["direct"]),
                licenses=json.loads(r["licenses_json"]),
                declared_in=json.loads(r["declared_in_json"]),
            )
            for r in conn.execute(
                "SELECT * FROM components WHERE scan_id = ? ORDER BY ref", (scan_id,)
            )
        ]
        edges = [
            DependencyEdge(source=r["source"], target=r["target"])
            for r in conn.execute(
                "SELECT source, target FROM dependency_edges WHERE scan_id = ? "
                "ORDER BY source, target",
                (scan_id,),
            )
        ]
        return Sbom(
            spec_version=head["spec_version"],
            generator=head["generator"],
            root_ref=head["root_ref"],
            components=components,
            edges=edges,
            direct_source=DirectSource(head["direct_source"]),
            warnings=json.loads(head["warnings_json"]),
        )

    def raw(self, scan_id: str) -> bytes | None:
        row = self.db.conn.execute(
            "SELECT raw_bom FROM sboms WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return zlib.decompress(row["raw_bom"]) if row and row["raw_bom"] is not None else None
