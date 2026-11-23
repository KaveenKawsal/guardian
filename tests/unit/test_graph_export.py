import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.analysis.osv import parse_osv_output
from guardian.core.models import GitInfo, RepositoryProfile, ScanRecord, ScanStatus
from guardian.reporting.graph_export import graph_payload, render_graph_html, write_graph_page

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _inputs(name="shop"):
    profile = RepositoryProfile(
        name=name,
        root="/work/shop",
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True, head_commit="c" * 40),
    )
    raw = (FIXTURES / "sbom" / "node-express.cdx.json").read_bytes()
    sbom = parse_cyclonedx(raw, repo_root=Path("/work/shop"), manifests=set())
    findings, _ = parse_osv_output((FIXTURES / "osv" / "node.osv.json").read_bytes(), sbom)
    record = ScanRecord(
        id="0123456789abcdef",
        repository_name=name,
        repository_root="/work/shop",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        git_commit="c" * 40,
    )
    return record, profile, sbom, findings


def test_payload_structure():
    payload = graph_payload(*_inputs())
    nodes = payload["nodes"]
    assert nodes[0] == {"name": "shop", "root": True, "depth": 0}
    assert payload["meta"]["components"] == len(nodes) - 1 == 7
    assert payload["meta"]["direct"] == 2
    by_name = {n["name"]: n for n in nodes}
    lodash = by_name["lodash"]
    assert lodash["depth"] == 1
    assert [payload["findings"][i]["vulnerability_id"] for i in lodash["f"]] == [
        "CVE-2021-23337",
        "CVE-2020-28500",
    ]
    assert payload["findings"][lodash["f"][0]]["fix"] == "4.17.21"
    assert by_name["@types/node"]["eco"] == "node"
    assert by_name["mime-types"]["depth"] == 3
    assert "depth" in by_name["lodash-nested-plugin"]  # unreachable: depth None, still listed
    assert by_name["lodash-nested-plugin"]["depth"] is None
    # Only vulnerabilities on SBOM components are drawn (unmapped OSV packages are not).
    assert len(payload["findings"]) == 2
    assert all(0 <= s < len(nodes) and 0 <= t < len(nodes) for s, t in payload["links"])


def test_untrusted_text_cannot_break_out_of_the_page():
    payload = graph_payload(*_inputs(name="</script><img src=x onerror=alert(1)>"))
    page = render_graph_html(payload)
    assert "</script><img" not in page
    assert page.startswith(
        "<title>&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt; dependency graph</title>"
    )
    embedded = page.split('<script id="graph-data" type="application/json">', 1)[1].split(
        "</script>", 1
    )[0]
    assert json.loads(embedded)["meta"]["repository"].startswith("</script>")


def test_write_page_embedded_and_hosted(tmp_path):
    payload = graph_payload(*_inputs())
    embedded = write_graph_page(payload, tmp_path / "local")
    assert '"nodes"' in embedded.read_text(encoding="utf-8")
    hosted = write_graph_page(payload, tmp_path / "hosted", embed_data=False)
    assert "/*__GRAPH_DATA__*/" in hosted.read_text(encoding="utf-8")
    assert json.loads((tmp_path / "hosted" / "graph.json").read_text(encoding="utf-8")) == payload
