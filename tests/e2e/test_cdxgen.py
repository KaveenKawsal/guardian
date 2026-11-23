"""End-to-end scan with the real cdxgen binary (skipped when it is not installed)."""

import json
import shutil

import pytest

from guardian.core.config import GuardianSettings
from guardian.core.models import ScanStatus
from guardian.orchestration.pipeline import ScanPipeline
from guardian.storage.database import Database

pytestmark = pytest.mark.skipif(shutil.which("cdxgen") is None, reason="cdxgen not installed")

PACKAGE_LOCK = {
    "name": "e2e",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "e2e", "version": "1.0.0", "dependencies": {"accepts": "1.3.8"}},
        "node_modules/accepts": {
            "version": "1.3.8",
            "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
            "dependencies": {"mime-types": "~2.1.34", "negotiator": "0.6.3"},
        },
        "node_modules/mime-types": {
            "version": "2.1.35",
            "resolved": "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
            "dependencies": {"mime-db": "1.52.0"},
        },
        "node_modules/mime-db": {
            "version": "1.52.0",
            "resolved": "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
        },
        "node_modules/negotiator": {
            "version": "0.6.3",
            "resolved": "https://registry.npmjs.org/negotiator/-/negotiator-0.6.3.tgz",
        },
    },
}


def test_real_cdxgen_scan(make_repo, tmp_path):
    root = make_repo(
        {
            "package.json": json.dumps(
                {"name": "e2e", "version": "1.0.0", "dependencies": {"accepts": "1.3.8"}}
            ),
            "package-lock.json": json.dumps(PACKAGE_LOCK),
        }
    )
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path / "data")
    with Database(settings.database_path) as db:
        outcome = ScanPipeline(db, settings).run(root)

    assert outcome.record.status is ScanStatus.COMPLETED, outcome.record.warnings
    assert [c.name for c in outcome.graph.direct_dependencies()] == ["accepts"]
    mime_db = outcome.graph.find("mime-db")[0]
    paths = outcome.graph.introduction_paths(mime_db.ref)
    assert [c.name for c in paths[0]] == ["accepts", "mime-types", "mime-db"]
    assert "package-lock.json" in outcome.graph.find("accepts")[0].declared_in


LODASH_LOCK = {
    "name": "e2e-vuln",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "e2e-vuln", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
        "node_modules/lodash": {
            "version": "4.17.20",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
        },
    },
}


@pytest.mark.skipif(
    shutil.which("osv-scanner") is None or shutil.which("semgrep") is None,
    reason="osv-scanner and semgrep are required (and network access)",
)
def test_real_security_scan(make_repo, tmp_path):
    root = make_repo(
        {
            "package.json": json.dumps(
                {"name": "e2e-vuln", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}
            ),
            "package-lock.json": json.dumps(LODASH_LOCK),
            "app.py": (
                "import subprocess\nfrom flask import request\n\n"
                "def run():\n"
                "    return subprocess.check_output(request.args['cmd'], shell=True)\n"
            ),
        }
    )
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path / "data")
    with Database(settings.database_path) as db:
        outcome = ScanPipeline(db, settings).run(root)

    runs = {r.tool: r.status for r in outcome.record.tool_runs}
    assert runs["osv-scanner"] == "success", outcome.record.warnings
    assert runs["semgrep"] == "success", outcome.record.warnings
    ids = {f.details.vulnerability_id for f in outcome.findings if f.kind.value == "vulnerability"}
    assert "CVE-2021-23337" in ids
    lodash = outcome.graph.find("lodash")[0]
    assert outcome.graph.findings_for_component(lodash.ref)
    code = [f for f in outcome.findings if f.kind.value == "code"]
    assert any(f.path == "app.py" and "CWE-78" in f.details.cwe_ids for f in code)
