"""Render ReportData as machine-readable JSON (the report contract, versioned by meta)."""

import json

from guardian.reporting.models import ReportData, report_payload


def render_json(report: ReportData) -> str:
    """Pretty-printed, keys in model field order so diffs between reports stay small."""
    return json.dumps(report_payload(report), indent=2, ensure_ascii=False) + "\n"
