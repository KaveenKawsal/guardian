"""Render ReportData as a self-contained HTML evaluation workspace.

All report text is untrusted. The only values substituted into the template are the
HTML-escaped title, the report as script-safe JSON inside ``<script type="application/json">``
and the hash of the page's own script for its Content-Security-Policy. The page script
renders every value with ``textContent`` and links only ``https://`` URLs.
"""

import base64
import hashlib
import html
import json
import re
from functools import cache
from importlib.resources import files
from typing import Any

from guardian.reporting.models import ReportData

DATA_PLACEHOLDER = "/*__REPORT_DATA__*/"
TITLE_PLACEHOLDER = "__TITLE__"
HASH_PLACEHOLDER = "__SCRIPT_HASH__"
_PLACEHOLDERS = re.compile(
    "|".join(re.escape(p) for p in (DATA_PLACEHOLDER, TITLE_PLACEHOLDER, HASH_PLACEHOLDER))
)
_APP_SCRIPT = re.compile(r"<script id=\"app\">(.*?)</script>", re.DOTALL)


def script_safe_json(payload: Any) -> str:  # noqa: ANN401
    """JSON that cannot terminate or comment out the surrounding <script> element."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


@cache
def _template() -> tuple[str, str]:
    """The template text and the CSP hash of its application script."""
    text = files("guardian.reporting").joinpath("templates", "report.html").read_text("utf-8")
    match = _APP_SCRIPT.search(text)
    if match is None:  # pragma: no cover - guarded by tests
        msg = "report template has no application script"
        raise RuntimeError(msg)
    digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
    return text, "sha256-" + base64.b64encode(digest).decode("ascii")


def render_html(report: ReportData) -> str:
    template, script_hash = _template()
    values = {
        TITLE_PLACEHOLDER: html.escape(f"{report.meta.repository} · Guardian security report"),
        DATA_PLACEHOLDER: script_safe_json(report.model_dump(mode="json")),
        HASH_PLACEHOLDER: script_hash,
    }
    # One pass, so a substituted value can never be mistaken for another placeholder.
    return _PLACEHOLDERS.sub(lambda m: values[m.group(0)], template)
