"""Local review console (``guardian ui``): a backup for the Jira decision step.

Stdlib HTTP server bound to 127.0.0.1, a JSON API over the remediation store, and static
assets shipped as package data. Decisions go through the same strict ``/guardian`` parser and
CLI approver allowlist as ``guardian decide`` and are recorded with ``channel="cli"``.
"""
