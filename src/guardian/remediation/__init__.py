"""Deterministic remediation: candidate fixes, registry facts, plans and remediation cases.

Submodules are imported directly (``guardian.remediation.candidates`` ...); this package keeps
no eager imports so ``analysis`` can use ``npm_semver`` without pulling in storage or LLM code.
"""
