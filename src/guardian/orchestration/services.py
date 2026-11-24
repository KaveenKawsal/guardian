"""The seam between the remediation graph and the code that does the work.

The graph only sequences, guards state transitions and audits. Everything that touches the
outside world (planner, Jira, git worktree, sandbox, rescan) sits behind this protocol, which the
integrator fills with the real implementations. Every method must be idempotent: a node can be
replayed after a crash or a resume, and it will call the service again.

Failure contract: a method raises a ``GuardianError`` subclass for a *domain* failure (the patch
does not apply, the sandbox refused the build). The graph routes ``apply``/``validate`` domain
failures to ``VALIDATION_FAILED`` and back to human review; an ``open_pr`` domain failure is
recorded (``pr:failed``) and the case still closes as VERIFIED. Any other exception is treated as a
crash: it propagates, the checkpoint keeps the node pending, and ``continue_case`` retries it.
"""

from typing import Protocol

from guardian.core.remediation_models import HumanDecision


class RemediationServices(Protocol):
    def plan(self, case_id: str) -> None:
        """Ensure the case has deterministic candidates and a plan."""
        ...

    def publish(self, case_id: str) -> str | None:
        """Create or update the Jira issue; return its key, or None when Jira is disabled."""
        ...

    def notify(self, case_id: str, stage: str, payload: dict) -> None:
        """Jira write-back for ``stage`` (idempotent per stage and ``payload["attempt"]``)."""
        ...

    def apply(self, case_id: str, decision: HumanDecision) -> dict:
        """Apply the approved change in an isolated worktree; return ``AppliedChange`` JSON."""
        ...

    def validate(self, case_id: str, applied: dict) -> dict:
        """Build and test in the sandbox; return ``ValidationRun`` JSON."""
        ...

    def verify(self, case_id: str, applied: dict, validation: dict) -> dict:
        """Rescan the worktree and compare; return ``VerificationResult`` JSON."""
        ...

    def open_pr(self, case_id: str, applied: dict, verification: dict) -> dict | None:
        """Push ``guardian/fix-<case>`` and open (or find) its pull request after a VERIFIED
        verdict; return ``{"url", "number", ...}``, or None when pull requests are disabled."""
        ...

    def record_acceptance(self, case_id: str, decision: HumanDecision) -> None:
        """Record a DECLINE (accepted risk, false positive, ...) where reports can see it."""
        ...
