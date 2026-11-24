"""Who may decide on a remediation case (ADR 11, rule 11).

Allowlists only: an empty list authorizes nobody. Guardian's own Jira account is never an
approver, even if someone lists it, so Guardian cannot approve its own proposals.
"""

from guardian.core.config import GuardianSettings


def is_authorized_jira(
    account_id: str | None, settings: GuardianSettings, *, guardian_account_id: str | None = None
) -> bool:
    if not account_id or account_id == guardian_account_id:
        return False
    return account_id in set(settings.approvers)


def is_authorized_cli(os_user: str | None, settings: GuardianSettings) -> bool:
    return bool(os_user) and os_user in set(settings.cli_approvers)
