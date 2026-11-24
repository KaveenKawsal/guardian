"""Guardian exception hierarchy."""


class GuardianError(Exception):
    """Base class for all Guardian errors."""


class ConfigurationError(GuardianError):
    """Invalid or inconsistent configuration."""


class RepositoryNotFoundError(GuardianError):
    """The requested repository path does not exist or is not a directory."""


class ManifestReadError(GuardianError):
    """A manifest could not be read (too large, unreadable, or outside the repository)."""


class ToolNotAllowedError(GuardianError):
    """A tool was requested that the active execution policy does not permit."""


class UnsafeArgumentError(GuardianError):
    """A tool argument cannot be passed safely to the target executable."""


class IllegalTransitionError(GuardianError):
    """A remediation case was asked to move along an edge its state machine does not allow."""


class ApplyError(GuardianError):
    """A remediation candidate cannot be applied to a worktree (non-code action, unsafe or
    missing manifest, dependency not declared)."""
