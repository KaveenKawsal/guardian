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
