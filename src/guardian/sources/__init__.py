"""Where a scan's source code comes from: a local directory or a cloned remote repository."""

from guardian.sources.remote import (
    CloneError,
    InvalidTargetError,
    LocalTarget,
    RemoteTarget,
    Target,
    clone,
    parse_target,
    remove_workspace,
    workspaces_dir,
)

__all__ = [
    "CloneError",
    "InvalidTargetError",
    "LocalTarget",
    "RemoteTarget",
    "Target",
    "clone",
    "parse_target",
    "remove_workspace",
    "workspaces_dir",
]
