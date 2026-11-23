"""Minimal, comment-preserving updates to a ``.env`` file (non-secret settings only)."""

import os
import re
from collections.abc import Mapping
from pathlib import Path

from guardian.core.config import user_env_file
from guardian.core.exceptions import ConfigurationError

# Only these keys may be written: API keys are never touched by Guardian.
WRITABLE_KEYS = frozenset({"GUARDIAN_LLM_PROVIDER", "GUARDIAN_GROQ_MODEL", "GUARDIAN_GOOGLE_MODEL"})
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/@+-]{1,200}$")
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def target_env_file(cwd: Path | None = None) -> Path:
    """``./.env`` when it exists, else the per-user ``~/.guardian/.env``."""
    local = (cwd or Path.cwd()) / ".env"
    return local if local.is_file() else user_env_file()


def update_env_file(path: Path, updates: Mapping[str, str]) -> None:
    """Set ``updates`` in ``path``; every other line (comments, keys) is kept byte-for-byte."""
    for key, value in updates.items():
        if key not in WRITABLE_KEYS:
            msg = f"refusing to write {key}: Guardian only writes provider/model selections"
            raise ConfigurationError(msg)
        if not _SAFE_VALUE.match(value):
            msg = f"invalid value for {key}: use letters, digits and . _ : / @ + - only"
            raise ConfigurationError(msg)

    if path.exists():
        text = path.read_bytes().decode("utf-8")
    else:
        _create_private(path)
        text = ""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    pending = dict(updates)
    for index, line in enumerate(lines):
        match = _ASSIGNMENT.match(line)
        if match and match.group(1).upper() in updates:
            name = match.group(1).upper()
            ending = line[len(line.rstrip("\r\n")) :]
            lines[index] = f"{name}={updates[name]}{ending}"
            pending.pop(name, None)
    if pending:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        lines.extend(f"{key}={value}{newline}" for key, value in pending.items())
    path.write_bytes("".join(lines).encode("utf-8"))


def _create_private(path: Path) -> None:
    """Create an empty file readable only by the owner (best effort on Windows)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
