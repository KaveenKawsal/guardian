"""Execution policies for external tools.

Guardian runs scanners against untrusted repositories, so every external process is started
with an explicit allowlist, no shell, a scrubbed environment, a timeout and bounded output.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

DEFAULT_ALLOWED_TOOLS: frozenset[str] = frozenset({"git", "cdxgen", "osv-scanner", "semgrep"})

# Variables a child process needs to function; everything else (API keys, tokens, cloud
# credentials) is withheld from scanners.
DEFAULT_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
)

# A malicious repository's .git/config can execute commands during otherwise read-only git
# operations (core.fsmonitor, diff.external, hooks). These overrides neutralise that and
# must be passed before the git subcommand.
GIT_HARDENING_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("diff.external", ""),
    ("core.pager", "cat"),
    ("protocol.allow", "never"),
    ("credential.helper", ""),
)

GIT_HARDENING_ARGS: tuple[str, ...] = tuple(
    arg for key, value in GIT_HARDENING_CONFIG for arg in ("-c", f"{key}={value}")
)


def _git_config_env() -> dict[str, str]:
    """The same overrides as environment variables (git >= 2.31).

    Unlike ``-c`` arguments these also reach git processes that *other* tools spawn, e.g.
    Semgrep listing files with ``git ls-files`` inside the scanned repository.
    """
    env = {"GIT_CONFIG_COUNT": str(len(GIT_HARDENING_CONFIG))}
    for i, (key, value) in enumerate(GIT_HARDENING_CONFIG):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


GIT_HARDENING_ENV: Mapping[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",  # `git status` must not rewrite the scanned repo's index
    "GIT_PAGER": "cat",
    **_git_config_env(),
    # System config is admin-controlled and trusted (Git for Windows sets core.autocrlf there;
    # ignoring it makes clean checkouts look dirty). The threat is the repo-local config.
}


@dataclass(frozen=True)
class ExecutionPolicy:
    allowed_tools: frozenset[str] = DEFAULT_ALLOWED_TOOLS
    timeout_seconds: float = 300.0
    max_output_bytes: int = 20 * 1024 * 1024
    env_allowlist: frozenset[str] = DEFAULT_ENV_ALLOWLIST
    extra_env: Mapping[str, str] = field(default_factory=dict)

    def build_env(self, source: Mapping[str, str] | None = None) -> dict[str, str]:
        source = os.environ if source is None else source
        allowed = {k.upper() for k in self.env_allowlist}
        env = {k: v for k, v in source.items() if k.upper() in allowed}
        env.update(self.extra_env)
        return env
