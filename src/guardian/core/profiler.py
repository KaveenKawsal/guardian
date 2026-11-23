"""Repository profiler: the first stage of every Guardian scan.

It walks the repository once (never following symlinks, honouring exclusions), then hands an
immutable file listing to every ecosystem adapter, detects CI systems and reads git state.
"""

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from guardian.adapters.base import RepositoryView
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import RepositoryNotFoundError
from guardian.core.models import CIConfig, GitInfo, LanguageStat, RepositoryProfile
from guardian.core.registry import AdapterRegistry, default_registry
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".groovy": "Groovy",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".hpp": "C++",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".tf": "HCL",
}

CI_FILES: dict[str, str] = {
    ".gitlab-ci.yml": "gitlab-ci",
    "Jenkinsfile": "jenkins",
    "azure-pipelines.yml": "azure-pipelines",
    "bitbucket-pipelines.yml": "bitbucket-pipelines",
    ".travis.yml": "travis-ci",
}


def detect_ci(files: tuple[PurePosixPath, ...]) -> list[CIConfig]:
    found: list[CIConfig] = []
    for f in files:
        parts = f.parts
        if (
            len(parts) == 3  # noqa: PLR2004 - .github/workflows/<file>
            and parts[:2] == (".github", "workflows")
            and f.suffix in {".yml", ".yaml"}
        ):
            found.append(CIConfig(provider="github-actions", path=str(f)))
        elif parts == (".circleci", "config.yml"):
            found.append(CIConfig(provider="circleci", path=str(f)))
        elif len(parts) == 1 and f.name in CI_FILES:
            found.append(CIConfig(provider=CI_FILES[f.name], path=str(f)))
    return sorted(found, key=lambda c: (c.provider, c.path))


@dataclass
class FileWalk:
    files: list[PurePosixPath] = field(default_factory=list)
    total_bytes: int = 0
    language_files: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    language_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    skipped_symlinks: int = 0
    truncated: bool = False


def _is_link(path: str) -> bool:
    isjunction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return os.path.islink(path) or bool(isjunction and isjunction(path))  # noqa: PTH114 - str paths from os.walk


def walk_repository(root: Path, excluded_dirs: frozenset[str], max_files: int) -> FileWalk:
    walk = FileWalk()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for d in sorted(dirnames):
            if d in excluded_dirs:
                continue
            if _is_link(os.path.join(dirpath, d)):  # noqa: PTH118 - os.walk yields str
                walk.skipped_symlinks += 1
                continue
            kept.append(d)
        dirnames[:] = kept

        rel_dir = PurePosixPath(Path(dirpath).relative_to(root).as_posix())
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)  # noqa: PTH118
            if _is_link(full):
                walk.skipped_symlinks += 1
                continue
            if len(walk.files) >= max_files:
                walk.truncated = True
                return walk
            try:
                size = os.stat(full).st_size  # noqa: PTH116
            except OSError:
                continue
            rel = rel_dir / name if rel_dir != PurePosixPath() else PurePosixPath(name)
            walk.files.append(rel)
            walk.total_bytes += size
            if language := LANGUAGE_EXTENSIONS.get(rel.suffix.lower()):
                walk.language_files[language] += 1
                walk.language_bytes[language] += size
    return walk


class RepositoryProfiler:
    def __init__(
        self,
        settings: GuardianSettings | None = None,
        registry: AdapterRegistry | None = None,
        runner: ToolRunner | None = None,
    ) -> None:
        self.settings = settings or GuardianSettings()
        self.registry = registry or default_registry()
        self.runner = runner or ToolRunner()

    def profile(self, path: Path) -> RepositoryProfile:
        root = path.expanduser().resolve()
        if not root.is_dir():
            msg = f"Repository path does not exist or is not a directory: {path}"
            raise RepositoryNotFoundError(msg)

        walk = walk_repository(root, self.settings.excluded_dirs, self.settings.max_files)
        files = tuple(walk.files)
        view = RepositoryView(
            root=root, files=files, max_read_bytes=self.settings.max_manifest_bytes
        )
        ecosystems, warnings = self.registry.detect(view)
        if walk.truncated:
            warnings.append(
                f"File limit of {self.settings.max_files} reached; profile covers a partial walk"
            )

        languages = sorted(
            (
                LanguageStat(name=lang, files=walk.language_files[lang], bytes=size)
                for lang, size in walk.language_bytes.items()
            ),
            key=lambda s: (-s.bytes, s.name),
        )
        return RepositoryProfile(
            name=root.name,
            root=str(root),
            total_files=len(files),
            total_bytes=walk.total_bytes,
            skipped_symlinks=walk.skipped_symlinks,
            truncated=walk.truncated,
            languages=languages,
            ecosystems=ecosystems,
            ci=detect_ci(files),
            git=self.git_info(root),
            warnings=warnings,
        )

    def git_info(self, root: Path) -> GitInfo:
        def git(*args: str) -> tuple[ToolStatus, str, str]:
            result = self.runner.run("git", args, cwd=root, timeout_seconds=60)
            return result.status, result.stdout.strip(), (result.error or result.stderr).strip()

        status, _, err = git("rev-parse", "--is-inside-work-tree")
        if status is ToolStatus.NOT_FOUND:
            return GitInfo(is_repository=False, error="git is not installed")
        if status is not ToolStatus.SUCCESS:
            # "not a git repository" is the normal case; anything else is worth surfacing.
            not_repo = "not a git repository" in err.lower()
            return GitInfo(is_repository=False, error=None if not_repo else err or None)

        branch_status, branch, _ = git("symbolic-ref", "--short", "-q", "HEAD")
        head_status, head, _ = git("rev-parse", "--verify", "-q", "HEAD")
        dirty_status, porcelain, dirty_err = git("status", "--porcelain")
        return GitInfo(
            is_repository=True,
            branch=branch if branch_status is ToolStatus.SUCCESS and branch else None,
            head_commit=head if head_status is ToolStatus.SUCCESS and head else None,
            is_dirty=bool(porcelain) if dirty_status is ToolStatus.SUCCESS else None,
            error=dirty_err or None if dirty_status is not ToolStatus.SUCCESS else None,
        )
