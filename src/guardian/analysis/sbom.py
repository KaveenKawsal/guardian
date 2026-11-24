"""SBOM generation with cdxgen.

cdxgen is run in its secure mode, without installing dependencies, and (when the paths allow)
under the Node.js permission model so it can read only the repository, its own install and
the temp directory, and write only to the temp directory.
"""

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from guardian.execution.results import ToolResult
from guardian.execution.runner import ToolRunner

CDXGEN = "cdxgen"
CDXGEN_PACKAGE = "@cyclonedx/cdxgen"
CYCLONEDX_SPEC_VERSION = "1.6"


@dataclass(frozen=True)
class SbomGeneration:
    result: ToolResult
    bom_path: Path | None
    sandboxed: bool = False
    warnings: list[str] = field(default_factory=list)


def find_cdxgen_install(executable: Path) -> Path | None:
    """Locate the cdxgen package directory from its launcher (npm shim or symlink)."""
    candidates = [executable.parent / "node_modules" / "@cyclonedx" / "cdxgen"]
    candidates += list(executable.resolve().parents)
    for candidate in candidates:
        manifest = candidate / "package.json"
        try:
            name = json.loads(manifest.read_text(encoding="utf-8")).get("name")
        except (OSError, ValueError, AttributeError):
            continue
        if name == CDXGEN_PACKAGE:
            return candidate
    return None


def node_permission_options(read_dirs: list[Path], write_dirs: list[Path]) -> str | None:
    """NODE_OPTIONS enabling the Node.js permission model, or None if it cannot be expressed.

    Node does not accept quoted paths in these grants on Windows, so paths containing
    whitespace cannot be granted; the caller then falls back to secure mode alone.
    """
    paths = [str(p) for p in (*read_dirs, *write_dirs)]
    if any(any(ch.isspace() for ch in p) for p in paths):
        return None
    parts = ["--permission"]
    parts += [f"--allow-fs-read={p}" for p in read_dirs]
    parts += [f"--allow-fs-write={p}" for p in write_dirs]
    # cdxgen shells out to package managers (npm ls, pip inspect, ...) to read metadata.
    parts.append("--allow-child-process")
    return " ".join(parts)


class SbomGenerator:
    def __init__(self, runner: ToolRunner, timeout_seconds: float | None = None) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def generate(self, repo_root: Path, work_dir: Path) -> SbomGeneration:
        """Generate ``work_dir/bom.json`` for ``repo_root``. ``work_dir`` must be in temp."""
        output = work_dir / "bom.json"
        args = [
            "--no-install-deps",
            "--spec-version",
            CYCLONEDX_SPEC_VERSION,
            "--output",
            str(output),
            str(repo_root),
        ]
        env = {"CDXGEN_SECURE_MODE": "true"}
        warnings: list[str] = []
        sandboxed = False

        executable = self.runner.resolve(CDXGEN)
        if executable is not None:
            install = find_cdxgen_install(Path(executable))
            # Grant the temp dir under both its literal and resolved names: Node's permission
            # model compares paths textually, and on macOS /var/folders -> /private/var/folders.
            raw_tmp = Path(tempfile.gettempdir())
            tmps = list(dict.fromkeys([raw_tmp, raw_tmp.resolve()]))
            options = (
                node_permission_options([install, repo_root, *tmps], tmps) if install else None
            )
            if options:
                env["NODE_OPTIONS"] = options
                sandboxed = True
            else:
                reason = "install not found" if install is None else "path contains whitespace"
                warnings.append(
                    f"cdxgen ran in secure mode without the Node.js permission model ({reason})"
                )

        result = self.runner.run(
            CDXGEN, args, cwd=work_dir, timeout_seconds=self.timeout_seconds, env=env
        )
        bom_path = output if output.is_file() else None
        if bom_path is not None and not result.ok:
            warnings.append(f"cdxgen exited with {result.exit_code} but produced an SBOM")
        return SbomGeneration(
            result=result, bom_path=bom_path, sandboxed=sandboxed, warnings=warnings
        )
