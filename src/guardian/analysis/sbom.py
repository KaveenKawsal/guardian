"""SBOM generation with cdxgen.

cdxgen is run in its secure mode, without installing dependencies, and (when the paths allow)
under the Node.js permission model so it can read only the repository, its own install and
the temp directory, and write only to the temp directory.
"""

import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from guardian.execution.policies import ExecutionPolicy
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


STABLE_PERMISSION_FLAG = "--permission"
EXPERIMENTAL_PERMISSION_FLAG = "--experimental-permission"
_NODE_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)")
_EXPERIMENTAL_SINCE = (20, 0)  # Node 20.0 introduced --experimental-permission
_STABLE_SINCE = (22, 13)  # --permission was backported to 22.13 ...
_STABLE_SINCE_23 = (23, 5)  # ... and is stable from 23.5; 23.0-23.4 still need the old flag
NODE_VERSION_TIMEOUT_SECONDS = 15.0


def permission_flag_for(node_version: str | None) -> str | None:
    """The permission-model flag the given ``node --version`` output accepts.

    Unknown versions get the stable flag (current Node). Versions before 20 have no permission
    model, so ``None`` is returned and cdxgen runs in secure mode alone.
    """
    match = _NODE_VERSION_RE.match((node_version or "").strip())
    if match is None:
        return STABLE_PERMISSION_FLAG
    version = (int(match.group(1)), int(match.group(2)))
    stable = _STABLE_SINCE <= version < (23, 0) or version >= _STABLE_SINCE_23
    if stable:
        return STABLE_PERMISSION_FLAG
    if version >= _EXPERIMENTAL_SINCE:
        return EXPERIMENTAL_PERMISSION_FLAG
    return None


def detect_node_version() -> str | None:
    """``node --version`` of the node on PATH (the one cdxgen's ``env node`` shim will use)."""
    runner = ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"node"}), max_output_bytes=4096))
    with tempfile.TemporaryDirectory(prefix="guardian-node-") as cwd:
        result = runner.run(
            "node", ["--version"], cwd=Path(cwd), timeout_seconds=NODE_VERSION_TIMEOUT_SECONDS
        )
    return result.stdout.strip() if result.ok else None


def node_permission_options(
    read_dirs: list[Path], write_dirs: list[Path], flag: str = STABLE_PERMISSION_FLAG
) -> str | None:
    """NODE_OPTIONS enabling the Node.js permission model, or None if it cannot be expressed.

    Node does not accept quoted paths in these grants on Windows, so paths containing
    whitespace cannot be granted; the caller then falls back to secure mode alone.
    """
    paths = [str(p) for p in (*read_dirs, *write_dirs)]
    if any(any(ch.isspace() for ch in p) for p in paths):
        return None
    parts = [flag]
    parts += [f"--allow-fs-read={p}" for p in read_dirs]
    parts += [f"--allow-fs-write={p}" for p in write_dirs]
    # cdxgen shells out to package managers (npm ls, pip inspect, ...) to read metadata.
    parts.append("--allow-child-process")
    return " ".join(parts)


class SbomGenerator:
    def __init__(
        self,
        runner: ToolRunner,
        timeout_seconds: float | None = None,
        *,
        node_version: Callable[[], str | None] = detect_node_version,
    ) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds
        self.node_version = node_version

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
            flag = permission_flag_for(self.node_version()) if install else None
            # Node 20 also checks read access to the launcher itself (often a symlink into the
            # install), so grant that one file next to the resolved package directory.
            launcher = Path(executable)
            options = (
                node_permission_options([launcher, install, repo_root, *tmps], tmps, flag)
                if install and flag
                else None
            )
            if options:
                env["NODE_OPTIONS"] = options
                sandboxed = True
            else:
                if install is None:
                    reason = "install not found"
                elif flag is None:
                    reason = "Node.js older than 20 has no permission model"
                else:
                    reason = "path contains whitespace"
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
