"""Insecure code pattern detection with Semgrep (OSS engine, metrics off).

Rule packs are chosen from the profiled languages. Matched source text is never stored: the
fingerprint hashes it, so a hard-coded secret found by a rule does not end up in Guardian's
database or reports.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardian.analysis.base import AnalysisResult, decode_tool_output, skipped, stable_id, summarize
from guardian.core.models import (
    CodeDetails,
    Ecosystem,
    Evidence,
    EvidenceKind,
    Finding,
    FindingKind,
    RepositoryProfile,
    Severity,
)
from guardian.execution.runner import ToolRunner

SEMGREP = "semgrep"
SEMGREP_OK_EXIT_CODES = frozenset({0, 1})  # 1 only when findings and --error
MAX_REFERENCES = 5
MAX_SEMGREPIGNORE_BYTES = 64 * 1024

LANGUAGE_PACKS: dict[str, tuple[str, ...]] = {
    "Python": ("p/python",),
    "JavaScript": ("p/javascript",),
    "TypeScript": ("p/typescript",),
    "Java": ("p/java",),
    "Kotlin": ("p/kotlin",),
    "Go": ("p/golang",),
    "Ruby": ("p/ruby",),
    "PHP": ("p/php",),
    "C#": ("p/csharp",),
    "Scala": ("p/scala",),
    "HCL": ("p/terraform",),
}
ALWAYS_PACKS = ("p/secrets",)

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


def select_configs(profile: RepositoryProfile) -> list[str]:
    packs = [p for lang in profile.languages for p in LANGUAGE_PACKS.get(lang.name, ())]
    if profile.ecosystem(Ecosystem.CONTAINER):
        packs.append("p/dockerfile")
    if any(c.provider == "github-actions" for c in profile.ci):
        packs.append("p/github-actions")
    return list(dict.fromkeys([*packs, *ALWAYS_PACKS]))


class _Raw(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SemgrepPosition(_Raw):
    line: int
    col: int | None = None


class SemgrepExtra(_Raw):
    message: str = ""
    severity: str = "INFO"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SemgrepMatch(_Raw):
    check_id: str
    path: str
    start: SemgrepPosition
    end: SemgrepPosition
    extra: SemgrepExtra = Field(default_factory=SemgrepExtra)


class SemgrepError(_Raw):
    type: Any = None
    level: str | None = None
    message: str | None = None


class SemgrepOutput(_Raw):
    results: list[SemgrepMatch] = Field(default_factory=list)
    errors: list[SemgrepError] = Field(default_factory=list)


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value else []


def _cwe_ids(metadata: dict[str, Any]) -> list[str]:
    """``"CWE-78: Improper Neutralization..."`` -> ``"CWE-78"``."""
    return sorted({c.split(":", 1)[0].strip() for c in _as_list(metadata.get("cwe"))})


def _match_fingerprint(repo_root: Path, path: str, start: int, end: int) -> str:
    """Hash of the matched lines with whitespace removed: stable when code merely moves."""
    try:
        lines = (repo_root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    text = "".join("".join(line.split()) for line in lines[max(start - 1, 0) : end])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_semgrep_output(data: str | bytes, repo_root: Path) -> tuple[list[Finding], list[str]]:
    output = SemgrepOutput.model_validate(json.loads(decode_tool_output(data)))
    findings: dict[str, Finding] = {}
    for match in output.results:
        path = PurePosixPath(match.path.replace("\\", "/")).as_posix().removeprefix("./")
        meta = match.extra.metadata
        severity = _SEVERITY.get(match.extra.severity.upper(), Severity.UNKNOWN)
        fingerprint = _match_fingerprint(repo_root, path, match.start.line, match.end.line)
        finding_id = stable_id(FindingKind.CODE, match.check_id, path, fingerprint)
        rule_name = match.check_id.rsplit(".", 1)[-1]
        findings.setdefault(
            finding_id,
            Finding(
                id=finding_id,
                kind=FindingKind.CODE,
                title=f"{rule_name} in {path}:{match.start.line}",
                severity=severity,
                tool=SEMGREP,
                path=path,
                start_line=match.start.line,
                end_line=match.end.line,
                details=CodeDetails(
                    rule_id=match.check_id,
                    message=match.extra.message.strip(),
                    confidence=_upper(meta.get("confidence")),
                    likelihood=_upper(meta.get("likelihood")),
                    impact=_upper(meta.get("impact")),
                    category=meta.get("category")
                    if isinstance(meta.get("category"), str)
                    else None,
                    cwe_ids=_cwe_ids(meta),
                    owasp=_as_list(meta.get("owasp")),
                    references=_as_list(meta.get("references"))[:MAX_REFERENCES],
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SOURCE_LOCATION,
                        tool=SEMGREP,
                        summary=f"Rule {match.check_id} matched lines "
                        f"{match.start.line}-{match.end.line}",
                        path=path,
                        line=match.start.line,
                    )
                ],
            ),
        )

    warnings = []
    errors = [e for e in output.errors if (e.level or "error").lower() == "error"]
    if errors:
        kinds = sorted({str(e.type[0] if isinstance(e.type, list) else e.type) for e in errors})
        warnings.append(f"Semgrep reported {len(errors)} error(s): {', '.join(kinds)}")
    ordered = sorted(
        findings.values(), key=lambda f: (-f.severity.rank, f.path or "", f.start_line or 0)
    )
    return ordered, warnings


def _upper(value: object) -> str | None:
    return value.upper() if isinstance(value, str) else None


def repository_ignore_warning(repo_root: Path) -> str | None:
    """Semgrep honours a .semgrepignore the scanned repository ships, and no flag disables it.

    A hostile repository could use it to hide files from analysis, so its patterns are
    surfaced instead of silently obeyed.
    """
    path = repo_root / ".semgrepignore"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            text = handle.read(MAX_SEMGREPIGNORE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None
    patterns = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    shown = ", ".join(patterns[:10]) + (" ..." if len(patterns) > 10 else "")  # noqa: PLR2004
    return (
        "Repository-provided .semgrepignore excludes paths from static analysis: "
        f"{shown or '(empty)'}"
    )


class SemgrepScanner:
    def __init__(
        self,
        runner: ToolRunner,
        configs: list[str] | None = None,
        rule_timeout_seconds: float = 30.0,
        timeout_seconds: float | None = None,
    ) -> None:
        self.runner = runner
        self.configs = configs
        self.rule_timeout_seconds = rule_timeout_seconds
        self.timeout_seconds = timeout_seconds

    def scan(
        self,
        profile: RepositoryProfile,
        work_dir: Path,
        excluded_dirs: frozenset[str] = frozenset(),
    ) -> AnalysisResult:
        repo_root = Path(profile.root)
        configs = self.configs or select_configs(profile)
        if not profile.languages and not self.configs:
            return skipped(SEMGREP, "No source files in supported languages")

        output = work_dir / "semgrep.json"
        args = [
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--oss-only",
            # Repository-controlled .gitignore must not hide files from the scan.
            "--no-git-ignore",
            "--timeout",
            f"{self.rule_timeout_seconds:g}",
            "--max-target-bytes",
            "2000000",
            "--output",
            str(output),
        ]
        for config in configs:
            args += ["--config", config]
        for name in sorted(excluded_dirs):
            args += ["--exclude", name]
        args.append(".")

        env = {
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "PYTHONUTF8": "1",  # Semgrep's CLI is Python: force UTF-8 output on Windows
        }
        result = self.runner.run(
            SEMGREP, args, cwd=repo_root, timeout_seconds=self.timeout_seconds, env=env
        )
        ignore_warning = repository_ignore_warning(repo_root)
        warnings = [ignore_warning] if ignore_warning else []
        if not output.is_file():
            return AnalysisResult(
                tool_run=summarize(result, SEMGREP_OK_EXIT_CODES), warnings=warnings
            )
        try:
            findings, parse_warnings = parse_semgrep_output(output.read_bytes(), repo_root)
        except (ValidationError, ValueError) as exc:
            run = summarize(result, (), error=f"Unreadable Semgrep output: {exc}"[:500])
            return AnalysisResult(tool_run=run, warnings=warnings)
        return AnalysisResult(
            tool_run=summarize(result, SEMGREP_OK_EXIT_CODES),
            findings=findings,
            warnings=warnings + parse_warnings,
        )
