"""Container ecosystem: Dockerfiles, Containerfiles and Compose files."""

import re
from pathlib import PurePosixPath

from guardian.adapters.base import EcosystemAdapter, RepositoryView, manifest, sorted_unique
from guardian.core.exceptions import ManifestReadError
from guardian.core.models import Ecosystem, EcosystemProfile, ManifestFile, ManifestKind

COMPOSE_FILES = frozenset(
    {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
)

# FROM [--platform=...] image[:tag|@digest] [AS stage]
_FROM = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?",
    re.IGNORECASE | re.MULTILINE,
)


def is_dockerfile(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return (
        name in {"dockerfile", "containerfile"}
        or name.startswith(("dockerfile.", "containerfile."))
        or name.endswith(".dockerfile")
    )


def base_images(text: str) -> list[str]:
    """External base images, excluding ``scratch`` and references to earlier build stages."""
    images: list[str] = []
    stages: set[str] = set()
    for match in _FROM.finditer(text):
        image = match.group("image")
        if image.lower() != "scratch" and image.lower() not in stages:
            images.append(image)
        if stage := match.group("stage"):
            stages.add(stage.lower())
    return images


class ContainerAdapter(EcosystemAdapter):
    name = "container"
    ecosystem = Ecosystem.CONTAINER

    def detect(self, repo: RepositoryView) -> EcosystemProfile | None:
        manifests: list[ManifestFile] = []
        images: list[str] = []
        warnings: list[str] = []
        tools: list[str] = []
        eco = self.ecosystem

        for path in repo.matching(is_dockerfile):
            tools.append("docker")
            manifests.append(manifest(path, eco, ManifestKind.CONTAINER, "docker"))
            try:
                images += base_images(repo.read_text(path))
            except ManifestReadError as exc:
                warnings.append(str(exc))

        for path in repo.named(*COMPOSE_FILES, case_insensitive=True):
            tools.append("docker-compose")
            manifests.append(manifest(path, eco, ManifestKind.CONTAINER, "docker-compose"))

        if not manifests:
            return None
        return EcosystemProfile(
            ecosystem=eco,
            adapter=self.name,
            package_managers=sorted_unique(tools),
            manifests=sorted(manifests, key=lambda m: m.path),
            metadata={"base_images": sorted_unique(images)} if images else {},
            warnings=warnings,
        )
