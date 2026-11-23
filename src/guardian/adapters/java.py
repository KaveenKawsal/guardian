"""Java ecosystem: Maven and Gradle builds."""

from guardian.adapters.base import (
    EcosystemAdapter,
    RepositoryView,
    dedupe_frameworks,
    manifest,
    sorted_unique,
)
from guardian.core.exceptions import ManifestReadError
from guardian.core.models import Ecosystem, EcosystemProfile, Framework, ManifestFile, ManifestKind

BUILD_FILES: dict[str, str] = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
}

LOCKFILES: dict[str, str] = {
    "gradle.lockfile": "gradle",
}

# Build files reference frameworks by group/artifact id; a substring match is a reliable
# enough signal for profiling. Full coordinate resolution happens in SBOM generation.
FRAMEWORK_MARKERS: dict[str, str] = {
    "spring-boot": "Spring Boot",
    "org.springframework": "Spring",
    "io.quarkus": "Quarkus",
    "io.micronaut": "Micronaut",
    "jakarta.": "Jakarta EE",
    "io.dropwizard": "Dropwizard",
}


class JavaAdapter(EcosystemAdapter):
    name = "java"
    ecosystem = Ecosystem.JAVA

    def detect(self, repo: RepositoryView) -> EcosystemProfile | None:
        manifests: list[ManifestFile] = []
        managers: list[str] = []
        frameworks: list[Framework] = []
        warnings: list[str] = []
        eco = self.ecosystem

        for path in repo.named(*BUILD_FILES):
            manager = BUILD_FILES[path.name]
            managers.append(manager)
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, manager))
            try:
                text = repo.read_text(path)
            except ManifestReadError as exc:
                warnings.append(str(exc))
                continue
            frameworks += [
                Framework(name=display, ecosystem=eco, evidence=str(path))
                for marker, display in FRAMEWORK_MARKERS.items()
                if marker in text
            ]

        for path in repo.named(*LOCKFILES):
            managers.append(LOCKFILES[path.name])
            manifests.append(manifest(path, eco, ManifestKind.LOCKFILE, LOCKFILES[path.name]))

        if not manifests:
            return None
        return EcosystemProfile(
            ecosystem=eco,
            adapter=self.name,
            package_managers=sorted_unique(managers),
            manifests=sorted(manifests, key=lambda m: m.path),
            frameworks=dedupe_frameworks(frameworks),
            warnings=warnings,
        )
