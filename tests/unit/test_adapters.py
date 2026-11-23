import json

from guardian.adapters.container import ContainerAdapter, base_images
from guardian.adapters.java import JavaAdapter
from guardian.adapters.node import NodeAdapter
from guardian.adapters.python import PythonAdapter
from guardian.core.models import Ecosystem, ManifestKind


def _framework_names(profile):
    return [f.name for f in profile.frameworks]


class TestPythonAdapter:
    def test_absent_returns_none(self, make_view):
        assert PythonAdapter().detect(make_view({"main.go": "package main"})) is None

    def test_pyproject_pep621_and_uv_lock(self, make_view):
        view = make_view(
            {
                "pyproject.toml": (
                    '[project]\nname = "x"\n'
                    'dependencies = ["FastAPI[all]>=0.110", "requests"]\n'
                    '[project.optional-dependencies]\nweb = ["Django>=5"]\n'
                    '[dependency-groups]\ndev = ["pytest"]\n'
                ),
                "uv.lock": "version = 1\n",
            }
        )
        profile = PythonAdapter().detect(view)
        assert profile is not None
        assert profile.ecosystem is Ecosystem.PYTHON
        assert profile.package_managers == ["pip", "uv"]
        assert _framework_names(profile) == ["Django", "FastAPI"]
        assert [m.path for m in profile.lockfiles] == ["uv.lock"]

    def test_poetry(self, make_view):
        view = make_view(
            {
                "pyproject.toml": (
                    "[tool.poetry.dependencies]\npython = '^3.11'\nflask = '^3'\n"
                    "[tool.poetry.group.dev.dependencies]\ncelery = '*'\n"
                ),
                "poetry.lock": "",
            }
        )
        profile = PythonAdapter().detect(view)
        assert profile.package_managers == ["poetry"]
        assert _framework_names(profile) == ["Celery", "Flask"]

    def test_requirements_files_skip_options_and_comments(self, make_view):
        view = make_view(
            {
                "requirements.txt": "-r base.txt\n# flask\nDjango==4.2  # web\n--hash=sha256:abc\n",
                "requirements/dev.txt": "sqlalchemy\n",
                "notes.txt": "flask\n",
            }
        )
        profile = PythonAdapter().detect(view)
        assert sorted(m.path for m in profile.manifests) == [
            "requirements.txt",
            "requirements/dev.txt",
        ]
        assert _framework_names(profile) == ["Django", "SQLAlchemy"]

    def test_malformed_pyproject_is_a_warning(self, make_view):
        profile = PythonAdapter().detect(make_view({"pyproject.toml": "[project\n"}))
        assert profile is not None
        assert len(profile.manifests) == 1
        assert "Could not parse pyproject.toml" in profile.warnings[0]

    def test_wrongly_typed_sections_are_tolerated(self, make_view):
        view = make_view({"pyproject.toml": 'project = "oops"\n[tool]\npoetry = 3\n'})
        profile = PythonAdapter().detect(view)
        assert profile.frameworks == []
        assert profile.warnings == []

    def test_oversized_manifest_is_a_warning(self, make_view):
        view = make_view({"requirements.txt": "flask\n" * 100}, max_read_bytes=10)
        profile = PythonAdapter().detect(view)
        assert profile.frameworks == []
        assert "byte limit" in profile.warnings[0]


class TestNodeAdapter:
    def test_package_json_with_pnpm_lock(self, make_view):
        pkg = {"dependencies": {"express": "^4"}, "devDependencies": {"typescript": "5"}}
        view = make_view({"package.json": json.dumps(pkg), "pnpm-lock.yaml": ""})
        profile = NodeAdapter().detect(view)
        assert profile.package_managers == ["pnpm"]
        assert _framework_names(profile) == ["Express", "TypeScript"]
        manifest = next(m for m in profile.manifests if m.kind is ManifestKind.MANIFEST)
        assert manifest.package_manager == "pnpm"

    def test_package_manager_field_wins(self, make_view):
        pkg = {"packageManager": "yarn@4.1.0", "dependencies": {"@nestjs/core": "10"}}
        profile = NodeAdapter().detect(make_view({"package.json": json.dumps(pkg)}))
        assert profile.package_managers == ["yarn"]
        assert _framework_names(profile) == ["NestJS"]

    def test_defaults_to_npm_and_ignores_node_modules(self, make_view):
        view = make_view(
            {"package.json": "{}", "node_modules/react/package.json": '{"name": "react"}'}
        )
        profile = NodeAdapter().detect(view)
        assert [m.path for m in profile.manifests] == ["package.json"]
        assert profile.package_managers == ["npm"]

    def test_invalid_json(self, make_view):
        profile = NodeAdapter().detect(make_view({"package.json": "[1, 2]"}))
        assert profile.warnings == ["package.json is not a JSON object"]
        profile = NodeAdapter().detect(make_view({"package.json": "{"}))
        assert "Could not parse" in profile.warnings[0]


class TestJavaAdapter:
    def test_maven_spring_boot(self, make_view):
        pom = "<project><parent><groupId>org.springframework.boot</groupId>"
        pom += "<artifactId>spring-boot-starter-parent</artifactId></parent></project>"
        profile = JavaAdapter().detect(make_view({"pom.xml": pom}))
        assert profile.package_managers == ["maven"]
        assert _framework_names(profile) == ["Spring", "Spring Boot"]

    def test_gradle_with_lockfile(self, make_view):
        view = make_view(
            {"build.gradle.kts": 'implementation("io.quarkus:quarkus-core")', "gradle.lockfile": ""}
        )
        profile = JavaAdapter().detect(view)
        assert profile.package_managers == ["gradle"]
        assert _framework_names(profile) == ["Quarkus"]
        assert len(profile.lockfiles) == 1

    def test_absent(self, make_view):
        assert JavaAdapter().detect(make_view({"README.md": ""})) is None


class TestContainerAdapter:
    def test_base_images_skip_stages_and_scratch(self):
        dockerfile = (
            "FROM --platform=linux/amd64 python:3.12-slim AS build\n"
            "RUN pip install .\n"
            "from build as test\n"
            "FROM scratch\n"
            "FROM gcr.io/distroless/python3@sha256:abc\n"
        )
        assert base_images(dockerfile) == [
            "python:3.12-slim",
            "gcr.io/distroless/python3@sha256:abc",
        ]

    def test_dockerfiles_and_compose(self, make_view):
        view = make_view(
            {
                "Dockerfile": "FROM node:20\n",
                "deploy/api.Dockerfile": "FROM nginx:1.27\n",
                "Dockerfile.dev": "FROM node:20\n",
                "compose.yaml": "services: {}\n",
            }
        )
        profile = ContainerAdapter().detect(view)
        assert profile.package_managers == ["docker", "docker-compose"]
        assert len(profile.manifests) == 4
        assert profile.metadata == {"base_images": ["nginx:1.27", "node:20"]}

    def test_absent(self, make_view):
        assert ContainerAdapter().detect(make_view({"app.py": ""})) is None
