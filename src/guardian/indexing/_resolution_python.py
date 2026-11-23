"""Python import resolution: relative, absolute (internal), stdlib and distributions."""

import sys
from dataclasses import dataclass, field

from guardian.adapters.base import normalize_package_name
from guardian.core.models import Ecosystem, ImportRef, ImportTarget
from guardian.indexing._resolution_layout import (
    UNRESOLVED,
    PackageIndex,
    RepoLayout,
    Resolution,
    join,
    parent_dir,
)

_REMOVED_STDLIB = frozenset({
    "aifc", "asynchat", "asyncore", "audioop", "cgi", "cgitb", "chunk", "crypt", "distutils",
    "imghdr", "imp", "lib2to3", "mailcap", "msilib", "nis", "nntplib", "ossaudiodev", "pipes",
    "smtpd", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib",
})  # fmt: skip
STDLIB_MODULES = frozenset(sys.stdlib_module_names) | _REMOVED_STDLIB | {"__future__"}

# Import name -> candidate distribution names (first declared/SBOM match wins, else first).
DISTRIBUTION_ALIASES: dict[str, tuple[str, ...]] = {
    "yaml": ("pyyaml",),
    "PIL": ("pillow",),
    "sklearn": ("scikit-learn",),
    "skimage": ("scikit-image",),
    "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python"),
    "bs4": ("beautifulsoup4",),
    "dateutil": ("python-dateutil",),
    "jwt": ("pyjwt",),
    "dotenv": ("python-dotenv",),
    "Crypto": ("pycryptodome", "pycrypto"),
    "Cryptodome": ("pycryptodomex",),
    "OpenSSL": ("pyopenssl",),
    "magic": ("python-magic",),
    "attr": ("attrs",),
    "google.protobuf": ("protobuf",),
    "MySQLdb": ("mysqlclient",),
    "psycopg2": ("psycopg2", "psycopg2-binary"),
    "serial": ("pyserial",),
    "docx": ("python-docx",),
    "pptx": ("python-pptx",),
    "multipart": ("python-multipart",),
    "jose": ("python-jose",),
    "Levenshtein": ("python-levenshtein",),
    "slugify": ("python-slugify",),
    "socketio": ("python-socketio",),
    "engineio": ("python-engineio",),
    "telegram": ("python-telegram-bot",),
    "ldap": ("python-ldap",),
    "nacl": ("pynacl",),
    "git": ("gitpython",),
    "github": ("pygithub",),
    "zmq": ("pyzmq",),
    "usb": ("pyusb",),
    "win32api": ("pywin32",),
    "win32con": ("pywin32",),
    "pythoncom": ("pywin32",),
    "dns": ("dnspython",),
    "Bio": ("biopython",),
    "fitz": ("pymupdf",),
    "lxml": ("lxml",),
    "markdown": ("markdown",),
    "kafka": ("kafka-python",),
    "memcache": ("python-memcached",),
    "snappy": ("python-snappy",),
    "faiss": ("faiss-cpu", "faiss-gpu"),
    "tensorflow": ("tensorflow", "tensorflow-cpu"),
    "Image": ("pillow",),
    "flask_sqlalchemy": ("flask-sqlalchemy",),
    "rest_framework": ("djangorestframework",),
    "jinja2": ("jinja2",),
    "OpenGL": ("pyopengl",),
    "gi": ("pygobject",),
    "pkg_resources": ("setuptools",),
    "setuptools": ("setuptools",),
    "websocket": ("websocket-client",),
    "ruamel": ("ruamel-yaml",),
    "ruamel.yaml": ("ruamel-yaml",),
}

_SEARCH_ROOTS = ("", "src", "lib")


@dataclass
class PythonResolver:
    layout: RepoLayout
    packages: PackageIndex
    _roots: dict[str, str] = field(default_factory=dict)

    def resolve(self, ref: ImportRef, importer: str) -> Resolution:
        module = ref.module.strip()
        dots = len(module) - len(module.lstrip("."))
        level = max(ref.level, dots)
        parts = [p.strip() for p in module.lstrip(".").split(".")] if module.lstrip(".") else []
        if any(not p.isidentifier() for p in parts):
            return UNRESOLVED
        if level > 0:
            return self._relative(importer, level, parts)
        if not parts:
            return UNRESOLVED
        return self._absolute(importer, parts)

    def _relative(self, importer: str, level: int, parts: list[str]) -> Resolution:
        base = parent_dir(importer)
        for _ in range(level - 1):
            if not base:
                return UNRESOLVED
            base = parent_dir(base)
        match = self._deepest(
            base, parts, min_depth=min(len(parts), 1), namespaces=self.layout.dirs
        )
        if match is None:
            return UNRESOLVED
        return Resolution(ImportTarget.INTERNAL, target_path=match[1])

    def _absolute(self, importer: str, parts: list[str]) -> Resolution:
        top = parts[0]
        best: tuple[int, bool, int] | None = None
        best_path: str | None = None
        for root in self._candidate_roots(importer):
            match = self._deepest(root, parts, min_depth=1, namespaces=self.layout.py_dirs)
            if match is None:
                continue
            rank = (match[0], match[1] is not None, -len(root))
            if best is None or rank > best:
                best, best_path = rank, match[1]
        shadows = best is not None and (
            best[1]
            or (
                top not in STDLIB_MODULES
                and not self.packages.known(Ecosystem.PYTHON, self.distribution(parts))
            )
        )
        if shadows:
            return Resolution(ImportTarget.INTERNAL, target_path=best_path)
        if top in STDLIB_MODULES:
            return Resolution(ImportTarget.STDLIB, package=top)
        name = self.distribution(parts)
        return Resolution(
            ImportTarget.EXTERNAL,
            package=name,
            component_ref=self.packages.ref(Ecosystem.PYTHON, name),
        )

    def distribution(self, parts: list[str]) -> str:
        """Distribution name for an import path (alias map, then PEP 503 normalization)."""
        candidates: list[str] = [
            "-".join(parts[:n]) for n in (3, 2) if len(parts) >= n
        ]  # e.g. google.cloud.storage -> google-cloud-storage
        aliases: list[str] = []
        for n in (2, 1):
            if len(parts) >= n:
                aliases.extend(DISTRIBUTION_ALIASES.get(".".join(parts[:n]), ()))
        candidates.extend(aliases)
        candidates.append(parts[0])
        for candidate in candidates:
            if self.packages.known(Ecosystem.PYTHON, candidate):
                return normalize_package_name(candidate)
        return normalize_package_name(aliases[0] if aliases else parts[0])

    def _candidate_roots(self, importer: str) -> list[str]:
        roots = list(_SEARCH_ROOTS)
        package_root = self._package_root(parent_dir(importer))
        if package_root not in roots:
            roots.append(package_root)
        return roots

    def _package_root(self, directory: str) -> str:
        """Parent of the importing file's top-level package (or its directory if none)."""
        cached = self._roots.get(directory)
        if cached is not None:
            return cached
        current = directory
        while current and join(current, "__init__.py") in self.layout.files:
            current = parent_dir(current)
        self._roots[directory] = current
        return current

    def _deepest(
        self, root: str, parts: list[str], *, min_depth: int, namespaces: frozenset[str]
    ) -> tuple[int, str | None] | None:
        """Deepest prefix of ``parts`` that is a module under ``root``: (depth, file|None)."""
        files = self.layout.files
        for depth in range(len(parts), min_depth - 1, -1):
            key = join(root, *parts[:depth])
            if depth > 0 and f"{key}.py" in files:
                return depth, f"{key}.py"
            init = join(key, "__init__.py")
            if init in files:
                return depth, init
            if key in namespaces or (not key and files):
                return depth, None
        return None
