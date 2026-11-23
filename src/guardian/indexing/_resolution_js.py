"""JavaScript/TypeScript import resolution: relative files, Node built-ins, npm packages."""

from dataclasses import dataclass

from guardian.core.models import Ecosystem, ImportRef, ImportTarget
from guardian.indexing._resolution_layout import (
    UNRESOLVED,
    PackageIndex,
    RepoLayout,
    Resolution,
    join,
    parent_dir,
)

NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
})  # fmt: skip

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".mts", ".cts", ".d.ts")
_TS_SOURCES = {
    ".js": (".ts", ".tsx"),
    ".jsx": (".tsx",),
    ".mjs": (".mts",),
    ".cjs": (".cts",),
}
_ALIAS_PREFIXES = ("@/", "~/", "#")
_ALIAS_ROOTS = ("", "src")


def normalize_join(base: str, relative: str) -> str | None:
    """Join ``relative`` onto directory ``base``; None when it escapes the repository root."""
    parts = [p for p in base.split("/") if p]
    for segment in relative.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(segment)
    return "/".join(parts)


def _clean_specifier(module: str) -> str:
    spec = module.strip().rpartition("!")[2]  # webpack loader syntax: "loader!./x"
    return spec.split("?", 1)[0]


def package_name(spec: str) -> str | None:
    """npm package of a bare specifier: '@scope/name' or the first path segment."""
    segments = spec.split("/")
    if spec.startswith("@"):
        if len(segments) < 2 or len(segments[0]) < 2 or not segments[1]:  # noqa: PLR2004
            return None
        return f"{segments[0]}/{segments[1]}"
    return segments[0] or None


@dataclass
class JsResolver:
    layout: RepoLayout
    packages: PackageIndex

    def resolve(self, ref: ImportRef, importer: str) -> Resolution:
        spec = _clean_specifier(ref.module)
        if not spec:
            return UNRESOLVED
        if spec in {".", ".."} or spec.startswith(("./", "../", "/")):
            base = "" if spec.startswith("/") else parent_dir(importer)
            path = normalize_join(base, spec)
            return self._internal(path)
        if spec.startswith("node:"):
            name = spec[5:].split("/", 1)[0]
            return Resolution(ImportTarget.STDLIB, package=name) if name else UNRESOLVED
        if spec.startswith(_ALIAS_PREFIXES) or spec == "~":
            return self._aliased(spec.lstrip("@~#").lstrip("/"))
        if ":" in spec or "\\" in spec:
            return UNRESOLVED  # URL imports (https:, jsr:, npm: ...) and odd text
        return self._bare(spec)

    def _bare(self, spec: str) -> Resolution:
        name = package_name(spec)
        if name is None:
            return UNRESOLVED
        known = self.packages.known(Ecosystem.NODE, name)
        first = spec.split("/", 1)[0]
        if not known and first in NODE_BUILTINS:
            return Resolution(ImportTarget.STDLIB, package=first)
        if not known and (first in self.layout.top_dirs or join("src", first) in self.layout.dirs):
            return self._aliased(spec)
        return Resolution(
            ImportTarget.EXTERNAL,
            package=name,
            component_ref=self.packages.ref(Ecosystem.NODE, name),
        )

    def _aliased(self, rest: str) -> Resolution:
        for root in _ALIAS_ROOTS:
            found = self._internal(normalize_join(root, rest))
            if found.target is ImportTarget.INTERNAL:
                return found
        return UNRESOLVED

    def _internal(self, path: str | None) -> Resolution:
        if path is None:
            return UNRESOLVED
        found = self.find_file(path)
        if found is None:
            return UNRESOLVED
        return Resolution(ImportTarget.INTERNAL, target_path=found)

    def find_file(self, path: str) -> str | None:
        files = self.layout.files
        if path and path in files:
            return path
        stem, dot, ext = path.rpartition(".")
        if dot and "/" not in ext:
            for source_ext in _TS_SOURCES.get(f".{ext}", ()):
                if stem + source_ext in files:
                    return stem + source_ext
        if path:
            for ext_candidate in EXTENSIONS:
                if path + ext_candidate in files:
                    return path + ext_candidate
        for ext_candidate in EXTENSIONS:
            index = join(path, f"index{ext_candidate}")
            if index in files:
                return index
        return None
