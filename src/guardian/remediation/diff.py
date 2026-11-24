"""Before/after comparison of SBOMs (by purl without version) and findings (by finding id)."""

from collections import defaultdict
from collections.abc import Sequence

from guardian.core.models import Component, Finding, Sbom
from guardian.core.remediation_models import ComponentChange, SbomDiff


def split_purl(purl: str) -> tuple[str, str | None]:
    """``pkg:npm/%40scope/name@1.2.3?x=y#sub`` -> (``pkg:npm/%40scope/name``, ``1.2.3``)."""
    core = purl.split("#", 1)[0].split("?", 1)[0]
    head, sep, last = core.rpartition("/")
    if "@" in last:
        name, version = last.rsplit("@", 1)
        return f"{head}{sep}{name}", version or None
    return core, None


def _key(component: Component) -> tuple[str, str | None, str]:
    """(base, version, full identifier) for one component."""
    if component.purl:
        base, version = split_purl(component.purl)
        return base, version or component.version, component.purl
    prefix = f"{component.purl_type or 'component'}:"
    name = f"{component.group}/{component.name}" if component.group else component.name
    base = prefix + name
    full = f"{base}@{component.version}" if component.version else base
    return base, component.version, full


def _index(sbom: Sbom | None) -> dict[str, dict[str | None, str]]:
    index: dict[str, dict[str | None, str]] = defaultdict(dict)
    for component in sbom.components if sbom else ():
        base, version, full = _key(component)
        index[base].setdefault(version, full)
    return index


def _sort_versions(versions: set[str | None]) -> list[str | None]:
    return sorted(versions, key=lambda v: (v is None, v or ""))


def diff_sboms(before: Sbom | None, after: Sbom | None) -> SbomDiff:
    """Components keyed by purl without version. A base present on both sides whose versions
    differ yields ``changed`` entries (old and new versions paired in sorted order); unpaired
    versions are reported as added/removed purls."""
    old, new = _index(before), _index(after)
    added: list[str] = []
    removed: list[str] = []
    changed: list[ComponentChange] = []
    for base in sorted(old.keys() | new.keys()):
        old_versions, new_versions = old.get(base, {}), new.get(base, {})
        gone = _sort_versions(set(old_versions) - set(new_versions))
        came = _sort_versions(set(new_versions) - set(old_versions))
        pairs = min(len(gone), len(came)) if old_versions and new_versions else 0
        changed += [
            ComponentChange(purl_base=base, from_version=f, to_version=t)
            for f, t in zip(gone[:pairs], came[:pairs], strict=True)
        ]
        removed += [old_versions[v] for v in gone[pairs:]]
        added += [new_versions[v] for v in came[pairs:]]
    return SbomDiff(added=sorted(added), removed=sorted(removed), changed=changed)


def diff_findings(
    before: Sequence[Finding], after: Sequence[Finding]
) -> tuple[list[str], list[str], list[str]]:
    """``(resolved, still_present, new)`` finding ids, each sorted."""
    old = {f.id for f in before}
    new = {f.id for f in after}
    return sorted(old - new), sorted(old & new), sorted(new - old)
