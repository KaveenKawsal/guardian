"""Adapter registry: selects which ecosystem adapters apply to a repository."""

import logging
from collections.abc import Iterable

from guardian.adapters.base import EcosystemAdapter, RepositoryView
from guardian.core.models import EcosystemProfile

logger = logging.getLogger(__name__)


class AdapterRegistry:
    def __init__(self, adapters: Iterable[EcosystemAdapter] = ()) -> None:
        self._adapters: dict[str, EcosystemAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: EcosystemAdapter) -> None:
        if adapter.name in self._adapters:
            msg = f"Adapter {adapter.name!r} is already registered"
            raise ValueError(msg)
        self._adapters[adapter.name] = adapter

    @property
    def adapters(self) -> list[EcosystemAdapter]:
        return list(self._adapters.values())

    def detect(self, repo: RepositoryView) -> tuple[list[EcosystemProfile], list[str]]:
        """Run every adapter; a failing adapter yields a warning instead of aborting the scan."""
        profiles: list[EcosystemProfile] = []
        warnings: list[str] = []
        for adapter in self._adapters.values():
            try:
                profile = adapter.detect(repo)
            except Exception as exc:
                logger.exception("Adapter %s failed", adapter.name)
                warnings.append(f"Adapter {adapter.name!r} failed: {exc}")
                continue
            if profile is not None:
                profiles.append(profile)
        return profiles, warnings


def default_registry() -> AdapterRegistry:
    from guardian.adapters.container import ContainerAdapter  # noqa: PLC0415
    from guardian.adapters.java import JavaAdapter  # noqa: PLC0415
    from guardian.adapters.node import NodeAdapter  # noqa: PLC0415
    from guardian.adapters.python import PythonAdapter  # noqa: PLC0415

    return AdapterRegistry([PythonAdapter(), NodeAdapter(), JavaAdapter(), ContainerAdapter()])
