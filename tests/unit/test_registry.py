import pytest

from guardian.adapters.base import EcosystemAdapter, normalize_package_name
from guardian.adapters.python import PythonAdapter
from guardian.core.models import Ecosystem
from guardian.core.registry import AdapterRegistry, default_registry


class ExplodingAdapter(EcosystemAdapter):
    name = "exploding"
    ecosystem = Ecosystem.PYTHON

    def detect(self, repo):
        msg = "boom"
        raise RuntimeError(msg)


def test_default_registry_has_all_builtin_adapters():
    assert [a.name for a in default_registry().adapters] == ["python", "node", "java", "container"]


def test_duplicate_registration_rejected():
    registry = AdapterRegistry([PythonAdapter()])
    with pytest.raises(ValueError, match="already registered"):
        registry.register(PythonAdapter())


def test_failing_adapter_produces_warning_not_crash(make_view):
    registry = AdapterRegistry([ExplodingAdapter(), PythonAdapter()])
    profiles, warnings = registry.detect(make_view({"requirements.txt": "flask"}))
    assert [p.adapter for p in profiles] == ["python"]
    assert warnings == ["Adapter 'exploding' failed: boom"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Flask", "flask"), ("zope.interface", "zope-interface"), ("Foo__Bar", "foo-bar")],
)
def test_normalize_package_name(raw, expected):
    assert normalize_package_name(raw) == expected
