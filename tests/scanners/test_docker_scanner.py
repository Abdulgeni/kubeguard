"""Tests for DockerScanner (no Docker daemon needed)."""

import pytest

from tests.conftest import FakeDockerAdapter
from kubeguard.core.exceptions import (
    ImageNotFoundError,
    PackageEnumerationError,
    ScannerError,
)
from kubeguard.core.models import Severity
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.targets import PackageInfo
from kubeguard.scanners.docker_scanner import DockerScanner


class FakeEnumerator:
    def __init__(self, packages=None, error: Exception | None = None) -> None:
        self.packages = packages or []
        self.error = error

    def list_packages(self, reference: str):
        if self.error:
            raise self.error
        return self.packages


@pytest.fixture
def registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.discover("kubeguard.rules")
    return reg


def rule_ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


def test_root_image_produces_finding(registry, make_raw_image) -> None:
    adapter = FakeDockerAdapter(make_raw_image(user=""))
    result = DockerScanner(registry, adapter).scan("nginx")
    assert "KG-DOCKER-001" in rule_ids(result)
    finding = next(f for f in result.findings if f.rule_id == "KG-DOCKER-001")
    assert finding.resource == "nginx:latest"
    assert finding.severity is Severity.HIGH
    assert adapter.calls == ["nginx"]


def test_non_root_image_is_clean(registry, make_raw_image) -> None:
    adapter = FakeDockerAdapter(make_raw_image(user="10001"))
    result = DockerScanner(registry, adapter).scan("nginx:latest")
    assert result.findings == []
    assert result.errors == []


def test_disabled_rule_is_not_reported(make_raw_image) -> None:
    reg = RuleRegistry(disabled_rules=["KG-DOCKER-001"])
    reg.discover("kubeguard.rules")
    result = DockerScanner(reg, FakeDockerAdapter(make_raw_image(user=""))).scan("nginx")
    assert "KG-DOCKER-001" not in rule_ids(result)


def test_severity_override_applies(make_raw_image) -> None:
    reg = RuleRegistry(severity_overrides={"KG-DOCKER-001": Severity.LOW})
    reg.discover("kubeguard.rules")
    result = DockerScanner(reg, FakeDockerAdapter(make_raw_image(user=""))).scan("nginx")
    assert result.findings[0].severity is Severity.LOW


class TestBuildTarget:
    def test_layers_are_oldest_first(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(registry, FakeDockerAdapter(make_raw_image()))
        target = scanner.build_target("nginx")
        assert target.layers[0].created_by.startswith("ADD file")
        assert target.layers[-1].created_by.startswith("CMD")
        assert [l.index for l in target.layers] == [0, 1, 2]

    def test_tolerates_missing_config(self, registry, make_raw_image) -> None:
        raw = make_raw_image(with_config=False, history=[])
        target = DockerScanner(registry, FakeDockerAdapter(raw)).build_target("nginx")
        assert target.user == ""
        assert target.env == []
        assert target.labels == {}
        assert target.layers == []

    def test_tolerates_null_env_and_labels(self, registry, make_raw_image) -> None:
        target = DockerScanner(registry, FakeDockerAdapter(make_raw_image())).build_target("nginx")
        assert target.env == [] and target.labels == {}

    def test_empty_reference_rejected(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(registry, FakeDockerAdapter(make_raw_image()))
        with pytest.raises(ScannerError):
            scanner.build_target("  ")

    def test_image_not_found_propagates(self, registry) -> None:
        adapter = FakeDockerAdapter(error=ImageNotFoundError("missing"))
        with pytest.raises(ImageNotFoundError):
            DockerScanner(registry, adapter).scan("ghost:1")


class TestPackageEnumeration:
    PKGS = [PackageInfo(name="openssl", version="3.0.11", ecosystem="deb")]

    def test_packages_attached_on_success(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(
            registry,
            FakeDockerAdapter(make_raw_image(user="10001")),
            FakeEnumerator(packages=self.PKGS),
        )
        target = scanner.build_target("nginx")
        assert target.packages == self.PKGS
        assert target.package_error is None
        assert scanner.scan("nginx").findings == []

    def test_failure_emits_info_finding(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(
            registry,
            FakeDockerAdapter(make_raw_image(user="10001")),
            FakeEnumerator(error=PackageEnumerationError("no package database found")),
        )
        result = scanner.scan("nginx")
        assert rule_ids(result) == ["KG-DOCKER-005"]
        assert result.findings[0].severity is Severity.INFO
        assert "no package database found" in result.findings[0].description

    def test_unexpected_enumerator_crash_is_not_silent(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(
            registry,
            FakeDockerAdapter(make_raw_image(user="10001")),
            FakeEnumerator(error=RuntimeError("tar corrupted")),
        )
        result = scanner.scan("nginx")
        assert rule_ids(result) == ["KG-DOCKER-005"]
        assert "tar corrupted" in result.findings[0].description

    def test_no_enumerator_means_no_info_finding(self, registry, make_raw_image) -> None:
        scanner = DockerScanner(registry, FakeDockerAdapter(make_raw_image(user="10001")))
        assert scanner.scan("nginx").findings == []