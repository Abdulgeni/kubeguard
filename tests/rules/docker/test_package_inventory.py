"""Tests for KG-DOCKER-005."""

from kubeguard.core.models import Severity
from kubeguard.rules.docker.package_inventory import PackageInventoryUnavailableRule


def test_no_finding_when_no_error(make_target) -> None:
    assert PackageInventoryUnavailableRule().check(make_target()) is None


def test_info_finding_on_error(make_target) -> None:
    finding = PackageInventoryUnavailableRule().check(
        make_target(package_error="no dpkg/apk/rpm database found")
    )
    assert finding is not None
    assert finding.rule_id == "KG-DOCKER-005"
    assert finding.severity is Severity.INFO
    assert "no dpkg/apk/rpm database found" in finding.description
    assert finding.metadata["error"] == "no dpkg/apk/rpm database found"
    assert finding.resource == "nginx:latest"