"""Tests for Severity.from_cvss and the Step 4 additions to Rule/Registry."""

import pytest

from kubeguard.core.models import Severity, TargetType
from kubeguard.core.registry import RuleRegistry


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, Severity.INFO),
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_from_cvss_boundaries(score, expected) -> None:
    assert Severity.from_cvss(score) is expected


def test_make_finding_overrides(make_rule) -> None:
    rule = make_rule(severity=Severity.HIGH)()
    finding = rule.make_finding("img", severity=Severity.LOW, remediation="do X")
    assert finding.severity is Severity.LOW
    assert finding.remediation == "do X"
    assert rule.make_finding("img").severity is Severity.HIGH


def test_registry_marks_overridden_rules(make_rule) -> None:
    registry = RuleRegistry(severity_overrides={"KG-TEST-001": Severity.LOW})
    registry.register(make_rule("KG-TEST-001"))
    registry.register(make_rule("KG-TEST-002"))
    assert registry.get("KG-TEST-001").severity_overridden is True
    assert registry.get("KG-TEST-002").severity_overridden is False


def test_docker_package_target_type_value() -> None:
    assert TargetType.DOCKER_PACKAGE.value == "docker-package"