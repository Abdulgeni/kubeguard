"""Tests for KG-DOCKER-004 and KG-DOCKER-006."""

import pytest

from kubeguard.core.models import Severity, TargetType
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.targets import PackageInfo, PackageVulnerabilityTarget
from kubeguard.rules.docker.cve_incomplete import CveResultsIncompleteRule
from kubeguard.rules.docker.package_cve import PackageCveRule


def vuln(score=7.5, confidence="high", method="cpe", **overrides) -> PackageVulnerabilityTarget:
    data = dict(
        image="nginx:1.25",
        package=PackageInfo(name="libssl3", version="3.0.11-1", ecosystem="deb", source="openssl"),
        cve_id="CVE-2024-0001",
        cvss_score=score,
        cvss_version="3.1",
        description="Buffer   overflow\nin   foo.",
        remediation_url="https://vendor.example/patch",
        confidence=confidence,
        match_method=method,
        cpe="cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
        also_affects=["openssl"],
    )
    data.update(overrides)
    return PackageVulnerabilityTarget(**data)


class TestPackageCveRule:
    def test_metadata(self) -> None:
        rule = PackageCveRule()
        assert rule.id == "KG-DOCKER-004"
        assert rule.target_type is TargetType.DOCKER_PACKAGE

    @pytest.mark.parametrize(
        ("score", "expected"),
        [(9.8, Severity.CRITICAL), (7.5, Severity.HIGH), (5.0, Severity.MEDIUM), (2.0, Severity.LOW), (None, Severity.INFO)],
    )
    def test_severity_from_cvss(self, score, expected) -> None:
        assert PackageCveRule().check(vuln(score=score)).severity is expected

    def test_finding_content_and_metadata(self) -> None:
        finding = PackageCveRule().check(vuln())
        assert finding.resource == "nginx:1.25"
        assert "libssl3 3.0.11-1" in finding.description
        assert "CVE-2024-0001" in finding.description and "CVSS 7.5" in finding.description
        assert "Buffer overflow in foo." in finding.description  # whitespace collapsed
        assert "backported" in finding.description
        assert "https://vendor.example/patch" in finding.remediation
        assert finding.metadata["cve_id"] == "CVE-2024-0001"
        assert finding.metadata["cvss_score"] == 7.5
        assert finding.metadata["remediation_url"] == "https://vendor.example/patch"
        assert finding.metadata["confidence"] == "high"
        assert finding.metadata["match_method"] == "cpe"
        assert finding.metadata["also_affects"] == ["openssl"]

    def test_low_confidence_is_flagged(self) -> None:
        finding = PackageCveRule().check(vuln(confidence="low", method="keyword", cpe=None))
        assert finding.metadata["confidence"] == "low"
        assert finding.metadata["match_method"] == "keyword"
        assert "keyword search only" in finding.description

    def test_unscored_wording(self) -> None:
        assert "unscored" in PackageCveRule().check(vuln(score=None)).description

    def test_config_override_replaces_cvss_severity(self) -> None:
        registry = RuleRegistry(severity_overrides={"KG-DOCKER-004": Severity.LOW})
        registry.discover("kubeguard.rules")
        finding = registry.get("KG-DOCKER-004").check(vuln(score=9.8))
        assert finding.severity is Severity.LOW


class TestCveResultsIncompleteRule:
    def test_silent_when_complete(self, make_target) -> None:
        assert CveResultsIncompleteRule().check(make_target()) is None

    def test_reports_omitted(self, make_target) -> None:
        finding = CveResultsIncompleteRule().check(make_target(cve_omitted=7))
        assert finding.severity is Severity.INFO
        assert "7 lower-severity CVE finding(s) were omitted" in finding.description
        assert finding.metadata["omitted"] == 7

    def test_reports_lookup_errors(self, make_target) -> None:
        finding = CveResultsIncompleteRule().check(make_target(cve_lookup_errors=["curl 7.88: HTTP 503"]))
        assert "curl 7.88: HTTP 503" in finding.description