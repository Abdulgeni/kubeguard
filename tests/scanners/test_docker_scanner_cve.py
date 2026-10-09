"""Scanner-level CVE integration tests (fake adapter, enumerator and matcher)."""

import pytest

from kubeguard.core.models import Severity
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.targets import PackageInfo
from kubeguard.integrations.cve_matcher import CveMatch
from kubeguard.integrations.nvd_client import CveRecord
from kubeguard.scanners.docker_scanner import DockerScanner
from tests.conftest import FakeDockerAdapter

PKG = PackageInfo(name="libssl3", version="3.0.11-1", ecosystem="deb", source="openssl")


class FakeEnumerator:
    def __init__(self, packages) -> None:
        self.packages = packages

    def list_packages(self, reference):
        return self.packages


class FakeMatcher:
    def __init__(self, matches=(), notes=()) -> None:
        self.matches, self.notes, self.calls = list(matches), list(notes), []

    def match_all(self, packages):
        self.calls.append(list(packages))
        return list(self.matches), list(self.notes)


def match(cve_id: str, score: float | None) -> CveMatch:
    record = CveRecord(id=cve_id, cvss_score=score, cvss_version="3.1", remediation_url="https://x/" + cve_id)
    return CveMatch(cve=record, package=PKG, confidence="high", method="cpe", cpe="cpe:2.3:a:o:o:1:*:*:*:*:*:*:*")


@pytest.fixture
def registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.discover("kubeguard.rules")
    return reg


def scanner(registry, raw, matcher, packages=(PKG,), cap=50) -> DockerScanner:
    return DockerScanner(
        registry, FakeDockerAdapter(raw), FakeEnumerator(list(packages)), matcher, max_cve_findings=cap
    )


def cve_findings(result):
    return [f for f in result.findings if f.rule_id == "KG-DOCKER-004"]


def test_findings_sorted_by_cvss_with_derived_severity(registry, make_raw_image) -> None:
    matcher = FakeMatcher([match("CVE-LOW", 2.0), match("CVE-CRIT", 9.8), match("CVE-UNSCORED", None), match("CVE-HIGH", 7.5)])
    result = scanner(registry, make_raw_image(user="10001"), matcher).scan("nginx")
    found = [(f.metadata["cve_id"], f.severity) for f in cve_findings(result)]
    assert found == [
        ("CVE-CRIT", Severity.CRITICAL),
        ("CVE-HIGH", Severity.HIGH),
        ("CVE-LOW", Severity.LOW),
        ("CVE-UNSCORED", Severity.INFO),
    ]
    assert all(f.resource == "nginx:latest" for f in cve_findings(result))


def test_cap_keeps_highest_and_adds_summary(registry, make_raw_image) -> None:
    matcher = FakeMatcher([match("CVE-A", 5.0), match("CVE-B", 9.0), match("CVE-C", 7.0), match("CVE-D", 1.0)])
    result = scanner(registry, make_raw_image(user="10001"), matcher, cap=2).scan("nginx")
    assert [f.metadata["cve_id"] for f in cve_findings(result)] == ["CVE-B", "CVE-C"]
    summary = [f for f in result.findings if f.rule_id == "KG-DOCKER-006"]
    assert len(summary) == 1
    assert summary[0].severity is Severity.INFO
    assert summary[0].metadata["omitted"] == 2


def test_no_cap_when_none(registry, make_raw_image) -> None:
    matcher = FakeMatcher([match(f"CVE-{i}", 5.0) for i in range(80)])
    result = scanner(registry, make_raw_image(user="10001"), matcher, cap=None).scan("nginx")
    assert len(cve_findings(result)) == 80
    assert not [f for f in result.findings if f.rule_id == "KG-DOCKER-006"]


def test_lookup_notes_surface_as_info_finding(registry, make_raw_image) -> None:
    matcher = FakeMatcher(notes=["curl 7.88: HTTP 503"])
    result = scanner(registry, make_raw_image(user="10001"), matcher).scan("nginx")
    summary = [f for f in result.findings if f.rule_id == "KG-DOCKER-006"]
    assert len(summary) == 1 and "HTTP 503" in summary[0].description


def test_matcher_not_called_without_packages(registry, make_raw_image) -> None:
    matcher = FakeMatcher([match("CVE-1", 9.0)])
    result = scanner(registry, make_raw_image(user="10001"), matcher, packages=()).scan("nginx")
    assert matcher.calls == []
    assert cve_findings(result) == []


def test_matcher_not_called_when_cve_rule_disabled(make_raw_image) -> None:
    reg = RuleRegistry(disabled_rules=["KG-DOCKER-004"])
    reg.discover("kubeguard.rules")
    matcher = FakeMatcher([match("CVE-1", 9.0)])
    scanner(reg, make_raw_image(user="10001"), matcher).scan("nginx")
    assert matcher.calls == []


def test_no_matcher_means_no_cve_findings(registry, make_raw_image) -> None:
    result = scanner(registry, make_raw_image(user="10001"), None).scan("nginx")
    assert result.findings == []


def test_image_and_cve_findings_coexist(registry, make_raw_image) -> None:
    matcher = FakeMatcher([match("CVE-1", 9.0)])
    result = scanner(registry, make_raw_image(user=""), matcher).scan("nginx")
    assert {f.rule_id for f in result.findings} == {"KG-DOCKER-001", "KG-DOCKER-004"}


def test_severity_override_applies_to_cve_findings(make_raw_image) -> None:
    reg = RuleRegistry(severity_overrides={"KG-DOCKER-004": Severity.LOW})
    reg.discover("kubeguard.rules")
    result = scanner(reg, make_raw_image(user="10001"), FakeMatcher([match("CVE-1", 9.8)])).scan("nginx")
    assert cve_findings(result)[0].severity is Severity.LOW