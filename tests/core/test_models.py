"""Tests for Severity, Finding, and ScanResult."""

import pytest
from pydantic import ValidationError

from kubeguard.core.models import Finding, ScanResult, Severity, TargetType


def make_finding(severity: Severity, rule_id: str = "KG-TEST-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="n",
        severity=severity,
        target_type=TargetType.K8S,
        resource="Pod/x",
        description="d",
        remediation="r",
    )


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.LOW <= Severity.MEDIUM

    def test_sorting_and_max(self) -> None:
        sevs = [Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW]
        assert max(sevs) is Severity.CRITICAL
        assert sorted(sevs)[0] is Severity.INFO

    @pytest.mark.parametrize("raw", ["high", "HIGH", " High "])
    def test_from_string_case_insensitive(self, raw: str) -> None:
        assert Severity.from_string(raw) is Severity.HIGH

    def test_from_string_invalid(self) -> None:
        with pytest.raises(ValueError, match="Invalid severity"):
            Severity.from_string("urgent")

    def test_compare_with_non_severity(self) -> None:
        with pytest.raises(TypeError):
            _ = Severity.HIGH < 3  # type: ignore[operator]


class TestFinding:
    def test_is_frozen(self) -> None:
        finding = make_finding(Severity.LOW)
        with pytest.raises(ValidationError):
            finding.severity = Severity.HIGH  # type: ignore[misc]

    def test_json_roundtrip(self) -> None:
        finding = make_finding(Severity.HIGH)
        restored = Finding.model_validate_json(finding.model_dump_json())
        assert restored == finding
        assert '"severity":"HIGH"' in finding.model_dump_json()


class TestScanResult:
    def test_empty(self) -> None:
        result = ScanResult()
        assert result.max_severity() is None
        assert not result.should_fail(Severity.INFO)

    def test_should_fail_threshold(self) -> None:
        result = ScanResult()
        result.extend([make_finding(Severity.MEDIUM)])
        assert result.should_fail(Severity.MEDIUM)
        assert result.should_fail(Severity.LOW)
        assert not result.should_fail(Severity.HIGH)
        assert not result.should_fail(None)

    def test_counts_by_severity(self) -> None:
        result = ScanResult()
        result.extend([make_finding(Severity.HIGH), make_finding(Severity.HIGH)])
        counts = result.counts_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.CRITICAL] == 0
        assert list(counts)[0] is Severity.CRITICAL

    def test_extend_collects_errors(self) -> None:
        result = ScanResult()
        result.extend([], errors=["oops"])
        assert result.errors == ["oops"]