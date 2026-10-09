"""Shared data models: severity, findings, and scan results."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Finding severity, ordered Info < Low < Medium < High < Critical."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse a severity case-insensitively (e.g. ``"high"`` -> ``HIGH``)."""
        try:
            return cls(value.strip().upper())
        except ValueError:
            valid = ", ".join(s.value.lower() for s in cls)
            raise ValueError(f"Invalid severity {value!r}; expected one of: {valid}") from None

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS base score to a severity. Unscored (None or 0) is INFO."""
        if score is None or score <= 0:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    @property
    def rank(self) -> int:
        """Numeric rank; higher is more severe."""
        return _SEVERITY_ORDER.index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


class TargetType(str, Enum):
    """The kind of target a rule applies to."""

    DOCKER = "docker"
    DOCKER_PACKAGE = "docker-package"
    K8S = "k8s"


class Finding(BaseModel):
    """A single security issue reported by a rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    severity: Severity
    target_type: TargetType
    resource: str = Field(description="Affected resource, e.g. 'nginx:1.25' or 'Deployment/web'.")
    description: str
    remediation: str
    location: str | None = Field(
        default=None, description="File path/line or image layer context, if known."
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregated output of one scan run."""

    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(
        default_factory=list, description="Non-fatal problems (e.g. a rule that crashed)."
    )

    def extend(self, findings: list[Finding], errors: list[str] | None = None) -> None:
        """Add findings and optional errors to this result."""
        self.findings.extend(findings)
        if errors:
            self.errors.extend(errors)

    def max_severity(self) -> Severity | None:
        """Highest severity present, or ``None`` if there are no findings."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def at_or_above(self, threshold: Severity) -> list[Finding]:
        """Findings whose severity is >= ``threshold``."""
        return [f for f in self.findings if f.severity >= threshold]

    def should_fail(self, threshold: Severity | None) -> bool:
        """True if any finding meets ``threshold``. ``None`` means never fail."""
        if threshold is None:
            return False
        return bool(self.at_or_above(threshold))

    def counts_by_severity(self) -> dict[Severity, int]:
        """Finding counts for every severity (zeros included), most severe first."""
        counts = {sev: 0 for sev in reversed(_SEVERITY_ORDER)}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts