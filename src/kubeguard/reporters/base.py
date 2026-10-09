"""Reporter base class and shared ordering."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kubeguard.core.models import Finding, ScanResult


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by resource, rule, and location (stable and deterministic)."""
    return sorted(
        findings, key=lambda f: (-f.severity.rank, f.resource, f.rule_id, f.location or "")
    )


class Reporter(ABC):
    """Turns a ``ScanResult`` into text."""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Return the formatted report (no trailing newline)."""