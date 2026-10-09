"""Abstract base class for all KubeGuard rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kubeguard.core.models import Finding, Severity, TargetType


class Rule(ABC):
    """Base class for a security rule.

    Subclasses must define the class attributes below and implement ``check``.
    Rules are discovered automatically from the ``kubeguard.rules`` package;
    no registration code is needed.

    Attributes:
        id: Unique ID in the form ``KG-<AREA>-<NNN>``, e.g. ``KG-DOCKER-001``.
        name: Short human-readable title.
        severity: Default severity (can be overridden via config).
        description: What the rule detects and why it matters.
        remediation: How to fix a violation.
        target_type: Which scanner's targets this rule inspects.
        severity_overridden: Set by the registry when config overrides the severity.
    """

    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    target_type: TargetType
    severity_overridden: bool = False

    @abstractmethod
    def check(self, target: Any) -> Finding | None:
        """Evaluate ``target``; return a Finding on violation, else ``None``."""

    def make_finding(
        self,
        resource: str,
        description: str | None = None,
        *,
        location: str | None = None,
        severity: Severity | None = None,
        remediation: str | None = None,
        **metadata: Any,
    ) -> Finding:
        """Build a Finding pre-filled with this rule's metadata.

        Args:
            resource: The affected resource (image, Deployment/name, ...).
            description: Context-specific text; defaults to the rule description.
            location: Optional file/layer context.
            severity: Per-finding severity; defaults to the rule's.
            remediation: Per-finding remediation; defaults to the rule's.
            **metadata: Extra structured data attached to the finding.
        """
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.severity,
            target_type=self.target_type,
            resource=resource,
            description=description or self.description,
            remediation=remediation or self.remediation,
            location=location,
            metadata=metadata,
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {getattr(self, 'id', '?')}>"