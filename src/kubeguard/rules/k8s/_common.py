"""Helpers shared by Kubernetes rules."""

from __future__ import annotations

from kubeguard.core.models import Finding
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget


def affected_containers(rule: Rule, target: K8sResourceTarget, names: list[str]) -> Finding | None:
    """One aggregated finding listing every offending container, or ``None``."""
    if not names:
        return None
    return rule.make_finding(
        resource=target.display_name,
        description=f"{rule.description} Affected containers: {', '.join(names)}.",
        location=target.location,
        containers=names,
        namespace=target.namespace,
    )