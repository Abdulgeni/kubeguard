"""KG-K8S-002: allowPrivilegeEscalation is not false."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget
from kubeguard.rules.k8s._common import affected_containers


class PrivilegeEscalationRule(Rule):
    id = "KG-K8S-002"
    name = "Privilege escalation allowed"
    severity = Severity.MEDIUM
    description = (
        "securityContext.allowPrivilegeEscalation is not explicitly false, so processes can "
        "gain more privileges than their parent (for example through setuid binaries)."
    )
    remediation = "Set securityContext.allowPrivilegeEscalation: false on every container."
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        offenders = [
            c.name for c in target.containers if c.security_context.get("allowPrivilegeEscalation") is not False
        ]
        return affected_containers(self, target, offenders)