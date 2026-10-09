"""KG-K8S-003: CPU/memory limits missing."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget, as_dict
from kubeguard.rules.k8s._common import affected_containers


class ResourceLimitsRule(Rule):
    id = "KG-K8S-003"
    name = "Resource limits missing"
    severity = Severity.LOW
    description = (
        "resources.limits does not set both cpu and memory. A single container can then "
        "starve other workloads on the node."
    )
    remediation = "Set resources.limits.cpu and resources.limits.memory on every container."
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        offenders = []
        for container in target.containers:
            limits = as_dict(as_dict(container.spec.get("resources")).get("limits"))
            missing = [res for res in ("cpu", "memory") if res not in limits]
            if missing:
                offenders.append(f"{container.name} (missing {', '.join(missing)})")
        return affected_containers(self, target, offenders)