"""KG-K8S-001: runAsNonRoot is not true."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget
from kubeguard.rules.k8s._common import affected_containers


class RunAsNonRootRule(Rule):
    id = "KG-K8S-001"
    name = "Container may run as root"
    severity = Severity.MEDIUM
    description = (
        "securityContext.runAsNonRoot is not true at container or pod level, so the "
        "container is allowed to run as root."
    )
    remediation = (
        "Set securityContext.runAsNonRoot: true on the pod or on each container, and make "
        "sure the image defines a non-root user."
    )
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        pod_context = target.pod_security_context
        offenders = []
        for container in target.containers:
            context = container.security_context
            value = context["runAsNonRoot"] if "runAsNonRoot" in context else pod_context.get("runAsNonRoot")
            if value is not True:  # container-level value overrides the pod-level one
                offenders.append(container.name)
        return affected_containers(self, target, offenders)