"""KG-K8S-004 privileged containers and KG-K8S-005 hostPath volumes."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget, as_dict
from kubeguard.rules.k8s._common import affected_containers


class PrivilegedContainerRule(Rule):
    id = "KG-K8S-004"
    name = "Privileged container"
    severity = Severity.CRITICAL
    description = (
        "The container runs with securityContext.privileged: true, giving it nearly all "
        "host capabilities and device access."
    )
    remediation = (
        "Remove securityContext.privileged. Grant only the specific capabilities required "
        "via securityContext.capabilities.add."
    )
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        offenders = [c.name for c in target.containers if c.security_context.get("privileged") is True]
        return affected_containers(self, target, offenders)


class HostPathVolumeRule(Rule):
    id = "KG-K8S-005"
    name = "hostPath volume mounted"
    severity = Severity.HIGH
    description = (
        "The pod mounts a hostPath volume, exposing part of the node's filesystem to the "
        "workload and enabling container escape or node tampering."
    )
    remediation = (
        "Use emptyDir, a PersistentVolumeClaim, or a ConfigMap/Secret volume instead. If a "
        "hostPath is unavoidable, make it read-only and as narrow as possible."
    )
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        volumes = [
            {"name": str(v.get("name") or "<unnamed>"), "path": as_dict(v["hostPath"]).get("path")}
            for v in target.volumes
            if "hostPath" in v
        ]
        if not volumes:
            return None
        listing = ", ".join(f"{v['name']} ({v['path']})" for v in volumes)
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Volumes: {listing}.",
            location=target.location,
            volumes=volumes,
            namespace=target.namespace,
        )