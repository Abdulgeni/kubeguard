"""KG-K8S-007: overly permissive RBAC."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import RBAC_KINDS, K8sResourceTarget, as_dict


class RbacWildcardRule(Rule):
    id = "KG-K8S-007"
    name = "RBAC wildcard permissions"
    severity = Severity.HIGH
    description = (
        "A Role or ClusterRole grants '*' for verbs or resources, which violates least "
        "privilege and can amount to cluster-admin."
    )
    remediation = "List only the specific verbs and resources the subject needs."
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        if target.kind not in RBAC_KINDS:
            return None
        rules = target.manifest.get("rules")
        if not isinstance(rules, list):
            return None
        offenders: list[str] = []
        indexes: list[int] = []
        for index, rule in enumerate(rules):
            entry = as_dict(rule)
            wild = [field for field in ("verbs", "resources") if "*" in (entry.get(field) or [])]
            if wild:
                indexes.append(index)
                offenders.append(f"#{index} (wildcard {' and '.join(wild)})")
        if not offenders:
            return None
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Offending rules: {'; '.join(offenders)}.",
            location=target.location,
            rule_indexes=indexes,
            namespace=target.namespace,
        )