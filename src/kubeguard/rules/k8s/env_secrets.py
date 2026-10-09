"""KG-K8S-006: secrets stored directly in env vars."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.patterns import looks_like_secret_name
from kubeguard.core.rule import Rule
from kubeguard.core.targets import K8sResourceTarget, as_dict, as_list


class K8sEnvSecretsRule(Rule):
    id = "KG-K8S-006"
    name = "Secret stored directly in env var"
    severity = Severity.HIGH
    description = (
        "A container sets a credential-like environment variable (API key, password, secret, "
        "token) to a literal value in the manifest, where anyone with read access or the Git "
        "history can see it."
    )
    remediation = (
        "Store the value in a Kubernetes Secret (or an external secrets manager) and reference "
        "it with env[].valueFrom.secretKeyRef or mount it as a file."
    )
    target_type = TargetType.K8S

    def check(self, target: K8sResourceTarget) -> Finding | None:
        variables: list[str] = []
        for container in target.containers:
            for entry in as_list(container.spec.get("env")):
                env = as_dict(entry)
                name, value = env.get("name"), env.get("value")
                if (
                    isinstance(name, str)
                    and value not in (None, "")
                    and "valueFrom" not in env
                    and looks_like_secret_name(name)
                ):
                    variables.append(f"{container.name}:{name}")
        if not variables:
            return None
        return self.make_finding(
            resource=target.display_name,
            # Variable names only; values are never copied into reports.
            description=f"{self.description} Variables: {', '.join(variables)}.",
            location=target.location,
            variables=variables,
            namespace=target.namespace,
        )