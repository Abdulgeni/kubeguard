"""KG-DOCKER-002: secrets exposed in image environment variables."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.patterns import looks_like_secret_name
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget


class DockerEnvSecretsRule(Rule):
    id = "KG-DOCKER-002"
    name = "Secrets exposed in environment variables"
    severity = Severity.HIGH
    description = (
        "The image bakes in environment variables whose names suggest credentials (API key, "
        "password, secret, token) together with a value. Anyone who can pull or inspect the "
        "image can read them."
    )
    remediation = (
        "Remove the values from the image. Inject secrets at runtime (Docker/Kubernetes "
        "secrets or a secrets manager) and prefer files over environment variables."
    )
    target_type = TargetType.DOCKER

    def check(self, target: DockerImageTarget) -> Finding | None:
        names: list[str] = []
        for entry in target.env:
            name, sep, value = entry.partition("=")
            if sep and value and looks_like_secret_name(name) and name not in names:
                names.append(name)
        if not names:
            return None
        location = next(
            (f"layer {layer.index}" for name in names for layer in target.layers if name in layer.created_by),
            None,
        )
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Variables: {', '.join(names)}.",  # names only, never values
            location=location,
            variables=names,
        )