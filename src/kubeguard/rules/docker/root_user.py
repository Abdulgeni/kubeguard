"""KG-DOCKER-001: container runs as root."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget


def is_root_user(user: str) -> bool:
    """True if a Docker ``Config.User`` value resolves to root.

    Accepts ``user`` or ``user:group`` forms. An empty user means root.
    """
    name = user.strip().split(":", 1)[0].strip()
    if name in ("", "root"):
        return True
    return name.isascii() and name.isdigit() and int(name) == 0


class RootUserRule(Rule):
    """Flags images whose default user is root."""

    id = "KG-DOCKER-001"
    name = "Container runs as root"
    severity = Severity.HIGH
    description = (
        "The image's default user is root (Config.User is empty, '0', or 'root'). "
        "A compromised process then has root inside the container, which widens the "
        "impact of container-escape and file-permission attacks. Note that a runtime "
        "setting (docker --user, Kubernetes runAsUser) can override this default."
    )
    remediation = (
        "Create an unprivileged user and switch to it in the Dockerfile, e.g. "
        "`RUN useradd --uid 10001 --no-create-home app` then `USER 10001` "
        "(Alpine: `adduser -D -u 10001 app`). Prefer a numeric UID so Kubernetes "
        "`runAsNonRoot` can verify it."
    )
    target_type = TargetType.DOCKER

    def check(self, target: DockerImageTarget) -> Finding | None:
        if not is_root_user(target.user):
            return None

        metadata: dict[str, object] = {
            "image_id": target.image_id,
            "config_user": target.user,
        }
        location: str | None
        if not target.layers:
            location = None
        else:
            last_user = target.last_user_instruction()
            if last_user is None:
                location = "no USER instruction found in image history"
            else:
                layer, value = last_user
                location = f"layer {layer.index}: USER {value}"
                metadata["layer_index"] = layer.index

        shown = target.user if target.user else "<not set>"
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Config.User is {shown}.",
            location=location,
            **metadata,
        )