"""KG-DOCKER-003: outdated base image (age heuristic)."""

from __future__ import annotations

from datetime import datetime, UTC

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget

_OCI_CREATED = "org.opencontainers.image.created"


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class OutdatedBaseImageRule(Rule):
    """Flags images whose oldest layer is older than ``max_age_days`` (default 180).

    Heuristic: age is only a proxy for missing security patches.
    Configure with ``rule_options: {KG-DOCKER-003: {max_age_days: 365}}``.
    """

    id = "KG-DOCKER-003"
    name = "Outdated base image"
    severity = Severity.MEDIUM
    description = (
        "Heuristic: the image's oldest layer (a proxy for its base image) is older than the "
        "allowed age, so it probably lacks recent security patches. Verify against the base "
        "image's current tag."
    )
    remediation = "Rebuild on a current base image tag and refresh it regularly (pin by digest)."
    target_type = TargetType.DOCKER
    max_age_days: int = 180

    def _now(self) -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _created(target: DockerImageTarget) -> tuple[datetime, str, str | None] | None:
        for layer in sorted(target.layers, key=lambda item: item.index):
            if layer.created and layer.created > 0:
                created = datetime.fromtimestamp(layer.created, tz=UTC)
                return created, "base layer", f"layer {layer.index}"
        label = _parse_time(target.labels.get(_OCI_CREATED))
        if label:
            return label, "image label", None
        built = _parse_time(target.created)
        if built:
            return built, "image creation time", None
        return None

    def check(self, target: DockerImageTarget) -> Finding | None:
        found = self._created(target)
        if found is None:
            return None
        created, source, location = found
        age_days = (self._now() - created).days
        limit = int(self.max_age_days)
        if age_days <= limit:
            return None
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Age: {age_days} days (source: {source}; limit: {limit}).",
            location=location,
            age_days=age_days,
            max_age_days=limit,
            age_source=source,
        )