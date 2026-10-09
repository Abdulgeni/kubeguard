"""KG-DOCKER-006: CVE results are incomplete (truncated or lookups failed)."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget


class CveResultsIncompleteRule(Rule):
    """Summarises CVE findings omitted by the cap and NVD lookup problems."""

    id = "KG-DOCKER-006"
    name = "CVE results incomplete"
    severity = Severity.INFO
    description = "CVE results for this image are incomplete, so the findings shown are not exhaustive."
    remediation = (
        "Raise the CVE findings limit, set NVD_API_KEY for a higher rate limit, and re-run. "
        "Cached lookups are reused, so a re-run is cheaper."
    )
    target_type = TargetType.DOCKER

    def check(self, target: DockerImageTarget) -> Finding | None:
        if not target.cve_omitted and not target.cve_lookup_errors:
            return None
        parts: list[str] = []
        if target.cve_omitted:
            parts.append(
                f"{target.cve_omitted} lower-severity CVE finding(s) were omitted (per-image limit)."
            )
        if target.cve_lookup_errors:
            parts.append("Lookup problems: " + "; ".join(target.cve_lookup_errors))
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} " + " ".join(parts),
            omitted=target.cve_omitted,
            lookup_errors=target.cve_lookup_errors,
        )