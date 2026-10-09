"""KG-DOCKER-005: package inventory unavailable (CVE checks could not run)."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget


class PackageInventoryUnavailableRule(Rule):
    """Reports that installed packages could not be listed, so CVE results are incomplete."""

    id = "KG-DOCKER-005"
    name = "Package inventory unavailable"
    severity = Severity.INFO
    description = (
        "Installed packages could not be enumerated, so package CVE checks were "
        "not performed for this image. Absence of CVE findings does not mean the "
        "image is free of known vulnerabilities."
    )
    remediation = (
        "Check the reported error. Common causes: the image has no supported package "
        "database (distroless/scratch) or the image archive could not be read. "
        "Use a dedicated image scanner for such images, or opt in to runtime "
        "enumeration with --allow-container-exec if you accept running the image."
    )
    target_type = TargetType.DOCKER

    def check(self, target: DockerImageTarget) -> Finding | None:
        if target.package_error is None:
            return None
        return self.make_finding(
            resource=target.display_name,
            description=f"{self.description} Reason: {target.package_error}",
            error=target.package_error,
        )