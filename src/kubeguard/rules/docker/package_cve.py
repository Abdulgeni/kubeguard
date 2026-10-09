"""KG-DOCKER-004: installed package has a known CVE."""

from __future__ import annotations

from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import PackageVulnerabilityTarget

_CAVEAT = "Distribution-backported fixes are not considered, so this may be a false positive."
_LOW_CONFIDENCE = " Matched by keyword search only; verify manually."


class PackageCveRule(Rule):
    """One finding per (package, CVE). Severity is derived from the CVSS base score.

    A config severity override for this rule ID replaces the CVSS-derived severity.
    """

    id = "KG-DOCKER-004"
    name = "Package has known CVE"
    severity = Severity.MEDIUM  # default only; per-finding severity comes from CVSS
    description = (
        "An installed package matches a vulnerability published in the NVD. Matching uses "
        "upstream version data."
    )
    remediation = "Upgrade the package to a fixed release or rebuild the image from an updated base."
    target_type = TargetType.DOCKER_PACKAGE

    def check(self, target: PackageVulnerabilityTarget) -> Finding | None:
        severity = self.severity if self.severity_overridden else Severity.from_cvss(target.cvss_score)
        score = f"CVSS {target.cvss_score:.1f}" if target.cvss_score is not None else "unscored"
        pkg = target.package
        summary = " ".join(target.description.split())[:300]
        description = (
            f"{pkg.name} {pkg.version} is affected by {target.cve_id} "
            f"({score}, {target.confidence} confidence). {summary} {_CAVEAT}"
        )
        if target.confidence == "low":
            description += _LOW_CONFIDENCE
        return self.make_finding(
            resource=target.image,
            description=description,
            severity=severity,
            remediation=(
                f"Upgrade {pkg.name} to a release that fixes {target.cve_id} or rebuild from an "
                f"updated base image. Details: {target.remediation_url}"
            ),
            cve_id=target.cve_id,
            cvss_score=target.cvss_score,
            cvss_version=target.cvss_version,
            remediation_url=target.remediation_url,
            package=pkg.name,
            version=pkg.version,
            ecosystem=pkg.ecosystem,
            confidence=target.confidence,
            match_method=target.match_method,
            cpe=target.cpe,
            also_affects=target.also_affects,
        )