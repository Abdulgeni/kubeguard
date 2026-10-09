"""Docker image scanner."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Protocol

from kubeguard.core.exceptions import PackageEnumerationError, ScannerError
from kubeguard.core.models import Finding, ScanResult, TargetType
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.targets import (
    DockerImageTarget,
    LayerInfo,
    PackageInfo,
    PackageVulnerabilityTarget,
)
from kubeguard.integrations.cve_matcher import CveMatch
from kubeguard.scanners.base import Scanner
from kubeguard.scanners.docker_adapter import DockerAdapter, RawImageData

logger = logging.getLogger(__name__)


class PackageEnumerator(Protocol):
    """Lists the OS packages installed in an image (static or runtime strategy)."""

    def list_packages(self, reference: str) -> list[PackageInfo]:
        """Return installed packages.

        Raises:
            PackageEnumerationError: Packages could not be determined.
        """
        ...


class VulnerabilityMatcher(Protocol):
    """Finds CVEs for a package inventory (``CveMatcher`` or a fake)."""

    def match_all(self, packages: Sequence[PackageInfo]) -> tuple[list[CveMatch], list[str]]: ...


def build_docker_target(
    reference: str,
    raw: RawImageData,
    packages: list[PackageInfo] | None = None,
    package_error: str | None = None,
) -> DockerImageTarget:
    """Convert raw Docker data into a ``DockerImageTarget``.

    Tolerates missing or null fields, which Docker emits for minimal images.
    """
    inspect = raw.inspect
    config = inspect.get("Config") or {}
    # Docker returns history newest-first; store oldest-first with index 0 = base layer.
    layers = [
        LayerInfo(
            index=i,
            created_by=entry.get("CreatedBy") or "",
            created=entry.get("Created"),
            size=entry.get("Size"),
        )
        for i, entry in enumerate(reversed(raw.history))
    ]
    return DockerImageTarget(
        reference=reference,
        image_id=inspect.get("Id") or "",
        repo_tags=list(inspect.get("RepoTags") or []),
        user=config.get("User") or "",
        env=list(config.get("Env") or []),
        labels=dict(config.get("Labels") or {}),
        created=inspect.get("Created"),
        architecture=inspect.get("Architecture"),
        os=inspect.get("Os"),
        layers=layers,
        packages=packages,
        package_error=package_error,
    )


def _sort_key(match: CveMatch) -> tuple[float, str]:
    score = match.cve.cvss_score
    return (-(score if score is not None else -1.0), match.cve.id)


class DockerScanner(Scanner):
    """Scans a local Docker image against all enabled Docker rules.

    Args:
        registry: Rule registry (already populated via ``discover``).
        adapter: Docker access layer; inject a fake in tests.
        package_enumerator: Strategy for listing packages; ``None`` skips enumeration.
        cve_matcher: CVE lookup; ``None`` skips CVE checks.
        max_cve_findings: Cap on CVE findings per image (highest CVSS kept); ``None`` = no cap.
    """

    def __init__(
        self,
        registry: RuleRegistry,
        adapter: DockerAdapter,
        package_enumerator: PackageEnumerator | None = None,
        cve_matcher: VulnerabilityMatcher | None = None,
        max_cve_findings: int | None = 50,
    ) -> None:
        self._registry = registry
        self._adapter = adapter
        self._enumerator = package_enumerator
        self._cve_matcher = cve_matcher
        self._max_cve_findings = max_cve_findings

    def build_target(self, reference: str) -> DockerImageTarget:
        """Fetch the image and assemble the target the rules will inspect.

        Raises:
            ScannerError: Empty reference.
            ImageNotFoundError: Image not present locally.
            DockerUnavailableError: Docker unreachable.
        """
        if not reference or not reference.strip():
            raise ScannerError("Image reference must not be empty")
        raw = self._adapter.fetch_image(reference)

        packages: list[PackageInfo] | None = None
        package_error: str | None = None
        if self._enumerator is not None:
            try:
                packages = self._enumerator.list_packages(reference)
            except PackageEnumerationError as exc:
                logger.warning("Package enumeration failed for %s: %s", reference, exc)
                package_error = str(exc)
            except Exception as exc:  # noqa: BLE001 - never let enumeration abort a scan
                logger.exception("Unexpected error enumerating packages for %s", reference)
                package_error = f"unexpected {type(exc).__name__}: {exc}"

        return build_docker_target(reference, raw, packages, package_error)

    def scan(self, source: str) -> ScanResult:
        """Scan the local image ``source`` (e.g. ``nginx:1.25``)."""
        target = self.build_target(source)

        vuln_targets: list[PackageVulnerabilityTarget] = []
        if (
            self._cve_matcher is not None
            and target.packages
            and self._registry.rules_for(TargetType.DOCKER_PACKAGE)
        ):
            vuln_targets, notes, omitted = self._collect_vulnerabilities(target)
            target = target.model_copy(update={"cve_lookup_errors": notes, "cve_omitted": omitted})

        findings: list[Finding]
        findings, errors = self._registry.evaluate(target, TargetType.DOCKER)
        for vuln in vuln_targets:
            more_findings, more_errors = self._registry.evaluate(vuln, TargetType.DOCKER_PACKAGE)
            findings.extend(more_findings)
            errors.extend(more_errors)

        result = ScanResult()
        result.extend(findings, errors)
        return result

    def _collect_vulnerabilities(
        self, target: DockerImageTarget
    ) -> tuple[list[PackageVulnerabilityTarget], list[str], int]:
        assert self._cve_matcher is not None
        matches, notes = self._cve_matcher.match_all(target.packages or [])
        matches = sorted(matches, key=_sort_key)
        omitted = 0
        if self._max_cve_findings is not None and len(matches) > self._max_cve_findings:
            omitted = len(matches) - self._max_cve_findings
            matches = matches[: self._max_cve_findings]
        vulns = [
            PackageVulnerabilityTarget(
                image=target.display_name,
                package=m.package,
                cve_id=m.cve.id,
                cvss_score=m.cve.cvss_score,
                cvss_version=m.cve.cvss_version,
                description=m.cve.description,
                remediation_url=m.cve.remediation_url,
                confidence=m.confidence,
                match_method=m.method,
                cpe=m.cpe,
                also_affects=list(m.also_affects),
            )
            for m in matches
        ]
        return vulns, notes, omitted