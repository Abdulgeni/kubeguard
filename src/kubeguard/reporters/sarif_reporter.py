"""SARIF 2.1.0 reporter (GitHub Code Scanning compatible)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from kubeguard import __version__
from kubeguard.core.models import Finding, ScanResult, Severity, TargetType
from kubeguard.reporters.base import Reporter, sort_findings

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub bands: >9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def split_location(location: str | None) -> tuple[str | None, int | None]:
    """Split ``path:line`` into its parts. Windows drive letters and non-path text are preserved."""
    if not location:
        return None, None
    head, sep, tail = location.rpartition(":")
    if sep and head and tail.isdigit():
        return head, int(tail)
    return location, None


def normalise_uri(path: str) -> str:
    """Forward-slash path, relative to the working directory when possible."""
    candidate = Path(path)
    try:
        candidate = candidate.resolve().relative_to(Path.cwd().resolve())
    except (ValueError, OSError):
        pass
    return candidate.as_posix()


class SarifReporter(Reporter):
    """Renders SARIF 2.1.0.

    Args:
        docker_artifact_uri: File that Docker/CVE findings are attached to (Code Scanning needs
            a file location); the image is recorded as a logical location.
    """

    def __init__(self, docker_artifact_uri: str = "Dockerfile") -> None:
        self._docker_uri = docker_artifact_uri

    def render(self, result: ScanResult) -> str:
        findings = sort_findings(result.findings)
        rules: list[dict[str, Any]] = []
        index: dict[str, int] = {}
        worst: dict[str, Severity] = {}
        for f in findings:
            if f.rule_id not in index:
                index[f.rule_id] = len(rules)
                rules.append(
                    {
                        "id": f.rule_id,
                        "name": f.rule_name,
                        "shortDescription": {"text": f.rule_name},
                        "properties": {"tags": ["security", f.target_type.value]},
                    }
                )
            worst[f.rule_id] = max(worst.get(f.rule_id, f.severity), f.severity)
        for rule in rules:
            severity = worst[rule["id"]]
            rule["defaultConfiguration"] = {"level": _LEVEL[severity]}
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY[severity]

        run = {
            "tool": {"driver": {"name": "KubeGuard", "version": __version__, "rules": rules}},
            "results": [self._result(f, index[f.rule_id]) for f in findings],
            "invocations": [
                {
                    "executionSuccessful": not result.errors,
                    "toolExecutionNotifications": [
                        {"level": "warning", "message": {"text": error}} for error in result.errors
                    ],
                }
            ],
        }
        return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)

    def _result(self, f: Finding, rule_index: int) -> dict[str, Any]:
        is_k8s = f.target_type is TargetType.K8S
        path, line = split_location(f.location) if is_k8s else (None, None)
        uri = normalise_uri(path) if path else self._docker_uri
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line or 1},
            }
        }
        if not is_k8s:
            location["logicalLocations"] = [{"name": f.resource, "kind": "resource"}]
        fingerprint = "|".join(
            [f.rule_id, f.resource, path or "", str(f.metadata.get("cve_id", "")), str(f.metadata.get("package", ""))]
        )
        return {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.description}\n\nRemediation: {f.remediation}"},
            "locations": [location],
            "partialFingerprints": {"kubeguard/v1": hashlib.sha256(fingerprint.encode()).hexdigest()[:32]},
            "properties": {
                "severity": f.severity.value,
                "resource": f.resource,
                "remediation": f.remediation,
                "metadata": json.loads(json.dumps(f.metadata, default=str)),
            },
        }