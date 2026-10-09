"""Target models handed to rules by the scanners."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Matches a USER instruction in `docker history` CreatedBy text, both the legacy
# builder ("/bin/sh -c #(nop)  USER root") and BuildKit ("USER root").
_USER_INSTRUCTION = re.compile(r"^(?:/bin/sh -c #\(nop\)\s+)?USER\s+(?P<user>\S+)")


class LayerInfo(BaseModel):
    """One image layer. ``index`` 0 is the oldest (base) layer."""

    model_config = ConfigDict(frozen=True)

    index: int
    created_by: str = ""
    created: int | None = None
    size: int | None = None


class PackageInfo(BaseModel):
    """An installed OS package."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    ecosystem: str = Field(description="Package manager family: 'deb', 'apk', or 'rpm'.")
    source: str | None = Field(
        default=None, description="Source/origin package name (e.g. 'openssl' for 'libssl3')."
    )


class DockerImageTarget(BaseModel):
    """Everything rules need to know about one local Docker image."""

    model_config = ConfigDict(frozen=True)

    reference: str = Field(description="The image reference exactly as the user supplied it.")
    image_id: str = ""
    repo_tags: list[str] = Field(default_factory=list)
    user: str = Field(default="", description="Raw Config.User; empty string if unset.")
    env: list[str] = Field(default_factory=list, description="Config.Env as 'KEY=value' strings.")
    labels: dict[str, str] = Field(default_factory=dict)
    created: str | None = None
    architecture: str | None = None
    os: str | None = None
    layers: list[LayerInfo] = Field(default_factory=list)
    packages: list[PackageInfo] | None = Field(
        default=None, description="None means enumeration was not attempted or failed."
    )
    package_error: str | None = Field(
        default=None, description="Why package enumeration failed, if it was attempted."
    )
    cve_omitted: int = Field(default=0, description="CVE findings dropped by the per-image cap.")
    cve_lookup_errors: list[str] = Field(
        default_factory=list, description="Problems that made CVE results incomplete."
    )

    @property
    def display_name(self) -> str:
        """Best ``name:tag`` for reports.

        Uses the supplied reference when it carries a tag or digest; otherwise
        prefers a matching entry from ``repo_tags`` (so ``nginx`` -> ``nginx:latest``).
        """
        ref = self.reference
        if ":" in ref.rsplit("/", 1)[-1] or "@" in ref:
            return ref
        match = next((t for t in self.repo_tags if t.rsplit(":", 1)[0] == ref), None)
        return match or ref

    def last_user_instruction(self) -> tuple[LayerInfo, str] | None:
        """The most recent ``USER`` instruction in the image history, if any."""
        for layer in sorted(self.layers, key=lambda item: item.index, reverse=True):
            found = _USER_INSTRUCTION.match(layer.created_by.strip())
            if found:
                return layer, found.group("user")
        return None


class PackageVulnerabilityTarget(BaseModel):
    """One (installed package, CVE) pair, evaluated by KG-DOCKER-004."""

    model_config = ConfigDict(frozen=True)

    image: str
    package: PackageInfo
    cve_id: str
    cvss_score: float | None = None
    cvss_version: str | None = None
    description: str = ""
    remediation_url: str
    confidence: Literal["high", "low"]
    match_method: Literal["cpe", "keyword"]
    cpe: str | None = None
    also_affects: list[str] = Field(default_factory=list)


def as_dict(value: Any) -> dict[str, Any]:
    """``value`` if it is a dict, else ``{}`` (manifests may be malformed)."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """``value`` if it is a list, else ``[]``."""
    return value if isinstance(value, list) else []


_TEMPLATE = ("spec", "template", "spec")
_POD_SPEC_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": _TEMPLATE,
    "StatefulSet": _TEMPLATE,
    "DaemonSet": _TEMPLATE,
    "ReplicaSet": _TEMPLATE,
    "ReplicationController": _TEMPLATE,
    "Job": _TEMPLATE,
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
WORKLOAD_KINDS = frozenset(_POD_SPEC_PATHS)
RBAC_KINDS = frozenset({"Role", "ClusterRole"})
SUPPORTED_KINDS = WORKLOAD_KINDS | RBAC_KINDS


class ContainerRef(BaseModel):
    """One container (or init/ephemeral container) of a workload."""

    model_config = ConfigDict(frozen=True)

    name: str
    kind: Literal["container", "initContainer", "ephemeralContainer"]
    spec: dict[str, Any]

    @property
    def security_context(self) -> dict[str, Any]:
        return as_dict(self.spec.get("securityContext"))


class K8sResourceTarget(BaseModel):
    """One Kubernetes resource parsed from a manifest."""

    model_config = ConfigDict(frozen=True)

    api_version: str = ""
    kind: str
    name: str
    namespace: str | None = None
    source: str
    line: int | None = None
    manifest: dict[str, Any]
    pod_spec: dict[str, Any] | None = None

    @classmethod
    def from_manifest(
        cls, manifest: dict[str, Any], source: str, line: int | None = None
    ) -> K8sResourceTarget | None:
        """Build a target, or ``None`` if the kind is not one KubeGuard evaluates."""
        kind = manifest.get("kind")
        if not isinstance(kind, str) or kind not in SUPPORTED_KINDS:
            return None
        meta = as_dict(manifest.get("metadata"))
        pod_spec: dict[str, Any] | None = None
        path = _POD_SPEC_PATHS.get(kind)
        if path:
            node: Any = manifest
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            pod_spec = node if isinstance(node, dict) else None
        namespace = meta.get("namespace")
        return cls(
            api_version=str(manifest.get("apiVersion") or ""),
            kind=kind,
            name=str(meta.get("name") or "<unnamed>"),
            namespace=str(namespace) if namespace else None,
            source=source,
            line=line,
            manifest=manifest,
            pod_spec=pod_spec,
        )

    @property
    def display_name(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def location(self) -> str:
        return f"{self.source}:{self.line}" if self.line else self.source

    @property
    def containers(self) -> list[ContainerRef]:
        if self.pod_spec is None:
            return []
        refs: list[ContainerRef] = []
        for field, kind in (
            ("containers", "container"),
            ("initContainers", "initContainer"),
            ("ephemeralContainers", "ephemeralContainer"),
        ):
            for item in as_list(self.pod_spec.get(field)):
                if isinstance(item, dict):
                    refs.append(
                        ContainerRef(
                            name=str(item.get("name") or "<unnamed>"), kind=kind, spec=item  # type: ignore[arg-type]
                        )
                    )
        return refs

    @property
    def pod_security_context(self) -> dict[str, Any]:
        return as_dict((self.pod_spec or {}).get("securityContext"))

    @property
    def volumes(self) -> list[dict[str, Any]]:
        return [v for v in as_list((self.pod_spec or {}).get("volumes")) if isinstance(v, dict)]