"""Target models handed to rules by the scanners."""

from __future__ import annotations

import re
from typing import Literal

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
        for layer in sorted(self.layers, key=lambda l: l.index, reverse=True):
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