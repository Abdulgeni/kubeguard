"""YAML configuration model and loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from kubeguard.core.exceptions import ConfigError
from kubeguard.core.models import Severity


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo in the config must fail, not be ignored


class CacheConfig(_Section):
    enabled: bool = True
    ttl_hours: float = Field(default=24.0, gt=0)
    directory: Path | None = None


class DockerConfig(_Section):
    images: list[str] = Field(default_factory=list)
    allow_container_exec: bool = False
    keyword_fallback: bool = True
    max_cve_findings: int | None = Field(default=50, ge=1)


class KubernetesConfig(_Section):
    paths: list[str] = Field(default_factory=list)


class SarifConfig(_Section):
    docker_artifact_uri: str = "Dockerfile"


class KubeGuardConfig(_Section):
    """Top-level configuration. Relative paths resolve against the working directory."""

    disabled_rules: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    rule_options: dict[str, dict[str, Any]] = Field(default_factory=dict)
    fail_on: Severity | None = None
    output: Literal["table", "json", "sarif"] = "table"
    cache: CacheConfig = Field(default_factory=CacheConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    kubernetes: KubernetesConfig = Field(default_factory=KubernetesConfig)
    sarif: SarifConfig = Field(default_factory=SarifConfig)

    @field_validator("severity_overrides", mode="before")
    @classmethod
    def _parse_overrides(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(rule): Severity.from_string(str(sev)) for rule, sev in value.items()}
        return value

    @field_validator("fail_on", mode="before")
    @classmethod
    def _parse_fail_on(cls, value: Any) -> Any:
        if isinstance(value, str):
            return None if value.strip().lower() == "none" else Severity.from_string(value)
        return value


def load_config(path: Path | str | None) -> KubeGuardConfig:
    """Load and validate a config file; ``None`` returns the defaults.

    Raises:
        ConfigError: The file cannot be read, is not valid YAML, or fails validation.
    """
    if path is None:
        return KubeGuardConfig()
    file = Path(path)
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Cannot read config {file}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {file}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Invalid config {file}: the top level must be a mapping")
    try:
        return KubeGuardConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid config {file}:\n{exc}") from exc