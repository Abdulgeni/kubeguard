"""Tests for config loading."""

import pytest

from kubeguard.core.config import KubeGuardConfig, load_config
from kubeguard.core.exceptions import ConfigError
from kubeguard.core.models import Severity


def write(tmp_path, text: str):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults() -> None:
    cfg = load_config(None)
    assert cfg == KubeGuardConfig()
    assert cfg.output == "table" and cfg.fail_on is None
    assert cfg.cache.enabled and cfg.cache.ttl_hours == 24
    assert cfg.docker.max_cve_findings == 50 and not cfg.docker.allow_container_exec


def test_empty_file_gives_defaults(tmp_path) -> None:
    assert load_config(write(tmp_path, "")) == KubeGuardConfig()


def test_full_config(tmp_path) -> None:
    cfg = load_config(
        write(
            tmp_path,
            """
disabled_rules: [KG-K8S-003]
severity_overrides: {KG-DOCKER-001: medium}
rule_options: {KG-DOCKER-003: {max_age_days: 365}}
fail_on: High
output: json
cache: {enabled: false, ttl_hours: 1}
docker: {images: [nginx:1.25], max_cve_findings: 10, keyword_fallback: false}
kubernetes: {paths: [./k8s]}
sarif: {docker_artifact_uri: build/Dockerfile}
""",
        )
    )
    assert cfg.disabled_rules == ["KG-K8S-003"]
    assert cfg.severity_overrides == {"KG-DOCKER-001": Severity.MEDIUM}
    assert cfg.rule_options == {"KG-DOCKER-003": {"max_age_days": 365}}
    assert cfg.fail_on is Severity.HIGH and cfg.output == "json"
    assert cfg.docker.images == ["nginx:1.25"] and not cfg.docker.keyword_fallback
    assert cfg.kubernetes.paths == ["./k8s"]
    assert cfg.sarif.docker_artifact_uri == "build/Dockerfile"


def test_fail_on_none_string(tmp_path) -> None:
    assert load_config(write(tmp_path, "fail_on: none")).fail_on is None


@pytest.mark.parametrize(
    "text",
    [
        "unknown_key: 1",
        "docker: {imagez: []}",
        "fail_on: urgent",
        "severity_overrides: {KG-X-001: urgent}",
        "output: xml",
        "cache: {ttl_hours: 0}",
        "docker: {max_cve_findings: 0}",
        "- just\n- a list",
    ],
)
def test_invalid_config_raises_config_error(tmp_path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


def test_bad_yaml_and_missing_file(tmp_path) -> None:
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(write(tmp_path, "a: [unclosed"))
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path / "missing.yaml")