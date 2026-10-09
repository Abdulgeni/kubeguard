"""Tests for secret-name detection and registry rule options."""

import pytest

from kubeguard.core.exceptions import RuleDefinitionError
from kubeguard.core.patterns import looks_like_secret_name
from kubeguard.core.registry import RuleRegistry


@pytest.mark.parametrize(
    "name",
    ["API_KEY", "api-key", "ApiKey", "DB_PASSWORD", "passwd", "CLIENT_SECRET", "GITHUB_TOKEN"],
)
def test_secret_names_detected(name: str) -> None:
    assert looks_like_secret_name(name)


@pytest.mark.parametrize(
    "name", ["PATH", "HOME", "LOG_LEVEL", "SECRET_FILE", "DB_PASSWORD_FILE", "TOKEN_PATH"]
)
def test_non_secret_names_ignored(name: str) -> None:
    assert not looks_like_secret_name(name)


def registry_with(make_rule, options):
    cls = make_rule("KG-TEST-001")
    cls.threshold = 1
    registry = RuleRegistry(rule_options={"KG-TEST-001": options})
    registry.register(cls)
    return registry, cls


def test_rule_option_is_applied_to_instance_only(make_rule) -> None:
    registry, cls = registry_with(make_rule, {"threshold": 9})
    assert registry.get("KG-TEST-001").threshold == 9
    assert cls.threshold == 1


@pytest.mark.parametrize("option", ["nonexistent", "severity", "_private", "check"])
def test_invalid_options_fail_loudly(make_rule, option: str) -> None:
    registry, _ = registry_with(make_rule, {option: 1})
    with pytest.raises(RuleDefinitionError, match="unknown rule option"):
        registry.get("KG-TEST-001")


def test_options_for_unknown_rule_are_reported(make_rule) -> None:
    registry = RuleRegistry(rule_options={"KG-GONE-001": {"x": 1}})
    registry.register(make_rule("KG-TEST-001"))
    assert registry.unknown_config_ids() == ["KG-GONE-001"]