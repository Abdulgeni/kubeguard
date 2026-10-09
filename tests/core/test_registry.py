"""Tests for Rule and RuleRegistry."""

import pytest

from kubeguard.core.exceptions import (
    DuplicateRuleError,
    RuleDefinitionError,
    RuleLoadError,
)
from kubeguard.core.models import Severity, TargetType
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.rule import Rule


class TestRule:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            Rule()  # type: ignore[abstract]

    def test_make_finding_uses_rule_metadata(self, make_rule) -> None:
        rule = make_rule("KG-TEST-001", TargetType.K8S, Severity.CRITICAL)()
        finding = rule.make_finding("Pod/web", location="a.yaml:3", container="app")
        assert finding.rule_id == "KG-TEST-001"
        assert finding.severity is Severity.CRITICAL
        assert finding.target_type is TargetType.K8S
        assert finding.description == "A test rule."
        assert finding.remediation == "Fix it."
        assert finding.location == "a.yaml:3"
        assert finding.metadata == {"container": "app"}

    def test_make_finding_custom_description(self, make_rule) -> None:
        finding = make_rule()().make_finding("img", "custom text")
        assert finding.description == "custom text"


class TestRegistration:
    def test_register_and_get(self, make_rule) -> None:
        registry = RuleRegistry()
        registry.register(make_rule("KG-TEST-001"))
        assert len(registry) == 1
        assert registry.get("KG-TEST-001") is not None
        assert registry.get("KG-NOPE-999") is None

    def test_register_same_class_twice_is_noop(self, make_rule) -> None:
        registry = RuleRegistry()
        cls = make_rule()
        registry.register(cls)
        registry.register(cls)
        assert len(registry) == 1

    def test_duplicate_id_different_class(self, make_rule) -> None:
        registry = RuleRegistry()
        registry.register(make_rule("KG-TEST-001"))
        with pytest.raises(DuplicateRuleError):
            registry.register(make_rule("KG-TEST-001"))

    @pytest.mark.parametrize("bad_id", ["", "TEST-001", "KG-TEST-1", "kg-test-001"])
    def test_invalid_id(self, make_rule, bad_id: str) -> None:
        with pytest.raises(RuleDefinitionError):
            RuleRegistry().register(make_rule(bad_id))

    def test_missing_metadata(self) -> None:
        class Incomplete(Rule):
            id = "KG-TEST-001"

            def check(self, target):  # type: ignore[no-untyped-def]
                return None

        with pytest.raises(RuleDefinitionError, match="name"):
            RuleRegistry().register(Incomplete)

    def test_works_as_decorator(self, make_rule) -> None:
        registry = RuleRegistry()
        cls = registry.register(make_rule())
        assert registry.get("KG-TEST-001").__class__ is cls


class TestConfiguration:
    def test_disabled_rule_excluded(self, make_rule) -> None:
        registry = RuleRegistry(disabled_rules=["KG-TEST-001"])
        registry.register(make_rule("KG-TEST-001"))
        registry.register(make_rule("KG-TEST-002"))
        assert [r.id for r in registry.all_rules()] == ["KG-TEST-002"]
        assert [r.id for r in registry.all_rules(include_disabled=True)] == [
            "KG-TEST-001",
            "KG-TEST-002",
        ]
        assert not registry.is_enabled("KG-TEST-001")
        assert registry.is_enabled("KG-TEST-002")

    def test_severity_override(self, make_rule) -> None:
        registry = RuleRegistry(severity_overrides={"KG-TEST-001": Severity.LOW})
        registry.register(make_rule("KG-TEST-001", severity=Severity.CRITICAL))
        finding, _ = registry.evaluate("img", TargetType.DOCKER)
        assert finding[0].severity is Severity.LOW

    def test_override_does_not_mutate_class(self, make_rule) -> None:
        cls = make_rule("KG-TEST-001", severity=Severity.CRITICAL)
        RuleRegistry(severity_overrides={"KG-TEST-001": Severity.LOW}).register(cls)
        registry = RuleRegistry(severity_overrides={"KG-TEST-001": Severity.LOW})
        registry.register(cls)
        registry.get("KG-TEST-001")
        assert cls.severity is Severity.CRITICAL

    def test_unknown_config_ids(self, make_rule) -> None:
        registry = RuleRegistry(
            disabled_rules=["KG-GONE-001"], severity_overrides={"KG-GONE-002": Severity.LOW}
        )
        registry.register(make_rule("KG-TEST-001"))
        assert registry.unknown_config_ids() == ["KG-GONE-001", "KG-GONE-002"]

    def test_rules_for_filters_by_target_type(self, make_rule) -> None:
        registry = RuleRegistry()
        registry.register(make_rule("KG-TEST-001", TargetType.DOCKER))
        registry.register(make_rule("KG-TEST-002", TargetType.K8S))
        assert [r.id for r in registry.rules_for(TargetType.K8S)] == ["KG-TEST-002"]


class TestEvaluate:
    def test_collects_findings(self, make_rule) -> None:
        registry = RuleRegistry()
        registry.register(make_rule("KG-TEST-001", triggers=True))
        registry.register(make_rule("KG-TEST-002", triggers=False))
        findings, errors = registry.evaluate("img", TargetType.DOCKER)
        assert [f.rule_id for f in findings] == ["KG-TEST-001"]
        assert errors == []

    def test_crashing_rule_is_isolated(self, make_rule) -> None:
        registry = RuleRegistry()
        registry.register(make_rule("KG-TEST-001", raises=True))
        registry.register(make_rule("KG-TEST-002", triggers=True))
        findings, errors = registry.evaluate("img", TargetType.DOCKER)
        assert [f.rule_id for f in findings] == ["KG-TEST-002"]
        assert len(errors) == 1
        assert "KG-TEST-001" in errors[0] and "RuntimeError" in errors[0]

    def test_disabled_rules_not_run(self, make_rule) -> None:
        registry = RuleRegistry(disabled_rules=["KG-TEST-001"])
        registry.register(make_rule("KG-TEST-001", triggers=True))
        findings, _ = registry.evaluate("img", TargetType.DOCKER)
        assert findings == []


class TestDiscovery:
    def test_discovers_nested_rules(self, sample_package) -> None:
        name, _ = sample_package
        registry = RuleRegistry()
        assert registry.discover(name) == 2
        assert {r.id for r in registry.all_rules()} == {"KG-TEST-001", "KG-TEST-002"}

    def test_skips_abstract_and_imported_base(self, sample_package) -> None:
        name, _ = sample_package
        registry = RuleRegistry()
        registry.discover(name)
        assert len(registry) == 2  # AbstractHelper and the imported `Rule` are ignored

    def test_discover_is_idempotent(self, sample_package) -> None:
        name, _ = sample_package
        registry = RuleRegistry()
        registry.discover(name)
        assert registry.discover(name) == 0

    def test_discovered_rule_runs(self, sample_package) -> None:
        name, _ = sample_package
        registry = RuleRegistry()
        registry.discover(name)
        findings, _ = registry.evaluate({"bad": True}, TargetType.DOCKER)
        assert [f.rule_id for f in findings] == ["KG-TEST-001"]

    def test_broken_module_raises(self, sample_package) -> None:
        name, pkg = sample_package
        (pkg / "broken.py").write_text("raise RuntimeError('import boom')")
        with pytest.raises(RuleLoadError, match="broken"):
            RuleRegistry().discover(name)

    def test_real_rules_package_is_discoverable(self) -> None:
        registry = RuleRegistry()
        assert registry.discover("kubeguard.rules") >= 2
        assert registry.get("KG-DOCKER-001") is not None