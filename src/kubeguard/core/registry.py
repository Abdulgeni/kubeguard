"""Rule registry: discovery, validation, enable/disable, and safe execution."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
from collections.abc import Iterable, Mapping
from typing import Any

from kubeguard.core.exceptions import (
    DuplicateRuleError,
    RuleDefinitionError,
    RuleLoadError,
)
from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule

logger = logging.getLogger(__name__)

_RULE_ID_PATTERN = re.compile(r"^KG-[A-Z0-9]+-[0-9]{3}$")
_REQUIRED_TEXT_ATTRS = ("id", "name", "description", "remediation")
_RESERVED_OPTION_NAMES = frozenset(
    {"id", "name", "severity", "description", "remediation", "target_type", "severity_overridden"}
)


def _validate_rule_class(cls: type[Rule]) -> None:
    """Raise RuleDefinitionError if the rule's metadata is missing or invalid."""
    for attr in _REQUIRED_TEXT_ATTRS:
        value = getattr(cls, attr, None)
        if not isinstance(value, str) or not value.strip():
            raise RuleDefinitionError(f"{cls.__name__}: '{attr}' must be a non-empty string")
    if not _RULE_ID_PATTERN.match(cls.id):
        raise RuleDefinitionError(
            f"{cls.__name__}: id {cls.id!r} must match KG-<AREA>-<NNN> (e.g. KG-DOCKER-001)"
        )
    if not isinstance(getattr(cls, "severity", None), Severity):
        raise RuleDefinitionError(f"{cls.__name__}: 'severity' must be a Severity member")
    if not isinstance(getattr(cls, "target_type", None), TargetType):
        raise RuleDefinitionError(f"{cls.__name__}: 'target_type' must be a TargetType member")


class RuleRegistry:
    """Holds rule classes and hands out configured rule instances.

    Args:
        disabled_rules: Rule IDs to skip.
        severity_overrides: Mapping of rule ID -> replacement severity.
        rule_options: Mapping of rule ID -> per-rule option overrides.
    """

    def __init__(
        self,
        disabled_rules: Iterable[str] = (),
        severity_overrides: Mapping[str, Severity] | None = None,
        rule_options: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self._classes: dict[str, type[Rule]] = {}
        self._instances: dict[str, Rule] = {}
        self._disabled: frozenset[str] = frozenset(disabled_rules)
        self._overrides: dict[str, Severity] = dict(severity_overrides or {})
        self._options: dict[str, dict[str, Any]] = {
            rid: dict(opts) for rid, opts in (rule_options or {}).items()
        }

    # ------------------------------------------------------------------ register
    def register(self, rule_cls: type[Rule]) -> type[Rule]:
        """Register a rule class (also usable as a decorator).

        Re-registering the same class is a no-op.

        Raises:
            RuleDefinitionError: Metadata is missing or invalid.
            DuplicateRuleError: A different class already uses this ID.
        """
        _validate_rule_class(rule_cls)
        existing = self._classes.get(rule_cls.id)
        if existing is rule_cls:
            return rule_cls
        if existing is not None:
            raise DuplicateRuleError(
                f"Rule ID {rule_cls.id} used by both "
                f"{existing.__module__}.{existing.__name__} and "
                f"{rule_cls.__module__}.{rule_cls.__name__}"
            )
        self._classes[rule_cls.id] = rule_cls
        logger.debug("Registered rule %s (%s)", rule_cls.id, rule_cls.__name__)
        return rule_cls

    def discover(self, package: str = "kubeguard.rules") -> int:
        """Import every module under ``package`` and register the Rule subclasses found.

        Only classes *defined* in a scanned module are registered (not ones it
        merely imports), and abstract classes are skipped.

        Returns:
            Number of newly registered rules.

        Raises:
            RuleLoadError: A module failed to import.
        """
        root = importlib.import_module(package)
        before = len(self._classes)

        def _on_error(name: str) -> None:
            raise RuleLoadError(f"Failed to import rule package {name!r}")

        module_names = [package]
        for info in pkgutil.walk_packages(root.__path__, prefix=f"{package}.", onerror=_on_error):
            module_names.append(info.name)

        for name in module_names:
            try:
                module = importlib.import_module(name)
            except Exception as exc:
                raise RuleLoadError(f"Failed to import rule module {name!r}: {exc}") from exc
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    obj is not Rule
                    and issubclass(obj, Rule)
                    and obj.__module__ == module.__name__
                    and not inspect.isabstract(obj)
                ):
                    self.register(obj)

        added = len(self._classes) - before
        logger.info("Discovered %d rule(s) in %s", added, package)
        for unknown in self.unknown_config_ids():
            logger.warning("Config references unknown rule ID: %s", unknown)
        return added

    # -------------------------------------------------------------------- lookup
    def is_enabled(self, rule_id: str) -> bool:
        """True if the rule is registered and not disabled."""
        return rule_id in self._classes and rule_id not in self._disabled

    def get(self, rule_id: str) -> Rule | None:
        """Return the configured instance for ``rule_id`` (even if disabled)."""
        cls = self._classes.get(rule_id)
        if cls is None:
            return None
        if rule_id not in self._instances:
            instance = cls()
            override = self._overrides.get(rule_id)
            if override is not None:
                instance.severity = override
                instance.severity_overridden = True
            for key, value in self._options.get(rule_id, {}).items():
                if (
                    key.startswith("_")
                    or key in _RESERVED_OPTION_NAMES
                    or not hasattr(instance, key)
                    or callable(getattr(instance, key))
                ):
                    raise RuleDefinitionError(f"{rule_id}: unknown rule option {key!r}")
                setattr(instance, key, value)
            self._instances[rule_id] = instance
        return self._instances[rule_id]

    def all_rules(self, include_disabled: bool = False) -> list[Rule]:
        """All rule instances sorted by ID."""
        ids = sorted(self._classes)
        if not include_disabled:
            ids = [i for i in ids if i not in self._disabled]
        return [rule for i in ids if (rule := self.get(i)) is not None]

    def rules_for(self, target_type: TargetType) -> list[Rule]:
        """Enabled rules that apply to ``target_type``, sorted by ID."""
        return [r for r in self.all_rules() if r.target_type is target_type]

    def unknown_config_ids(self) -> list[str]:
        """Rule IDs mentioned in disabled/override/option config that don't exist."""
        configured = set(self._disabled) | set(self._overrides) | set(self._options)
        return sorted(configured - set(self._classes))

    def __len__(self) -> int:
        return len(self._classes)

    # ----------------------------------------------------------------- execution
    def evaluate(self, target: Any, target_type: TargetType) -> tuple[list[Finding], list[str]]:
        """Run all enabled rules of ``target_type`` against ``target``.

        A rule that raises is logged and reported in the returned error list;
        the remaining rules still run.

        Returns:
            ``(findings, errors)``.
        """
        findings: list[Finding] = []
        errors: list[str] = []
        for rule in self.rules_for(target_type):
            try:
                finding = rule.check(target)
            except Exception as exc:  # noqa: BLE001 - isolate faulty rules
                logger.exception("Rule %s crashed", rule.id)
                errors.append(f"{rule.id}: {type(exc).__name__}: {exc}")
                continue
            if finding is not None:
                findings.append(finding)
        return findings, errors