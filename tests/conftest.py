"""Shared test fixtures."""

from __future__ import annotations

import sys
import uuid
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from kubeguard.core.exceptions import ContainerExecError
from kubeguard.core.models import Finding, Severity, TargetType
from kubeguard.core.rule import Rule
from kubeguard.core.targets import DockerImageTarget
from kubeguard.scanners.docker_adapter import RawImageData

RuleFactory = Callable[..., type[Rule]]


@pytest.fixture
def make_rule() -> RuleFactory:
    """Factory that builds concrete Rule subclasses for tests."""

    def _make(
        rule_id: str = "KG-TEST-001",
        target_type: TargetType = TargetType.DOCKER,
        severity: Severity = Severity.HIGH,
        triggers: bool = True,
        raises: bool = False,
    ) -> type[Rule]:
        def check(self: Rule, target: Any) -> Finding | None:
            if raises:
                raise RuntimeError("boom")
            return self.make_finding(resource=str(target)) if triggers else None

        return type(
            f"Rule_{rule_id.replace('-', '_')}",
            (Rule,),
            {
                "id": rule_id,
                "name": f"Test rule {rule_id}",
                "severity": severity,
                "description": "A test rule.",
                "remediation": "Fix it.",
                "target_type": target_type,
                "check": check,
            },
        )

    return _make


_RULE_A = '''
from kubeguard.core.models import Severity, TargetType
from kubeguard.core.rule import Rule


class RuleA(Rule):
    id = "KG-TEST-001"
    name = "Rule A"
    severity = Severity.HIGH
    description = "desc a"
    remediation = "fix a"
    target_type = TargetType.DOCKER

    def check(self, target):
        return self.make_finding(resource="img") if target.get("bad") else None
'''

_RULE_B = '''
from kubeguard.core.models import Severity, TargetType
from kubeguard.core.rule import Rule


class RuleB(Rule):
    id = "KG-TEST-002"
    name = "Rule B"
    severity = Severity.LOW
    description = "desc b"
    remediation = "fix b"
    target_type = TargetType.K8S

    def check(self, target):
        return None
'''

_ABSTRACT = '''
from abc import abstractmethod
from kubeguard.core.rule import Rule


class AbstractHelper(Rule):
    @abstractmethod
    def extra(self): ...
'''


@pytest.fixture
def sample_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, Path]]:
    """A throwaway rule package on sys.path. Yields (package_name, package_dir)."""
    name = f"kg_sample_rules_{uuid.uuid4().hex[:8]}"
    pkg = tmp_path / name
    (pkg / "sub").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "rule_a.py").write_text(_RULE_A)
    (pkg / "abstract_helper.py").write_text(_ABSTRACT)
    (pkg / "sub" / "__init__.py").write_text("")
    (pkg / "sub" / "rule_b.py").write_text(_RULE_B)
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name, pkg
    for mod in [m for m in sys.modules if m == name or m.startswith(f"{name}.")]:
        del sys.modules[mod]


@pytest.fixture
def make_target() -> Callable[..., DockerImageTarget]:
    """Factory for DockerImageTarget with sensible defaults."""

    def _make(**overrides: Any) -> DockerImageTarget:
        data: dict[str, Any] = {"reference": "nginx:latest"}
        data.update(overrides)
        return DockerImageTarget(**data)

    return _make


@pytest.fixture
def make_raw_image() -> Callable[..., RawImageData]:
    """Factory for RawImageData shaped like Docker's real output (history newest-first)."""

    def _make(
        user: str = "",
        tags: tuple[str, ...] = ("nginx:latest",),
        env: list[str] | None = None,
        labels: dict[str, str] | None = None,
        history: list[dict[str, Any]] | None = None,
        with_config: bool = True,
    ) -> RawImageData:
        inspect: dict[str, Any] = {
            "Id": "sha256:abc123",
            "RepoTags": list(tags),
            "Created": "2026-01-01T00:00:00Z",
            "Architecture": "amd64",
            "Os": "linux",
        }
        if with_config:
            # Docker reports null for unset Env/Labels, so we do too.
            inspect["Config"] = {"User": user, "Env": env, "Labels": labels}
        if history is None:
            history = [
                {"CreatedBy": 'CMD ["nginx"]', "Created": 3, "Size": 0},
                {"CreatedBy": "/bin/sh -c #(nop)  USER root", "Created": 2, "Size": 0},
                {"CreatedBy": "ADD file:abc in /", "Created": 1, "Size": 1000},
            ]
        return RawImageData(inspect=inspect, history=history)

    return _make


class FakeDockerAdapter:
    """In-memory DockerAdapter for tests."""

    def __init__(
        self,
        raw: RawImageData | None = None,
        error: Exception | None = None,
        archive: bytes | None = None,
        commands: dict[str, str | Exception] | None = None,
    ) -> None:
        self.raw = raw
        self.error = error
        self.archive = archive
        self.commands = commands or {}
        self.calls: list[str] = []
        self.save_calls: list[str] = []
        self.run_calls: list[list[str]] = []

    def fetch_image(self, reference: str) -> RawImageData:
        self.calls.append(reference)
        if self.error is not None:
            raise self.error
        assert self.raw is not None
        return self.raw

    def save_image(self, reference: str) -> Iterator[bytes]:
        self.save_calls.append(reference)
        assert self.archive is not None
        for i in range(0, len(self.archive), 1024):
            yield self.archive[i : i + 1024]

    def run_command(self, reference: str, command: Sequence[str]) -> str:
        self.run_calls.append(list(command))
        result = self.commands.get(command[0], ContainerExecError("not found", 127))
        if isinstance(result, Exception):
            raise result
        return result