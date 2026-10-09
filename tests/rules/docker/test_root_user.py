"""Tests for KG-DOCKER-001."""

import pytest

from kubeguard.core.models import Severity, TargetType
from kubeguard.core.targets import LayerInfo
from kubeguard.rules.docker.root_user import RootUserRule, is_root_user


@pytest.mark.parametrize(
    "user", ["", "0", "root", "root:root", "0:0", "root:wheel", " root ", "00", ":1000"]
)
def test_is_root_user_true(user: str) -> None:
    assert is_root_user(user)


@pytest.mark.parametrize("user", ["1000", "app", "nobody", "1000:1000", "rootless", "10", "app:0"])
def test_is_root_user_false(user: str) -> None:
    assert not is_root_user(user)


class TestRootUserRule:
    def test_metadata(self) -> None:
        rule = RootUserRule()
        assert rule.id == "KG-DOCKER-001"
        assert rule.severity is Severity.HIGH
        assert rule.target_type is TargetType.DOCKER

    @pytest.mark.parametrize("user", ["", "0", "root"])
    def test_flags_root(self, make_target, user: str) -> None:
        finding = RootUserRule().check(make_target(user=user))
        assert finding is not None
        assert finding.rule_id == "KG-DOCKER-001"
        assert finding.severity is Severity.HIGH
        assert finding.resource == "nginx:latest"
        assert finding.remediation

    def test_non_root_passes(self, make_target) -> None:
        assert RootUserRule().check(make_target(user="10001")) is None

    def test_unset_user_is_called_out(self, make_target) -> None:
        finding = RootUserRule().check(make_target(user=""))
        assert "<not set>" in finding.description

    def test_layer_context_when_user_instruction_present(self, make_target) -> None:
        layers = [
            LayerInfo(index=0, created_by="ADD file:abc in /"),
            LayerInfo(index=1, created_by="/bin/sh -c #(nop)  USER root"),
        ]
        finding = RootUserRule().check(make_target(user="root", layers=layers))
        assert finding.location == "layer 1: USER root"
        assert finding.metadata["layer_index"] == 1

    def test_layer_context_when_no_user_instruction(self, make_target) -> None:
        layers = [LayerInfo(index=0, created_by="ADD file:abc in /")]
        finding = RootUserRule().check(make_target(user="", layers=layers))
        assert finding.location == "no USER instruction found in image history"
        assert "layer_index" not in finding.metadata

    def test_no_layer_context_when_history_unavailable(self, make_target) -> None:
        finding = RootUserRule().check(make_target(user="", layers=[]))
        assert finding.location is None