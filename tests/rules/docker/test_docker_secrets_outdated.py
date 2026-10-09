"""Tests for KG-DOCKER-002 and KG-DOCKER-003."""

from datetime import UTC, datetime

from kubeguard.core.targets import LayerInfo
from kubeguard.rules.docker.env_secrets import DockerEnvSecretsRule
from kubeguard.rules.docker.outdated_base import OutdatedBaseImageRule

NOW = datetime(2026, 10, 9, tzinfo=UTC)


def ts(year: int, month: int, day: int) -> int:
    return int(datetime(year, month, day, tzinfo=UTC).timestamp())


class TestDockerEnvSecrets:
    rule = DockerEnvSecretsRule()

    def test_flags_secret_names_with_values_only(self, make_target) -> None:
        env = [
            "PATH=/usr/bin",
            "API_KEY=abc123",
            "DB_PASSWORD=",
            "SECRET_FILE=/run/s",
            "NOVALUE",
        ]
        finding = self.rule.check(make_target(env=env))
        assert finding.metadata["variables"] == ["API_KEY"]
        assert "abc123" not in finding.description

    def test_layer_context_without_leaking_value(self, make_target) -> None:
        layers = [
            LayerInfo(index=0, created_by="ADD file in /"),
            LayerInfo(index=1, created_by="/bin/sh -c #(nop)  ENV API_KEY=abc123"),
        ]
        finding = self.rule.check(make_target(env=["API_KEY=abc123"], layers=layers))
        assert finding.location == "layer 1"
        assert "abc123" not in finding.description

    def test_clean_env_passes(self, make_target) -> None:
        assert self.rule.check(make_target(env=["PATH=/usr/bin", "LANG=C"])) is None


class TestOutdatedBase:
    def rule(self) -> OutdatedBaseImageRule:
        rule = OutdatedBaseImageRule()
        rule._now = lambda: NOW
        return rule

    def test_old_base_layer_flagged(self, make_target) -> None:
        # 2025-01-01 to 2026-10-09 is 646 days.
        layers = [
            LayerInfo(index=0, created=ts(2025, 1, 1)),
            LayerInfo(index=1, created=ts(2026, 10, 1)),
        ]
        finding = self.rule().check(make_target(layers=layers))
        assert finding.metadata["age_days"] == 646
        assert finding.metadata["age_source"] == "base layer"
        assert finding.location == "layer 0"

    def test_recent_base_layer_passes(self, make_target) -> None:
        layers = [LayerInfo(index=0, created=ts(2026, 9, 20))]
        assert self.rule().check(make_target(layers=layers)) is None

    def test_falls_back_to_oci_label(self, make_target) -> None:
        target = make_target(labels={"org.opencontainers.image.created": "2020-01-01T00:00:00Z"})
        assert self.rule().check(target).metadata["age_source"] == "image label"

    def test_falls_back_to_image_creation_time(self, make_target) -> None:
        target = make_target(
            layers=[LayerInfo(index=0, created=0)],
            created="2020-01-01T00:00:00.123456789Z",
        )
        assert self.rule().check(target).metadata["age_source"] == "image creation time"

    def test_unknown_age_is_not_flagged(self, make_target) -> None:
        assert self.rule().check(make_target(created="not a date")) is None
        assert self.rule().check(make_target()) is None

    def test_threshold_is_configurable(self, make_target) -> None:
        rule = self.rule()
        rule.max_age_days = 10_000
        assert rule.check(make_target(created="2020-01-01T00:00:00Z")) is None