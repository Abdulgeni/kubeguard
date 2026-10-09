"""Tests for target models."""

import pytest

from kubeguard.core.targets import LayerInfo


class TestDisplayName:
    def test_tagged_reference_unchanged(self, make_target) -> None:
        assert make_target(reference="nginx:1.25").display_name == "nginx:1.25"

    def test_digest_reference_unchanged(self, make_target) -> None:
        ref = "nginx@sha256:" + "a" * 64
        assert make_target(reference=ref).display_name == ref

    def test_image_id_reference_unchanged(self, make_target) -> None:
        assert make_target(reference="sha256:abc123").display_name == "sha256:abc123"

    def test_untagged_uses_matching_repo_tag(self, make_target) -> None:
        target = make_target(reference="nginx", repo_tags=["other:1", "nginx:latest"])
        assert target.display_name == "nginx:latest"

    def test_registry_with_port(self, make_target) -> None:
        target = make_target(reference="localhost:5000/app", repo_tags=["localhost:5000/app:latest"])
        assert target.display_name == "localhost:5000/app:latest"

    def test_untagged_without_match_falls_back_to_reference(self, make_target) -> None:
        assert make_target(reference="nginx", repo_tags=[]).display_name == "nginx"


class TestLastUserInstruction:
    def layers(self, *created_by: str) -> list[LayerInfo]:
        return [LayerInfo(index=i, created_by=c) for i, c in enumerate(created_by)]

    def test_latest_user_wins(self, make_target) -> None:
        target = make_target(
            layers=self.layers("USER root", "RUN apt-get update", "USER app", "CMD x")
        )
        layer, value = target.last_user_instruction()
        assert (layer.index, value) == (2, "app")

    def test_legacy_builder_format(self, make_target) -> None:
        target = make_target(layers=self.layers("/bin/sh -c #(nop)  USER root"))
        assert target.last_user_instruction()[1] == "root"

    def test_ignores_user_inside_run(self, make_target) -> None:
        target = make_target(layers=self.layers("/bin/sh -c echo USER root"))
        assert target.last_user_instruction() is None

    def test_none_when_absent(self, make_target) -> None:
        assert make_target().last_user_instruction() is None


def test_target_is_frozen(make_target) -> None:
    with pytest.raises(Exception):
        make_target().user = "x"  # type: ignore[misc]