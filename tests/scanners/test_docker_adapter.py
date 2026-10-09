"""Tests for SdkDockerAdapter using a fake SDK client."""

import docker
import pytest
from docker.errors import DockerException, ImageNotFound

from kubeguard.core.exceptions import DockerUnavailableError, ImageNotFoundError
from kubeguard.scanners.docker_adapter import SdkDockerAdapter


class FakeImage:
    def __init__(self, attrs: dict, history: list) -> None:
        self.attrs = attrs
        self._history = history

    def history(self) -> list:
        return self._history


class FakeImages:
    def __init__(self, image: FakeImage | None = None, error: Exception | None = None) -> None:
        self.image = image
        self.error = error

    def get(self, reference: str) -> FakeImage:
        if self.error:
            raise self.error
        assert self.image is not None
        return self.image


class FakeClient:
    def __init__(self, images: FakeImages) -> None:
        self.images = images


def test_fetch_image_returns_attrs_and_history() -> None:
    image = FakeImage({"Id": "sha256:1"}, [{"CreatedBy": "x"}])
    adapter = SdkDockerAdapter(client=FakeClient(FakeImages(image)))
    raw = adapter.fetch_image("nginx")
    assert raw.inspect == {"Id": "sha256:1"}
    assert raw.history == [{"CreatedBy": "x"}]


def test_image_not_found_is_mapped() -> None:
    adapter = SdkDockerAdapter(client=FakeClient(FakeImages(error=ImageNotFound("nope"))))
    with pytest.raises(ImageNotFoundError, match="docker pull nginx"):
        adapter.fetch_image("nginx")


def test_daemon_error_is_mapped() -> None:
    adapter = SdkDockerAdapter(client=FakeClient(FakeImages(error=DockerException("daemon down"))))
    with pytest.raises(DockerUnavailableError, match="daemon down"):
        adapter.fetch_image("nginx")


def test_client_is_created_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> None:
        raise DockerException("no socket")

    monkeypatch.setattr(docker, "from_env", boom)
    adapter = SdkDockerAdapter()  # must not touch Docker yet
    with pytest.raises(DockerUnavailableError, match="no socket"):
        adapter.fetch_image("nginx")