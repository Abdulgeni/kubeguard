"""Tests for SdkDockerAdapter.save_image / run_command using fake SDK objects."""

import pytest
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound

from kubeguard.core.exceptions import (
    ContainerExecError,
    DockerUnavailableError,
    ImageNotFoundError,
)
from kubeguard.scanners.docker_adapter import SdkDockerAdapter


class FakeImage:
    def __init__(self, chunks=None, error=None) -> None:
        self._chunks = chunks or []
        self._error = error

    def save(self):
        if self._error:
            raise self._error
        return iter(self._chunks)


class FakeImages:
    def __init__(self, image=None, error=None) -> None:
        self.image, self.error = image, error

    def get(self, reference):
        if self.error:
            raise self.error
        return self.image


class FakeContainers:
    def __init__(self, result=b"", error=None) -> None:
        self.result, self.error = result, error
        self.args = None
        self.kwargs = None

    def run(self, image, command, **kwargs):
        self.args, self.kwargs = (image, command), kwargs
        if self.error:
            raise self.error
        return self.result


class FakeClient:
    def __init__(self, images=None, containers=None) -> None:
        self.images = images or FakeImages()
        self.containers = containers or FakeContainers()


def test_save_image_streams_chunks() -> None:
    client = FakeClient(images=FakeImages(FakeImage(chunks=[b"ab", b"cd"])))
    assert b"".join(SdkDockerAdapter(client).save_image("img")) == b"abcd"


def test_save_image_not_found() -> None:
    client = FakeClient(images=FakeImages(error=ImageNotFound("nope")))
    with pytest.raises(ImageNotFoundError):
        list(SdkDockerAdapter(client).save_image("img"))


def test_save_image_daemon_error() -> None:
    client = FakeClient(images=FakeImages(FakeImage(error=DockerException("boom"))))
    with pytest.raises(DockerUnavailableError, match="boom"):
        list(SdkDockerAdapter(client).save_image("img"))


def test_run_command_returns_decoded_stdout_with_hardening() -> None:
    containers = FakeContainers(result=b"hello\n")
    out = SdkDockerAdapter(FakeClient(containers=containers)).run_command("img", ["echo", "hi"])
    assert out == "hello\n"
    assert containers.args == ("img", ["echo", "hi"])
    kwargs = containers.kwargs
    assert kwargs["remove"] is True
    assert kwargs["entrypoint"] == [""]
    assert kwargs["network_disabled"] is True
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]


def test_run_command_nonzero_exit_maps_to_exec_error() -> None:
    err = ContainerError(None, 127, "dpkg-query", "img", b"not found")
    adapter = SdkDockerAdapter(FakeClient(containers=FakeContainers(error=err)))
    with pytest.raises(ContainerExecError, match="not found") as info:
        adapter.run_command("img", ["dpkg-query"])
    assert info.value.exit_status == 127


def test_run_command_api_error_maps_to_exec_error() -> None:
    adapter = SdkDockerAdapter(FakeClient(containers=FakeContainers(error=APIError("exec not found"))))
    with pytest.raises(ContainerExecError, match="could not run") as info:
        adapter.run_command("img", ["apk"])
    assert info.value.exit_status is None