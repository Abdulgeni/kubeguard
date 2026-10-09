"""Thin wrapper around the Docker SDK so the rest of the code never imports it.

Tests substitute a fake ``DockerAdapter``; no daemon is required.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import docker
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound

from kubeguard.core.exceptions import (
    ContainerExecError,
    DockerUnavailableError,
    ImageNotFoundError,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawImageData:
    """Unprocessed image data as returned by Docker.

    Attributes:
        inspect: The ``docker inspect`` dictionary (``image.attrs``).
        history: ``docker history`` entries, newest layer first.
    """

    inspect: dict[str, Any]
    history: list[dict[str, Any]]


class DockerAdapter(Protocol):
    """The only Docker operations the scanner depends on."""

    def fetch_image(self, reference: str) -> RawImageData:
        """Return inspect + history data for a local image."""
        ...

    def save_image(self, reference: str) -> Iterator[bytes]:
        """Stream the image as a ``docker save`` tar archive. Creates no container."""
        ...

    def run_command(self, reference: str, command: Sequence[str]) -> str:
        """Run ``command`` in a throwaway container and return stdout.

        Executes code from the image: only used on the opt-in runtime path.

        Raises:
            ContainerExecError: The command failed or could not start.
        """
        ...


def _text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


class SdkDockerAdapter:
    """``DockerAdapter`` backed by the Docker SDK for Python.

    Args:
        client: Optional pre-built client (used by tests). If omitted, one is
            created lazily from the environment on first use.
    """

    def __init__(self, client: docker.DockerClient | None = None) -> None:
        self._client = client

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as exc:
                raise DockerUnavailableError(f"Cannot create Docker client: {exc}") from exc
        return self._client

    def fetch_image(self, reference: str) -> RawImageData:
        client = self._get_client()
        try:
            image = client.images.get(reference)
            history = image.history()
        except ImageNotFound as exc:
            raise ImageNotFoundError(
                f"Image {reference!r} not found locally. Pull it first: docker pull {reference}"
            ) from exc
        except DockerException as exc:
            raise DockerUnavailableError(
                f"Docker error while reading image {reference!r}: {exc}"
            ) from exc
        return RawImageData(inspect=dict(image.attrs), history=list(history))

    def save_image(self, reference: str) -> Iterator[bytes]:
        client = self._get_client()
        try:
            image = client.images.get(reference)
            yield from image.save()
        except ImageNotFound as exc:
            raise ImageNotFoundError(f"Image {reference!r} not found locally") from exc
        except DockerException as exc:
            raise DockerUnavailableError(
                f"Docker error while saving image {reference!r}: {exc}"
            ) from exc

    def run_command(self, reference: str, command: Sequence[str]) -> str:
        client = self._get_client()
        try:
            output = client.containers.run(
                reference,
                list(command),
                entrypoint=[""],  # [""] resets the image ENTRYPOINT
                remove=True,
                detach=False,
                stdout=True,
                stderr=False,
                network_disabled=True,
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                mem_limit="256m",
                pids_limit=128,
            )
        except ImageNotFound as exc:
            raise ImageNotFoundError(f"Image {reference!r} not found locally") from exc
        except ContainerError as exc:
            stderr = _text(exc.stderr).strip()[:200]
            raise ContainerExecError(
                f"{command[0]} exited with status {exc.exit_status}" + (f": {stderr}" if stderr else ""),
                exit_status=exc.exit_status,
            ) from exc
        except APIError as exc:
            raise ContainerExecError(f"Docker could not run {command[0]}: {exc}") from exc
        except DockerException as exc:
            raise DockerUnavailableError(f"Docker error running {command[0]}: {exc}") from exc
        return _text(output)