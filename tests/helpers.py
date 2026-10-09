"""Shared test doubles. Import with ``from tests.helpers import ...``."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from typing import Any

_INVALID_JSON = object()
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class FakeClock:
    """Deterministic clock whose sleep() just advances time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        invalid_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._payload = _INVALID_JSON if invalid_json else payload
        self.headers = headers or {}

    def json(self) -> Any:
        if self._payload is _INVALID_JSON:
            raise ValueError("bad json")
        return self._payload


class FakeSession:
    """Replays queued responses (or raises queued exceptions); records every call."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> Any:
        self.calls.append({"url": url, **kwargs})
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def make_cve_item(
    cve_id: str = "CVE-2024-0001",
    score: float | None = 7.5,
    version: str = "3.1",
    description: str = "A flaw.",
    references: list[dict[str, Any]] | None = None,
    extra_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if score is not None:
        key = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "2.0": "cvssMetricV2"}[version]
        metrics[key] = [{"type": "Primary", "cvssData": {"baseScore": score}}]
    metrics.update(extra_metrics or {})
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [
                {"lang": "es", "value": "otra cosa"},
                {"lang": "en", "value": description},
            ],
            "metrics": metrics,
            "references": references or [],
        }
    }


def nvd_page(items: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    return {"totalResults": len(items) if total is None else total, "vulnerabilities": items}


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_image_archive(
    layers: list[dict[str, bytes]],
    *,
    gzip_layers: bool = False,
    zstd_magic: bool = False,
    manifest: bool = True,
) -> bytes:
    """Build a ``docker save``-style archive. Layers are oldest first."""
    outer: dict[str, bytes] = {}
    names: list[str] = []
    for index, entries in enumerate(layers):
        data = _tar_bytes(entries)
        if gzip_layers:
            data = gzip.compress(data)
        if zstd_magic:
            data = ZSTD_MAGIC + data
        name = f"blobs/sha256/layer{index}"
        outer[name] = data
        names.append(name)
    if manifest:
        outer["manifest.json"] = json.dumps([{"Config": "x", "RepoTags": None, "Layers": names}]).encode()
    return _tar_bytes(outer)