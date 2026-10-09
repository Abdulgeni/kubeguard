"""Package enumerators: static (default, never runs the image) and runtime (opt-in)."""

from __future__ import annotations

import json
import logging
import posixpath
import tarfile
import tempfile
from collections.abc import Sequence
from typing import IO

from kubeguard.core.exceptions import ContainerExecError, PackageEnumerationError
from kubeguard.core.targets import PackageInfo
from kubeguard.scanners.docker_adapter import DockerAdapter
from kubeguard.scanners.package_parsers import (
    ApkParser,
    DpkgParser,
    PackageParser,
    RpmParser,
    parse_apk_info,
    parse_dpkg_query,
    parse_rpm_qa,
)

logger = logging.getLogger(__name__)

MAX_DB_BYTES = 64 * 1024 * 1024
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _normalise(name: str) -> str:
    return posixpath.normpath(name).lstrip("/")


def _under(path: str, directory: str) -> bool:
    return directory == "" or path == directory or path.startswith(directory + "/")


class StaticPackageEnumerator:
    """Lists packages by reading package databases out of an image's layer tarballs.

    Never starts or creates a container. The image archive is spooled to an
    auto-deleted temporary file; only database files are read, into memory.
    Whiteouts and opaque directories are honoured so deleted databases don't linger.
    """

    def __init__(self, adapter: DockerAdapter, parsers: Sequence[PackageParser] | None = None) -> None:
        self._adapter = adapter
        self._parsers: list[PackageParser] = (
            list(parsers) if parsers is not None else [DpkgParser(), ApkParser(), RpmParser()]
        )

    def list_packages(self, reference: str) -> list[PackageInfo]:
        try:
            with tempfile.TemporaryFile() as spool:
                for chunk in self._adapter.save_image(reference):
                    spool.write(chunk)
                spool.seek(0)
                files = self._collect_files(spool)
        except PackageEnumerationError:
            raise
        except (tarfile.TarError, OSError, ValueError) as exc:
            raise PackageEnumerationError(f"could not read image archive: {exc}") from exc

        packages = [pkg for parser in self._parsers for pkg in parser.parse(files)]
        if packages:
            return packages
        reasons = [r for p in self._parsers if (r := p.unsupported_reason(files))]
        if reasons:
            raise PackageEnumerationError("; ".join(reasons))
        raise PackageEnumerationError(
            "no supported package database found (looked for dpkg, apk, rpm); "
            "the image may be distroless/scratch or use another package manager"
        )

    # ---------------------------------------------------------------- internals
    def _collect_files(self, spool: IO[bytes]) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        with tarfile.open(fileobj=spool, mode="r:") as outer:
            for layer_path in self._layer_paths(outer):
                try:
                    member = outer.getmember(layer_path)
                except KeyError:
                    raise PackageEnumerationError(
                        f"layer {layer_path} listed in manifest.json is missing from the archive"
                    ) from None
                stream = outer.extractfile(member)
                if stream is None:
                    raise PackageEnumerationError(f"layer {layer_path} is not a regular file")
                head = stream.read(4)
                stream.seek(0)
                if head == _ZSTD_MAGIC:
                    raise PackageEnumerationError(
                        "image layers are zstd-compressed; static enumeration does not support zstd"
                    )
                with tarfile.open(fileobj=stream, mode="r:*") as layer:
                    self._apply_layer(layer, files)
        return files

    @staticmethod
    def _layer_paths(outer: tarfile.TarFile) -> list[str]:
        try:
            raw = outer.extractfile("manifest.json")
        except KeyError:
            raise PackageEnumerationError(
                "image archive has no manifest.json (OCI-only archives are not supported)"
            ) from None
        manifest = json.load(raw) if raw is not None else None
        if (
            not isinstance(manifest, list)
            or not manifest
            or not isinstance(manifest[0], dict)
            or not manifest[0].get("Layers")
        ):
            raise PackageEnumerationError("unrecognised manifest.json structure")
        if len(manifest) > 1:
            logger.warning("Image archive holds %d images; using the first", len(manifest))
        return [str(p) for p in manifest[0]["Layers"]]

    def _apply_layer(self, layer: tarfile.TarFile, files: dict[str, bytes]) -> None:
        whiteouts: set[str] = set()
        opaque: set[str] = set()
        added: dict[str, bytes] = {}
        for member in layer:
            path = _normalise(member.name)
            directory, base = posixpath.split(path)
            if base == ".wh..wh..opq":
                opaque.add(directory)
                continue
            if base.startswith(".wh."):
                whiteouts.add(posixpath.join(directory, base[4:]))
                continue
            if not member.isfile():
                continue
            parser = next((p for p in self._parsers if p.wants(path)), None)
            if parser is None:
                continue
            if not parser.needs_content:
                added[path] = b""
                continue
            if member.size > MAX_DB_BYTES:
                raise PackageEnumerationError(f"{path} is unreasonably large ({member.size} bytes)")
            data = layer.extractfile(member)
            added[path] = data.read() if data is not None else b""
        # Deletions apply to earlier layers only; this layer's own files survive.
        for existing in list(files):
            if any(_under(existing, w) and w != "" for w in whiteouts) or any(
                _under(existing, o) for o in opaque
            ):
                del files[existing]
        files.update(added)


_RUNTIME_TOOLS: tuple[tuple[list[str], object], ...] = (
    (["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\n"],
     parse_dpkg_query),
    (["apk", "info", "-v"], parse_apk_info),
    (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"], parse_rpm_qa),
)


class RuntimePackageEnumerator:
    """Lists packages by running the image's own package manager (``--allow-container-exec``).

    SECURITY TRADE-OFF: this executes binaries from the image being scanned.
    The container runs with no network, a read-only root, all capabilities
    dropped, no-new-privileges, and memory/PID limits, but it is still
    untrusted code. Prefer ``StaticPackageEnumerator`` for untrusted images.
    """

    def __init__(self, adapter: DockerAdapter) -> None:
        self._adapter = adapter

    def list_packages(self, reference: str) -> list[PackageInfo]:
        logger.warning("Running package manager inside %s (--allow-container-exec)", reference)
        failures: list[str] = []
        for command, parse in _RUNTIME_TOOLS:
            try:
                output = self._adapter.run_command(reference, command)
            except ContainerExecError as exc:
                failures.append(f"{command[0]}: {exc}")
                continue
            packages = parse(output)  # type: ignore[operator]
            if packages:
                return list(packages)
            failures.append(f"{command[0]}: no packages in output")
        raise PackageEnumerationError("runtime enumeration failed (" + "; ".join(failures) + ")")