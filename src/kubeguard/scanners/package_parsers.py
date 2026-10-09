"""Package-database parsers (one class per ecosystem) and runtime tool-output parsers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar

from kubeguard.core.targets import PackageInfo

_STANZAS = re.compile(r"\n\s*\n")
_APK_VERSIONED = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*-r\d+)$")


class PackageParser(ABC):
    """Parses one package-manager database found in an image filesystem.

    Paths are normalised: relative, no leading ``./`` or ``/``.
    """

    ecosystem: ClassVar[str]
    needs_content: ClassVar[bool] = True  # False: only the file's presence matters

    @abstractmethod
    def wants(self, path: str) -> bool:
        """True if ``path`` is a database file this parser reads."""

    @abstractmethod
    def parse(self, files: Mapping[str, bytes]) -> list[PackageInfo]:
        """Parse the matching files in ``files`` into packages."""

    def unsupported_reason(self, files: Mapping[str, bytes]) -> str | None:
        """Why an ecosystem was detected but cannot be parsed, if applicable."""
        return None


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _rfc822_fields(stanza: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in stanza.splitlines():
        if not line or line[0] in " \t" or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


class DpkgParser(PackageParser):
    """Debian/Ubuntu: ``/var/lib/dpkg/status`` and distroless ``status.d/``."""

    ecosystem = "deb"

    def wants(self, path: str) -> bool:
        if path == "var/lib/dpkg/status":
            return True
        return path.startswith("var/lib/dpkg/status.d/") and not path.endswith(".md5sums")

    def parse(self, files: Mapping[str, bytes]) -> list[PackageInfo]:
        packages: list[PackageInfo] = []
        for path in sorted(p for p in files if self.wants(p)):
            for stanza in _STANZAS.split(_decode(files[path])):
                fields = _rfc822_fields(stanza)
                name, version = fields.get("Package"), fields.get("Version")
                status = fields.get("Status")
                if not name or not version:
                    continue
                if status is not None and not status.endswith(" installed"):
                    continue
                source = fields.get("Source", "").split(" ")[0] or None
                packages.append(
                    PackageInfo(name=name, version=version, ecosystem="deb", source=source)
                )
        return packages


class ApkParser(PackageParser):
    """Alpine: ``/lib/apk/db/installed``."""

    ecosystem = "apk"

    def wants(self, path: str) -> bool:
        return path == "lib/apk/db/installed"

    def parse(self, files: Mapping[str, bytes]) -> list[PackageInfo]:
        packages: list[PackageInfo] = []
        for path in sorted(p for p in files if self.wants(p)):
            for stanza in _STANZAS.split(_decode(files[path])):
                fields = {
                    line[0]: line[2:]
                    for line in stanza.splitlines()
                    if len(line) > 2 and line[1] == ":"
                }
                name, version = fields.get("P"), fields.get("V")
                if not name or not version:
                    continue
                origin = fields.get("o")
                packages.append(
                    PackageInfo(
                        name=name,
                        version=version,
                        ecosystem="apk",
                        source=origin if origin and origin != name else None,
                    )
                )
        return packages


class RpmParser(PackageParser):
    """RPM databases (BerkeleyDB/SQLite header blobs): detected, not parsed."""

    ecosystem = "rpm"
    needs_content = False
    _PATHS = frozenset(
        f"{base}/{name}"
        for base in ("var/lib/rpm", "usr/lib/sysimage/rpm")
        for name in ("Packages", "Packages.db", "rpmdb.sqlite")
    )

    def wants(self, path: str) -> bool:
        return path in self._PATHS

    def parse(self, files: Mapping[str, bytes]) -> list[PackageInfo]:
        return []

    def unsupported_reason(self, files: Mapping[str, bytes]) -> str | None:
        found = sorted(p for p in files if self.wants(p))
        if not found:
            return None
        return (
            f"RPM package databases are not supported by static enumeration (found {found[0]}); "
            "use --allow-container-exec to list packages by running rpm in the image"
        )


# ----------------------------------------------------------- runtime tool output
def parse_dpkg_query(output: str) -> list[PackageInfo]:
    """Parse ``dpkg-query -W -f '${Package}\\t${Version}\\t${source:Package}\\t${db:Status-Abbrev}\\n'``."""
    packages: list[PackageInfo] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3].startswith("ii"):
            continue
        name, version, source = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if name and version:
            packages.append(
                PackageInfo(
                    name=name,
                    version=version,
                    ecosystem="deb",
                    source=source if source and source != name else None,
                )
            )
    return packages


def parse_apk_info(output: str) -> list[PackageInfo]:
    """Parse ``apk info -v`` lines such as ``busybox-1.36.1-r5``."""
    packages: list[PackageInfo] = []
    for line in output.splitlines():
        found = _APK_VERSIONED.match(line.strip())
        if found:
            packages.append(
                PackageInfo(name=found["name"], version=found["version"], ecosystem="apk")
            )
    return packages


def parse_rpm_qa(output: str) -> list[PackageInfo]:
    """Parse ``rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n'``."""
    packages: list[PackageInfo] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip() or not parts[1].strip():
            continue
        source: str | None = None
        if len(parts) > 2 and parts[2].strip() not in ("", "(none)"):
            source = parts[2].strip().removesuffix(".src.rpm").rsplit("-", 2)[0] or None
        packages.append(
            PackageInfo(name=parts[0].strip(), version=parts[1].strip(), ecosystem="rpm", source=source)
        )
    return packages