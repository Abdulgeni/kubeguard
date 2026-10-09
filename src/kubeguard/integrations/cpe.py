"""CPE 2.3 construction and package-version normalisation."""

from __future__ import annotations

import re
from collections.abc import Mapping

from kubeguard.core.targets import PackageInfo

# Starter map: package or source-package name -> (NVD vendor, NVD product).
# Extend via CveMatcher(extra_cpe_map=...). Names without an entry fall back to keyword search.
KNOWN_PRODUCTS: dict[str, tuple[str, str]] = {
    "openssl": ("openssl", "openssl"),
    "libssl3": ("openssl", "openssl"),
    "libssl1.1": ("openssl", "openssl"),
    "curl": ("haxx", "curl"),
    "libcurl4": ("haxx", "curl"),
    "zlib": ("zlib", "zlib"),
    "zlib1g": ("zlib", "zlib"),
    "glibc": ("gnu", "glibc"),
    "libc6": ("gnu", "glibc"),
    "bash": ("gnu", "bash"),
    "busybox": ("busybox", "busybox"),
    "musl": ("musl-libc", "musl"),
    "libxml2": ("xmlsoft", "libxml2"),
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "nginx": ("f5", "nginx"),
    "apache2": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "sudo": ("sudo_project", "sudo"),
    "git": ("git-scm", "git"),
    "expat": ("libexpat_project", "libexpat"),
    "libpng": ("libpng", "libpng"),
    "gnutls28": ("gnu", "gnutls"),
    "gnupg2": ("gnupg", "gnupg"),
    "gnupg": ("gnupg", "gnupg"),
    "tar": ("gnu", "tar"),
    "coreutils": ("gnu", "coreutils"),
    "util-linux": ("kernel", "util-linux"),
    "pcre2": ("pcre", "pcre2"),
    "krb5": ("mit", "kerberos_5"),
    "perl": ("perl", "perl"),
    "ncurses": ("gnu", "ncurses"),
}
_PYTHON = re.compile(r"python3(\.\d+)?")
_EPOCH = re.compile(r"^\d+:")
_PACKAGING_SUFFIX = re.compile(r"[+~.]?(?:dfsg|ds)\d*$")


def normalize_version(ecosystem: str, version: str) -> str:
    """Reduce a distro package version to the upstream version NVD uses.

    ``1:3.0.11-1~deb12u2`` (deb) -> ``3.0.11``; ``3.1.4-r5`` (apk) -> ``3.1.4``;
    ``3.0.7-24.el9`` (rpm) -> ``3.0.7``.
    """
    value = _EPOCH.sub("", version.strip())
    if ecosystem == "apk":
        value = re.sub(r"-r\d+$", "", value)
    elif ecosystem in ("deb", "rpm"):
        if "-" in value:
            value = value.rsplit("-", 1)[0]
        value = _PACKAGING_SUFFIX.sub("", value)
    return value


def _escape(component: str) -> str:
    """Escape a CPE 2.3 formatted-string component."""
    return "".join(
        c if c.isascii() and (c.isalnum() or c in "_-.") else "\\" + c for c in component.lower()
    )


def build_cpe(
    package: PackageInfo, extra: Mapping[str, tuple[str, str]] | None = None
) -> str | None:
    """Build a CPE 2.3 name for ``package``, or ``None`` if the product is unknown.

    The source/origin package name is tried before the binary package name.
    """
    table = {**KNOWN_PRODUCTS, **(extra or {})}
    entry: tuple[str, str] | None = None
    for candidate in (package.source, package.name):
        if not candidate:
            continue
        if candidate in table:
            entry = table[candidate]
        elif _PYTHON.fullmatch(candidate):
            entry = ("python", "python")
        if entry:
            break
    if entry is None:
        return None
    version = normalize_version(package.ecosystem, package.version)
    if not version:
        return None
    vendor, product = entry
    return f"cpe:2.3:a:{_escape(vendor)}:{_escape(product)}:{_escape(version)}:*:*:*:*:*:*:*"