"""Maps installed packages to NVD CVEs: CPE first, keyword search as a low-confidence fallback."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from kubeguard.core.exceptions import NvdError
from kubeguard.core.targets import PackageInfo
from kubeguard.integrations.cpe import build_cpe, normalize_version
from kubeguard.integrations.nvd_client import CveRecord

logger = logging.getLogger(__name__)


class CveSource(Protocol):
    """What the matcher needs from an NVD client."""

    def search_by_cpe(self, cpe: str) -> list[CveRecord]: ...

    def search_by_keyword(self, keyword: str) -> list[CveRecord]: ...


@dataclass(frozen=True)
class CveMatch:
    """A CVE matched to an installed package."""

    cve: CveRecord
    package: PackageInfo
    confidence: Literal["high", "low"]
    method: Literal["cpe", "keyword"]
    cpe: str | None = None
    also_affects: tuple[str, ...] = ()


class CveMatcher:
    """Looks up CVEs for packages, deduplicating identical queries.

    Args:
        source: NVD client (or fake).
        keyword_fallback: Use keyword search for packages with no CPE mapping.
        extra_cpe_map: Additional ``name -> (vendor, product)`` entries.
        max_consecutive_failures: Abort remaining lookups after this many NVD failures in a row.
    """

    def __init__(
        self,
        source: CveSource,
        *,
        keyword_fallback: bool = True,
        extra_cpe_map: Mapping[str, tuple[str, str]] | None = None,
        max_consecutive_failures: int = 3,
    ) -> None:
        self._source = source
        self._fallback = keyword_fallback
        self._extra = dict(extra_cpe_map or {})
        self._max_failures = max_consecutive_failures

    @staticmethod
    def _keyword(package: PackageInfo) -> str:
        return f"{package.name} {normalize_version(package.ecosystem, package.version)}"

    def match_all(self, packages: Sequence[PackageInfo]) -> tuple[list[CveMatch], list[str]]:
        """Find CVEs for ``packages``.

        Returns:
            ``(matches, notes)``; notes describe anything that made results incomplete.
        """
        groups: dict[str, list[PackageInfo]] = {}
        cpes: dict[str, str | None] = {}
        skipped = 0
        for package in packages:
            cpe = build_cpe(package, self._extra)
            if cpe is not None:
                key = cpe
            elif self._fallback:
                key = f"keyword:{self._keyword(package)}"
            else:
                skipped += 1
                continue
            groups.setdefault(key, []).append(package)
            cpes[key] = cpe

        matches: list[CveMatch] = []
        notes: list[str] = []
        if skipped:
            notes.append(
                f"{skipped} package(s) not checked: no CPE mapping and keyword fallback is disabled"
            )

        failures = 0
        items = list(groups.items())
        for index, (key, members) in enumerate(items):
            first = members[0]
            also = tuple(sorted({m.name for m in members} - {first.name}))
            try:
                matches.extend(self._lookup(first, cpes[key], also))
            except NvdError as exc:
                failures += 1
                notes.append(f"{first.name} {first.version}: {exc}")
                if failures >= self._max_failures:
                    remaining = len(items) - index - 1
                    notes.append(
                        f"NVD lookups aborted after {failures} consecutive failures; "
                        f"{remaining} package group(s) not checked"
                    )
                    break
            else:
                failures = 0
        return matches, notes

    def _lookup(
        self, package: PackageInfo, cpe: str | None, also: tuple[str, ...]
    ) -> list[CveMatch]:
        if cpe is not None:
            records, method, confidence = self._source.search_by_cpe(cpe), "cpe", "high"
        else:
            records = self._source.search_by_keyword(self._keyword(package))
            method, confidence = "keyword", "low"
        return [
            CveMatch(
                cve=record,
                package=package,
                confidence=confidence,  # type: ignore[arg-type]
                method=method,  # type: ignore[arg-type]
                cpe=cpe,
                also_affects=also,
            )
            for record in records
        ]