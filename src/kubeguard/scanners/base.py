"""Scanner abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kubeguard.core.models import ScanResult


class Scanner(ABC):
    """A scanner turns one input into targets and evaluates the rules against them."""

    @abstractmethod
    def scan(self, source: str) -> ScanResult:
        """Scan ``source`` (an image reference or a path) and return the result."""