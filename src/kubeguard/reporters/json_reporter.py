"""JSON reporter for automation."""

from __future__ import annotations

import json

from kubeguard import __version__
from kubeguard.core.models import ScanResult
from kubeguard.reporters.base import Reporter, sort_findings


class JsonReporter(Reporter):
    def __init__(self, indent: int | None = 2) -> None:
        self._indent = indent

    def render(self, result: ScanResult) -> str:
        highest = result.max_severity()
        payload = {
            "tool": {"name": "kubeguard", "version": __version__},
            "summary": {
                "total": len(result.findings),
                "by_severity": {sev.value: n for sev, n in result.counts_by_severity().items()},
                "max_severity": highest.value if highest else None,
            },
            "findings": [f.model_dump(mode="json") for f in sort_findings(result.findings)],
            "errors": list(result.errors),
        }
        return json.dumps(payload, indent=self._indent)