"""Report formatters."""

from kubeguard.reporters.base import Reporter, sort_findings
from kubeguard.reporters.json_reporter import JsonReporter
from kubeguard.reporters.sarif_reporter import SarifReporter
from kubeguard.reporters.table_reporter import TableReporter


def create_reporter(
    fmt: str,
    *,
    color: bool = True,
    ascii_only: bool = False,
    docker_artifact_uri: str = "Dockerfile",
) -> Reporter:
    """Build the reporter for ``fmt`` (``table``, ``json`` or ``sarif``)."""
    if fmt == "table":
        return TableReporter(color=color, ascii_only=ascii_only)
    if fmt == "json":
        return JsonReporter()
    if fmt == "sarif":
        return SarifReporter(docker_artifact_uri=docker_artifact_uri)
    raise ValueError(f"Unknown output format: {fmt!r}")


__all__ = [
    "JsonReporter",
    "Reporter",
    "SarifReporter",
    "TableReporter",
    "create_reporter",
    "sort_findings",
]