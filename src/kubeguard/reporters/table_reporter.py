"""Human-readable table reporter (rich)."""

from __future__ import annotations

import io
import shutil

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from kubeguard.core.models import ScanResult, Severity
from kubeguard.reporters.base import Reporter, sort_findings

_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class TableReporter(Reporter):
    """Renders findings as a table.

    Args:
        color: Emit ANSI styles (click strips them when output is not a terminal).
        width: Fixed width; default is the terminal width (at least 100).
        ascii_only: Use an ASCII box, for consoles that cannot encode Unicode.
    """

    def __init__(self, color: bool = True, width: int | None = None, ascii_only: bool = False) -> None:
        self._color = color
        self._width = width
        self._ascii = ascii_only

    def render(self, result: ScanResult) -> str:
        width = self._width or max(shutil.get_terminal_size((120, 24)).columns, 100)
        buffer = io.StringIO()
        console = Console(
            file=buffer,
            force_terminal=self._color,
            color_system="standard" if self._color else None,
            width=width,
            highlight=False,
            legacy_windows=False,
        )
        findings = sort_findings(result.findings)
        if not findings:
            console.print(Text("No findings.", style="green"))
        else:
            table = Table(
                box=box.ASCII if self._ascii else box.SIMPLE_HEAD, header_style="bold", expand=True
            )
            table.add_column("Severity", no_wrap=True)
            table.add_column("Rule", no_wrap=True)
            table.add_column("Resource", ratio=1, overflow="fold")
            table.add_column("Details", ratio=3)
            for f in findings:
                # Text objects (not markup strings) so manifest content can never inject styling.
                resource = Text(f.resource)
                if f.location:
                    resource.append(f"\n{f.location}", style="dim")
                details = Text(f.description)
                details.append("\nFix: ", style="bold")
                details.append(f.remediation, style="dim")
                table.add_row(Text(f.severity.value, style=_STYLES[f.severity]), Text(f.rule_id), resource, details)
            console.print(table)
            counts = [f"{n} {sev.value}" for sev, n in result.counts_by_severity().items() if n]
            console.print(Text(f"{len(findings)} finding(s): {', '.join(counts)}", style="bold"))
        if result.errors:
            console.print(Text("Errors:", style="bold red"))
            for error in result.errors:
                console.print(Text(f"  - {error}", style="red"))
        return buffer.getvalue().rstrip("\n")