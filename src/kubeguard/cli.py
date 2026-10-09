"""KubeGuard command-line interface.

Exit codes: 0 = clean, 1 = findings at or above --fail-on, 2 = usage or tool errors.
Note: no ``from __future__ import annotations`` here; Typer reads the real annotations.
"""

import logging
import os
import sqlite3
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, NoReturn, Optional

import typer

from kubeguard import __version__
from kubeguard.core.config import KubeGuardConfig, load_config
from kubeguard.core.exceptions import ConfigError, KubeGuardError
from kubeguard.core.models import ScanResult, Severity, TargetType
from kubeguard.core.registry import RuleRegistry
from kubeguard.integrations.cache import Cache, NullCache, SqliteCache, default_nvd_cache_path
from kubeguard.integrations.cve_matcher import CveMatcher
from kubeguard.integrations.nvd_client import NvdClient
from kubeguard.reporters import create_reporter
from kubeguard.scanners.docker_adapter import SdkDockerAdapter
from kubeguard.scanners.docker_scanner import DockerScanner, PackageEnumerator
from kubeguard.scanners.k8s_scanner import KubernetesScanner
from kubeguard.scanners.package_enumerators import (
    RuntimePackageEnumerator,
    StaticPackageEnumerator,
)

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="kubeguard",
    help="Scan Docker images and Kubernetes manifests for misconfigurations and known CVEs.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(help="Scan images and manifests.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


class FailOn(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


OutputOption = Annotated[
    Optional[OutputFormat],
    typer.Option("--output", "-o", case_sensitive=False, help="Report format (default: table)."),
]
FailOnOption = Annotated[
    Optional[FailOn],
    typer.Option(
        "--fail-on",
        case_sensitive=False,
        help="Exit with status 1 if any finding is at or above this severity.",
    ),
]
ConfigOption = Annotated[
    Optional[Path],
    typer.Option("--config", "-c", exists=True, dir_okay=False, readable=True, help="YAML config file."),
]
NoCacheOption = Annotated[bool, typer.Option("--no-cache", help="Do not read or write the NVD cache.")]
ExecOption = Annotated[
    bool,
    typer.Option(
        "--allow-container-exec",
        help="List image packages by RUNNING the image's package manager in a container. "
        "Executes code from the image; see the README security notes.",
    ),
]
OutputFileOption = Annotated[
    Optional[Path], typer.Option("--output-file", help="Write the report to this file instead of stdout.")
]
VerboseOption = Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logging on stderr.")]


# ---------------------------------------------------------------- helpers
class _StderrHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Logs to whatever ``sys.stderr`` is at emit time (safe under test runners)."""

    def __init__(self) -> None:
        super().__init__()

    @property  # type: ignore[override]
    def stream(self):  # type: ignore[no-untyped-def]
        return sys.stderr

    @stream.setter
    def stream(self, value) -> None:  # type: ignore[no-untyped-def]
        pass


def _configure_logging(verbose: bool) -> None:
    log = logging.getLogger("kubeguard")
    for handler in [h for h in log.handlers if isinstance(h, _StderrHandler)]:
        log.removeHandler(handler)
    handler = _StderrHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.WARNING)


def _fail(message: str) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2)


def _stdout_supports_unicode() -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "─│".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _echo(text: str) -> None:
    try:
        typer.echo(text)
    except UnicodeEncodeError:  # e.g. cp1252 console receiving non-Latin text
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        typer.echo(text.encode(encoding, "replace").decode(encoding))


def _load_config(path: Optional[Path]) -> KubeGuardConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        _fail(str(exc))


# ------------------------------------------------------- dependency factories
def build_registry(cfg: KubeGuardConfig) -> RuleRegistry:
    """Discover rules and apply config; unknown rule IDs or options are errors."""
    registry = RuleRegistry(
        disabled_rules=cfg.disabled_rules,
        severity_overrides=cfg.severity_overrides,
        rule_options=cfg.rule_options,
    )
    registry.discover()
    unknown = registry.unknown_config_ids()
    if unknown:
        raise ConfigError("Config references unknown rule ID(s): " + ", ".join(unknown))
    registry.all_rules(include_disabled=True)  # builds every rule now so bad options fail early
    return registry


def build_cache(cfg: KubeGuardConfig, no_cache: bool) -> Cache:
    """NVD cache honouring ``--no-cache``; an unusable cache degrades to none."""
    if no_cache or not cfg.cache.enabled:
        return NullCache()
    path = cfg.cache.directory / "nvd.db" if cfg.cache.directory else default_nvd_cache_path()
    try:
        return SqliteCache(path)
    except (OSError, sqlite3.Error) as exc:
        logger.warning("NVD cache unavailable (%s); continuing without cache", exc)
        return NullCache()


def build_docker_scanner(
    cfg: KubeGuardConfig, registry: RuleRegistry, *, no_cache: bool, allow_container_exec: bool
) -> DockerScanner:
    """Wire the Docker scanner; the enumeration strategy depends on ``allow_container_exec``."""
    adapter = SdkDockerAdapter()
    if not registry.rules_for(TargetType.DOCKER_PACKAGE):  # CVE rule disabled: skip enumeration
        return DockerScanner(registry, adapter)
    enumerator: PackageEnumerator = (
        RuntimePackageEnumerator(adapter) if allow_container_exec else StaticPackageEnumerator(adapter)
    )
    if not os.environ.get("NVD_API_KEY"):
        logger.warning(
            "NVD_API_KEY is not set: NVD lookups are limited to 5 requests per 30 seconds, "
            "so images with many packages will be slow"
        )
    nvd = NvdClient.from_env(cache=build_cache(cfg, no_cache), cache_ttl=cfg.cache.ttl_hours * 3600)
    matcher = CveMatcher(nvd, keyword_fallback=cfg.docker.keyword_fallback)
    return DockerScanner(
        registry, adapter, enumerator, matcher, max_cve_findings=cfg.docker.max_cve_findings
    )


# ------------------------------------------------------------------ commands
def _version(value: bool) -> None:
    if value:
        typer.echo(f"kubeguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool], typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = None,
) -> None:
    """KubeGuard: security scanner for Docker images and Kubernetes manifests."""


def _execute(
    cfg: KubeGuardConfig,
    *,
    images: list[str],
    k8s_paths: list[str],
    output: Optional[OutputFormat],
    fail_on: Optional[FailOn],
    no_cache: bool,
    allow_container_exec: bool,
    output_file: Optional[Path],
    verbose: bool,
) -> None:
    _configure_logging(verbose)
    fmt = output.value if output else cfg.output
    threshold = Severity.from_string(fail_on.value) if fail_on else cfg.fail_on
    exec_allowed = allow_container_exec or cfg.docker.allow_container_exec
    try:
        registry = build_registry(cfg)
        result = ScanResult()
        if images:
            docker_scanner = build_docker_scanner(
                cfg, registry, no_cache=no_cache, allow_container_exec=exec_allowed
            )
            for image in images:
                try:
                    sub = docker_scanner.scan(image)
                except KubeGuardError as exc:
                    result.errors.append(f"{image}: {exc}")
                else:
                    result.extend(sub.findings, sub.errors)
        if k8s_paths:
            k8s_scanner = KubernetesScanner(registry)
            for path in k8s_paths:
                try:
                    sub = k8s_scanner.scan(path)
                except KubeGuardError as exc:
                    result.errors.append(f"{path}: {exc}")
                else:
                    result.extend(sub.findings, sub.errors)
    except typer.Exit:
        raise
    except KubeGuardError as exc:
        _fail(str(exc))
    except Exception as exc:  # noqa: BLE001 - last-resort guard so bugs exit with 2, not 1
        logger.exception("Unhandled error")
        _fail(f"internal error: {type(exc).__name__}: {exc}")

    reporter = create_reporter(
        fmt,
        color=output_file is None,
        ascii_only=not _stdout_supports_unicode(),
        docker_artifact_uri=cfg.sarif.docker_artifact_uri,
    )
    text = reporter.render(result)
    if output_file is not None:
        output_file.write_text(text + "\n", encoding="utf-8")
    else:
        _echo(text)

    if result.should_fail(threshold):
        raise typer.Exit(code=1)
    if result.errors:
        typer.echo(f"kubeguard: {len(result.errors)} error(s) during the scan; results may be incomplete", err=True)
        raise typer.Exit(code=2)


@scan_app.command("image")
def scan_image(
    image: Annotated[str, typer.Argument(help="Local image reference, e.g. nginx:1.25")],
    output: OutputOption = None,
    fail_on: FailOnOption = None,
    config: ConfigOption = None,
    no_cache: NoCacheOption = False,
    allow_container_exec: ExecOption = False,
    output_file: OutputFileOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Scan a local Docker image."""
    _execute(
        _load_config(config), images=[image], k8s_paths=[], output=output, fail_on=fail_on,
        no_cache=no_cache, allow_container_exec=allow_container_exec, output_file=output_file, verbose=verbose,
    )


@scan_app.command("k8s")
def scan_k8s(
    path: Annotated[str, typer.Argument(help="A manifest file or a directory of manifests.")],
    output: OutputOption = None,
    fail_on: FailOnOption = None,
    config: ConfigOption = None,
    no_cache: NoCacheOption = False,
    output_file: OutputFileOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Scan Kubernetes manifests."""
    _execute(
        _load_config(config), images=[], k8s_paths=[path], output=output, fail_on=fail_on,
        no_cache=no_cache, allow_container_exec=False, output_file=output_file, verbose=verbose,
    )


@scan_app.command("all")
def scan_all(
    output: OutputOption = None,
    fail_on: FailOnOption = None,
    config: ConfigOption = None,
    no_cache: NoCacheOption = False,
    allow_container_exec: ExecOption = False,
    output_file: OutputFileOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Scan every image and path listed in the config file."""
    if config is None:
        _fail("'scan all' requires --config")
    cfg = _load_config(config)
    if not cfg.docker.images and not cfg.kubernetes.paths:
        _fail("the config lists no docker.images or kubernetes.paths to scan")
    _execute(
        cfg, images=list(cfg.docker.images), k8s_paths=list(cfg.kubernetes.paths), output=output,
        fail_on=fail_on, no_cache=no_cache, allow_container_exec=allow_container_exec,
        output_file=output_file, verbose=verbose,
    )


@app.command("rules")
def list_rules(config: ConfigOption = None) -> None:
    """List all rules and whether they are enabled."""
    cfg = _load_config(config)
    try:
        registry = build_registry(cfg)
    except KubeGuardError as exc:
        _fail(str(exc))
    for rule in registry.all_rules(include_disabled=True):
        state = "on " if registry.is_enabled(rule.id) else "off"
        typer.echo(f"{rule.id:<14} {rule.severity.value:<8} {state} {rule.name}")


if __name__ == "__main__":
    app()