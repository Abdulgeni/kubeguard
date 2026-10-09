"""Kubernetes manifest scanner. Offline: parses YAML files and never contacts a cluster."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from kubeguard.core.exceptions import ScannerError
from kubeguard.core.models import ScanResult, TargetType
from kubeguard.core.registry import RuleRegistry
from kubeguard.core.targets import K8sResourceTarget
from kubeguard.scanners.base import Scanner

logger = logging.getLogger(__name__)

YAML_SUFFIXES = frozenset({".yaml", ".yml"})
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024


class KubernetesScanner(Scanner):
    """Scans a manifest file or a directory tree of ``.yaml``/``.yml`` files.

    Handles multi-document YAML and ``kind: List``. Hidden directories (``.git``,
    ``.github``) are skipped. Problems with individual files are reported in
    ``ScanResult.errors`` and never abort the scan.
    """

    def __init__(self, registry: RuleRegistry, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
        self._registry = registry
        self._max_file_bytes = max_file_bytes

    def scan(self, source: str) -> ScanResult:
        root = Path(source)
        if not root.exists():
            raise ScannerError(f"Path does not exist: {source}")
        result = ScanResult()
        files = self.find_files(root)
        if not files:
            result.errors.append(f"No YAML files (.yaml/.yml) found under {source}")
            return result
        for path in files:
            targets, errors = self.load_file(path)
            result.errors.extend(errors)
            for target in targets:
                findings, rule_errors = self._registry.evaluate(target, TargetType.K8S)
                result.extend(findings, rule_errors)
        return result

    @staticmethod
    def find_files(root: Path) -> list[Path]:
        """Manifest files under ``root`` (or ``root`` itself if it is a file)."""
        if root.is_file():
            return [root]
        found: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in YAML_SUFFIXES:
                continue
            if any(part.startswith(".") for part in path.relative_to(root).parts[:-1]):
                continue
            found.append(path)
        return sorted(found)

    def load_file(self, path: Path) -> tuple[list[K8sResourceTarget], list[str]]:
        """Parse one file into targets. Returns ``(targets, errors)``; documents parsed before a
        syntax error are kept."""
        try:
            if path.stat().st_size > self._max_file_bytes:
                return [], [f"{path}: file is larger than {self._max_file_bytes} bytes; skipped"]
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [], [f"{path}: cannot read file: {exc}"]

        documents: list[tuple[Any, int]] = []
        errors: list[str] = []
        loader = yaml.SafeLoader(text)  # SafeLoader: never constructs arbitrary Python objects
        try:
            while loader.check_node():
                node = loader.get_node()
                documents.append((loader.construct_document(node), node.start_mark.line + 1))
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1})" if mark is not None else ""
            problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
            errors.append(f"{path}: invalid YAML{where}: {problem}")
        finally:
            loader.dispose()

        targets: list[K8sResourceTarget] = []
        for document, line in documents:
            targets.extend(self._targets_from(document, str(path), line))
        return targets, errors

    def _targets_from(self, document: Any, source: str, line: int) -> list[K8sResourceTarget]:
        if not isinstance(document, dict):
            return []
        if document.get("kind") == "List":
            targets: list[K8sResourceTarget] = []
            for item in document.get("items") or []:
                targets.extend(self._targets_from(item, source, line))
            return targets
        target = K8sResourceTarget.from_manifest(document, source, line)
        if target is None:
            logger.debug("Skipping %s: not a supported kind (%r)", source, document.get("kind"))
            return []
        return [target]