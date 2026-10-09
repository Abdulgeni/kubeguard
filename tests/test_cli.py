"""CLI tests: real K8s scanning, Docker scanning replaced by fakes."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kubeguard import __version__, cli
from kubeguard.cli import app, build_cache, build_docker_scanner, build_registry
from kubeguard.core.config import KubeGuardConfig
from kubeguard.core.exceptions import ImageNotFoundError
from kubeguard.core.models import Finding, ScanResult, Severity, TargetType
from kubeguard.integrations.cache import NullCache, SqliteCache
from kubeguard.scanners.package_enumerators import (
    RuntimePackageEnumerator,
    StaticPackageEnumerator,
)

runner = CliRunner()

INSECURE = (
    "apiVersion: v1\nkind: Pod\nmetadata: {name: bad}\n"
    "spec:\n  containers:\n    - name: app\n      image: nginx\n      securityContext: {privileged: true}\n"
)
SECURE = (
    "apiVersion: v1\nkind: Pod\nmetadata: {name: good}\n"
    "spec:\n  securityContext: {runAsNonRoot: true}\n  containers:\n    - name: app\n      image: nginx\n"
    "      securityContext: {allowPrivilegeEscalation: false}\n"
    "      resources: {limits: {cpu: '1', memory: 1Gi}}\n"
)


def invoke(*args: str):
    return runner.invoke(app, list(args))


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def docker_finding() -> Finding:
    return Finding(
        rule_id="KG-DOCKER-001",
        rule_name="Container runs as root",
        severity=Severity.HIGH,
        target_type=TargetType.DOCKER,
        resource="nginx:1.25",
        description="d",
        remediation="r",
    )


class FakeScanner:
    def __init__(self, findings=(), error: Exception | None = None) -> None:
        self.findings, self.error, self.images = list(findings), error, []

    def scan(self, image: str) -> ScanResult:
        self.images.append(image)
        if self.error:
            raise self.error
        result = ScanResult()
        result.extend(self.findings)
        return result


@pytest.fixture
def fake_docker(monkeypatch):
    holder = {"scanner": FakeScanner([docker_finding()]), "kwargs": None}

    def factory(cfg, registry, **kwargs):
        holder["kwargs"] = kwargs
        return holder["scanner"]

    monkeypatch.setattr(cli, "build_docker_scanner", factory)
    return holder


def test_version() -> None:
    result = invoke("--version")
    assert result.exit_code == 0 and __version__ in result.output


def test_no_args_shows_help() -> None:
    assert "scan" in invoke().output


class TestScanK8s:
    def test_json_output_and_exit_zero_without_fail_on(self, tmp_path) -> None:
        file = write(tmp_path, "p.yaml", INSECURE)
        result = invoke("scan", "k8s", str(file), "--output", "json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "KG-K8S-004" in {f["rule_id"] for f in data["findings"]}

    def test_fail_on_threshold(self, tmp_path) -> None:
        file = str(write(tmp_path, "p.yaml", INSECURE))
        assert invoke("scan", "k8s", file, "--fail-on", "critical").exit_code == 1
        assert invoke("scan", "k8s", file, "--fail-on", "CRITICAL").exit_code == 1
        clean = str(write(tmp_path, "s.yaml", SECURE))
        assert invoke("scan", "k8s", clean, "--fail-on", "info").exit_code == 0

    def test_table_output(self, tmp_path) -> None:
        result = invoke("scan", "k8s", str(write(tmp_path, "s.yaml", SECURE)))
        assert result.exit_code == 0 and "No findings" in result.output

    def test_sarif_output(self, tmp_path) -> None:
        result = invoke("scan", "k8s", str(write(tmp_path, "p.yaml", INSECURE)), "-o", "sarif")
        assert json.loads(result.stdout)["version"] == "2.1.0"

    def test_output_file(self, tmp_path) -> None:
        out = tmp_path / "report.json"
        result = invoke(
            "scan",
            "k8s",
            str(write(tmp_path, "p.yaml", INSECURE)),
            "-o",
            "json",
            "--output-file",
            str(out),
        )
        assert result.exit_code == 0 and result.stdout.strip() == ""
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["total"] > 0

    def test_missing_path_is_a_tool_error(self, tmp_path) -> None:
        result = invoke("scan", "k8s", str(tmp_path / "nope"), "-o", "json")
        assert result.exit_code == 2
        assert "does not exist" in json.loads(result.stdout)["errors"][0]

    def test_findings_take_precedence_over_errors(self, tmp_path) -> None:
        file = write(tmp_path, "p.yaml", INSECURE + "---\nfoo: [unclosed\n")
        assert invoke("scan", "k8s", str(file), "--fail-on", "high").exit_code == 1
        assert invoke("scan", "k8s", str(file)).exit_code == 2


class TestConfigHandling:
    def test_disabled_rule_changes_exit_code(self, tmp_path) -> None:
        file = str(write(tmp_path, "p.yaml", INSECURE))
        cfg = str(write(tmp_path, "c.yaml", "disabled_rules: [KG-K8S-004]\n"))
        assert invoke("scan", "k8s", file, "--fail-on", "critical", "--config", cfg).exit_code == 0

    def test_severity_override_applies(self, tmp_path) -> None:
        file = str(write(tmp_path, "p.yaml", INSECURE))
        cfg = str(write(tmp_path, "c.yaml", "severity_overrides: {KG-K8S-004: low}\n"))
        data = json.loads(invoke("scan", "k8s", file, "-o", "json", "-c", cfg).stdout)
        sev = {f["rule_id"]: f["severity"] for f in data["findings"]}
        assert sev["KG-K8S-004"] == "LOW"

    def test_config_fail_on_and_output_defaults(self, tmp_path) -> None:
        file = str(write(tmp_path, "p.yaml", INSECURE))
        cfg = str(write(tmp_path, "c.yaml", "fail_on: high\noutput: json\n"))
        result = invoke("scan", "k8s", file, "-c", cfg)
        assert result.exit_code == 1 and json.loads(result.stdout)["findings"]

    @pytest.mark.parametrize(
        "text",
        [
            "bogus_key: 1\n",
            "disabled_rules: [KG-NOPE-999]\n",
            "rule_options: {KG-K8S-001: {x: 1}}\n",
        ],
    )
    def test_bad_config_exits_2(self, tmp_path, text: str) -> None:
        file = str(write(tmp_path, "p.yaml", INSECURE))
        result = invoke("scan", "k8s", file, "-c", str(write(tmp_path, "c.yaml", text)))
        assert result.exit_code == 2 and "error" in result.output.lower()

    def test_missing_config_file_exits_2(self, tmp_path) -> None:
        assert invoke("scan", "k8s", str(tmp_path), "-c", str(tmp_path / "nope.yaml")).exit_code == 2


class TestScanDocker:
    def test_scan_image(self, fake_docker) -> None:
        result = invoke(
            "scan", "image", "nginx:1.25", "-o", "json", "--fail-on", "high", "--no-cache"
        )
        assert result.exit_code == 1
        assert fake_docker["scanner"].images == ["nginx:1.25"]
        assert fake_docker["kwargs"] == {"no_cache": True, "allow_container_exec": False}

    def test_allow_container_exec_is_forwarded(self, fake_docker) -> None:
        invoke("scan", "image", "nginx:1.25", "--allow-container-exec")
        assert fake_docker["kwargs"]["allow_container_exec"] is True

    def test_image_errors_are_reported_with_exit_2(self, fake_docker) -> None:
        fake_docker["scanner"] = FakeScanner(error=ImageNotFoundError("missing locally"))
        result = invoke("scan", "image", "ghost:1", "-o", "json")
        assert result.exit_code == 2
        assert "missing locally" in json.loads(result.stdout)["errors"][0]


class TestScanAll:
    def test_requires_config(self) -> None:
        result = invoke("scan", "all")
        assert result.exit_code == 2 and "--config" in result.output

    def test_empty_config_exits_2(self, tmp_path) -> None:
        assert (
            invoke("scan", "all", "-c", str(write(tmp_path, "c.yaml", "output: json\n"))).exit_code
            == 2
        )

    def test_scans_images_and_paths_from_config(self, tmp_path, fake_docker) -> None:
        manifest = write(tmp_path, "p.yaml", INSECURE)
        cfg = write(
            tmp_path,
            "c.yaml",
            f"docker: {{images: [nginx:1.25, redis:7]}}\n"
            f"kubernetes: {{paths: [{json.dumps(str(manifest))}]}}\n",
        )
        result = invoke("scan", "all", "--config", str(cfg), "-o", "json")
        assert result.exit_code == 0
        assert fake_docker["scanner"].images == ["nginx:1.25", "redis:7"]
        rule_ids = {f["rule_id"] for f in json.loads(result.stdout)["findings"]}
        assert {"KG-DOCKER-001", "KG-K8S-004"} <= rule_ids


def test_rules_command(tmp_path) -> None:
    out = invoke("rules").output
    assert "KG-DOCKER-001" in out and "KG-K8S-007" in out
    cfg = write(tmp_path, "c.yaml", "disabled_rules: [KG-K8S-003]\n")
    line = next(
        l for l in invoke("rules", "-c", str(cfg)).output.splitlines() if "KG-K8S-003" in l
    )
    assert " off " in line


class TestFactories:
    class DummyAdapter:
        pass

    @pytest.fixture(autouse=True)
    def _patch_adapter(self, monkeypatch):
        monkeypatch.setattr(cli, "SdkDockerAdapter", self.DummyAdapter)

    def test_static_enumerator_by_default(self) -> None:
        cfg = KubeGuardConfig()
        scanner = build_docker_scanner(
            cfg, build_registry(cfg), no_cache=True, allow_container_exec=False
        )
        assert isinstance(scanner._enumerator, StaticPackageEnumerator)
        assert scanner._cve_matcher is not None

    def test_runtime_enumerator_only_when_opted_in(self) -> None:
        cfg = KubeGuardConfig()
        scanner = build_docker_scanner(
            cfg, build_registry(cfg), no_cache=True, allow_container_exec=True
        )
        assert isinstance(scanner._enumerator, RuntimePackageEnumerator)

    def test_no_enumeration_when_cve_rule_disabled(self) -> None:
        cfg = KubeGuardConfig(disabled_rules=["KG-DOCKER-004"])
        scanner = build_docker_scanner(
            cfg, build_registry(cfg), no_cache=True, allow_container_exec=False
        )
        assert scanner._enumerator is None and scanner._cve_matcher is None

    def test_cache_selection(self, tmp_path) -> None:
        assert isinstance(build_cache(KubeGuardConfig(), no_cache=True), NullCache)
        disabled = KubeGuardConfig.model_validate({"cache": {"enabled": False}})
        assert isinstance(build_cache(disabled, no_cache=False), NullCache)
        enabled = KubeGuardConfig.model_validate({"cache": {"directory": str(tmp_path / "c")}})
        assert isinstance(build_cache(enabled, no_cache=False), SqliteCache)
        assert (tmp_path / "c" / "nvd.db").exists()