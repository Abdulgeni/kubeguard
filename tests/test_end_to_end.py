"""End-to-end: the shipped example manifests through the real CLI."""

import json
from pathlib import Path

from typer.testing import CliRunner

from kubeguard.cli import app

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "k8s"
runner = CliRunner()


def scan(path: Path, *extra: str):
    return runner.invoke(app, ["scan", "k8s", str(path), "-o", "json", *extra])


def rules_by_resource(stdout: str) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for f in json.loads(stdout)["findings"]:
        grouped.setdefault(f["resource"], set()).add(f["rule_id"])
    return grouped


def test_insecure_example_triggers_every_k8s_rule() -> None:
    result = scan(EXAMPLES / "insecure-deployment.yaml")
    assert result.exit_code == 0
    grouped = rules_by_resource(result.stdout)
    assert grouped["Deployment/insecure-web"] == {f"KG-K8S-00{n}" for n in range(1, 7)}
    assert grouped["ClusterRole/too-powerful"] == {"KG-K8S-007"}


def test_secure_example_is_clean_even_at_info_threshold() -> None:
    result = scan(EXAMPLES / "secure-deployment.yaml", "--fail-on", "info")
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []


def test_directory_scan_only_flags_the_insecure_resources() -> None:
    result = scan(EXAMPLES, "--fail-on", "high")
    assert result.exit_code == 1
    assert set(rules_by_resource(result.stdout)) == {
        "Deployment/insecure-web",
        "ClusterRole/too-powerful",
    }


def test_sarif_for_examples_points_at_example_files() -> None:
    result = runner.invoke(app, ["scan", "k8s", str(EXAMPLES), "-o", "sarif"])
    results = json.loads(result.stdout)["runs"][0]["results"]
    assert results and all(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results
    )