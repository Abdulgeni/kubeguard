"""Tests for the table, JSON and SARIF reporters."""

import json

import pytest

from kubeguard.core.models import Finding, ScanResult, Severity, TargetType
from kubeguard.reporters import create_reporter, sort_findings
from kubeguard.reporters.json_reporter import JsonReporter
from kubeguard.reporters.sarif_reporter import SarifReporter, normalise_uri, split_location
from kubeguard.reporters.table_reporter import TableReporter


def finding(
    rule_id="KG-K8S-001",
    severity=Severity.MEDIUM,
    resource="Pod/web",
    target_type=TargetType.K8S,
    location="deploy/app.yaml:12",
    **metadata,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        target_type=target_type,
        resource=resource,
        description=f"desc {rule_id}",
        remediation=f"fix {rule_id}",
        location=location,
        metadata=metadata,
    )


def result_of(*findings: Finding, errors: list[str] | None = None) -> ScanResult:
    result = ScanResult()
    result.extend(list(findings), errors)
    return result


def test_sort_order_is_severity_desc_then_stable() -> None:
    ordered = sort_findings(
        [
            finding("KG-A-001", Severity.INFO),
            finding("KG-B-001", Severity.CRITICAL),
            finding("KG-C-001", Severity.HIGH, resource="Pod/a"),
            finding("KG-D-001", Severity.HIGH, resource="Pod/b"),
        ]
    )
    assert [f.rule_id for f in ordered] == ["KG-B-001", "KG-C-001", "KG-D-001", "KG-A-001"]


def test_create_reporter() -> None:
    assert isinstance(create_reporter("json"), JsonReporter)
    assert isinstance(create_reporter("table"), TableReporter)
    assert isinstance(create_reporter("sarif"), SarifReporter)
    with pytest.raises(ValueError):
        create_reporter("xml")


class TestJson:
    def test_structure(self) -> None:
        text = JsonReporter().render(
            result_of(
                finding(severity=Severity.HIGH),
                finding("KG-X-002", Severity.LOW),
                errors=["boom"],
            )
        )
        data = json.loads(text)
        assert set(data) == {"tool", "summary", "findings", "errors"}
        assert data["summary"]["total"] == 2
        assert data["summary"]["max_severity"] == "HIGH"
        assert data["summary"]["by_severity"] == {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 0,
            "LOW": 1,
            "INFO": 0,
        }
        assert data["errors"] == ["boom"]
        first = data["findings"][0]
        for key in ("rule_id", "severity", "resource", "description", "remediation"):
            assert key in first
        assert first["severity"] == "HIGH"

    def test_empty(self) -> None:
        data = json.loads(JsonReporter().render(ScanResult()))
        assert data["findings"] == [] and data["summary"]["max_severity"] is None


class TestTable:
    def render(self, result: ScanResult) -> str:
        return TableReporter(color=False, width=120, ascii_only=True).render(result)

    def test_contains_required_fields(self) -> None:
        text = self.render(
            result_of(finding(severity=Severity.HIGH), finding("KG-X-002", Severity.LOW))
        )
        for expected in (
            "KG-K8S-001",
            "KG-X-002",
            "Pod/web",
            "HIGH",
            "Fix:",
            "fix KG-K8S-001",
            "2 finding(s)",
        ):
            assert expected in text
        assert "\x1b" not in text

    def test_most_severe_first(self) -> None:
        text = self.render(
            result_of(
                finding("KG-LOW-001", Severity.LOW), finding("KG-CRIT-001", Severity.CRITICAL)
            )
        )
        assert text.index("KG-CRIT-001") < text.index("KG-LOW-001")

    def test_empty_and_errors(self) -> None:
        text = self.render(result_of(errors=["something broke"]))
        assert "No findings" in text and "something broke" in text

    def test_markup_in_content_is_not_interpreted(self) -> None:
        text = self.render(result_of(finding(resource="Pod/[bold]x[/bold]")))
        assert "[bold]x[/bold]" in text

    def test_color_mode_emits_ansi(self) -> None:
        text = TableReporter(color=True, width=120, ascii_only=True).render(result_of(finding()))
        assert "\x1b[" in text


class TestSarif:
    def render(self, result: ScanResult, **kwargs) -> dict:
        return json.loads(SarifReporter(**kwargs).render(result))

    def test_top_level_shape(self) -> None:
        sarif = self.render(result_of(finding()))
        assert sarif["version"] == "2.1.0"
        assert "sarif-2.1.0" in sarif["$schema"]
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "KubeGuard"
        assert [r["id"] for r in driver["rules"]] == ["KG-K8S-001"]

    def test_results_levels_and_rule_index(self) -> None:
        sarif = self.render(
            result_of(
                finding("KG-A-001", Severity.CRITICAL),
                finding("KG-B-001", Severity.MEDIUM),
                finding("KG-C-001", Severity.INFO),
                finding("KG-B-001", Severity.MEDIUM, resource="Pod/other"),
            )
        )
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["KG-A-001", "KG-B-001", "KG-C-001"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        assert levels == {"KG-A-001": "error", "KG-B-001": "warning", "KG-C-001": "note"}
        assert rules[0]["properties"]["security-severity"] == "9.5"

    def test_k8s_location(self) -> None:
        result = self.render(result_of(finding(location="deploy/app.yaml:12")))["runs"][0][
            "results"
        ][0]
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "deploy/app.yaml"
        assert physical["region"]["startLine"] == 12

    def test_docker_finding_uses_configurable_uri_and_logical_location(self) -> None:
        docker = finding(
            "KG-DOCKER-001",
            Severity.HIGH,
            "nginx:1.25",
            TargetType.DOCKER,
            location="layer 1",
        )
        default = self.render(result_of(docker))["runs"][0]["results"][0]["locations"][0]
        assert default["physicalLocation"]["artifactLocation"]["uri"] == "Dockerfile"
        assert default["physicalLocation"]["region"]["startLine"] == 1
        assert default["logicalLocations"][0]["name"] == "nginx:1.25"
        custom = self.render(result_of(docker), docker_artifact_uri="build/Dockerfile")
        assert (
            custom["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"]
            == "build/Dockerfile"
        )

    def test_message_carries_remediation_and_fingerprint_ignores_line_changes(self) -> None:
        a = self.render(result_of(finding(location="deploy/app.yaml:12")))["runs"][0]["results"][0]
        b = self.render(result_of(finding(location="deploy/app.yaml:99")))["runs"][0]["results"][0]
        assert "Remediation: fix KG-K8S-001" in a["message"]["text"]
        assert a["partialFingerprints"] == b["partialFingerprints"]

    def test_cve_findings_get_distinct_fingerprints(self) -> None:
        one = finding(
            "KG-DOCKER-004",
            target_type=TargetType.DOCKER_PACKAGE,
            location=None,
            cve_id="CVE-1",
            package="a",
        )
        two = finding(
            "KG-DOCKER-004",
            target_type=TargetType.DOCKER_PACKAGE,
            location=None,
            cve_id="CVE-2",
            package="a",
        )
        results = self.render(result_of(one, two))["runs"][0]["results"]
        assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]

    def test_errors_become_notifications(self) -> None:
        invocation = self.render(result_of(errors=["bad file"]))["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "bad file"
        clean = self.render(ScanResult())["runs"][0]["invocations"][0]
        assert clean["executionSuccessful"] is True


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("deploy/app.yaml:12", ("deploy/app.yaml", 12)),
        ("C:\\x\\a.yaml:7", ("C:\\x\\a.yaml", 7)),
        ("C:\\x\\a.yaml", ("C:\\x\\a.yaml", None)),
        ("layer 1: USER root", ("layer 1: USER root", None)),
        (None, (None, None)),
    ],
)
def test_split_location(location, expected) -> None:
    assert split_location(location) == expected


def test_normalise_uri_is_relative_to_cwd(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert normalise_uri(str(tmp_path / "k" / "a.yaml")) == "k/a.yaml"
    assert normalise_uri("k/a.yaml") == "k/a.yaml"