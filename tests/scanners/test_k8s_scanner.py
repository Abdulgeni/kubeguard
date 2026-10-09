"""Tests for KubernetesScanner."""

from pathlib import Path

import pytest

from kubeguard.core.exceptions import ScannerError
from kubeguard.core.registry import RuleRegistry
from kubeguard.scanners.k8s_scanner import KubernetesScanner


def pod_yaml(name: str = "bad") -> str:
    return (
        f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\n"
        "spec:\n  containers:\n    - name: app\n      image: nginx\n"
    )


@pytest.fixture
def registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.discover("kubeguard.rules")
    return reg


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def resources(result) -> set[str]:
    return {f.resource for f in result.findings}


def test_single_file(registry, tmp_path) -> None:
    file = write(tmp_path / "pod.yaml", pod_yaml())
    result = KubernetesScanner(registry).scan(str(file))
    assert {f.rule_id for f in result.findings} == {"KG-K8S-001", "KG-K8S-002", "KG-K8S-003"}
    assert resources(result) == {"Pod/bad"}
    assert all(f.location == f"{file}:1" for f in result.findings)
    assert result.errors == []


def test_multi_document_with_empty_documents(registry, tmp_path) -> None:
    text = "---\n" + pod_yaml("a") + "---\n---\n" + pod_yaml("b")
    result = KubernetesScanner(registry).scan(str(write(tmp_path / "m.yaml", text)))
    assert resources(result) == {"Pod/a", "Pod/b"}


def test_list_kind_is_expanded(registry, tmp_path) -> None:
    text = (
        "apiVersion: v1\nkind: List\nitems:\n"
        "  - {apiVersion: v1, kind: Pod, metadata: {name: one}, spec: {containers: [{name: app, image: x}]}}\n"
        "  - {apiVersion: v1, kind: Pod, metadata: {name: two}, spec: {containers: [{name: app, image: x}]}}\n"
    )
    result = KubernetesScanner(registry).scan(str(write(tmp_path / "l.yaml", text)))
    assert resources(result) == {"Pod/one", "Pod/two"}


def test_directory_recursion_skips_hidden_dirs_and_other_files(registry, tmp_path) -> None:
    write(tmp_path / "a.yaml", pod_yaml("a"))
    write(tmp_path / "sub" / "b.yml", pod_yaml("b"))
    write(tmp_path / ".git" / "c.yaml", pod_yaml("hidden"))
    write(tmp_path / "readme.md", pod_yaml("markdown"))
    result = KubernetesScanner(registry).scan(str(tmp_path))
    assert resources(result) == {"Pod/a", "Pod/b"}


def test_invalid_yaml_is_reported_and_earlier_documents_kept(registry, tmp_path) -> None:
    file = write(tmp_path / "broken.yaml", pod_yaml("ok") + "---\nfoo: [unclosed\n")
    result = KubernetesScanner(registry).scan(str(file))
    assert resources(result) == {"Pod/ok"}
    assert len(result.errors) == 1 and "invalid YAML" in result.errors[0]


def test_unreadable_encoding_is_reported(registry, tmp_path) -> None:
    file = tmp_path / "bin.yaml"
    file.write_bytes(b"\xff\xfe\x00bad")
    result = KubernetesScanner(registry).scan(str(file))
    assert "cannot read file" in result.errors[0]


def test_oversized_file_is_reported(registry, tmp_path) -> None:
    file = write(tmp_path / "big.yaml", pod_yaml())
    result = KubernetesScanner(registry, max_file_bytes=10).scan(str(file))
    assert "larger than" in result.errors[0] and result.findings == []


def test_missing_path_raises(registry, tmp_path) -> None:
    with pytest.raises(ScannerError, match="does not exist"):
        KubernetesScanner(registry).scan(str(tmp_path / "nope"))


def test_directory_without_yaml_is_an_error(registry, tmp_path) -> None:
    write(tmp_path / "notes.txt", "hi")
    result = KubernetesScanner(registry).scan(str(tmp_path))
    assert "No YAML files" in result.errors[0]


def test_non_manifests_and_unsupported_kinds_are_ignored(registry, tmp_path) -> None:
    write(tmp_path / "values.yaml", "foo: bar\nlist: [1, 2]\n")
    write(tmp_path / "svc.yaml", "apiVersion: v1\nkind: Service\nmetadata: {name: s}\n")
    write(tmp_path / "scalar.yaml", "just a string\n")
    result = KubernetesScanner(registry).scan(str(tmp_path))
    assert result.findings == [] and result.errors == []


def test_disabled_rules_are_respected(tmp_path) -> None:
    reg = RuleRegistry(disabled_rules=["KG-K8S-001", "KG-K8S-002", "KG-K8S-003"])
    reg.discover("kubeguard.rules")
    result = KubernetesScanner(reg).scan(str(write(tmp_path / "p.yaml", pod_yaml())))
    assert result.findings == []