"""Tests for K8s target models."""

import pytest

from kubeguard.core.targets import K8sResourceTarget, as_dict, as_list
from tests.helpers import container, k8s_target, workload


@pytest.mark.parametrize(
    "kind",
    [
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
    ],
)
def test_pod_spec_found_for_every_workload_kind(kind: str) -> None:
    target = k8s_target(workload(kind))
    assert target.pod_spec is not None
    assert [c.name for c in target.containers] == ["app"]


def test_unsupported_or_missing_kind_returns_none() -> None:
    assert (
        K8sResourceTarget.from_manifest({"kind": "Service", "metadata": {"name": "x"}}, "a.yaml")
        is None
    )
    assert K8sResourceTarget.from_manifest({"metadata": {"name": "x"}}, "a.yaml") is None


def test_rbac_target_has_no_pod_spec() -> None:
    target = k8s_target({"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": []})
    assert target.pod_spec is None
    assert target.containers == []


def test_init_and_ephemeral_containers_are_included() -> None:
    target = k8s_target(
        workload(
            "Pod",
            pod_spec={
                "initContainers": [container("init")],
                "ephemeralContainers": [container("dbg")],
            },
        )
    )
    assert [(c.name, c.kind) for c in target.containers] == [
        ("app", "container"),
        ("init", "initContainer"),
        ("dbg", "ephemeralContainer"),
    ]


def test_display_name_namespace_and_location() -> None:
    manifest = workload("Deployment", name="web")
    manifest["metadata"]["namespace"] = "prod"
    target = k8s_target(manifest, source="deploy/app.yaml", line=7)
    assert target.display_name == "Deployment/web"
    assert target.namespace == "prod"
    assert target.location == "deploy/app.yaml:7"
    assert k8s_target(manifest, line=None).location == "app.yaml"


def test_missing_name_is_tolerated() -> None:
    target = k8s_target({"kind": "Pod", "spec": {"containers": []}})
    assert target.name == "<unnamed>"


def test_malformed_fields_are_tolerated() -> None:
    target = k8s_target(
        workload("Pod", pod_spec={"containers": "oops", "volumes": 5, "securityContext": "x"})
    )
    assert target.containers == []
    assert target.volumes == []
    assert target.pod_security_context == {}


def test_as_dict_and_as_list() -> None:
    assert as_dict({"a": 1}) == {"a": 1}
    assert as_dict("x") == {} and as_dict(None) == {}
    assert as_list([1]) == [1]
    assert as_list({"a": 1}) == [] and as_list(None) == []