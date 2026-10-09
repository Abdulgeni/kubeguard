"""Tests for KG-K8S-001..007."""

import pytest

from kubeguard.core.models import Severity
from kubeguard.rules.k8s.env_secrets import K8sEnvSecretsRule
from kubeguard.rules.k8s.privilege_escalation import PrivilegeEscalationRule
from kubeguard.rules.k8s.privileged_hostpath import HostPathVolumeRule, PrivilegedContainerRule
from kubeguard.rules.k8s.rbac_wildcards import RbacWildcardRule
from kubeguard.rules.k8s.resource_limits import ResourceLimitsRule
from kubeguard.rules.k8s.run_as_non_root import RunAsNonRootRule
from tests.helpers import container, k8s_target, workload


def check(rule, **workload_args):
    return rule.check(k8s_target(workload(**workload_args)))


class TestRunAsNonRoot:
    rule = RunAsNonRootRule()

    def test_missing_is_flagged(self) -> None:
        finding = check(self.rule)
        assert finding.rule_id == "KG-K8S-001"
        assert finding.resource == "Deployment/web"
        assert finding.location == "app.yaml:3"
        assert finding.metadata["containers"] == ["app"]

    def test_container_level_true_passes(self) -> None:
        c = container(securityContext={"runAsNonRoot": True})
        assert check(self.rule, containers=[c]) is None

    def test_pod_level_true_passes(self) -> None:
        assert check(self.rule, pod_spec={"securityContext": {"runAsNonRoot": True}}) is None

    def test_container_false_overrides_pod_true(self) -> None:
        c = container(securityContext={"runAsNonRoot": False})
        finding = check(
            self.rule, containers=[c], pod_spec={"securityContext": {"runAsNonRoot": True}}
        )
        assert finding is not None

    def test_only_offenders_are_listed(self) -> None:
        good = container("good", securityContext={"runAsNonRoot": True})
        finding = check(self.rule, containers=[good, container("bad")])
        assert finding.metadata["containers"] == ["bad"]

    def test_init_containers_are_checked(self) -> None:
        finding = check(
            self.rule,
            containers=[container(securityContext={"runAsNonRoot": True})],
            pod_spec={"initContainers": [container("init")]},
        )
        assert finding.metadata["containers"] == ["init"]

    def test_non_workload_is_ignored(self) -> None:
        assert (
            self.rule.check(k8s_target({"kind": "ClusterRole", "metadata": {"name": "r"}})) is None
        )


class TestPrivilegeEscalation:
    rule = PrivilegeEscalationRule()

    @pytest.mark.parametrize("ctx", [{}, {"allowPrivilegeEscalation": True}])
    def test_flagged(self, ctx) -> None:
        assert check(self.rule, containers=[container(securityContext=ctx)]) is not None

    def test_explicit_false_passes(self) -> None:
        c = container(securityContext={"allowPrivilegeEscalation": False})
        assert check(self.rule, containers=[c]) is None


class TestResourceLimits:
    rule = ResourceLimitsRule()

    def test_missing_resources(self) -> None:
        finding = check(self.rule)
        assert "app (missing cpu, memory)" in finding.description
        assert finding.severity is Severity.LOW

    def test_partial_limits(self) -> None:
        c = container(resources={"limits": {"cpu": "1"}})
        assert "app (missing memory)" in check(self.rule, containers=[c]).description

    def test_requests_alone_do_not_count(self) -> None:
        c = container(resources={"requests": {"cpu": "1", "memory": "1Gi"}})
        assert check(self.rule, containers=[c]) is not None

    def test_full_limits_pass(self) -> None:
        c = container(resources={"limits": {"cpu": "1", "memory": "1Gi"}})
        assert check(self.rule, containers=[c]) is None


class TestPrivileged:
    rule = PrivilegedContainerRule()

    def test_privileged_is_critical(self) -> None:
        finding = check(self.rule, containers=[container(securityContext={"privileged": True})])
        assert finding.severity is Severity.CRITICAL

    @pytest.mark.parametrize("ctx", [{}, {"privileged": False}])
    def test_others_pass(self, ctx) -> None:
        assert check(self.rule, containers=[container(securityContext=ctx)]) is None


class TestHostPath:
    rule = HostPathVolumeRule()

    def test_hostpath_flagged_with_path(self) -> None:
        volumes = [{"name": "root", "hostPath": {"path": "/"}}, {"name": "tmp", "emptyDir": {}}]
        finding = check(self.rule, pod_spec={"volumes": volumes})
        assert finding.severity is Severity.HIGH
        assert finding.metadata["volumes"] == [{"name": "root", "path": "/"}]
        assert "root (/)" in finding.description

    def test_other_volumes_pass(self) -> None:
        assert check(self.rule, pod_spec={"volumes": [{"name": "t", "emptyDir": {}}]}) is None
        assert check(self.rule) is None


class TestEnvSecrets:
    rule = K8sEnvSecretsRule()

    def test_literal_secret_flagged_and_value_never_leaked(self) -> None:
        env = [{"name": "DB_PASSWORD", "value": "hunter2"}, {"name": "LOG_LEVEL", "value": "info"}]
        finding = check(self.rule, containers=[container(env=env)])
        assert finding.metadata["variables"] == ["app:DB_PASSWORD"]
        assert "hunter2" not in finding.description
        assert "hunter2" not in str(finding.metadata)

    def test_value_from_passes(self) -> None:
        env = [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "p"}}}]
        assert check(self.rule, containers=[container(env=env)]) is None

    def test_empty_value_and_file_references_pass(self) -> None:
        env = [
            {"name": "API_TOKEN", "value": ""},
            {"name": "API_TOKEN_FILE", "value": "/run/secrets/t"},
        ]
        assert check(self.rule, containers=[container(env=env)]) is None

    def test_malformed_env_is_tolerated(self) -> None:
        assert check(self.rule, containers=[container(env="oops")]) is None
        assert check(self.rule, containers=[container(env=["x", 5, None])]) is None


class TestRbacWildcards:
    rule = RbacWildcardRule()

    def role(self, kind: str, rules):
        return k8s_target({"kind": kind, "metadata": {"name": "r"}, "rules": rules})

    @pytest.mark.parametrize("kind", ["Role", "ClusterRole"])
    def test_wildcard_verbs_flagged(self, kind: str) -> None:
        finding = self.rule.check(self.role(kind, [{"resources": ["pods"], "verbs": ["*"]}]))
        assert finding.metadata["rule_indexes"] == [0]
        assert "wildcard verbs" in finding.description

    def test_wildcard_resources_and_both(self) -> None:
        rules = [
            {"resources": ["*"], "verbs": ["get"]},
            {"resources": ["pods"], "verbs": ["get"]},
            {"resources": ["*"], "verbs": ["*"]},
        ]
        finding = self.rule.check(self.role("ClusterRole", rules))
        assert finding.metadata["rule_indexes"] == [0, 2]
        assert "wildcard verbs and resources" in finding.description

    def test_specific_rules_pass(self) -> None:
        assert (
            self.rule.check(
                self.role("Role", [{"resources": ["pods"], "verbs": ["get", "list"]}])
            )
            is None
        )

    def test_malformed_rules_tolerated(self) -> None:
        assert self.rule.check(self.role("Role", "oops")) is None
        assert self.rule.check(self.role("Role", [None, "x"])) is None

    def test_workloads_ignored(self) -> None:
        assert check(self.rule) is None