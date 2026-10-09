"""Tests for CPE building, version normalisation, and CVE matching."""

import pytest

from kubeguard.core.exceptions import NvdError
from kubeguard.core.targets import PackageInfo
from kubeguard.integrations.cpe import build_cpe, normalize_version
from kubeguard.integrations.cve_matcher import CveMatcher
from kubeguard.integrations.nvd_client import CveRecord


def pkg(name="libssl3", version="3.0.11-1~deb12u2", eco="deb", source="openssl") -> PackageInfo:
    return PackageInfo(name=name, version=version, ecosystem=eco, source=source)


def cve(cve_id="CVE-1", score=7.5) -> CveRecord:
    return CveRecord(id=cve_id, cvss_score=score, remediation_url="https://nvd.example/" + cve_id)


@pytest.mark.parametrize(
    ("eco", "raw", "expected"),
    [
        ("deb", "1:3.0.11-1~deb12u2", "3.0.11"),
        ("deb", "1.1.1n-0+deb11u5", "1.1.1n"),
        ("deb", "1.2.13.dfsg-1", "1.2.13"),
        ("deb", "5.2.15", "5.2.15"),
        ("apk", "3.1.4-r5", "3.1.4"),
        ("rpm", "3.0.7-24.el9", "3.0.7"),
        ("rpm", "2:1.1.1k-9.el9", "1.1.1k"),
    ],
)
def test_normalize_version(eco: str, raw: str, expected: str) -> None:
    assert normalize_version(eco, raw) == expected


class TestBuildCpe:
    def test_uses_source_name(self) -> None:
        assert build_cpe(pkg()) == "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"

    def test_uses_binary_name_when_no_source(self) -> None:
        cpe = build_cpe(pkg(name="curl", version="7.88.1-10", source=None))
        assert cpe == "cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*"

    def test_python_variants(self) -> None:
        cpe = build_cpe(pkg(name="python3.11", version="3.11.2-6", source=None))
        assert cpe == "cpe:2.3:a:python:python:3.11.2:*:*:*:*:*:*:*"

    def test_unknown_product(self) -> None:
        assert build_cpe(pkg(name="libfoo", source=None)) is None

    def test_extra_map(self) -> None:
        cpe = build_cpe(pkg(name="libfoo", version="1.0-1", source=None), {"libfoo": ("acme", "foo")})
        assert cpe == "cpe:2.3:a:acme:foo:1.0:*:*:*:*:*:*:*"

    def test_special_characters_are_escaped(self) -> None:
        cpe = build_cpe(pkg(name="x", version="1.0+git~rc1", source=None), {"x": ("a b", "c")})
        assert cpe == "cpe:2.3:a:a\\ b:c:1.0\\+git\\~rc1:*:*:*:*:*:*:*"


class FakeSource:
    def __init__(self, by_cpe=None, by_keyword=None, errors=None) -> None:
        self.by_cpe = by_cpe or {}
        self.by_keyword = by_keyword or {}
        self.errors = errors or {}
        self.cpe_calls: list[str] = []
        self.keyword_calls: list[str] = []

    def search_by_cpe(self, cpe: str):
        self.cpe_calls.append(cpe)
        if cpe in self.errors:
            raise self.errors[cpe]
        return self.by_cpe.get(cpe, [])

    def search_by_keyword(self, keyword: str):
        self.keyword_calls.append(keyword)
        if keyword in self.errors:
            raise self.errors[keyword]
        return self.by_keyword.get(keyword, [])


OPENSSL_CPE = "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"


class TestCveMatcher:
    def test_cpe_match_is_high_confidence(self) -> None:
        source = FakeSource(by_cpe={OPENSSL_CPE: [cve("CVE-1")]})
        matches, notes = CveMatcher(source).match_all([pkg()])
        assert notes == []
        assert (matches[0].confidence, matches[0].method, matches[0].cpe) == ("high", "cpe", OPENSSL_CPE)
        assert source.keyword_calls == []

    def test_unmapped_package_uses_low_confidence_keyword_search(self) -> None:
        source = FakeSource(by_keyword={"libfoo 1.0": [cve("CVE-9")]})
        matches, _ = CveMatcher(source).match_all([pkg(name="libfoo", version="1.0-1", source=None)])
        assert (matches[0].confidence, matches[0].method, matches[0].cpe) == ("low", "keyword", None)
        assert source.keyword_calls == ["libfoo 1.0"]

    def test_fallback_disabled_reports_skipped_packages(self) -> None:
        source = FakeSource()
        matches, notes = CveMatcher(source, keyword_fallback=False).match_all(
            [pkg(name="libfoo", source=None)]
        )
        assert matches == []
        assert "1 package(s) not checked" in notes[0]
        assert source.keyword_calls == []

    def test_packages_sharing_a_lookup_are_queried_once(self) -> None:
        source = FakeSource(by_cpe={OPENSSL_CPE: [cve("CVE-1")]})
        packages = [pkg("libssl3"), pkg("openssl"), pkg("libssl-dev")]
        matches, _ = CveMatcher(source).match_all(packages)
        assert len(source.cpe_calls) == 1
        assert len(matches) == 1
        assert matches[0].package.name == "libssl3"
        assert matches[0].also_affects == ("libssl-dev", "openssl")

    def test_lookup_failure_is_reported_and_others_continue(self) -> None:
        curl_cpe = "cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*"
        source = FakeSource(
            by_cpe={curl_cpe: [cve("CVE-2")]}, errors={OPENSSL_CPE: NvdError("HTTP 503")}
        )
        packages = [pkg(), pkg("curl", "7.88.1-10", source=None)]
        matches, notes = CveMatcher(source).match_all(packages)
        assert [m.cve.id for m in matches] == ["CVE-2"]
        assert "libssl3" in notes[0] and "HTTP 503" in notes[0]

    def test_circuit_breaker_aborts_after_consecutive_failures(self) -> None:
        names = ["curl", "bash", "tar", "git", "perl"]
        packages = [pkg(n, "1.0-1", source=None) for n in names]
        errors = {build_cpe(p): NvdError("down") for p in packages}
        source = FakeSource(errors=errors)
        matches, notes = CveMatcher(source, max_consecutive_failures=3).match_all(packages)
        assert matches == []
        assert len(source.cpe_calls) == 3
        assert "aborted after 3 consecutive failures; 2 package group(s) not checked" in notes[-1]

    def test_success_resets_failure_streak(self) -> None:
        names = ["curl", "bash", "tar", "git"]
        packages = [pkg(n, "1.0-1", source=None) for n in names]
        cpes = [build_cpe(p) for p in packages]
        source = FakeSource(errors={cpes[0]: NvdError("x"), cpes[1]: NvdError("x"), cpes[3]: NvdError("x")})
        _, notes = CveMatcher(source, max_consecutive_failures=3).match_all(packages)
        assert len(source.cpe_calls) == 4
        assert not any("aborted" in n for n in notes)