"""Tests for the NVD client. All HTTP is faked; no network access."""

from urllib.parse import parse_qs

import pytest
import requests

from kubeguard.core.exceptions import NvdError
from kubeguard.integrations.cache import NullCache, SqliteCache
from kubeguard.integrations.nvd_client import NvdClient, RateLimiter, parse_cve
from tests.helpers import FakeClock, FakeResponse, FakeSession, make_cve_item, nvd_page


def ok(*items: dict) -> FakeResponse:
    return FakeResponse(200, nvd_page(list(items)))


def make_client(responses, api_key=None, **kwargs):
    clock = FakeClock()
    session = FakeSession(responses)
    kwargs.setdefault("cache", SqliteCache(clock=clock.time))
    client = NvdClient(api_key, session=session, clock=clock.time, sleep=clock.sleep, **kwargs)
    return client, session, clock


def query(call: dict) -> dict[str, list[str]]:
    return parse_qs(call["params"], keep_blank_values=True)


class TestRateLimiter:
    def test_allows_burst_then_waits_for_window(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(5, 30.0, clock=clock.time, sleep=clock.sleep)
        for _ in range(5):
            limiter.acquire()
        assert clock.sleeps == []
        limiter.acquire()
        assert clock.sleeps == [30.0]

    def test_window_slides(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(2, 10.0, clock=clock.time, sleep=clock.sleep)
        limiter.acquire()
        clock.now = 6
        limiter.acquire()
        limiter.acquire()  # must wait until the first stamp (t=0) leaves the window
        assert clock.sleeps == [4.0]


class TestClientRateLimits:
    def test_without_key_sixth_request_waits(self) -> None:
        client, _, clock = make_client([ok() for _ in range(6)])
        for i in range(6):
            client.search_by_keyword(f"pkg{i}")
        assert clock.sleeps == [30.0]

    def test_with_key_allows_fifty(self) -> None:
        client, _, clock = make_client([ok() for _ in range(50)], api_key="secret")
        for i in range(50):
            client.search_by_keyword(f"pkg{i}")
        assert clock.sleeps == []


class TestRequests:
    def test_cpe_query_shape_and_no_key_header(self) -> None:
        client, session, _ = make_client([ok()])
        client.search_by_cpe("cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*")
        params = query(session.calls[0])
        assert params["cpeName"] == ["cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"]
        assert "isVulnerable" in params
        assert session.calls[0]["headers"] == {}
        assert session.calls[0]["url"].endswith("/rest/json/cves/2.0")

    def test_keyword_query_and_api_key_header(self) -> None:
        client, session, _ = make_client([ok()], api_key="secret")
        client.search_by_keyword("libfoo 1.2.3")
        params = query(session.calls[0])
        assert params["keywordSearch"] == ["libfoo 1.2.3"]
        assert "isVulnerable" not in params
        assert session.calls[0]["headers"] == {"apiKey": "secret"}

    def test_from_env_reads_key(self) -> None:
        client = NvdClient.from_env({"NVD_API_KEY": " abc "}, session=FakeSession([ok()]))
        client.search_by_keyword("x")
        assert client._api_key == "abc"
        assert NvdClient.from_env({})._api_key is None

    def test_pagination(self) -> None:
        pages = [
            FakeResponse(200, nvd_page([make_cve_item("CVE-1"), make_cve_item("CVE-2")], total=3)),
            FakeResponse(200, nvd_page([make_cve_item("CVE-3")], total=3)),
        ]
        client, session, _ = make_client(pages)
        records = client.search_by_keyword("x")
        assert [r.id for r in records] == ["CVE-1", "CVE-2", "CVE-3"]
        assert [query(c)["startIndex"] for c in session.calls] == [["0"], ["2"]]


class TestCaching:
    def test_second_call_is_served_from_cache(self) -> None:
        client, session, _ = make_client([ok(make_cve_item("CVE-1"))])
        first = client.search_by_keyword("x")
        second = client.search_by_keyword("x")
        assert first == second
        assert len(session.calls) == 1

    def test_cache_expires(self) -> None:
        client, session, clock = make_client([ok(), ok()], cache_ttl=100)
        client.search_by_keyword("x")
        clock.now += 101
        client.search_by_keyword("x")
        assert len(session.calls) == 2

    def test_null_cache_always_fetches(self) -> None:
        client, session, _ = make_client([ok(), ok()], cache=NullCache())
        client.search_by_keyword("x")
        client.search_by_keyword("x")
        assert len(session.calls) == 2

    def test_truncated_results_are_not_cached(self) -> None:
        page = FakeResponse(200, nvd_page([make_cve_item("CVE-1")], total=999))
        client, session, _ = make_client([page, page], max_pages=1)
        client.search_by_keyword("x")
        client.search_by_keyword("x")
        assert len(session.calls) == 2


class TestRetries:
    def test_exponential_backoff_on_429(self) -> None:
        client, session, clock = make_client(
            [FakeResponse(429), FakeResponse(429), ok(make_cve_item("CVE-1"))]
        )
        assert [r.id for r in client.search_by_keyword("x")] == ["CVE-1"]
        assert len(session.calls) == 3
        assert clock.sleeps == [2.0, 4.0]

    def test_retry_after_is_honoured(self) -> None:
        client, _, clock = make_client([FakeResponse(429, headers={"Retry-After": "10"}), ok()])
        client.search_by_keyword("x")
        assert clock.sleeps == [10.0]

    def test_503_is_retried(self) -> None:
        client, session, _ = make_client([FakeResponse(503), ok()])
        client.search_by_keyword("x")
        assert len(session.calls) == 2

    def test_gives_up_after_max_retries(self) -> None:
        client, session, clock = make_client([FakeResponse(503)] * 3, max_retries=2)
        with pytest.raises(NvdError, match="after 3 attempts"):
            client.search_by_keyword("x")
        assert len(session.calls) == 3
        assert clock.sleeps == [2.0, 4.0]

    def test_network_errors_are_retried(self) -> None:
        client, session, _ = make_client([requests.ConnectionError("boom"), ok()])
        client.search_by_keyword("x")
        assert len(session.calls) == 2

    def test_404_is_an_error_not_empty_results(self) -> None:
        resp = FakeResponse(404, headers={"message": "Invalid apiKey"})
        client, session, _ = make_client([resp])
        with pytest.raises(NvdError, match="Invalid apiKey") as info:
            client.search_by_keyword("x")
        assert info.value.status_code == 404
        assert len(session.calls) == 1

    def test_invalid_json(self) -> None:
        client, _, _ = make_client([FakeResponse(200, invalid_json=True)])
        with pytest.raises(NvdError, match="valid JSON"):
            client.search_by_keyword("x")


class TestParseCve:
    def test_prefers_newest_scoring_and_english_description(self) -> None:
        item = make_cve_item(
            "CVE-1",
            score=9.8,
            version="3.1",
            description="English text",
            extra_metrics={"cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}]},
        )
        record = parse_cve(item["cve"])
        assert (record.cvss_score, record.cvss_version) == (9.8, "3.1")
        assert record.description == "English text"

    def test_v40_beats_v31(self) -> None:
        item = make_cve_item(
            "CVE-1",
            score=7.0,
            version="3.1",
            extra_metrics={"cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseScore": 8.7}}]},
        )
        record = parse_cve(item["cve"])
        assert (record.cvss_score, record.cvss_version) == (8.7, "4.0")

    def test_falls_back_to_v2(self) -> None:
        record = parse_cve(make_cve_item("CVE-1", score=5.0, version="2.0")["cve"])
        assert (record.cvss_score, record.cvss_version) == (5.0, "2.0")

    def test_unscored(self) -> None:
        record = parse_cve(make_cve_item("CVE-1", score=None)["cve"])
        assert record.cvss_score is None and record.cvss_version is None

    def test_remediation_url_prefers_patch_reference(self) -> None:
        refs = [
            {"url": "https://example.com/blog", "tags": []},
            {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://vendor.example/patch", "tags": ["Patch"]},
        ]
        assert parse_cve(make_cve_item(references=refs)["cve"]).remediation_url == (
            "https://vendor.example/patch"
        )

    def test_remediation_url_defaults_to_nvd(self) -> None:
        record = parse_cve(make_cve_item("CVE-2024-9")["cve"])
        assert record.remediation_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-9"