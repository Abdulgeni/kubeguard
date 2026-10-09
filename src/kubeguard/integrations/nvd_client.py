"""NVD CVE API v2.0 client with client-side rate limiting, backoff and caching."""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from urllib.parse import quote, urlencode

import requests
from pydantic import BaseModel, ConfigDict

from kubeguard.core.exceptions import NvdError
from kubeguard.integrations.cache import Cache, NullCache

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
WINDOW_SECONDS = 30.0
LIMIT_NO_KEY = 5
LIMIT_WITH_KEY = 50
PAGE_SIZE = 2000
RETRY_STATUSES = frozenset({429, 503})
# Newest scoring system first; the first one present wins.
_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class CveRecord(BaseModel):
    """The subset of an NVD CVE record KubeGuard uses."""

    model_config = ConfigDict(frozen=True)

    id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_version: str | None = None
    published: str | None = None
    remediation_url: str


def _pick_score(metrics: Mapping[str, Any]) -> tuple[float | None, str | None]:
    for key, version in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        score = (chosen.get("cvssData") or {}).get("baseScore")
        if isinstance(score, (int, float)):
            return float(score), version
    return None, None


def _pick_remediation_url(cve_id: str, references: list[dict[str, Any]]) -> str:
    for tag in ("Patch", "Vendor Advisory"):
        for ref in references:
            if tag in (ref.get("tags") or []) and ref.get("url"):
                return str(ref["url"])
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def parse_cve(cve: Mapping[str, Any]) -> CveRecord:
    """Convert one NVD ``cve`` object into a ``CveRecord``."""
    cve_id = str(cve["id"])
    description = next(
        (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), ""
    )
    score, version = _pick_score(cve.get("metrics") or {})
    return CveRecord(
        id=cve_id,
        description=description,
        cvss_score=score,
        cvss_version=version,
        published=cve.get("published"),
        remediation_url=_pick_remediation_url(cve_id, cve.get("references") or []),
    )


class RateLimiter:
    """Sliding-window limiter: at most ``max_requests`` per ``window`` seconds."""

    def __init__(
        self,
        max_requests: int,
        window: float = WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._max = max_requests
        self._window = window
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a request slot is available, then claim it."""
        while True:
            with self._lock:
                now = self._clock()
                while self._stamps and now - self._stamps[0] >= self._window:
                    self._stamps.popleft()
                if len(self._stamps) < self._max:
                    self._stamps.append(now)
                    return
                wait = self._window - (now - self._stamps[0])
            self._sleep(max(wait, 0.0))


class HttpSession(Protocol):
    """The slice of ``requests.Session`` the client uses (fakeable in tests)."""

    def get(self, url: str, **kwargs: Any) -> Any: ...


class NvdClient:
    """Queries the NVD CVE API.

    Args:
        api_key: NVD API key; raises the rate limit tenfold. Use ``from_env``.
        cache: Result cache (default: none).
        session: HTTP session (default: a new ``requests.Session``).
        rate_limiter: Override the limiter (default derived from key presence).
        max_retries: Retries after the first attempt on 429/503/network errors.
        backoff_base: First backoff delay in seconds; doubles each retry.
        cache_ttl: Seconds a cached result stays valid.
        max_pages: Safety cap on pagination (``PAGE_SIZE`` results per page).
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        cache: Cache | None = None,
        session: HttpSession | None = None,
        rate_limiter: RateLimiter | None = None,
        base_url: str = NVD_BASE_URL,
        max_retries: int = 5,
        backoff_base: float = 2.0,
        backoff_max: float = 60.0,
        timeout: float = 30.0,
        cache_ttl: float = 24 * 3600.0,
        max_pages: int = 5,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_key = api_key or None
        self._cache: Cache = cache if cache is not None else NullCache()
        if session is None:
            real = requests.Session()
            real.headers["User-Agent"] = "kubeguard/0.1"
            session = real
        self._session = session
        limit = LIMIT_WITH_KEY if self._api_key else LIMIT_NO_KEY
        self._limiter = rate_limiter or RateLimiter(limit, WINDOW_SECONDS, clock, sleep)
        self._base_url = base_url
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._timeout = timeout
        self._ttl = cache_ttl
        self._max_pages = max_pages
        self._sleep = sleep

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kwargs: Any) -> NvdClient:
        """Build a client reading the API key from ``NVD_API_KEY``."""
        env = os.environ if env is None else env
        key = (env.get(API_KEY_ENV) or "").strip() or None
        return cls(api_key=key, **kwargs)

    # ------------------------------------------------------------------ queries
    def search_by_cpe(self, cpe: str) -> list[CveRecord]:
        """CVEs whose applicability matches ``cpe`` and marks it vulnerable."""
        return self._search({"cpeName": cpe}, flags=("isVulnerable",))

    def search_by_keyword(self, keyword: str) -> list[CveRecord]:
        """CVEs whose description matches ``keyword`` (low-confidence fallback)."""
        return self._search({"keywordSearch": keyword})

    # ----------------------------------------------------------------- internals
    def _search(self, params: dict[str, str], flags: tuple[str, ...] = ()) -> list[CveRecord]:
        base = urlencode(sorted(params.items()), safe=":*", quote_via=quote)
        base += "".join(f"&{flag}" for flag in flags)
        key = "nvd:v1:" + hashlib.sha256(base.encode()).hexdigest()

        cached = self._cache.get(key)
        if cached is not None:
            return [CveRecord.model_validate(item) for item in cached]

        records: list[CveRecord] = []
        start = 0
        complete = False
        for _ in range(self._max_pages):
            data = self._request(f"{base}&resultsPerPage={PAGE_SIZE}&startIndex={start}")
            items = data.get("vulnerabilities") or []
            records.extend(parse_cve(item["cve"]) for item in items if "cve" in item)
            start += len(items)
            if not items or start >= int(data.get("totalResults") or 0):
                complete = True
                break

        if complete:
            self._cache.set(key, [r.model_dump() for r in records], self._ttl)
        else:
            logger.warning("NVD results for %s truncated at %d records; not cached", base, start)
        return records

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        delay = min(self._backoff_max, self._backoff_base * (2**attempt))
        if retry_after:
            try:
                delay = max(delay, min(float(retry_after), self._backoff_max))
            except ValueError:
                pass
        return delay

    def _request(self, query: str) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        last_error = "unknown error"
        for attempt in range(self._max_retries + 1):
            self._limiter.acquire()
            try:
                response = self._session.get(
                    self._base_url, params=query, headers=headers, timeout=self._timeout
                )
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                delay = self._backoff(attempt, None)
            else:
                if response.status_code == 200:
                    try:
                        return dict(response.json())
                    except ValueError as exc:
                        raise NvdError("NVD returned a response that is not valid JSON") from exc
                if response.status_code in RETRY_STATUSES:
                    last_error = f"HTTP {response.status_code}"
                    delay = self._backoff(attempt, response.headers.get("Retry-After"))
                else:
                    detail = response.headers.get("message") or ""
                    raise NvdError(
                        f"NVD request failed with HTTP {response.status_code}"
                        + (f": {detail}" if detail else ""),
                        status_code=response.status_code,
                    )
            if attempt == self._max_retries:
                break
            logger.warning("NVD request failed (%s); retrying in %.1fs", last_error, delay)
            self._sleep(delay)
        raise NvdError(f"NVD request failed after {self._max_retries + 1} attempts ({last_error})")