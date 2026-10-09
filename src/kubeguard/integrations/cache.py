"""SQLite-backed TTL cache and default cache locations."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


def default_cache_dir(env: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """Cache directory: ``KUBEGUARD_CACHE_DIR``, else per-platform default.

    Windows: ``%LOCALAPPDATA%\\kubeguard``; elsewhere: ``~/.cache/kubeguard``.
    """
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    override = env.get("KUBEGUARD_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if platform == "win32":
        local = env.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        return base / "kubeguard"
    return Path.home() / ".cache" / "kubeguard"


def default_nvd_cache_path(env: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """Path of the NVD cache database."""
    return default_cache_dir(env, platform) / "nvd.db"


class Cache(Protocol):
    """Minimal cache interface (JSON-serialisable values; ``None`` is never stored)."""

    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl_seconds: float) -> None: ...


class NullCache:
    """A cache that stores nothing (used for ``--no-cache``)."""

    def get(self, key: str) -> Any | None:
        return None

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        return None


class SqliteCache:
    """Thread-safe SQLite TTL cache. Cache failures degrade to misses, never crash a scan."""

    def __init__(self, path: str | Path = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        in_memory = str(path) == ":memory:"
        if not in_memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), timeout=10, check_same_thread=False)
        with self._lock, self._conn:
            if not in_memory:
                try:
                    self._conn.execute("PRAGMA journal_mode=WAL")
                except sqlite3.Error:
                    logger.debug("WAL mode unavailable for %s", path)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at REAL NOT NULL)"
            )

    def get(self, key: str) -> Any | None:
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return None
                if row[1] <= self._clock():
                    with self._conn:
                        self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    return None
                return json.loads(row[0])
        except (sqlite3.Error, ValueError) as exc:
            logger.warning("Cache read failed for %s: %s", key, exc)
            return None

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        try:
            payload = json.dumps(value)
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                    (key, payload, self._clock() + ttl_seconds),
                )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            logger.warning("Cache write failed for %s: %s", key, exc)

    def purge_expired(self) -> int:
        """Delete expired rows; returns how many were removed."""
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM cache WHERE expires_at <= ?", (self._clock(),))
            return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> SqliteCache:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()