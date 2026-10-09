"""Tests for SqliteCache and cache locations."""

from pathlib import Path

from kubeguard.integrations.cache import (
    NullCache,
    SqliteCache,
    default_cache_dir,
    default_nvd_cache_path,
)
from tests.helpers import FakeClock


def test_roundtrip_and_overwrite() -> None:
    cache = SqliteCache()
    cache.set("k", {"a": [1, 2]}, 60)
    assert cache.get("k") == {"a": [1, 2]}
    cache.set("k", [3], 60)
    assert cache.get("k") == [3]
    assert cache.get("missing") is None


def test_ttl_expiry() -> None:
    clock = FakeClock()
    cache = SqliteCache(clock=clock.time)
    cache.set("k", "v", 10)
    clock.now = 9.9
    assert cache.get("k") == "v"
    clock.now = 10.0
    assert cache.get("k") is None


def test_empty_list_is_a_hit() -> None:
    cache = SqliteCache()
    cache.set("k", [], 60)
    assert cache.get("k") == []


def test_purge_expired() -> None:
    clock = FakeClock()
    cache = SqliteCache(clock=clock.time)
    cache.set("old", 1, 5)
    cache.set("new", 2, 100)
    clock.now = 50
    assert cache.purge_expired() == 1
    assert cache.get("new") == 2


def test_persists_across_instances_and_creates_parent_dir(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "nvd.db"
    with SqliteCache(path) as first:
        first.set("k", "v", 3600)
    with SqliteCache(path) as second:
        assert second.get("k") == "v"


def test_unserialisable_value_is_not_fatal() -> None:
    cache = SqliteCache()
    cache.set("k", object(), 60)  # logged, ignored
    assert cache.get("k") is None


def test_null_cache() -> None:
    cache = NullCache()
    cache.set("k", "v", 60)
    assert cache.get("k") is None


class TestCacheLocations:
    def test_override_wins(self) -> None:
        env = {"KUBEGUARD_CACHE_DIR": "/custom/dir", "LOCALAPPDATA": "C:/ignored"}
        assert default_cache_dir(env, "win32") == Path("/custom/dir")

    def test_windows_uses_localappdata(self) -> None:
        env = {"LOCALAPPDATA": "C:/Users/me/AppData/Local"}
        assert default_nvd_cache_path(env, "win32") == (
            Path("C:/Users/me/AppData/Local") / "kubeguard" / "nvd.db"
        )

    def test_windows_without_localappdata_falls_back_to_home(self) -> None:
        path = default_cache_dir({}, "win32")
        assert path == Path.home() / "AppData" / "Local" / "kubeguard"

    def test_unix_default(self) -> None:
        assert default_nvd_cache_path({}, "linux") == Path.home() / ".cache" / "kubeguard" / "nvd.db"
        assert default_cache_dir({}, "darwin") == Path.home() / ".cache" / "kubeguard"