from sc_scanner.cache import DiskCache


def test_returns_none_for_missing_key(tmp_path):
    cache = DiskCache(tmp_path)
    assert cache.get("missing") is None


def test_set_then_get_roundtrips_json_serializable_values(tmp_path):
    cache = DiskCache(tmp_path)
    cache.set("key", {"a": 1, "b": [1, 2, 3]})
    assert cache.get("key") == {"a": 1, "b": [1, 2, 3]}


def test_persists_across_separate_instances_pointed_at_the_same_directory(tmp_path):
    DiskCache(tmp_path).set("key", ["persisted"])
    assert DiskCache(tmp_path).get("key") == ["persisted"]


def test_creates_the_cache_directory_if_missing(tmp_path):
    cache_dir = tmp_path / "nested" / "cache"
    DiskCache(cache_dir)
    assert cache_dir.is_dir()


def test_distinguishes_uncached_from_a_cached_empty_list(tmp_path):
    cache = DiskCache(tmp_path)
    cache.set("no-vulns", [])
    assert cache.get("no-vulns") == []
    assert cache.get("never-queried") is None
