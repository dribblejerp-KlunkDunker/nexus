"""Unit tests for the lock-guarded ban store (banstore.py)."""

import threading
import time

import pytest

import banstore
import policy


@pytest.fixture()
def store():
    return banstore.BanStore(ttl_sec=30.0, clock=lambda: 1000.0)


def test_add_and_get_roundtrip(store):
    rec = store.add("203.0.113.7", {"score": 0.91})
    assert rec["expire_ts"] == 1030.0
    assert store.get("203.0.113.7")["score"] == 0.91


def test_default_ttl_is_policy_ttl():
    s = banstore.BanStore(clock=lambda: 0.0)
    s.add("203.0.113.7", {})
    assert s.get("203.0.113.7")["expire_ts"] == policy.BAN_TTL_SEC


def test_records_are_copies(store):
    store.add("203.0.113.7", {"score": 0.91})
    got = store.get("203.0.113.7")
    got["score"] = 0.01
    assert store.get("203.0.113.7")["score"] == 0.91
    snap = store.active()
    snap["203.0.113.7"]["score"] = 0.0
    assert store.get("203.0.113.7")["score"] == 0.91


def test_readd_refreshes_not_duplicates(store):
    store.add("203.0.113.7", {"score": 0.91})
    store.add("203.0.113.7", {"score": 0.99})
    assert store.count() == 1
    assert store.get("203.0.113.7")["score"] == 0.99


def test_expiry_reads_as_absent(store):
    store.add("203.0.113.7", {})
    store._clock = lambda: 1031.0  # past expiry
    assert store.get("203.0.113.7") is None
    assert store.count() == 0
    assert store.is_banned("203.0.113.7") is False


def test_sweep_returns_purged_count(store):
    store.add("203.0.113.7", {})
    store.add("198.51.100.9", {})
    store._clock = lambda: 2000.0
    assert store.sweep() == 2
    assert store.sweep() == 0


def test_remove_idempotent(store):
    store.add("203.0.113.7", {})
    assert store.remove("203.0.113.7") is True
    assert store.remove("203.0.113.7") is False


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0"])
def test_loopback_refused(store, ip):
    with pytest.raises(ValueError):
        store.add(ip, {"score": 1.0})


def test_invalid_ttl_refused(store):
    with pytest.raises(ValueError):
        store.add("203.0.113.7", {}, ttl_sec=0)
    with pytest.raises(ValueError):
        store.add("203.0.113.7", {}, ttl_sec=-5)


def test_concurrent_hammer_is_exception_free():
    t = [0.0]
    s = banstore.BanStore(ttl_sec=60.0, clock=lambda: t[0])
    errors = []

    def worker(tid):
        try:
            for i in range(300):
                ip = "203.0.113.%d" % ((tid * 7 + i) % 200 + 1)
                s.add(ip, {"n": i})
                if i % 3 == 0:
                    s.remove(ip)
                s.active()
                s.count()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    snap = s.active()
    assert all(r["expire_ts"] > t[0] for r in snap.values())
    assert len(snap) == s.count()


def test_policy_loopback_set_is_the_source():
    # banstore must defer to policy, not carry its own list.
    assert banstore.policy is policy
    assert policy.is_loopback_ip("0.0.0.0")
