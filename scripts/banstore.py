"""
NEXUS Ban Store
===============

The single, lock-guarded home for active IP bans.

Before this module the dashboard's ban table was a plain dict mutated from
three concurrency domains -- the live sniffer thread (adds), asyncio request
handlers (unban, status), and the SSE ticker (broadcast) -- with no lock. The
specific hazards in CPython: an `del` racing an `add` can raise KeyError in
the unban handler, and a status/broadcast snapshot taken mid-mutation can
raise "dictionary changed size during iteration" inside an SSE send, killing
an event stream. The guardian process keeps its own `banned_ips` dict with the
same exposure (see decision_engine notes).

Rules:
  * Every read/write goes through an RLock; snapshots are copied under it.
  * Expired entries are purged on access (add / get / active / sweep), so a
    ban can never outlive its TTL and an expired ban can never be observed.
  * Loopback / unspecified sources are refused at the door via policy.py --
    automated verdicts must never be able to ban the host itself.
  * Records are copied on the way in and on the way out: callers cannot mutate
    the store through a returned reference.

Self-test:
    python scripts/banstore.py
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional

import policy


class BanStore:
    """Thread-safe ban table with TTL expiry and loopback protection."""

    def __init__(self, ttl_sec: float = policy.BAN_TTL_SEC,
                 clock: Callable[[], float] = time.time):
        self._ttl = float(ttl_sec)
        self._clock = clock
        self._lock = threading.RLock()
        self._bans: Dict[str, dict] = {}

    # -- internal (call with lock held) -----------------------------------

    def _purge_expired_locked(self, now: Optional[float] = None) -> int:
        if now is None:
            now = self._clock()
        dead = [ip for ip, rec in self._bans.items()
                if float(rec.get("expire_ts", 0.0)) <= now]
        for ip in dead:
            del self._bans[ip]
        return len(dead)

    # -- public API ---------------------------------------------------------

    def add(self, ip: str, record: dict, ttl_sec: float = None) -> dict:
        """Insert or refresh a ban. Returns the stored record (a copy).

        Refuses loopback/unspecified sources (policy.LOOPBACK_IPS) with
        ValueError: an automated verdict never blocks the host itself.
        """
        if policy.is_loopback_ip(ip):
            raise ValueError(f"refusing to ban loopback/unspecified source {ip!r}")
        ttl = self._ttl if ttl_sec is None else float(ttl_sec)
        if ttl <= 0:
            raise ValueError("ttl_sec must be positive")
        now = self._clock()
        stored = dict(record or {})
        stored["expire_ts"] = now + ttl
        with self._lock:
            self._purge_expired_locked(now)
            self._bans[str(ip)] = stored
        return dict(stored)

    def remove(self, ip: str) -> bool:
        """Drop a ban. Returns True if it was present (expired counts as absent)."""
        with self._lock:
            self._purge_expired_locked()
            return self._bans.pop(str(ip), None) is not None

    def get(self, ip: str) -> Optional[dict]:
        """The live record for an IP, or None (expired bans read as absent)."""
        with self._lock:
            self._purge_expired_locked()
            rec = self._bans.get(str(ip))
            return dict(rec) if rec is not None else None

    def active(self) -> Dict[str, dict]:
        """Snapshot of all live bans (copies; safe to broadcast/serialize)."""
        with self._lock:
            self._purge_expired_locked()
            return {ip: dict(rec) for ip, rec in self._bans.items()}

    def is_banned(self, ip: str) -> bool:
        return self.get(ip) is not None

    def count(self) -> int:
        with self._lock:
            self._purge_expired_locked()
            return len(self._bans)

    def sweep(self) -> int:
        """Explicit expiry sweep; returns how many entries dropped."""
        with self._lock:
            return self._purge_expired_locked()


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _selftest() -> int:
    failures = []

    def check(name, cond):
        status = "PASS" if cond else "FAIL"
        print(f"  [{status}] {name}")
        if not cond:
            failures.append(name)

    print("NEXUS ban store self-test")
    t = [1000.0]                      # controllable clock

    store = BanStore(ttl_sec=30.0, clock=lambda: t[0])
    rec = store.add("203.0.113.7", {"score": 0.91, "country": "XX"})
    check("add returns record with expiry",
          rec["expire_ts"] == 1030.0 and rec["score"] == 0.91)
    check("count reflects one ban", store.count() == 1)

    stored = store.get("203.0.113.7")
    stored["score"] = 0.01
    check("returned record is a copy (store unaffected)",
          store.get("203.0.113.7")["score"] == 0.91)

    store.add("203.0.113.7", {"score": 0.99})
    check("re-add refreshes record", store.get("203.0.113.7")["score"] == 0.99)
    check("re-add keeps one entry", store.count() == 1)

    t[0] = 1031.0                     # past expiry
    check("expired ban reads as absent", store.get("203.0.113.7") is None)
    check("expired ban is purged", store.count() == 0)

    store.add("198.51.100.9", {"score": 0.87})
    t[0] = 1050.0                     # 19s in: still live
    check("live ban survives sweep", store.is_banned("198.51.100.9"))
    check("remove reports presence", store.remove("198.51.100.9") is True)
    check("remove is idempotent", store.remove("198.51.100.9") is False)

    for ip in ("127.0.0.1", "::1", "0.0.0.0"):
        try:
            store.add(ip, {"score": 1.0})
            check(f"loopback refused: {ip}", False)
        except ValueError:
            check(f"loopback refused: {ip}", True)

    # Concurrency hammer: parallel add/remove/read must be exception-free and
    # leave the store internally consistent.
    store2 = BanStore(ttl_sec=60.0, clock=lambda: t[0])
    errors = []

    def hammer(thread_id):
        try:
            for i in range(400):
                ip = f"203.0.113.{(thread_id * 7 + i) % 200 + 1}"
                store2.add(ip, {"n": i})
                if i % 3 == 0:
                    store2.remove(ip)
                store2.active()
                store2.count()
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    check("concurrent hammer exception-free", not errors)
    live = store2.active()
    check("post-hammer snapshot consistent",
          all(r.get("expire_ts", 0) > t[0] for r in live.values())
          and len(live) == store2.count())

    print()
    if failures:
        print(f"{len(failures)} FAILURES: {failures}")
        return 1
    print("All ban store self-tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
