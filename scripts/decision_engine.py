"""
NEXUS Two-Tier Decision Engine

Why this exists
---------------
The detector was good; the decision rule was not. Blocking on a single packet's
score cannot be made safe, no matter how well the champion is trained, because
of the base rate. Measured on a real 16-hour capture with a champion at 0.00%
holdout FPR:

    packet FPR 0.97%  ->  after whitelist 0.23%
    extrapolated: 67 block events and 9.0 distinct REAL hosts
                  firewalled per 24 hours

Nine legitimate hosts a day. Cutting the model's FPR by 10x still leaves about
one a day, and a busy day carries 50-100x the packet volume of that capture.
Per-packet blocking is the wrong unit of decision.

Requiring repeated evidence from the same source fixes it outright. Measured on
the same capture:

    rule                    benign hosts firewalled / 24h
    k=1  (block on any)                  8.96
    k=3 within 60s                       2.99
    k=5 within 10s                       0.00
    k=10 within 60s                      0.00

And detection, by attacker IP, on injected attacks in the held-out window:

    class            k=1      k=5/10s
    syn_flood        2/2      2/2
    stealth_scan     6/6      6/6
    worm_lateral     5/5      5/5
    brute_force      12/12    10/12
    dropper          8/8      8/8
    exfiltration     1/1      1/1
    cryptomining     1/1      1/1
    exploit          57/59    2/59     <- single-packet by nature
    rst_injection    76/76    1/76     <- single-packet by nature
    c2_beacon        98/106   0/106    <- slow by nature

So: every high-volume class survives aggregation intact, at zero false blocks.
What aggregation cannot do is block on a one-off event -- and it should not try.
Those become alerts.

The two tiers
-------------
TIER 1 (BLOCK): k flagged packets from one source within W seconds. Acts on the
    firewall. Tuned so benign traffic never reaches it.
TIER 2 (ALERT): any flagged packet. Logs, webhooks, dashboard. Never touches the
    firewall.

A slow C2 beacon therefore produces a standing alert rather than a silent miss
or a reckless block. That is the honest handling of a signal this sensor can
see but cannot confirm.
"""

import json
import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

DEFAULT_CONFIG_PATH = "config/tiers.json"

# Conservative defaults, replaced by whatever calibrate_tiers.py measures on
# your own captures. Blocking thresholds should never be guesses.
DEFAULTS = {
    "block_min_events": 5,       # k
    "block_window_sec": 10.0,    # W
    "alert_min_events": 1,
    "evidence_ttl_sec": 300.0,   # forget a source that goes quiet this long
    "max_tracked_sources": 8192,
}


class TierDecision:
    """What the engine decided about one flagged packet."""

    __slots__ = ("tier", "source", "events_in_window", "window_sec", "reason")

    def __init__(self, tier: str, source: str, events_in_window: int,
                 window_sec: float, reason: str):
        self.tier = tier                      # "BLOCK" | "ALERT" | "NONE"
        self.source = source
        self.events_in_window = events_in_window
        self.window_sec = window_sec
        self.reason = reason

    @property
    def should_block(self) -> bool:
        return self.tier == "BLOCK"

    @property
    def should_alert(self) -> bool:
        return self.tier in ("BLOCK", "ALERT")

    def __repr__(self):
        return (f"TierDecision({self.tier} {self.source} "
                f"{self.events_in_window} events/{self.window_sec}s)")


class EvidenceTracker:
    """Sliding-window count of flagged packets per source address.

    Memory is bounded two ways: each source keeps only the timestamps inside its
    window, and sources idle past evidence_ttl_sec are dropped. A flood from
    spoofed addresses would otherwise grow this map without limit, which is
    itself a denial of service on the sensor.
    """

    def __init__(self, config: Optional[Dict] = None, config_path: str = DEFAULT_CONFIG_PATH):
        cfg = dict(DEFAULTS)
        loaded_from = "built-in defaults"
        if config is not None:
            cfg.update(config)
            loaded_from = "caller"
        elif os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    disk = json.load(f)
                cfg.update({k: v for k, v in disk.items() if k in DEFAULTS})
                loaded_from = config_path
            except Exception:
                pass

        self.k = int(cfg["block_min_events"])
        self.window = float(cfg["block_window_sec"])
        self.alert_k = int(cfg["alert_min_events"])
        self.ttl = float(cfg["evidence_ttl_sec"])
        self.max_sources = int(cfg["max_tracked_sources"])
        self.config_source = loaded_from

        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_seen: Dict[str, float] = {}
        self._blocked_at: Dict[str, float] = {}

    def describe(self) -> str:
        return (f"block tier: {self.k} flagged packets from one source within "
                f"{self.window:g}s | alert tier: {self.alert_k} | "
                f"evidence TTL {self.ttl:g}s | config from {self.config_source}")

    def _prune(self, now: float):
        """Drop sources that have gone quiet, and cap total tracked sources."""
        stale = [s for s, t in self._last_seen.items() if now - t > self.ttl]
        for s in stale:
            self._events.pop(s, None)
            self._last_seen.pop(s, None)

        if len(self._events) > self.max_sources:
            # Evict least-recently-seen first.
            ordered = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            for s, _ in ordered[: len(self._events) - self.max_sources]:
                self._events.pop(s, None)
                self._last_seen.pop(s, None)

    def record(self, source: str, now: Optional[float] = None) -> TierDecision:
        """Register one flagged packet from `source` and return the decision."""
        if now is None:
            now = time.time()

        q = self._events[source]
        q.append(now)
        self._last_seen[source] = now

        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()

        count = len(q)

        # Prune occasionally rather than every packet.
        if len(self._events) > 64 and int(now) % 17 == 0:
            self._prune(now)

        if count >= self.k:
            self._blocked_at[source] = now
            # Clearing the window stops one long burst from re-triggering a block
            # on every subsequent packet; the responder's own cooldown is a
            # second layer, not the only one.
            q.clear()
            return TierDecision(
                "BLOCK", source, count, self.window,
                f"{count} flagged packets within {self.window:g}s meets block threshold "
                f"of {self.k}")

        if count >= self.alert_k:
            return TierDecision(
                "ALERT", source, count, self.window,
                f"{count} flagged packet(s) within {self.window:g}s; below block "
                f"threshold of {self.k} -- alerting only, firewall untouched")

        return TierDecision("NONE", source, count, self.window, "below alert threshold")

    def stats(self) -> Dict:
        return {
            "tracked_sources": len(self._events),
            "sources_blocked": len(self._blocked_at),
            "block_min_events": self.k,
            "block_window_sec": self.window,
        }


def load_tracker(config_path: str = DEFAULT_CONFIG_PATH) -> EvidenceTracker:
    return EvidenceTracker(config_path=config_path)


def write_config(path: str, block_min_events: int, block_window_sec: float,
                 provenance: Dict) -> None:
    """Persist calibrated tier parameters with the evidence behind them."""
    cfg = dict(DEFAULTS)
    cfg["block_min_events"] = int(block_min_events)
    cfg["block_window_sec"] = float(block_window_sec)
    cfg["_provenance"] = provenance
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
