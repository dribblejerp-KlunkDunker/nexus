"""
NEXUS Corpus Builder v2 - Leak-Free Training Data

Replaces the synthetic-benign corpus in train_for_real.py, which produced a
detector that scored ~50% of real home traffic as hostile.

Three changes over v1:

1. THE BENIGN CLASS IS REAL TRAFFIC ONLY.
   v1 generated benign packets with ttl in {64, 128}. Real inbound packets
   arrive decremented (48-54 after a dozen hops) -- the same band v1 used for
   attacks. The genome learned `|ttl - 64| large -> attack`. Benign now comes
   exclusively from captured pcaps.

2. ATTACKS ARE INJECTED INTO A SHARED TIMELINE.
   PacketFeatureExtractor derives inter_arrival_time and stream_rate from the
   previous packet *on the interface*. v1 extracted attacks from a pure attack
   pcap written back-to-back, so every attack packet carried delta_t ~ 0.0002
   against 0.088 for real traffic -- a second free label. Attack packets are
   now scheduled onto the benign capture's real timeline at per-class rates,
   which is what the sensor actually sees in production.

3. THE HOLDOUT IS A LATER TIME WINDOW.
   v1 split one generated pool 80/20, so the holdout came from the same
   generator as training and validated nothing. Each real capture is now cut on
   its own timeline -- early portion trains, later portion validates -- which
   keeps both captured rate regimes on both sides while leaving the holdout
   traffic the evolver has never seen.

Output: data/corpus_v2.npz with X_train/y_train, X_val/y_val, feature names,
and the provenance of every source file.
"""

import os
import sys
import json
import random
import argparse
from typing import List, Tuple

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, FEATURE_NAMES_20

CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
BOLD = "\033[1m"; RESET = "\033[0m"

# Real captures, split temporally rather than by file.
#
# The two available captures are entirely different regimes:
#   continuous_baseline.pcap   19522 pkts / 57839s =  0.3 pps  (16h background)
#   home_live_baseline.pcap     2163 pkts /    60s = 36.1 pps  (60s burst)
#
# Training on one and validating on the other shifts inter_arrival_time and
# stream_rate by two orders of magnitude between the splits, which is what left
# the volumetric specialist at ~2% TPR: it learned a 0.3pps world and was
# graded on a 36pps one. Each capture is instead cut on its own timeline, early
# portion to train and late portion to holdout, so both regimes appear on both
# sides and the holdout is still traffic the evolver has never seen.
# Every real capture in these locations is used. Globbed rather than listed so a
# new capture dropped in by the daily routine is picked up without editing code.
BENIGN_GLOBS = ["data/normal_traffic/*.pcap", "data/captures/*.pcap", "data/continuous_baseline.pcap"]
TRAIN_FRACTION = 0.70


def _looks_synthetic(pkts):
    """Heuristic guard against a generated benign capture rejoining the pool.

    Returns a reason string, or None if the capture looks genuinely captured.

    Two independent signals, because a generated file with a handful of real
    packets prepended defeats either one alone (the first version of this check
    tested only that the TTL SET was a subset of {64,128}, and massive_normal.pcap
    -- 2500 generated packets plus 150 live ones -- sailed through):

      TTL concentration. Scapy defaults to ttl=64 and generators pick from a
      short literal list. Real traffic arrives decremented across many hops, so
      a capture with >=95% of packets at just 64/128 was not routed.

      No idle periods. wrpcap() stamps packets at write time when the generator
      never set .time, so the gaps are a tight write-loop band with no tail. Real
      captures are bursty: sub-millisecond gaps inside a burst AND long idle
      stretches between them. The 99th-percentile gap separates the two cleanly:

          home_live_baseline.pcap   (real, 36pps)   p99 = 260ms
          continuous_baseline.pcap  (real, 0.3pps)  p99 = 9.8s
          massive_normal.pcap       (generated)     p99 = 1.5ms
          synflood_portscan.pcap    (generated)     p99 = 3.0ms
          massive_attacks.pcap      (generated)     p99 = 1.4ms

      Median gap alone does NOT work and was the first version of this check: a
      real 36pps capture has a 90us median and was wrongly rejected by it.
    """
    from scapy.all import IP
    sample = pkts[:5000]
    ttls = [p[IP].ttl for p in sample if p.haslayer(IP)]
    if ttls:
        concentrated = sum(1 for t in ttls if t in (64, 128)) / len(ttls)
        if concentrated >= 0.95:
            return (f"{concentrated*100:.0f}% of packets have TTL 64 or 128 -- generated, "
                    f"not routed (real captures show decremented hop counts)")

    times = sorted(float(p.time) for p in sample)
    if len(times) > 100:
        p99 = float(np.percentile(np.diff(times), 99))
        if p99 < 0.050:
            return (f"99th-percentile inter-arrival only {p99*1e3:.1f}ms -- no idle periods, "
                    f"so these are wrpcap write-time stamps rather than capture timestamps")
    return None


def discover_benign_pcaps(base_dir: str = ".") -> List[str]:
    """Real captures, with anything that looks generated excluded and named."""
    import glob as _glob
    from scapy.all import rdpcap
    found, rejected = [], []
    for pattern in BENIGN_GLOBS:
        for path in sorted(_glob.glob(os.path.join(base_dir, pattern))):
            rel = os.path.relpath(path, base_dir)
            try:
                pkts = rdpcap(path)
            except Exception as e:
                rejected.append((rel, f"unreadable: {e}"))
                continue
            if len(pkts) < 50:
                rejected.append((rel, f"only {len(pkts)} packets"))
                continue
            why = _looks_synthetic(pkts)
            if why:
                rejected.append((rel, why))
                continue
            found.append(rel)
    if rejected:
        print(f"{YELLOW}  Excluded from the benign pool:{RESET}")
        for rel, why in rejected:
            print(f"{YELLOW}    {rel}: {why}{RESET}")
    return found

# Per-class mean inter-arrival in seconds, i.e. how fast this attack actually
# arrives at the sensor. A slow beacon must not be learnable by its rate.
ATTACK_PROFILES = {
    "syn_flood":     {"gap": 0.0008, "burst": (40, 200)},
    "stealth_scan":  {"gap": 0.015,  "burst": (8, 40)},
    "exploit":       {"gap": 0.25,   "burst": (1, 4)},
    "brute_force":   {"gap": 0.08,   "burst": (4, 20)},
    "rst_injection": {"gap": 0.4,    "burst": (1, 3)},
    "c2_beacon":     {"gap": 8.0,    "burst": (1, 2)},
    "exfiltration":  {"gap": 0.004,  "burst": (20, 120)},
    "cryptomining":  {"gap": 3.0,    "burst": (1, 3)},
    "worm_lateral":  {"gap": 0.01,   "burst": (10, 60)},
    "dropper":       {"gap": 0.02,   "burst": (5, 30)},
}


# Locally-administered placeholder MACs for every generated packet. Without
# them scapy resolves the Ethernet source against this machine's default
# interface at packet-construction time; on some hosts (e.g. a captured-only
# NPF_Loopback default) that resolution raises and the corpus build dies.
# Nothing in the 20-D feature space reads MACs, so the placeholders only make
# the generator environment-independent.
GEN_MAC = "02:de:ad:be:ef:01"
LOC_MAC = "02:de:ad:be:ef:02"


def _attacker_pool(base_dir: str) -> List[str]:
    """Real C2 addresses from the abuse.ch cache when present."""
    ti = os.path.join(base_dir, "data", "threat_intel_cache.json")
    if os.path.exists(ti):
        try:
            with open(ti, "r", encoding="utf-8") as f:
                ips = list(json.load(f).get("ips", {}).keys())
            if ips:
                return ips
        except Exception:
            pass
    return [f"185.220.{random.randint(10, 250)}.{random.randint(1, 254)}" for _ in range(50)]


def build_attack_packet(kind: str, attackers: List[str], target: str, src_ip: str = None):
    """One attack packet of the given class.

    TTLs deliberately span the same range real inbound traffic occupies, so TTL
    alone cannot separate the classes. External attack sources get externally
    plausible TTLs; nothing is pinned to a value the benign class never shows.
    """
    from scapy.all import Ether, IP, TCP, Raw

    # One source per burst, not per packet. Choosing a fresh random attacker for
    # every packet gave each hostile IP a single packet in the corpus, which made
    # it impossible to evaluate any per-IP evidence rule: a real scanner sends
    # hundreds of probes from one address, and that repetition is the signal a
    # k-of-n blocking rule depends on.
    src = src_ip or random.choice(attackers)
    ext_ttl = random.choice([46, 48, 50, 51, 52, 53, 54, 57, 64, 117, 118, 128])
    # Source ports must look like a real stack's ephemeral range. Drawing them
    # from 1024-65535 while real traffic sits in 32768-65535 left src_port as
    # the single strongest feature in the trained model (65pp permutation
    # impact) -- a property of the generator, not of attacks.
    eph = lambda: random.randint(32768, 60999)

    if kind == "syn_flood":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([80, 443, 22, 3389, 445]),
            flags="S", window=random.choice([1024, 8192, 14600, 29200]),
            seq=random.randint(1000, 99999), ack=0)

    if kind == "stealth_scan":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.randint(1, 1024),
            flags=random.choice(["FPU", 0, "F", "SF"]), window=random.choice([0, 1024]))

    if kind == "exploit":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([80, 8080, 445]),
            flags="PA", window=random.choice([1024, 14600, 64240]))/Raw(
            load=bytes(random.randint(0, 255) for _ in range(random.randint(128, 800))))

    if kind == "brute_force":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([22, 3389]),
            flags="S", window=14600)/Raw(load=b"SSH-2.0-OpenSSH_7.4\r\n")

    if kind == "rst_injection":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([80, 443]),
            flags="R", seq=99999999, window=0)

    if kind == "c2_beacon":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([8443, 8000, 4444, 8888, 9001]),
            flags="PA", window=random.choice([1024, 2048, 4096, 64240]))/Raw(
            load=bytes(random.randint(0, 255) for _ in range(random.randint(48, 128))))

    # Outbound classes. v1 sourced these from 192.168.1.50, which the runtime
    # whitelist bypasses (192.168.0.0/16), so they were trained on and then
    # never evaluated in production. They now use the capture's real local
    # subnet and are excluded from the src-IP whitelist check at scoring time.
    if kind == "exfiltration":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=target, dst=random.choice(attackers), ttl=64)/TCP(
            sport=eph(), dport=random.choice([443, 8080, 14432, 2083]),
            flags="PA", window=64240)/Raw(
            load=bytes(random.randint(0, 255) for _ in range(random.randint(1300, 1460))))

    if kind == "cryptomining":
        stratum = [
            b'{"id":1,"jsonrpc":"2.0","method":"mining.submit","params":["miner1","0x1a2b","0xabcd1234"]}\n',
            b'{"id":2,"jsonrpc":"2.0","method":"mining.subscribe","params":["XMRig/6.18.0",null]}\n',
            b'{"id":3,"jsonrpc":"2.0","method":"mining.authorize","params":["wallet.worker1","x"]}\n',
        ]
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=target, dst=random.choice(attackers), ttl=64)/TCP(
            sport=eph(), dport=random.choice([3333, 4444, 5555, 7777]),
            flags="PA", window=29200)/Raw(load=random.choice(stratum))

    if kind == "worm_lateral":
        return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
            sport=eph(), dport=random.choice([445, 3389, 139]),
            flags="S", window=random.choice([8192, 16384, 64240]), seq=random.randint(100, 50000))

    # dropper
    magic = random.choice([
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
        b"This program cannot be run in DOS mode.",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
    ])
    return Ether(src=GEN_MAC, dst=LOC_MAC)/IP(src=src, dst=target, ttl=ext_ttl)/TCP(
        sport=random.choice([80, 8080, 8000]), dport=eph(),
        flags="PA", window=65535)/Raw(
        load=magic + bytes(random.randint(0, 255) for _ in range(random.randint(500, 1200))))


def local_host_of(pkts) -> str:
    """Most frequent RFC1918 source in the capture: the machine being defended."""
    from scapy.all import IP
    import ipaddress
    from collections import Counter
    c = Counter()
    for p in pkts:
        if p.haslayer(IP):
            try:
                if ipaddress.ip_address(p[IP].src).is_private:
                    c[p[IP].src] += 1
            except ValueError:
                pass
    return c.most_common(1)[0][0] if c else "192.168.1.50"


def _inject_attacks(benign, attacks_per_class, attackers, target, rate_scale):
    """Schedule attack bursts inside the benign capture's own time window.

    Bursts are clamped to the window. Without the clamp, a slow class (an 8s
    beacon x 300 packets = 2400s of timeline) runs off the end of a short
    capture into empty time, and every one of those packets picks up a huge
    inter-arrival gap that the model can read as a label.
    """
    t0, t1 = float(benign[0].time), float(benign[-1].time)
    span = max(1.0, t1 - t0)
    out = []
    for kind, prof in ATTACK_PROFILES.items():
        gap = prof["gap"] * rate_scale
        made, guard = 0, 0
        while made < attacks_per_class and guard < attacks_per_class * 50:
            guard += 1
            burst = min(random.randint(*prof["burst"]), attacks_per_class - made)
            t = t0 + random.uniform(0.0, span * 0.98)
            burst_src = random.choice(attackers)
            for _ in range(burst):
                t += max(1e-6, random.expovariate(1.0 / gap))
                if t > t1:
                    break
                p = build_attack_packet(kind, attackers, target, src_ip=burst_src)
                p.time = t
                out.append(p)
                made += 1
    return out


def build_split(base_dir: str = ".", attacks_per_split: int = 300, seed: int = 0):
    """Temporal split of every benign capture, with attacks injected per side."""
    from scapy.all import rdpcap

    random.seed(seed)
    np.random.seed(seed)
    attackers = _attacker_pool(base_dir)
    halves = {"train": [], "val": []}

    for path in discover_benign_pcaps(base_dir):
        full = os.path.join(base_dir, path)
        if not os.path.exists(full):
            print(f"{YELLOW}  [warn] missing benign capture: {path}{RESET}")
            continue
        pkts = sorted(rdpcap(full), key=lambda p: float(p.time))
        cut = int(len(pkts) * TRAIN_FRACTION)
        target = local_host_of(pkts)
        t0, t1 = float(pkts[0].time), float(pkts[-1].time)
        pps = len(pkts) / max(1.0, t1 - t0)
        # Attack gaps are defined against a ~30pps reference link; on a much
        # quieter capture the same absolute gaps would make every attack the
        # fastest thing on the wire.
        rate_scale = float(np.clip(30.0 / max(0.05, pps), 0.2, 50.0))
        print(f"  {path:44s} {len(pkts):6d} pkts  {pps:7.2f} pps  "
              f"split {cut}/{len(pkts)-cut}  attack gap x{rate_scale:.1f}")
        for name, part, n_atk in (("train", pkts[:cut], attacks_per_split),
                                  ("val", pkts[cut:], max(40, attacks_per_split // 3))):
            if len(part) < 2:
                continue
            atk = _inject_attacks(part, n_atk, attackers, target, rate_scale)
            halves[name].extend([(float(p.time), 0, p) for p in part]
                                + [(float(p.time), 1, p) for p in atk])

    out = {}
    for name, merged in halves.items():
        merged.sort(key=lambda r: r[0])
        ex = PacketFeatureExtractor()
        X = np.empty((len(merged), 20), dtype=np.float32)
        y = np.empty(len(merged), dtype=np.int8)
        for i, (ts, label, pkt) in enumerate(merged):
            X[i] = ex.extract(pkt, current_time=ts, extended=True)
            y[i] = label
        out[name] = (X, y)
    return out["train"], out["val"]


def audit_leaks(X: np.ndarray, y: np.ndarray, top: int = 6):
    """Single-feature separability. A feature near 1.00 AUC is a shortcut, not a signal."""
    print(f"\n{BOLD}Single-feature AUC (1.00 = this feature alone is the label){RESET}")
    n_pos, n_neg = int(y.sum()), int((y == 0).sum())
    aucs = []
    for i, name in enumerate(FEATURE_NAMES_20):
        order = np.argsort(X[:, i], kind="mergesort")
        ranks = np.empty(len(y), dtype=np.float64)
        ranks[order] = np.arange(1, len(y) + 1)
        auc = (ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
        aucs.append((max(auc, 1 - auc), name, auc))
    for strength, name, auc in sorted(aucs, reverse=True)[:top]:
        flag = f"{RED}  <-- SHORTCUT{RESET}" if strength > 0.95 else (
               f"{YELLOW}  <-- strong{RESET}" if strength > 0.85 else "")
        print(f"  {name:20s} AUC {auc:.3f}{flag}")
    return dict((n, a) for _, n, a in aucs)


def audit_baseline_diversity(benign_pkts_summary):
    """Warn when the benign baseline is too narrow to teach the model much.

    A detector can only learn "normal" as wide as the traffic it was shown. If
    the baseline is all HTTPS and DNS to a handful of CDNs, the model has never
    seen legitimate high-source-port traffic (P2P, games, WebRTC, VoIP) and will
    happily flag it in production. Permutation importance on the first honest
    run showed exactly this: src_port carried ~79pp of the decision.
    """
    ports, hosts, total = benign_pkts_summary
    print(f"\n{BOLD}Baseline diversity{RESET}")
    top = ports.most_common(3)
    covered = sum(c for _, c in top) / max(1, total)
    print(f"  distinct remote hosts: {len(hosts)}")
    print(f"  top 3 service ports cover {covered*100:.0f}% of benign traffic: "
          + ", ".join(f"{p}({c})" for p, c in top))
    if covered > 0.85 or len(hosts) < 40:
        print(f"{YELLOW}  NARROW BASELINE. The model will have no idea what benign traffic on"
              f"\n  other ports looks like, and is likely to lean on port and TTL alone."
              f"\n  Capture while gaming, on a video call, over P2P or VPN, and rebuild.{RESET}")
    else:
        print(f"{GREEN}  Baseline spans a reasonable spread of services.{RESET}")


def main():
    ap = argparse.ArgumentParser(description="NEXUS leak-free corpus builder")
    ap.add_argument("--attacks-per-class", type=int, default=300)
    ap.add_argument("--out", type=str, default="data/corpus_v2.npz")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    print(f"{BOLD}{CYAN}--- NEXUS Corpus v2: real benign, timeline-injected attacks ---{RESET}\n")
    (X_tr, y_tr), (X_va, y_va) = build_split(attacks_per_split=args.attacks_per_class, seed=args.seed)

    print(f"\n  train: {len(y_tr):6d} vectors  ({int((y_tr==0).sum())} benign / {int(y_tr.sum())} attack)")
    print(f"  val:   {len(y_va):6d} vectors  ({int((y_va==0).sum())} benign / {int(y_va.sum())} attack)")

    audit_leaks(X_tr, y_tr)

    from collections import Counter
    from scapy.all import rdpcap, IP, TCP
    ports, hosts, total = Counter(), set(), 0
    for path in discover_benign_pcaps():  # default base_dir="." — the NameError
        full = os.path.join(".", path)
        if not os.path.exists(full):
            continue
        for p in rdpcap(full):
            if p.haslayer(TCP):
                ports[min(p[TCP].sport, p[TCP].dport)] += 1
                total += 1
            if p.haslayer(IP):
                hosts.add(p[IP].dst)
    audit_baseline_diversity((ports, hosts, total))

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    np.savez_compressed(
        args.out,
        X_train=X_tr, y_train=y_tr, X_val=X_va, y_val=y_va,
        feature_names=np.array(FEATURE_NAMES_20),
        benign_sources=np.array(discover_benign_pcaps()),
        train_fraction=np.array([TRAIN_FRACTION]),
    )
    print(f"\n{GREEN}Wrote {args.out}{RESET}")


if __name__ == "__main__":
    main()
