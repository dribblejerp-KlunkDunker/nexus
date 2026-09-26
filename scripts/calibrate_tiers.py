"""
NEXUS Tier Calibration

Chooses the block tier's (k, W) from measurement rather than intuition, by
replaying real captures and injected attacks through the actual champion and the
actual EvidenceTracker.

Two quantities decide it:

  COST   benign hosts firewalled per 24h, from the real captures with no attack
         traffic present. This must be zero. A single legitimate host in the
         firewall is a support call to yourself at 2am.

  BENEFIT attacker hosts caught, per attack class, from attacks injected into a
         held-out window. Reported per class because the classes differ in kind:
         a flood is inherently repetitive and a lone exploit packet is not.

The smallest (k, W) with zero benign blocks wins -- smallest because every extra
packet of required evidence is another packet the attacker gets to send first.

Run after every retrain. The champion changes what gets flagged, so the tier
parameters are only valid for the champion they were measured against.
"""

import argparse
import os
import pickle
import random
import sys
from collections import defaultdict
from datetime import datetime

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neat_vectorized import activate_batch
from feature_extractor import PacketFeatureExtractor
from council_arbiter import THREAT_THRESHOLD
from whitelist_manager import WhitelistManager
from decision_engine import EvidenceTracker, write_config
import build_corpus_v2 as B

CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
BOLD = "\033[1m"; RESET = "\033[0m"

def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# (k, W) grid, smallest evidence requirement first.
CANDIDATE_RULES = [
    (1, 0.0), (2, 5.0), (3, 10.0), (3, 60.0),
    (5, 10.0), (5, 60.0), (8, 30.0), (10, 60.0), (20, 300.0),
]


def make_scorer(champion, use_council: bool):
    """Returns a function scoring a feature matrix exactly as the runtime does.

    This has to match sniff_and_respond.py's scoring path or the calibration is
    worthless. Calibrating against the monolith while the runtime scores with the
    council is how a rule measured at "zero benign blocks" firewalled four real
    hosts on replay: the council's false positive rate is higher than the
    monolith's (1.25% vs 0.95% on this capture), so it crosses the block
    threshold on sources the monolith never would.
    """
    if use_council:
        from council_arbiter import CouncilArbiter
        arb = CouncilArbiter()
        if arb.active_mode == "MOE_COUNCIL":
            print(f"  scorer: council ({arb.active_mode}) -- matches the live responder")
            return lambda X: np.array([arb.evaluate(x.astype(np.float32))["is_threat"]
                                       for x in X], dtype=bool)
        print(f"{YELLOW}  council unavailable ({arb.active_mode}); scoring with monolith{RESET}")
    print("  scorer: monolithic champion")
    return lambda X: activate_batch(champion["genome"], champion["config"], X) >= THREAT_THRESHOLD


def score_packets(scorer, pkts, extractor=None):
    """Flag decisions and per-packet metadata for a time-ordered packet list."""
    from scapy.all import IP
    ex = extractor or PacketFeatureExtractor()
    rows = [(float(p.time), p) for p in pkts if p.haslayer(IP)]
    rows.sort(key=lambda r: r[0])
    if not rows:
        return np.array([]), np.array([]), np.array([])
    X = np.array([ex.extract(p, current_time=t, extended=True) for t, p in rows],
                 dtype=np.float64)
    ts = np.array([t for t, _ in rows])
    src = np.array([p[IP].src for _, p in rows])
    return scorer(X), ts, src


def replay(flag, ts, src, k, W, skip=None):
    """Sources the tracker would BLOCK under rule (k, W), in arrival order."""
    tracker = EvidenceTracker(config={"block_min_events": k, "block_window_sec": max(W, 1e-9)})
    blocked = set()
    for i in np.where(flag)[0]:
        s = src[i]
        if skip is not None and skip(s):
            continue
        if tracker.record(s, now=float(ts[i])).should_block:
            blocked.add(s)
    return blocked


def main():
    ap = argparse.ArgumentParser(description="Calibrate NEXUS block-tier parameters")
    ap.add_argument("--champion", default="genomes/champion.pkl")
    ap.add_argument("--out", default="config/tiers.json")
    ap.add_argument("--attacks-per-class", type=int, default=150)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--write", action="store_true",
                    help="Write the chosen rule to --out (otherwise report only)")
    ap.add_argument("--monolith-only", action="store_true",
                    help="Score with the monolith instead of the council. Only correct if "
                         "the live responder is also run with --no-council.")
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    from scapy.all import rdpcap
    with open(args.champion, "rb") as f:
        champion = pickle.load(f)
    wl = WhitelistManager("config/whitelist.json")

    print(f"{BOLD}{CYAN}=========== NEXUS TIER CALIBRATION ==========={RESET}")
    print(f"  champion: {args.champion}")
    print(f"  operating point: {THREAT_THRESHOLD}")
    scorer = make_scorer(champion, use_council=not args.monolith_only)
    print()

    # ---- COST: benign captures, no attacks present -------------------------
    print(f"{BOLD}Cost: benign hosts firewalled per 24h (real captures, no attacks){RESET}")
    cost = defaultdict(float)
    total_hours = 0.0
    for path in B.discover_benign_pcaps("."):
        if not os.path.exists(path):
            print(f"{YELLOW}  [skip] missing {path}{RESET}")
            continue
        pkts = list(rdpcap(path))
        flag, ts, src = score_packets(scorer, pkts)
        if len(ts) == 0:
            continue
        hours = (ts[-1] - ts[0]) / 3600.0
        total_hours += hours
        days = max(hours / 24.0, 1e-9)
        skip = lambda ip: wl.is_whitelisted(src_ip=ip)[0]
        print(f"  {os.path.basename(path):34s} {len(ts):6d} pkts  {hours:5.1f}h  "
              f"packet FPR {flag.mean()*100:5.2f}%")
        for k, W in CANDIDATE_RULES:
            cost[(k, W)] += len(replay(flag, ts, src, k, W, skip)) / days
    print(f"  total benign observation: {total_hours:.1f}h\n")

    # ---- BENEFIT: attacks injected into the held-out window ----------------
    print(f"{BOLD}Benefit: attacker hosts caught, by class (held-out window){RESET}")
    ref = next(iter(B.discover_benign_pcaps(".")), None)
    if ref is None:
        print(f"{RED}  No benign capture available; cannot calibrate.{RESET}")
        return
    base = sorted(rdpcap(ref), key=lambda p: float(p.time))
    holdout = base[int(len(base) * B.TRAIN_FRACTION):]
    attackers = B._attacker_pool(".")
    target = B.local_host_of(base)

    benefit = defaultdict(lambda: defaultdict(lambda: (0, 0)))
    all_profiles = B.ATTACK_PROFILES
    for kind, prof in all_profiles.items():
        B.ATTACK_PROFILES = {kind: prof}
        atk = B._inject_attacks(holdout, args.attacks_per_class, attackers, target, 0.8)
        B.ATTACK_PROFILES = all_profiles
        if not atk:
            continue
        flag, ts, src = score_packets(scorer, holdout + atk)
        from scapy.all import IP
        hostile = {p[IP].src for p in atk if p.haslayer(IP)}
        mask = np.isin(src, list(hostile))
        for k, W in CANDIDATE_RULES:
            caught = replay(flag[mask], ts[mask], src[mask], k, W)
            benefit[(k, W)][kind] = (len(caught), len(hostile))

    # ---- Report ------------------------------------------------------------
    hi_vol = ["syn_flood", "stealth_scan", "worm_lateral", "brute_force",
              "dropper", "exfiltration", "cryptomining"]
    print(f"\n{BOLD}{'rule':>12s}{'benign/24h':>12s}{'high-volume classes caught':>30s}{'':4s}verdict{RESET}")
    viable = []
    for k, W in CANDIDATE_RULES:
        c = cost[(k, W)]
        got = sum(benefit[(k, W)].get(x, (0, 0))[0] for x in hi_vol)
        tot = sum(benefit[(k, W)].get(x, (0, 0))[1] for x in hi_vol)
        pct = 100.0 * got / max(1, tot)
        ok = (c == 0.0)
        if ok:
            viable.append((k, W, pct))
        tag = f"{GREEN}zero false blocks{RESET}" if ok else f"{RED}blocks real hosts{RESET}"
        print(f"  k={k:<3d} W={W:<5g}{c:12.2f}{got:>18d}/{tot:<4d} ({pct:3.0f}%)  {tag}")

    if not viable:
        print(f"\n{RED}{BOLD}  No rule reaches zero false blocks. Do not arm blocking.{RESET}")
        print(f"{YELLOW}  The champion is flagging benign traffic too persistently for any"
              f"\n  aggregation window to filter. Retrain on more diverse captures first.{RESET}")
        return

    # Smallest evidence requirement that is free of false blocks, preferring
    # higher detection to break ties at equal k.
    viable.sort(key=lambda r: (r[0], r[1], -r[2]))
    k, W, pct = viable[0]
    print(f"\n{GREEN}{BOLD}  CHOSEN: k={k} within {W:g}s "
          f"-- zero benign blocks, {pct:.0f}% of high-volume attacker hosts caught{RESET}")

    low_vol = [x for x in all_profiles if x not in hi_vol]
    print(f"\n{BOLD}  Alert-only classes under this rule (block tier cannot confirm them):{RESET}")
    for kind in low_vol:
        got, tot = benefit[(k, W)].get(kind, (0, 0))
        print(f"    {kind:16s} {got}/{tot} attacker hosts would be blocked "
              f"-- the rest raise standing alerts")

    if args.write:
        write_config(args.out, k, W, {
            "calibrated": datetime.now().isoformat(),
            "champion": args.champion,
            # The hash is what lets ops_audit.py prove this calibration belongs to
            # the champion that is actually installed. A rule measured for a
            # different model is worse than no rule, because it looks valid.
            "champion_sha256": _sha256(args.champion),
            "scorer": "monolith" if args.monolith_only else "council",
            "operating_point": THREAT_THRESHOLD,
            "benign_observation_hours": round(total_hours, 2),
            "benign_blocks_per_24h": 0.0,
            "high_volume_hosts_caught_pct": round(pct, 1),
            "note": "Valid only for this champion. Re-run after every retrain.",
        })
        print(f"\n{GREEN}  wrote {args.out}{RESET}")
    else:
        print(f"\n{YELLOW}  Report only. Pass --write to save this rule to {args.out}.{RESET}")


if __name__ == "__main__":
    main()
