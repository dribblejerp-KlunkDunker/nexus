"""
NEXUS Regression Audit

A scheduled check that answers one question: is the thing currently installed
still as good as the thing that was measured? It re-measures rather than reading
a recorded number, because every serious defect this project has had was a
recorded number that no longer matched reality.

Checks, each PASS / WARN / FAIL with the measurement attached:

  1. CHAMPION FPR        Re-score every archived real capture with the champion
                         that is installed right now. Compare against the
                         baseline recorded in logs/audit_baseline.json. A rise
                         beyond tolerance is a regression.
  2. BLOCK DECISIONS     Replay those captures through the live EvidenceTracker
                         with the live tiers.json. Any benign host reaching the
                         block tier is a FAIL -- that is a real firewall rule on
                         a real host.
  3. CALIBRATION FRESH   tiers.json records the champion it was calibrated
                         against. If the installed champion's hash differs, the
                         calibration is stale and blocking is running on a rule
                         measured for a model that no longer exists.
  4. GATE CONSISTENCY    The promotion gate, the runtime operating point and the
                         council seats must agree across files. Drift between
                         them is how a model gets evolved against one boundary
                         and judged against another.
  5. DATA HYGIENE        No generated capture has re-entered the benign pool, and
                         the corpus leak audit still shows no single-feature
                         shortcut.
  6. PREDICTIVE GATE     Report whether the LSTM would be allowed to lower the
                         blocking threshold, so it can never switch on silently.
  7. CAPTURE COVERAGE    Hours captured and port diversity. This is the metric
                         that actually governs progress, so it is tracked
                         whether or not anything regressed.

Exit codes: 0 all pass, 1 warnings, 2 at least one failure. Written so a
scheduled task can branch on it.
"""

import argparse
import glob
import gzip
import json
import os
import pickle
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neat_vectorized import activate_batch
from feature_extractor import PacketFeatureExtractor, FEATURE_NAMES_20
from council_arbiter import THREAT_THRESHOLD
from whitelist_manager import WhitelistManager
from decision_engine import load_tracker
import ops_archive
import build_corpus_v2 as B

GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"
BOLD = "\033[1m"; RESET = "\033[0m"

BASELINE_PATH = "logs/audit_baseline.json"
REPORT_PATH = "logs/audit_report.json"

# A capture's false positive rate may drift this much before it is a regression.
FPR_TOLERANCE_PP = 0.50


class Audit:
    def __init__(self):
        self.checks = []

    def add(self, name, status, detail, data=None):
        self.checks.append({"check": name, "status": status, "detail": detail,
                            "data": data or {}})
        colour = {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED}[status]
        print(f"  {colour}[{status}]{RESET} {name}: {detail}")

    @property
    def worst(self):
        if any(c["status"] == "FAIL" for c in self.checks):
            return "FAIL"
        if any(c["status"] == "WARN" for c in self.checks):
            return "WARN"
        return "PASS"

    def exit_code(self):
        return {"PASS": 0, "WARN": 1, "FAIL": 2}[self.worst]


def open_maybe_gz(path):
    """Archived captures are gzipped; scapy needs a real file."""
    if not path.endswith(".gz"):
        return path, None
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    with gzip.open(path, "rb") as src:
        shutil.copyfileobj(src, tmp)
    tmp.close()
    return tmp.name, tmp.name


def live_captures(include_archive: bool):
    """Current captures, plus every distinct archived capture when asked."""
    paths = [os.path.join(".", p) for p in B.discover_benign_pcaps(".")]
    if include_archive:
        seen_names = {os.path.basename(p) for p in paths}
        for rec in ops_archive.load_manifest():
            if rec.get("kind") != "captures":
                continue
            ap = rec.get("archive_path", "")
            if os.path.exists(ap) and os.path.basename(rec["source_path"]) not in seen_names:
                paths.append(ap)
    return paths


def champion_hash():
    p = "genomes/champion.pkl"
    return ops_archive.sha256_of(p) if os.path.exists(p) else None


def score_capture(champion, path, tracker, wl):
    """Per-packet flags plus the set of hosts that would be firewalled."""
    from scapy.all import rdpcap, IP
    real, tmp = open_maybe_gz(path)
    try:
        pkts = sorted([p for p in rdpcap(real) if p.haslayer(IP)],
                      key=lambda p: float(p.time))
    finally:
        if tmp:
            os.unlink(tmp)
    if len(pkts) < 20:
        return None

    ex = PacketFeatureExtractor()
    X = np.empty((len(pkts), 20), dtype=np.float64)
    keep = np.zeros(len(pkts), dtype=bool)
    for i, p in enumerate(pkts):
        t = float(p.time)
        is_wl = wl.is_whitelisted(src_ip=p[IP].src, dst_ip=p[IP].dst)[0]
        if is_wl:
            # Mirror the responder: whitelisted packets advance timing state only.
            ex.observe_timing(t)
            X[i] = 0.0
            continue
        X[i] = ex.extract(p, current_time=t, extended=True)
        keep[i] = True

    flags = np.zeros(len(pkts), dtype=bool)
    if keep.any():
        s = activate_batch(champion["genome"], champion["config"], X[keep])
        flags[keep] = s >= THREAT_THRESHOLD

    blocked = set()
    tracker._events.clear(); tracker._last_seen.clear()
    for i in np.where(flags)[0]:
        if tracker.record(pkts[i][IP].src, now=float(pkts[i].time)).should_block:
            blocked.add(pkts[i][IP].src)

    span_h = (float(pkts[-1].time) - float(pkts[0].time)) / 3600.0
    return {
        "packets": len(pkts),
        "scored": int(keep.sum()),
        "fpr_pct": float(flags[keep].mean() * 100) if keep.any() else 0.0,
        "blocked_hosts": sorted(blocked),
        "hours": span_h,
    }


def main():
    ap = argparse.ArgumentParser(description="NEXUS regression audit")
    ap.add_argument("--set-baseline", action="store_true",
                    help="Record current measurements as the reference to compare against")
    ap.add_argument("--include-archive", action="store_true", default=True)
    ap.add_argument("--quick", action="store_true",
                    help="Current captures only, skip the archived history")
    args = ap.parse_args()

    started = datetime.now(timezone.utc).isoformat()
    print(f"{BOLD}{CYAN}================ NEXUS AUDIT ================{RESET}")
    print(f"  {started}\n")
    audit = Audit()

    if not os.path.exists("genomes/champion.pkl"):
        audit.add("champion present", "FAIL", "genomes/champion.pkl is missing")
        json.dump({"verdict": "FAIL", "checks": audit.checks}, open(REPORT_PATH, "w"), indent=2)
        sys.exit(2)

    with open("genomes/champion.pkl", "rb") as f:
        champion = pickle.load(f)
    ch_hash = champion_hash()
    tracker = load_tracker()
    wl = WhitelistManager("config/whitelist.json")

    baseline = {}
    if os.path.exists(BASELINE_PATH):
        try:
            baseline = json.load(open(BASELINE_PATH, encoding="utf-8"))
        except Exception:
            baseline = {}

    # ---- 1 & 2: per-capture FPR and block decisions ------------------------
    print(f"{BOLD}Champion behaviour on real captures{RESET}")
    results, total_hours, all_blocked = {}, 0.0, {}
    for path in live_captures(args.include_archive and not args.quick):
        r = score_capture(champion, path, tracker, wl)
        if r is None:
            continue
        key = os.path.basename(path)
        results[key] = r
        total_hours += r["hours"]
        if r["blocked_hosts"]:
            all_blocked[key] = r["blocked_hosts"]

        prev = (baseline.get("captures") or {}).get(key, {}).get("fpr_pct")
        if prev is None:
            audit.add(f"fpr:{key}", "PASS",
                      f"{r['fpr_pct']:.2f}% ({r['scored']} scored pkts, no baseline yet)",
                      r)
        else:
            delta = r["fpr_pct"] - prev
            status = "FAIL" if delta > FPR_TOLERANCE_PP else "PASS"
            audit.add(f"fpr:{key}", status,
                      f"{r['fpr_pct']:.2f}% vs baseline {prev:.2f}% ({delta:+.2f}pp)",
                      dict(r, baseline_fpr_pct=prev, delta_pp=delta))

    if all_blocked:
        n = sum(len(v) for v in all_blocked.values())
        audit.add("benign block decisions", "FAIL",
                  f"{n} benign host(s) would be firewalled: "
                  + "; ".join(f"{k}->{v}" for k, v in all_blocked.items()),
                  all_blocked)
    else:
        audit.add("benign block decisions", "PASS",
                  f"no benign host reaches the block tier across {total_hours:.1f}h "
                  f"({tracker.k} flags / {tracker.window:g}s)")

    # ---- 3: calibration freshness -----------------------------------------
    print(f"\n{BOLD}Configuration integrity{RESET}")
    tiers_path = "config/tiers.json"
    if not os.path.exists(tiers_path):
        audit.add("tier calibration", "WARN",
                  "config/tiers.json missing; engine is running on built-in defaults")
    else:
        tiers = json.load(open(tiers_path, encoding="utf-8"))
        prov = tiers.get("_provenance", {})
        cal_hash = prov.get("champion_sha256")
        if cal_hash is None:
            audit.add("tier calibration", "WARN",
                      "tiers.json records no champion hash; cannot prove it matches "
                      "the installed champion. Re-run calibrate_tiers.py --write.")
        elif cal_hash != ch_hash:
            audit.add("tier calibration", "FAIL",
                      f"calibrated for champion {cal_hash[:12]} but {ch_hash[:12]} is "
                      f"installed -- blocking rule is stale, re-run calibrate_tiers.py --write")
        else:
            audit.add("tier calibration", "PASS",
                      f"k={tiers['block_min_events']} / {tiers['block_window_sec']:g}s, "
                      f"calibrated for the installed champion")

    # ---- 4: gate consistency ----------------------------------------------
    man = "genomes/council_manifest.json"
    if os.path.exists(man):
        m = json.load(open(man, encoding="utf-8"))
        if abs(float(m.get("operating_point", THREAT_THRESHOLD)) - THREAT_THRESHOLD) > 1e-9:
            audit.add("operating point", "FAIL",
                      f"council manifest says {m.get('operating_point')} but runtime uses "
                      f"{THREAT_THRESHOLD}")
        else:
            audit.add("operating point", "PASS", f"{THREAT_THRESHOLD} everywhere")
        seated = [r for r, v in (m.get("specialists") or {}).items() if v.get("seated")]
        unseated = [r for r, v in (m.get("specialists") or {}).items() if not v.get("seated")]
        on_disk = {os.path.basename(p).replace("council_", "").replace(".pkl", "")
                   for p in glob.glob("genomes/council_*.pkl")}
        leaked = [r for r in unseated if r in on_disk]
        if leaked:
            audit.add("council seats", "FAIL",
                      f"{leaked} failed the holdout gate but the pickle is present -- "
                      f"it will be loaded and can veto on benign traffic")
        else:
            audit.add("council seats", "PASS",
                      f"seated {seated or 'none'}; rejected {unseated or 'none'} absent from disk")
    else:
        audit.add("council seats", "WARN", "genomes/council_manifest.json missing")

    # ---- 5: data hygiene ---------------------------------------------------
    print(f"\n{BOLD}Data hygiene{RESET}")
    accepted = B.discover_benign_pcaps(".")
    audit.add("benign pool", "PASS" if accepted else "FAIL",
              f"{len(accepted)} real capture(s) accepted"
              if accepted else "no real captures in the benign pool")

    if os.path.exists("data/corpus_v2.npz"):
        d = np.load("data/corpus_v2.npz", allow_pickle=True)
        X, y = d["X_train"], d["y_train"]
        npos, nneg = int(y.sum()), int((y == 0).sum())
        worst, worst_name = 0.0, ""
        for i, name in enumerate(FEATURE_NAMES_20):
            order = np.argsort(X[:, i], kind="mergesort")
            ranks = np.empty(len(y)); ranks[order] = np.arange(1, len(y) + 1)
            auc = (ranks[y == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg)
            strength = max(auc, 1 - auc)
            if strength > worst:
                worst, worst_name = strength, name
        audit.add("corpus leak audit",
                  "FAIL" if worst > 0.95 else ("WARN" if worst > 0.90 else "PASS"),
                  f"strongest single feature {worst_name} at {worst:.3f} separability")
    else:
        audit.add("corpus leak audit", "WARN", "data/corpus_v2.npz missing")

    # ---- 6: predictive gate ----------------------------------------------
    print(f"\n{BOLD}Predictive escalation{RESET}")
    pr = "logs/predictive_results.json"
    if not os.path.exists(pr):
        audit.add("predictive gate", "PASS",
                  "never validated, so escalation stays disabled (threshold pinned)")
    else:
        clean = (json.load(open(pr, encoding="utf-8")).get("holdout") or {}).get(
            "clean windows only") or {}
        auc, pos = clean.get("auc"), clean.get("positives", 0)
        from sniff_and_respond import MIN_PREDICTIVE_AUC, MIN_PREDICTIVE_POSITIVES
        would_arm = (auc is not None and auc >= MIN_PREDICTIVE_AUC
                     and pos >= MIN_PREDICTIVE_POSITIVES)
        audit.add("predictive gate", "PASS",
                  f"clean-window AUC {auc if auc is None else round(auc,3)} on {pos} positives -> "
                  f"escalation {'ARMED' if would_arm else 'disabled'}"
                  + ("" if would_arm else f" (needs AUC>={MIN_PREDICTIVE_AUC} "
                                          f"and >={MIN_PREDICTIVE_POSITIVES} positives)"),
                  {"auc": auc, "positives": pos, "armed": would_arm})

    # ---- 7: capture coverage ---------------------------------------------
    print(f"\n{BOLD}Capture coverage (the metric that governs progress){RESET}")
    ports = Counter()
    from scapy.all import rdpcap, TCP
    for path in accepted:
        try:
            for p in rdpcap(path)[:4000]:
                if p.haslayer(TCP):
                    ports[min(p[TCP].sport, p[TCP].dport)] += 1
        except Exception:
            pass
    top3 = sum(c for _, c in ports.most_common(3))
    conc = top3 / max(1, sum(ports.values()))
    audit.add("port diversity", "WARN" if conc > 0.85 else "PASS",
              f"top 3 ports cover {conc*100:.0f}% of benign traffic "
              f"({', '.join(str(p) for p, _ in ports.most_common(5))}); "
              f"{total_hours:.1f}h captured",
              {"concentration": conc, "hours": total_hours,
               "top_ports": ports.most_common(8)})

    # ---- report ----------------------------------------------------------
    report = {
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "champion_sha256": ch_hash,
        "operating_point": THREAT_THRESHOLD,
        "tier_rule": {"k": tracker.k, "window_sec": tracker.window},
        "verdict": audit.worst,
        "checks": audit.checks,
        "captures": results,
        "total_capture_hours": round(total_hours, 2),
    }
    os.makedirs("logs", exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    if args.set_baseline:
        with open(BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump({"recorded_utc": report["finished_utc"],
                       "champion_sha256": ch_hash,
                       "captures": results}, f, indent=2)
        print(f"\n  baseline recorded -> {BASELINE_PATH}")

    colour = {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED}[audit.worst]
    print(f"\n{colour}{BOLD}  VERDICT: {audit.worst}{RESET}   report -> {REPORT_PATH}")
    if audit.worst == "FAIL":
        print(f"{RED}  Do not leave blocking armed until the failures above are resolved.{RESET}")
    sys.exit(audit.exit_code())


if __name__ == "__main__":
    main()
