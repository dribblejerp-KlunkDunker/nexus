"""
NEXUS Ops Orchestrator

One entry point so no step has to be remembered.

    python scripts/ops.py rolling         continuous capture + archive, runs until stopped
    python scripts/ops.py audit           regression audit (scheduled; exit code carries verdict)
    python scripts/ops.py weekly          rebuild, retrain, recalibrate, audit, archive
    python scripts/ops.py status          what is installed, what it measured, what is due
    python scripts/ops.py archive         sweep new artifacts into the permanent archive

Why rolling capture is the accelerator
--------------------------------------
Generations are not the bottleneck. On an unchanged corpus, fitness plateaus
inside ~150 generations and 250 more bought +3pp TPR. The model is limited by how
much of the world it has seen: while 100% of the benign baseline is ports
443/53/80, the decision collapses onto two features and no amount of evolution
recovers.

`rolling` is therefore the thing worth running all day. Ten minutes of manual
capture a day is ~1 hour a week. Rolling capture during ordinary laptop use is
30-40 hours a week of genuinely varied traffic -- browsing, video calls, music
streaming, updates, whatever is actually happening. That is a 30x increase in the
only input that matters, and it needs no discipline, just a window left open.

Each chunk is written under data/captures/ with a dated, context-tagged name and
immediately archived by content hash, so an interrupted session loses at most one
chunk and nothing is ever silently overwritten.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ops_archive

GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"
BOLD = "\033[1m"; RESET = "\033[0m"

JOURNAL = "logs/ops_journal.md"
CAPTURE_INDEX = "logs/capture_index.jsonl"
STOP_FLAG = "logs/.rolling_stop"
STATE = "logs/ops_state.json"
PY = sys.executable


def _state():
    if os.path.exists(STATE):
        try:
            return json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(**kw):
    s = _state()
    s.update(kw)
    os.makedirs("logs", exist_ok=True)
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def journal(line: str):
    os.makedirs("logs", exist_ok=True)
    with open(JOURNAL, "a", encoding="utf-8") as f:
        f.write(f"- {datetime.now().strftime('%Y-%m-%d %H:%M')} {line}\n")


def run(cmd, label):
    print(f"\n{BOLD}{CYAN}$ {' '.join(cmd)}{RESET}")
    r = subprocess.run(cmd)
    print(f"  {label}: exit {r.returncode}")
    return r.returncode


# ---------------------------------------------------------------- rolling ----
def cmd_rolling(args):
    """Capture in chunks forever, archiving each one as it lands."""
    from scapy.all import sniff, wrpcap, conf

    os.makedirs("data/captures", exist_ok=True)
    stop = {"now": False}

    def handler(signum, frame):
        stop["now"] = True
        print(f"\n{YELLOW}  stopping after this chunk...{RESET}")

    signal.signal(signal.SIGINT, handler)
    try:
        signal.signal(signal.SIGTERM, handler)
    except (AttributeError, ValueError):
        pass

    # A stop FILE as well as a signal. The dashboard has to be able to stop this
    # cleanly, and on Windows terminating a process is a hard kill that would
    # lose the chunk currently being captured. Polling a flag between chunks
    # always finishes writing the current one.
    if os.path.exists(STOP_FLAG):
        os.remove(STOP_FLAG)

    print(f"{BOLD}{CYAN}=========== NEXUS ROLLING CAPTURE ==========={RESET}")
    print(f"  interface: {conf.iface}")
    print(f"  chunk:     {args.chunk_minutes} min, tag '{args.tag}'")
    print(f"  archive:   every chunk, by content hash")
    print(f"  stop with Ctrl-C; the current chunk is written first\n")

    chunk = 0
    while not stop["now"] and not os.path.exists(STOP_FLAG):
        chunk += 1
        started = datetime.now()
        name = (f"data/captures/{started.strftime('%Y-%m-%d_%H%M')}"
                f"_{args.tag}.pcap")
        print(f"  [{chunk:03d}] capturing -> {os.path.basename(name)} ...", end="", flush=True)
        try:
            pkts = sniff(timeout=args.chunk_minutes * 60,
                         count=args.max_packets,
                         iface=args.iface or None)
        except Exception as e:
            print(f"\n{RED}  capture failed: {e}{RESET}")
            print(f"{YELLOW}  Live capture needs Npcap and Administrator on Windows.{RESET}")
            return 2

        if len(pkts) < 20:
            print(f" only {len(pkts)} packets, discarded (link idle)")
        else:
            wrpcap(name, pkts)
            mins = (datetime.now() - started).total_seconds() / 60.0
            print(f" {len(pkts)} pkts in {mins:.1f} min")
            ops_archive.sweep(note=f"rolling:{args.tag}", quiet=True)
            _save_state(last_capture_utc=datetime.now(timezone.utc).isoformat(),
                        last_capture_file=name, last_capture_packets=len(pkts))
            # Per-chunk index. Coverage by context is the number that decides
            # whether the model can learn anything new, so it is recorded as the
            # chunks land rather than recomputed by re-reading every pcap.
            with open(CAPTURE_INDEX, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "utc": datetime.now(timezone.utc).isoformat(),
                    "file": name, "tag": args.tag,
                    "packets": len(pkts), "minutes": round(mins, 2),
                }) + "\n")

        if args.chunks and chunk >= args.chunks:
            break

    if os.path.exists(STOP_FLAG):
        os.remove(STOP_FLAG)
    journal(f"rolling capture: {chunk} chunk(s), tag '{args.tag}'")
    print(f"\n{GREEN}  {chunk} chunk(s) captured and archived.{RESET}")
    return 0


# ------------------------------------------------------------------ audit ----
def cmd_audit(args):
    ops_archive.sweep(note="pre-audit", quiet=True)
    code = run([PY, "scripts/ops_audit.py"] + (["--quick"] if args.quick else []), "audit")
    verdict = {0: "PASS", 1: "WARN", 2: "FAIL"}.get(code, "ERROR")
    _save_state(last_audit_utc=datetime.now(timezone.utc).isoformat(),
                last_audit_verdict=verdict)
    journal(f"audit: {verdict}")
    ops_archive.sweep(note="post-audit", quiet=True)
    if verdict == "FAIL":
        print(f"\n{RED}{BOLD}  Audit FAILED. logs/audit_report.json has the detail.{RESET}")
        print(f"{YELLOW}  Hand that file to your agent and ask it to diagnose before "
              f"leaving blocking armed.{RESET}")
    return code


# ----------------------------------------------------------------- weekly ----
def cmd_weekly(args):
    print(f"{BOLD}{CYAN}=========== NEXUS WEEKLY CYCLE ==========={RESET}")
    ops_archive.sweep(note="weekly:before", quiet=False)

    if run([PY, "scripts/build_corpus_v2.py", "--attacks-per-class",
            str(args.attacks_per_class)], "corpus") != 0:
        journal("weekly: corpus build FAILED, aborted")
        return 2

    # Retrain. A refused promotion is a valid outcome, not an error.
    run([PY, "scripts/train_honest.py", "--generations", str(args.generations)], "train")

    # Tiers must be recalibrated for whatever champion is now installed.
    if run([PY, "scripts/calibrate_tiers.py", "--write"], "calibrate") != 0:
        journal("weekly: tier calibration did not produce a safe rule")
        print(f"{RED}  No safe blocking rule. Leave blocking disarmed.{RESET}")

    code = run([PY, "scripts/ops_audit.py"], "audit")
    verdict = {0: "PASS", 1: "WARN", 2: "FAIL"}.get(code, "ERROR")
    ops_archive.sweep(note=f"weekly:after:{verdict}", quiet=False)
    _save_state(last_weekly_utc=datetime.now(timezone.utc).isoformat(),
                last_weekly_verdict=verdict)
    journal(f"weekly cycle complete: audit {verdict}")
    print(f"\n{BOLD}  weekly cycle done, audit verdict {verdict}{RESET}")
    return code


# ----------------------------------------------------------------- status ----
def cmd_status(args):
    st = _state()
    print(f"{BOLD}{CYAN}=========== NEXUS STATUS ==========={RESET}")

    def age(iso):
        if not iso:
            return "never"
        try:
            dt = datetime.fromisoformat(iso)
            d = datetime.now(timezone.utc) - dt
            return f"{d.total_seconds()/3600:.1f}h ago"
        except Exception:
            return iso

    print(f"\n{BOLD}Cadence{RESET}")
    print(f"  last capture : {age(st.get('last_capture_utc'))}"
          f"  {st.get('last_capture_file','')}")
    print(f"  last audit   : {age(st.get('last_audit_utc'))}"
          f"  verdict {st.get('last_audit_verdict','-')}")
    print(f"  last weekly  : {age(st.get('last_weekly_utc'))}"
          f"  verdict {st.get('last_weekly_verdict','-')}")

    print(f"\n{BOLD}Installed{RESET}")
    if os.path.exists("genomes/champion.pkl"):
        print(f"  champion  {ops_archive.sha256_of('genomes/champion.pkl')[:12]}")
    for path, label in [("config/tiers.json", "tiers"),
                        ("logs/honest_training_results.json", "training"),
                        ("logs/audit_report.json", "audit")]:
        if not os.path.exists(path):
            print(f"  {label:9s} (absent)")
            continue
        d = json.load(open(path, encoding="utf-8"))
        if label == "tiers":
            p = d.get("_provenance", {})
            print(f"  tiers     k={d.get('block_min_events')} / "
                  f"{d.get('block_window_sec')}s  "
                  f"caught {p.get('high_volume_hosts_caught_pct','?')}% of high-volume hosts")
        elif label == "training":
            m = d.get("monolith", {})
            print(f"  training  holdout TPR {m.get('holdout_tpr',0)*100:.1f}%  "
                  f"FPR {m.get('holdout_fpr',0)*100:.2f}%")
        else:
            print(f"  audit     {d.get('verdict')}  "
                  f"{d.get('total_capture_hours','?')}h of capture reviewed")

    s = ops_archive.summary()
    print(f"\n{BOLD}Archive{RESET}  {s['total_artifacts']} artifacts")
    for kind, d in sorted(s["by_kind"].items()):
        print(f"  {kind:10s} {d['count']:5d}  {d['bytes']/1024/1024:7.1f} MiB")

    print(f"\n{BOLD}Due{RESET}")
    last_weekly = st.get("last_weekly_utc")
    overdue = True
    if last_weekly:
        try:
            overdue = (datetime.now(timezone.utc)
                       - datetime.fromisoformat(last_weekly)) > timedelta(days=7)
        except Exception:
            pass
    print(f"  weekly cycle: {'DUE' if overdue else 'not yet'}")
    if st.get("last_audit_verdict") == "FAIL":
        print(f"  {RED}audit is FAILING -- read logs/audit_report.json{RESET}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="NEXUS operations orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("rolling", help="continuous chunked capture + archive")
    r.add_argument("--chunk-minutes", type=int, default=15)
    r.add_argument("--max-packets", type=int, default=200000)
    r.add_argument("--chunks", type=int, default=0, help="0 = until stopped")
    r.add_argument("--tag", type=str, default="mixed",
                   help="context label, e.g. browsing, call, gaming, vpn, idle")
    r.add_argument("--iface", type=str, default=None)

    a = sub.add_parser("audit", help="regression audit")
    a.add_argument("--quick", action="store_true")

    w = sub.add_parser("weekly", help="rebuild, retrain, recalibrate, audit")
    w.add_argument("--generations", type=int, default=150)
    w.add_argument("--attacks-per-class", type=int, default=400)

    sub.add_parser("status", help="what is installed and what is due")
    sub.add_parser("archive", help="sweep new artifacts into the archive")

    args = ap.parse_args()
    return {"rolling": cmd_rolling, "audit": cmd_audit, "weekly": cmd_weekly,
            "status": cmd_status,
            "archive": lambda a: (ops_archive.sweep(), 0)[1]}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
