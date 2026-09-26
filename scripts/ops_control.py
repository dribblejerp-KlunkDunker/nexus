"""
NEXUS Ops Control

Everything the dashboard's buttons need, kept out of dashboard.py so it can be
tested on its own and so the privileged operations live in one reviewable place.

What the buttons can and cannot reach
-------------------------------------
These functions spawn processes and, in one case, register Windows scheduled
tasks. That is a real capability, so it is fenced:

  * Loopback only. `assert_local()` refuses every control call unless the
    dashboard is bound to 127.0.0.1. Otherwise anyone on the LAN who can load the
    page could start captures and create scheduled tasks on this machine.
  * Fixed command shapes. Nothing from the request is interpolated into a shell.
    The only caller-supplied value is the capture tag, which is whitelisted
    against KNOWN_TAGS and re-checked against a strict character class.
  * No blocking mode from here. Nothing in this module can pass
    --active-defense. Arming the firewall stays a deliberate command-line act
    after a week of clean audits.
"""

import json
import os
import re
import subprocess
import sys
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ops_archive

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURE_INDEX = "logs/capture_index.jsonl"
STOP_FLAG = "logs/.rolling_stop"
STATE = "logs/ops_state.json"
JOB_LOG_DIR = "logs/jobs"

# The contexts worth capturing. Coverage across these is what decides whether the
# model can learn anything beyond "port 443 is normal".
KNOWN_TAGS = [
    ("idle", "Machine idle, nothing open"),
    ("browsing", "Normal web browsing"),
    ("streaming", "Music or video streaming"),
    ("call", "Video call (WebRTC, high-port UDP/TCP)"),
    ("gaming", "Online game (high ports, latency sensitive)"),
    ("download", "Large download or system update"),
    ("vpn", "Traffic over a VPN tunnel"),
    ("p2p", "Peer-to-peer or torrent"),
    ("inbound", "Someone reaching a service you host"),
    ("iot", "Phone, TV or IoT devices active on the LAN"),
    ("mixed", "Whatever is happening (catch-all)"),
]
TAG_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")

# Only these are launchable from the UI, by key. No free-form commands.
JOBS = {
    "audit": [PY, "scripts/ops.py", "audit"],
    "weekly": [PY, "scripts/ops.py", "weekly", "--generations", "150"],
    "calibrate": [PY, "scripts/calibrate_tiers.py", "--write"],
}

_procs: Dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


class ControlError(RuntimeError):
    pass


def assert_local(bind_host: Optional[str]) -> None:
    """Refuse control operations unless the dashboard is loopback-bound."""
    if bind_host not in ("127.0.0.1", "localhost", "::1"):
        raise ControlError(
            f"Control actions are disabled because the dashboard is bound to "
            f"{bind_host!r} rather than 127.0.0.1. Anything that can start captures "
            f"or create scheduled tasks stays loopback-only.")


def _state() -> Dict:
    if os.path.exists(STATE):
        try:
            return json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pass
    return {}


def _alive(key: str) -> bool:
    p = _procs.get(key)
    return p is not None and p.poll() is None


def _job_log_path(key: str) -> str:
    os.makedirs(JOB_LOG_DIR, exist_ok=True)
    return os.path.join(JOB_LOG_DIR, f"{key}.log")


# --------------------------------------------------------------- rolling -----
def rolling_start(tag: str = "mixed", chunk_minutes: int = 15,
                  bind_host: Optional[str] = "127.0.0.1") -> Dict:
    assert_local(bind_host)
    tag = (tag or "mixed").strip().lower()
    if not TAG_RE.match(tag) or tag not in {t for t, _ in KNOWN_TAGS}:
        raise ControlError(
            f"Unknown capture tag {tag!r}. Pick one of: "
            f"{', '.join(t for t, _ in KNOWN_TAGS)}")
    chunk_minutes = max(1, min(60, int(chunk_minutes)))

    with _lock:
        if _alive("rolling"):
            raise ControlError("Rolling capture is already running. Stop it first "
                               "to change the tag.")
        if os.path.exists(STOP_FLAG):
            os.remove(STOP_FLAG)
        log = open(_job_log_path("rolling"), "a", encoding="utf-8", buffering=1)
        log.write(f"\n=== rolling start tag={tag} "
                  f"{datetime.now(timezone.utc).isoformat()} ===\n")
        _procs["rolling"] = subprocess.Popen(
            [PY, "scripts/ops.py", "rolling", "--tag", tag,
             "--chunk-minutes", str(chunk_minutes)],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    return {"running": True, "tag": tag, "chunk_minutes": chunk_minutes,
            "pid": _procs["rolling"].pid}


def rolling_stop(bind_host: Optional[str] = "127.0.0.1") -> Dict:
    """Ask it to stop after the current chunk. Never a hard kill."""
    assert_local(bind_host)
    if not _alive("rolling"):
        return {"running": False, "note": "not running"}
    os.makedirs("logs", exist_ok=True)
    with open(os.path.join(ROOT, STOP_FLAG), "w", encoding="utf-8") as f:
        f.write(datetime.now(timezone.utc).isoformat())
    return {"running": True, "stopping": True,
            "note": "will finish writing the current chunk, then exit"}


def rolling_status() -> Dict:
    st = _state()
    return {
        "running": _alive("rolling"),
        "stopping": os.path.exists(os.path.join(ROOT, STOP_FLAG)),
        "last_capture_utc": st.get("last_capture_utc"),
        "last_capture_file": st.get("last_capture_file"),
        "last_capture_packets": st.get("last_capture_packets"),
    }


# -------------------------------------------------------------- coverage -----
def coverage() -> Dict:
    """Minutes and packets captured per context, from the per-chunk index."""
    agg = defaultdict(lambda: {"chunks": 0, "minutes": 0.0, "packets": 0})
    path = os.path.join(ROOT, CAPTURE_INDEX)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                d = agg[r.get("tag", "?")]
                d["chunks"] += 1
                d["minutes"] += float(r.get("minutes", 0) or 0)
                d["packets"] += int(r.get("packets", 0) or 0)

    rows = []
    for tag, label in KNOWN_TAGS:
        d = agg.get(tag, {"chunks": 0, "minutes": 0.0, "packets": 0})
        rows.append({"tag": tag, "label": label, "chunks": d["chunks"],
                     "hours": round(d["minutes"] / 60.0, 2), "packets": d["packets"],
                     "covered": d["minutes"] >= 30.0})
    for tag, d in agg.items():
        if tag not in {t for t, _ in KNOWN_TAGS}:
            rows.append({"tag": tag, "label": "(custom)", "chunks": d["chunks"],
                         "hours": round(d["minutes"] / 60.0, 2),
                         "packets": d["packets"], "covered": d["minutes"] >= 30.0})

    covered = sum(1 for r in rows if r["covered"])
    return {
        "rows": rows,
        "contexts_covered": covered,
        "contexts_total": len(KNOWN_TAGS),
        "total_hours": round(sum(r["hours"] for r in rows), 2),
        "next_suggestion": next((r["tag"] for r in rows if not r["covered"]), None),
    }


# ------------------------------------------------------------------ jobs -----
def job_start(key: str, bind_host: Optional[str] = "127.0.0.1") -> Dict:
    assert_local(bind_host)
    if key not in JOBS:
        raise ControlError(f"Unknown job {key!r}")
    with _lock:
        if _alive(key):
            raise ControlError(f"{key} is already running")
        log = open(_job_log_path(key), "w", encoding="utf-8", buffering=1)
        log.write(f"=== {key} {datetime.now(timezone.utc).isoformat()} ===\n")
        _procs[key] = subprocess.Popen(JOBS[key], cwd=ROOT,
                                       stdout=log, stderr=subprocess.STDOUT)
    return {"job": key, "running": True, "pid": _procs[key].pid}


def job_status(key: str, tail_lines: int = 40) -> Dict:
    p = _procs.get(key)
    running = _alive(key)
    code = None if (p is None or running) else p.returncode
    tail: List[str] = []
    path = os.path.join(ROOT, _job_log_path(key))
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                tail = f.read().splitlines()[-tail_lines:]
        except Exception:
            pass
    verdict = None
    if key in ("audit", "weekly") and code is not None:
        verdict = {0: "PASS", 1: "WARN", 2: "FAIL"}.get(code, "ERROR")
    return {"job": key, "running": running, "exit_code": code,
            "verdict": verdict, "tail": tail}


# -------------------------------------------------------------- schedule -----
SCHEDULED = [
    ("NEXUS_Audit", "NEXUS_AUDIT.bat", ["/SC", "DAILY", "/ST", "20:00"],
     "daily 20:00"),
    ("NEXUS_Weekly", "NEXUS_WEEKLY.bat", ["/SC", "WEEKLY", "/D", "SUN", "/ST", "21:00"],
     "Sundays 21:00"),
]


def schedule_supported() -> bool:
    return sys.platform == "win32"


def schedule_status() -> Dict:
    if not schedule_supported():
        return {"supported": False,
                "note": "Windows Task Scheduler only; this host is "
                        f"{sys.platform}. Use cron with the same two commands."}
    out = []
    for name, _, _, when in SCHEDULED:
        try:
            r = subprocess.run(["schtasks", "/Query", "/TN", name],
                               capture_output=True, text=True, timeout=20)
            out.append({"task": name, "installed": r.returncode == 0, "when": when})
        except Exception as e:
            out.append({"task": name, "installed": False, "when": when, "error": str(e)})
    return {"supported": True, "tasks": out,
            "all_installed": all(t.get("installed") for t in out)}


def schedule_install(bind_host: Optional[str] = "127.0.0.1") -> Dict:
    """Register the audit and weekly tasks. Needs an elevated dashboard process."""
    assert_local(bind_host)
    if not schedule_supported():
        raise ControlError(
            "Scheduled tasks are Windows-only here. On Linux or macOS add the same "
            "two commands to cron: 'ops.py audit' daily and 'ops.py weekly' weekly.")

    results, failures = [], []
    for name, bat, sched, when in SCHEDULED:
        bat_path = os.path.join(ROOT, bat)
        if not os.path.exists(bat_path):
            failures.append(f"{name}: {bat} not found in the project root")
            results.append({"task": name, "installed": False, "error": "missing .bat"})
            continue
        cmd = ["schtasks", "/Create", "/TN", name,
               "/TR", f'"{bat_path}" scheduled', *sched, "/RL", "HIGHEST", "/F"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            ok = r.returncode == 0
            msg = (r.stdout or r.stderr or "").strip().splitlines()
            results.append({"task": name, "installed": ok, "when": when,
                            "output": msg[-1] if msg else ""})
            if not ok:
                failures.append(f"{name}: {msg[-1] if msg else 'schtasks failed'}")
        except Exception as e:
            results.append({"task": name, "installed": False, "error": str(e)})
            failures.append(f"{name}: {e}")

    hint = None
    if failures:
        # schtasks needs elevation. Say so plainly rather than leaving the user
        # staring at "Access is denied".
        hint = ("Registering scheduled tasks requires Administrator. Either restart "
                "the dashboard from an elevated prompt and press this again, or run "
                "INSTALL_SCHEDULE.bat as administrator once.")
    return {"results": results, "failures": failures, "hint": hint,
            "all_installed": not failures}


# ---------------------------------------------------------------- summary ----
def ops_summary() -> Dict:
    st = _state()
    tiers, training, audit = {}, {}, {}
    for path, into in (("config/tiers.json", tiers),
                       ("logs/honest_training_results.json", training),
                       ("logs/audit_report.json", audit)):
        p = os.path.join(ROOT, path)
        if os.path.exists(p):
            try:
                into.update(json.load(open(p, encoding="utf-8")))
            except Exception:
                pass
    champ = os.path.join(ROOT, "genomes/champion.pkl")
    return {
        "champion_sha256": ops_archive.sha256_of(champ)[:12] if os.path.exists(champ) else None,
        "tiers": {"k": tiers.get("block_min_events"),
                  "window_sec": tiers.get("block_window_sec"),
                  "caught_pct": (tiers.get("_provenance") or {}).get(
                      "high_volume_hosts_caught_pct")},
        "training": {"holdout_tpr": (training.get("monolith") or {}).get("holdout_tpr"),
                     "holdout_fpr": (training.get("monolith") or {}).get("holdout_fpr")},
        "audit": {"verdict": audit.get("verdict"),
                  "hours_reviewed": audit.get("total_capture_hours"),
                  "finished_utc": audit.get("finished_utc")},
        "last_audit_utc": st.get("last_audit_utc"),
        "last_weekly_utc": st.get("last_weekly_utc"),
        "archive": ops_archive.summary(),
        "rolling": rolling_status(),
        "coverage": coverage(),
        "schedule": schedule_status(),
    }
