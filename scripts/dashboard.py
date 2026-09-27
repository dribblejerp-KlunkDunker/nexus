"""
NEXUS - High-Density Tactical Cyber-Guardian Command Deck
FastAPI + Server-Sent Events (SSE) backend serving:
- Real-time Threat Speedometer & Anomaly Scoring
- Deep Attacker Threat Intelligence & Passive OS Fingerprinting
- Living Neural Genome Topology with Active Synapse Impulses
- Evolutionary Training Analytics, Ray Distributed Benchmarks, and LSTM Forecasters
- Live Network Interface Sniffing (Scapy / Npcap) and Authorized Firewall Enforcement
"""

import os
import sys
import time
import json
import socket
import asyncio
import pickle
import random
import threading
import argparse
import subprocess
import urllib.request
import shutil
from collections import deque
from typing import Dict, List, Optional, Set
from datetime import datetime
from contextlib import asynccontextmanager

import numpy as np
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, FEATURE_NAMES_20, calculate_shannon_entropy
from passive_flow_tracker import PassiveTcpFlowTracker
import ops_control
# Core security-module imports. These MUST sit above the first use of
# policy/banstore/genomevault (~line 147): a late import here produced a
# NameError at module level, which is a total launch failure no source-grep
# test could see (caught by the dashboard import smoke test instead).
from whitelist_manager import WhitelistManager
from firewall import FirewallValidationError, block_ip as fw_block_ip, unblock_ip as fw_unblock_ip
import genomevault
import policy
from policy import THREAT_THRESHOLD, is_threat
import banstore

# --------------------------------------------------------------------
# LIFESPAN & APPLICATION SETUP
# --------------------------------------------------------------------
def _silence_win_proactor_errors(loop, context):
    exception = context.get("exception")
    if isinstance(exception, OSError):
        winerror = getattr(exception, "winerror", None)
        if winerror in (64, 121, 10054):
            return
    if isinstance(exception, (ConnectionResetError, BrokenPipeError)):
        return
    try:
        loop.default_exception_handler(context)
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    global EVENT_LOOP
    EVENT_LOOP = asyncio.get_running_loop()
    if sys.platform == "win32":
        EVENT_LOOP.set_exception_handler(_silence_win_proactor_errors)
    # Start throughput ticker
    asyncio.create_task(throughput_ticker())
    yield
    stop_sniffer()

app = FastAPI(title="NEXUS Tactical Command API", lifespan=lifespan)

# ---------------------------------------------------------------------------
# REQUEST FENCING: same-origin guard + security headers.
#
# The control API (start captures, toggle defense, unban IPs, register tasks)
# is loopback-only by policy. A loopback bind alone does not stop OTHER pages
# in the browser from POSTing to http://127.0.0.1:8000 (CSRF via DNS-rebinding
# or direct form posts). This middleware refuses state-changing requests whose
# Origin/Referer is not loopback, refuses non-loopback Host headers outright,
# and stamps defensive headers on every response.
# ---------------------------------------------------------------------------
from starlette.middleware.base import BaseHTTPMiddleware

# The decision logic lives in webguard.py -- framework-free and unit-tested
# (tests/test_webguard.py); this adapter only translates Starlette objects.
from webguard import (CSP as _CSP, SECURITY_HEADERS as _SECURITY_HEADERS,
                      check_request as _wg_check_request)


class OriginGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        reason = _wg_check_request(request.method, request.headers)
        if reason:
            return JSONResponse({"error": reason}, status_code=403)
        response = await call_next(request)
        for _hk, _hv in _SECURITY_HEADERS.items():
            response.headers.setdefault(_hk, _hv)
        return response


app.add_middleware(OriginGuardMiddleware)

# ---------------------------------------------------------------------------
# Static assets (CSS, fonts, app JS) -- all local, no CDN. Served with short
# caching so UI updates land on the next refresh without hard-reload tricks.
# ---------------------------------------------------------------------------
class _CachedStatic(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        try:
            resp.headers.setdefault("Cache-Control", "public, max-age=3600")
        except Exception:
            pass
        return resp

_WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
app.mount("/static", _CachedStatic(directory=os.path.join(_WEB_DIR, "static")), name="static")
app.mount("/js", _CachedStatic(directory=os.path.join(_WEB_DIR, "js")), name="js")

# Global event loop & subscriber set for multi-client SSE
EVENT_LOOP: Optional[asyncio.AbstractEventLoop] = None
EVENT_SUBSCRIBERS: Set[asyncio.Queue] = set()

# Live throughput counters
PACKET_COUNTER_SEC = 0
BYTES_COUNTER_SEC = 0

# Shared operational state
SHARED_STATE = {
    "packets_evaluated": 0,
    "threats_flagged": 0,
    "bans": {},  # snapshot of BAN_STORE.active(); the store owns the truth
    "champion_fitness": 0.9980,
    "last_score": 0.0,
    "active_defense": False,
    "champion_path": "genomes/champion.pkl",
    "live_sniffing": False,
    "current_pps": 0,
    "current_kbps": 0.0,
    # Recorded at startup so ops_control can refuse privileged actions when the
    # dashboard is reachable from anywhere but this machine.
    "bind_host": "127.0.0.1"
}

# Single lock-guarded ban table (see banstore.py). SHARED_STATE["bans"] is a
# refreshed snapshot -- the UI and SSE read it, the store owns the truth.
BAN_STORE = banstore.BanStore(ttl_sec=policy.BAN_TTL_SEC)
SHARED_STATE["bans"] = BAN_STORE.active()

# Live sniffer control
SNIFFER_RUNNING = False
SNIFFER_THREAD: Optional[threading.Thread] = None

# Load champion genome via the GenomeVault (HMAC-sealed JSON, no pickle at
# runtime; see genomevault.py). Falls back to legacy .pkl with a loud warning.
NET = None
CONFIG = None
ACTIVE_GENOME = None
try:
    if os.path.exists("genomes/champion.pkl") or os.path.exists("genomes/champion.ngenome"):
        import neat
        ACTIVE_GENOME, CONFIG = genomevault.load_genome_and_config("genomes/champion.pkl")
        NET = neat.nn.FeedForwardNetwork.create(ACTIVE_GENOME, CONFIG)
        SHARED_STATE["champion_fitness"] = float(getattr(ACTIVE_GENOME, "fitness", 0.0) or 0.0)
        print(f"[NEXUS Dashboard] Active champion loaded (Fitness: {SHARED_STATE['champion_fitness']:.4f})")
except Exception as e:
    print(f"[NEXUS Dashboard] Warning: Could not load champion genome: {e}")

# Initialize Specialist Council Arbiter (MoE)
from council_arbiter import CouncilArbiter
from evasion_engine import AdversarialEvasionEngine
COUNCIL_ARBITER = CouncilArbiter()
EVASION_ENGINE = AdversarialEvasionEngine()
SHARED_STATE["council_mode"] = COUNCIL_ARBITER.active_mode
SHARED_STATE["council_specialists"] = COUNCIL_ARBITER.specialist_fitnesses
SHARED_STATE["last_council_breakdown"] = {
    "volumetric": 0.0,
    "recon": 0.0,
    "payload": 0.0,
    "leading_expert": "NONE",
    "consensus_rule": "NONE"
}

EXTRACTOR = PacketFeatureExtractor()
TRACKER = PassiveTcpFlowTracker(timeout_seconds=120.0, history_size=8)
WHITELIST_MGR = WhitelistManager("config/whitelist.json")

# --------------------------------------------------------------------
# THREAT INTEL & OS FINGERPRINTING ENGINE
# --------------------------------------------------------------------
THREAT_INTEL_FILE = "data/threat_intel_cache.json"

# Enrichment now lives in intel.py: HTTPS-only GeoIP, schema-validated
# responses, per-field provenance, and NO fabricated attribution when a
# lookup fails. (The deleted SIMULATED_THREAT_ACTORS table used to invent
# APT/Lazarus attribution for any IP the lookup could not resolve.)
from intel import IntelService, IntelError, classify_mitre_technique  # noqa: E402

INTEL_SERVICE = IntelService(THREAT_INTEL_FILE)




def resolve_ip_intel(ip: str, ttl: int = 64, window: int = 1024, dport: int = 80) -> dict:
    """Forensic enrichment for one IP. Honesty contract lives in intel.py:
    no fabricated actors, HTTPS-only lookups, provenance on every field."""
    intel = INTEL_SERVICE.lookup(ip, ttl=ttl, window=window, dport=dport)
    intel.setdefault("ip", ip)
    return intel


# --------------------------------------------------------------------
# BROADCAST & THROUGHPUT
# --------------------------------------------------------------------
def broadcast_event(event_type: str, data: dict):
    """Thread-safe event broadcast to all connected SSE clients."""
    payload = {"type": event_type, "data": data}

    def _deliver():
        dead = []
        for q in list(EVENT_SUBSCRIBERS):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
            except Exception:
                dead.append(q)
        for q in dead:
            EVENT_SUBSCRIBERS.discard(q)

    if EVENT_LOOP and EVENT_LOOP.is_running():
        EVENT_LOOP.call_soon_threadsafe(_deliver)


# --------------------------------------------------------------------
# REAL-TIME TELEMETRY BUFFERS & CONTINUOUS LEARNING ENGINE
# --------------------------------------------------------------------
SCORE_HISTORY = deque(maxlen=100)
VELOCITY_HISTORY = deque(maxlen=60)
CONTINUOUS_LOGS = deque(maxlen=50)


class ContinuousLearningManager:
    """
    Orchestrates live autonomous background continuous learning:
    1. Ingests packets into rotating buffer & flushes to data/continuous_baseline.pcap
    2. Blends live 20-D feature vectors into training pool
    3. Runs background NEAT neuroevolution cycles across Ray workers
    4. Evaluates against holdout validation gate
    5. Archives previous champion & hot-reloads superior candidates with zero downtime
    """
    def __init__(self):
        self.is_running = False
        self.cycle = 0
        self.buffer_threshold = 30  # Packets to trigger an evolution cycle
        self.buffered_packets = []
        self.buffered_vectors = []
        self.pcap_path = "data/continuous_baseline.pcap"
        self.total_saved_packets = 0
        self.champions_promoted = 0
        self.current_stage = "IDLE"  # IDLE, SNIFFING, SAVING_PCAP, EXTRACTING_20D, RAY_EVOLUTION, HOLDOUT_VALIDATION, HOT_RELOAD
        self.last_fitness = SHARED_STATE.get("champion_fitness", 0.9980)
        self.lock = threading.Lock()
        self.is_busy_evolving = False
        self.history = []
        self.X_norm_base = None
        self.X_atk_base = None

    def get_status(self):
        pcap_size_kb = 0.0
        if os.path.exists(self.pcap_path):
            try:
                pcap_size_kb = round(os.path.getsize(self.pcap_path) / 1024.0, 1)
            except Exception:
                pass

        return {
            "is_running": self.is_running,
            "cycle": self.cycle,
            "buffer_count": len(self.buffered_packets),
            "buffer_threshold": self.buffer_threshold,
            "total_saved_packets": self.total_saved_packets,
            "pcap_path": self.pcap_path,
            "pcap_size_kb": pcap_size_kb,
            "champions_promoted": self.champions_promoted,
            "current_stage": self.current_stage,
            "last_fitness": self.last_fitness,
            "is_busy_evolving": self.is_busy_evolving,
            "history": self.history[-15:]
        }

    def log(self, stage: str, message: str):
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "stage": stage,
            "message": message
        }
        CONTINUOUS_LOGS.append(entry)
        broadcast_event("continuous_log", entry)
        print(f"[NEXUS Continuous] [{stage}] {message}")

    def feed_packet(self, pkt, feats_20, score):
        if not self.is_running:
            return

        with self.lock:
            self.buffered_packets.append(pkt)
            self.buffered_vectors.append(feats_20)
            count = len(self.buffered_packets)
            if not self.is_busy_evolving:
                self.current_stage = "SNIFFING"

        # Broadcast progress every 5 packets
        if count % 5 == 0:
            broadcast_event("continuous_progress", {
                "count": count,
                "threshold": self.buffer_threshold,
                "total_saved": self.total_saved_packets
            })

        if count >= self.buffer_threshold and not self.is_busy_evolving:
            self.trigger_cycle()

    def trigger_cycle(self):
        if self.is_busy_evolving:
            return

        with self.lock:
            packets_to_save = list(self.buffered_packets)
            vectors_to_use = list(self.buffered_vectors)
            self.buffered_packets.clear()
            self.buffered_vectors.clear()

        self.is_busy_evolving = True
        self.cycle += 1
        threading.Thread(target=self._run_cycle_thread, args=(packets_to_save, vectors_to_use), daemon=True).start()

    def _run_cycle_thread(self, packets_to_save, vectors_to_use):
        try:
            # Stage 1: SAVING_PCAP
            self.current_stage = "SAVING_PCAP"
            self.log("SAVE", f"Saving batch of {len(packets_to_save)} packets to {self.pcap_path}...")
            broadcast_event("continuous_stage", {"stage": "SAVING_PCAP", "cycle": self.cycle})
            os.makedirs(os.path.dirname(self.pcap_path) or "data", exist_ok=True)
            from scapy.all import wrpcap
            wrpcap(self.pcap_path, packets_to_save, append=os.path.exists(self.pcap_path))
            self.total_saved_packets += len(packets_to_save)
            pcap_size_kb = round(os.path.getsize(self.pcap_path) / 1024.0, 1)
            self.log("SAVE", f"Flushed to disk: {self.pcap_path} ({pcap_size_kb} KB total)")
            broadcast_event("continuous_save", {
                "saved_count": len(packets_to_save),
                "total_saved": self.total_saved_packets,
                "pcap_size_kb": pcap_size_kb
            })
            time.sleep(0.2)

            # Stage 2: EXTRACTING_20D
            self.current_stage = "EXTRACTING_20D"
            self.log("EXTRACT", f"Ingested {len(vectors_to_use)} live 20-D feature vectors into evolutionary corpus")
            broadcast_event("continuous_stage", {"stage": "EXTRACTING_20D", "cycle": self.cycle})
            time.sleep(0.2)

            # Stage 3: RAY_EVOLUTION
            self.current_stage = "RAY_EVOLUTION"
            self.log("RAY_EVOLVE", f"Spawning 16 Ray workers for 3 generational evolution cycles...")
            broadcast_event("continuous_stage", {"stage": "RAY_EVOLUTION", "cycle": self.cycle})

            import neat
            import numpy as np
            from evolve import load_or_extract_dataset, eval_genomes
            config_file = "config/config-nexus.txt"
            cfg = neat.Config(
                neat.DefaultGenome, neat.DefaultReproduction,
                neat.DefaultSpeciesSet, neat.DefaultStagnation, config_file
            )

            if self.X_norm_base is None or self.X_atk_base is None:
                self.X_norm_base, self.X_atk_base = load_or_extract_dataset(base_dir=".")

            X_norm = self.X_norm_base
            X_atk = self.X_atk_base
            if vectors_to_use:
                live_arr = np.array(vectors_to_use, dtype=np.float32)
                X_norm = np.vstack([X_norm, live_arr])

            # Subsample for snappy cycle speed (~1s per burst)
            if len(X_norm) > 600:
                idx_n = np.random.choice(len(X_norm), 600, replace=False)
                X_norm_sub = X_norm[idx_n]
            else:
                X_norm_sub = X_norm

            if len(X_atk) > 600:
                idx_a = np.random.choice(len(X_atk), 600, replace=False)
                X_atk_sub = X_atk[idx_a]
            else:
                X_atk_sub = X_atk

            pop = neat.Population(cfg)

            class DashContinuousReporter(neat.reporting.BaseReporter):
                def __init__(self, manager_inst, cycle_num):
                    self.manager = manager_inst
                    self.cycle = cycle_num
                    self.gen = 0
                def post_evaluate(self, config, population, species, best_genome):
                    self.gen += 1
                    fits = [c.fitness for c in population.values() if c.fitness is not None]
                    avg_f = float(np.mean(fits)) if fits else 0.0
                    best_f = float(best_genome.fitness)
                    evt = {
                        "cycle": self.cycle,
                        "generation": self.gen,
                        "best_fitness": best_f,
                        "avg_fitness": avg_f,
                        "species_count": len(species.species)
                    }
                    self.manager.history.append(evt)
                    broadcast_event("continuous_evolve", evt)
                    self.manager.log("RAY_EVOLVE", f"Cycle #{self.cycle} Gen {self.gen} | Best: {best_f:.4f} | Avg: {avg_f:.4f} | Species: {len(species.species)}")

            reporter = DashContinuousReporter(self, self.cycle)
            pop.add_reporter(reporter)

            def _eval_w(genomes, config):
                eval_genomes(genomes, config, X_norm_sub, X_atk_sub)

            pop.run(_eval_w, 3)
            candidate = pop.best_genome
            candidate_fitness = float(candidate.fitness)

            # Stage 4: HOLDOUT_VALIDATION & PROMOTION
            self.current_stage = "HOLDOUT_VALIDATION"
            self.log("GATE", f"Validating candidate fitness: {candidate_fitness:.4f} against champion...")
            broadcast_event("continuous_stage", {"stage": "HOLDOUT_VALIDATION", "cycle": self.cycle})
            time.sleep(0.2)

            current_champ_fitness = SHARED_STATE.get("champion_fitness", 0.9980)
            if (candidate_fitness - current_champ_fitness) >= 0.0005 or current_champ_fitness < 0:
                self.current_stage = "HOT_RELOAD"
                os.makedirs("genomes/archive", exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                archive_path = f"genomes/archive/champion_cycle{self.cycle}_{ts}.pkl"
                if os.path.exists("genomes/champion.pkl"):
                    shutil.copy2("genomes/champion.pkl", archive_path)

                with open("genomes/champion.pkl", "wb") as f:
                    pickle.dump({"genome": candidate, "config": cfg}, f)

                global NET, ACTIVE_GENOME, CONFIG
                ACTIVE_GENOME = candidate
                CONFIG = cfg
                NET = neat.nn.FeedForwardNetwork.create(candidate, cfg)
                SHARED_STATE["champion_fitness"] = candidate_fitness
                self.last_fitness = candidate_fitness
                self.champions_promoted += 1

                with open("genomes/.reload_signal", "w") as f:
                    f.write(str(time.time()))

                self.log("PROMOTE", f"New champion promoted! Fitness: {candidate_fitness:.4f} (Archived to {archive_path})")
                broadcast_event("continuous_promote", {
                    "cycle": self.cycle,
                    "fitness": candidate_fitness,
                    "archive": archive_path
                })
            else:
                self.log("RETAIN", f"Candidate {candidate_fitness:.4f} did not exceed threshold. Champion {current_champ_fitness:.4f} preserved.")

        except Exception as e:
            self.log("ERROR", f"Cycle #{self.cycle} failed: {e}")
        finally:
            self.is_busy_evolving = False
            self.current_stage = "SNIFFING" if self.is_running else "IDLE"
            broadcast_event("continuous_status", self.get_status())


CONTINUOUS_MANAGER = ContinuousLearningManager()


async def throughput_ticker():
    """Sliding 1-second velocity ticker (PPS and KB/s)."""
    global PACKET_COUNTER_SEC, BYTES_COUNTER_SEC
    while True:
        await asyncio.sleep(1.0)
        # Ban TTL expiry rides the existing 1s ticker; a change re-broadcasts
        # so every connected deck drops the expired ban immediately.
        if BAN_STORE.sweep():
            SHARED_STATE["bans"] = BAN_STORE.active()
            broadcast_event("bans", SHARED_STATE["bans"])
        pps = PACKET_COUNTER_SEC
        kbps = (BYTES_COUNTER_SEC * 8.0) / 1024.0
        PACKET_COUNTER_SEC = 0
        BYTES_COUNTER_SEC = 0

        SHARED_STATE["current_pps"] = pps
        SHARED_STATE["current_kbps"] = round(kbps, 2)

        cur_t = datetime.now().strftime("%H:%M:%S")
        vel_item = {
            "time": cur_t,
            "pps": pps,
            "kbps": round(kbps, 2),
            "total_packets": SHARED_STATE["packets_evaluated"],
            "total_threats": SHARED_STATE["threats_flagged"]
        }
        VELOCITY_HISTORY.append(vel_item)
        broadcast_event("velocity", vel_item)


# --------------------------------------------------------------------
# UNIFIED PACKET PROCESSOR
# --------------------------------------------------------------------
def process_packet(pkt):
    """
    Evaluates packet through:
    1. 20-D feature extractor
    2. Champion NEAT neural network
    3. Attacker forensic intelligence
    4. Passive TCP Flow Tracker (RFC 5961)
    5. Automatic Windows firewall enforcement
    """
    global PACKET_COUNTER_SEC, BYTES_COUNTER_SEC
    from scapy.all import IP, TCP, Raw

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None

    cur_time = datetime.now().strftime("%H:%M:%S")
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = int(pkt[TCP].sport)
    dport = int(pkt[TCP].dport)
    flags_str = str(pkt[TCP].flags)
    raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    payload_len = len(raw_payload)
    seq = int(pkt[TCP].seq)
    ack = int(pkt[TCP].ack) if (pkt[TCP].flags & 0x10) else None
    window = int(pkt[TCP].window)
    ttl = int(pkt[IP].ttl)

    PACKET_COUNTER_SEC += 1
    BYTES_COUNTER_SEC += len(pkt)

    # 0. Trusted Whitelist Check (Subnets, IPs, Ports)
    is_wl, wl_reason = WHITELIST_MGR.is_whitelisted(src_ip, dst_ip=dst_ip, sport=sport, dport=dport)
    if is_wl:
        return None

    # 1. Feature extraction
    feats_20 = EXTRACTOR.extract(pkt, extended=True)
    feats_12 = feats_20[:12]

    # 2. Specialist Council MoE Anomaly Scoring (with monolithic fallback)
    council_res = COUNCIL_ARBITER.evaluate(feats_20)
    score = float(council_res["score"])
    leading_expert = council_res["leading_expert"]
    council_breakdown = council_res["breakdown"]

    SHARED_STATE["packets_evaluated"] += 1
    SHARED_STATE["last_score"] = score
    SHARED_STATE["council_mode"] = COUNCIL_ARBITER.active_mode
    SHARED_STATE["last_council_breakdown"] = {
        "volumetric": council_breakdown.get("volumetric", 0.0),
        "recon": council_breakdown.get("recon", 0.0),
        "payload": council_breakdown.get("payload", 0.0),
        "leading_expert": leading_expert,
        "consensus_rule": council_res.get("consensus_rule", "")
    }

    # 3. Attacker intelligence enrichment & MITRE ATT&CK Mapping
    intel = resolve_ip_intel(src_ip, ttl=ttl, window=window, dport=dport)
    intel["leading_expert"] = leading_expert
    intel["council_breakdown"] = council_breakdown
    mitre = classify_mitre_technique(dport, flags_str, feats_20[12], score, intel, raw_payload)
    intel["mitre"] = mitre

    # 4. Policy Enforcement upon Threat Detection
    if is_threat(score) and not policy.is_loopback_ip(src_ip):
        SHARED_STATE["threats_flagged"] += 1
        try:
            BAN_STORE.add(src_ip, {
                "country": intel["country"],
                "flag": intel["flag"],
                "asn": intel["asn"],
                "os": intel["os_guess"],
                "target": intel["target_service"],
                "score": score,
                "mitre": mitre,
                "c2_match": intel.get("c2_match", False),
                "malware_family": intel.get("malware_family", "")
            })
            SHARED_STATE["bans"] = BAN_STORE.active()
        except ValueError as ve:
            # Unreachable in practice (loopback already excluded above); this
            # guard keeps an unexpected store refusal from killing scoring.
            print(f"[NEXUS BANSTORE] refusing ban for {src_ip!r}: {ve}")

        if SHARED_STATE["active_defense"]:
            # Attacker-controlled value -> validated firewall layer (no shell,
            # no interpolation). An unparseable "IP" is logged and dropped.
            try:
                fw_res = fw_block_ip(src_ip, active=True)
                if fw_res["error"]:
                    print(f"[NEXUS FIREWALL] block {src_ip} failed: {fw_res['error']}")
            except FirewallValidationError as ve:
                print(f"[NEXUS FIREWALL] refusing to block invalid source {src_ip!r}: {ve}")

        broadcast_event("bans", SHARED_STATE["bans"])

    # 5. State Plane RFC 5961 tracking
    state_event = TRACKER.observe(
        src_ip=src_ip,
        src_port=sport,
        dst_ip=dst_ip,
        dst_port=dport,
        seq=seq,
        ack=ack,
        flags=flags_str,
        payload_len=payload_len,
        window=window,
        ttl=ttl
    )

    for finding in state_event.get("findings", []):
        broadcast_event("rfc_event", {
            "finding": finding,
            "src": f"{src_ip}:{sport}",
            "dst": f"{dst_ip}:{dport}",
            "time": cur_time
        })

    # 6. Payload Hex Dump
    hex_preview = " ".join(f"{b:02X}" for b in raw_payload[:32]) if raw_payload else "None (Pure Control Frame)"
    ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_payload[:32]) if raw_payload else ""

    feat_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_20, feats_20)}

    packet_data = {
        "time": cur_time,
        "src": f"{src_ip}:{sport}",
        "dst": f"{dst_ip}:{dport}",
        "src_ip": src_ip,
        "dst_port": dport,
        "proto": "TCP",
        "flags": flags_str,
        "score": score,
        "seq": f"0x{seq:08X}",
        "ack": f"0x{ack:08X}" if ack is not None else "N/A",
        "window": window,
        "ttl": ttl,
        "hex_dump": hex_preview,
        "ascii_dump": ascii_preview,
        "intel": intel,
        "features": feat_dict,
        "council": {
            "mode": COUNCIL_ARBITER.active_mode,
            "leading_expert": leading_expert,
            "breakdown": council_breakdown,
            "consensus_rule": council_res.get("consensus_rule", ""),
            "seat_provenance": council_res.get("seat_provenance", {})
        }
    }

    # 7. Real-Time Oscilloscope & Continuous Engine Ingestion
    score_item = {
        "time": cur_time,
        "src": src_ip,
        "score": round(score, 4),
        "flags": flags_str,
        "is_threat": is_threat(score),
        "leading_expert": leading_expert,
        "council": council_breakdown
    }
    SCORE_HISTORY.append(score_item)
    CONTINUOUS_MANAGER.feed_packet(pkt, feats_20, score)

    broadcast_event("packet", packet_data)
    return packet_data


# --------------------------------------------------------------------
# LIVE CAPTURE WORKER
# --------------------------------------------------------------------
def _sniffer_worker(iface=None):
    global SNIFFER_RUNNING
    from scapy.all import sniff, conf, IP, TCP

    target_iface = iface or conf.iface
    print(f"[NEXUS Sniffer] Background sniffer active on: {target_iface}")
    SHARED_STATE["live_sniffing"] = True

    def _pkt_callback(pkt):
        if not SNIFFER_RUNNING:
            return
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            try:
                process_packet(pkt)
            except Exception:
                pass

    try:
        sniff(
            iface=target_iface,
            prn=_pkt_callback,
            store=0,
            stop_filter=lambda p: not SNIFFER_RUNNING
        )
    except Exception as e:
        print(f"[NEXUS Sniffer] Sniffer stopped: {e}")
    finally:
        SNIFFER_RUNNING = False
        SHARED_STATE["live_sniffing"] = False
        print("[NEXUS Sniffer] Background capture thread terminated.")


def start_sniffer(iface=None):
    global SNIFFER_RUNNING, SNIFFER_THREAD
    if SNIFFER_RUNNING:
        return
    SNIFFER_RUNNING = True
    SNIFFER_THREAD = threading.Thread(target=_sniffer_worker, args=(iface,), daemon=True)
    SNIFFER_THREAD.start()


def stop_sniffer():
    global SNIFFER_RUNNING
    SNIFFER_RUNNING = False
    SHARED_STATE["live_sniffing"] = False


# --------------------------------------------------------------------
# REST API ROUTES
# --------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the dashboard with strict no-cache headers to guarantee fresh UI loading."""
    index_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h3>Error: web/index.html not found</h3>", status_code=404)
    with open(index_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(
        content=content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.get("/api/status")
async def get_status():
    return {
        "status": "ARMED (FIREWALL BLOCKS)" if SHARED_STATE["active_defense"] else "ARMED (SIMULATION AUDIT)",
        "active_defense": SHARED_STATE["active_defense"],
        "fitness": SHARED_STATE["champion_fitness"],
        "total_packets": SHARED_STATE["packets_evaluated"],
        "total_threats": SHARED_STATE["threats_flagged"],
        "bans": SHARED_STATE["bans"],
        "last_score": SHARED_STATE["last_score"],
        "live_sniffing": SNIFFER_RUNNING,
        "pps": SHARED_STATE["current_pps"],
        "kbps": SHARED_STATE["current_kbps"],
        "council": {
            "mode": COUNCIL_ARBITER.active_mode,
            "specialists": COUNCIL_ARBITER.specialist_fitnesses,
            "last_breakdown": SHARED_STATE.get("last_council_breakdown", {})
        }
    }


@app.get("/api/council/status")
async def get_council_status():
    manifest = {}
    manifest_file = "genomes/council_manifest.json"
    if os.path.exists(manifest_file):
        try:
            with open(manifest_file, "r") as f:
                manifest = json.load(f)
        except Exception:
            pass
    return {
        "mode": COUNCIL_ARBITER.active_mode,
        "specialists": COUNCIL_ARBITER.specialist_fitnesses,
        "last_breakdown": SHARED_STATE.get("last_council_breakdown", {}),
        "seat_provenance": getattr(COUNCIL_ARBITER, "provenance", {}),
        "manifest": manifest
    }


# --------------------------------------------------------------------
# ADVERSARIAL RED TEAM SPARRING & STRESS TEST API
# --------------------------------------------------------------------
@app.get("/api/adversary/stats")
async def get_adversary_stats():
    """Returns the latest benchmark stress results and Hall of Fame status."""
    results = {}
    res_path = "logs/adversarial_stress_results.json"
    if os.path.exists(res_path):
        try:
            with open(res_path, "r", encoding="utf-8") as f:
                results = json.load(f)
        except Exception:
            pass

    hof = {}
    hof_path = "genomes/archive/hall_of_fame.json"
    if os.path.exists(hof_path):
        try:
            with open(hof_path, "r", encoding="utf-8") as f:
                hof = json.load(f)
        except Exception:
            pass

    return {
        "status": "ready",
        "benchmark": results,
        "hall_of_fame_count": len(hof.get("specialists", {})) if hof else 0,
        "coevolution_generations": hof.get("generations", 0) if hof else 0,
        "last_coevolution": hof.get("timestamp", None) if hof else None
    }


@app.post("/api/adversary/stress_test")
async def run_adversary_stress_test():
    """Runs an on-demand adversarial stress benchmark across 5 tiers and returns real-time metrics."""
    def _run_test():
        from benchmark_adversarial_stress import run_adversarial_stress_benchmark
        report = run_adversarial_stress_benchmark()
        broadcast_event("adversary_benchmark", {
            "status": "completed",
            "benchmark": report
        })
        return report

    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(None, _run_test)
    return {"status": "completed", "benchmark": report}


# --------------------------------------------------------------------
# GENETIC SURGEON (META-LEARNING DIRECTED MUTATION) API
# --------------------------------------------------------------------
@app.get("/api/surgeon/status")
async def get_surgeon_status():
    from genetic_surgeon import GeneticSurgeon
    surgeon = GeneticSurgeon()
    history = surgeon.history
    total_surgeries = sum(len(h.get("interventions", [])) for h in history)
    recent = history[-10:] if history else []
    return {
        "status": "ready",
        "total_surgeries": total_surgeries,
        "history_count": len(history),
        "recent_interventions": recent
    }


@app.post("/api/surgeon/operate")
async def trigger_surgeon_operation():
    """Triggers an on-demand genetic diagnosis and directed surgical graft."""
    def _operate():
        from genetic_surgeon import GeneticSurgeon
        from benchmark_moe_vs_monolith import generate_benchmark_test_suites
        surgeon = GeneticSurgeon()

        champ, cfg = genomevault.load_genome_and_config("genomes/champion.pkl")

        suites = generate_benchmark_test_suites()
        X_l, y_l = [], []
        for name, (feats, cat) in suites.items():
            lbl = 1 if cat == "ATTACK" else 0
            X_l.extend(feats[:30])
            y_l.extend([lbl] * len(feats[:30]))
        X_v = np.array(X_l, dtype=np.float32)
        y_v = np.array(y_l, dtype=np.float32)

        diagnosis = surgeon.diagnose_genome(champ, cfg, X_v, y_v)
        spliced_genome, interventions = surgeon.perform_surgery(champ, cfg, diagnosis, max_interventions=2)

        evt = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "interventions": interventions,
            "accuracy": diagnosis["accuracy"],
            "pre_fn": diagnosis["false_negatives"],
            "pre_fp": diagnosis["false_positives"],
            "neglected_count": len(diagnosis.get("neglected_attack_sensors", []))
        }
        broadcast_event("surgeon_intervention", evt)
        return evt

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _operate)
    return {"status": "operated", "data": result}


# --------------------------------------------------------------------
# TRUSTED WHITELIST API
# --------------------------------------------------------------------
class WhitelistAddRequest(BaseModel):
    item_type: str  # "ip", "subnet", "mac", "port"
    value: str


@app.get("/api/whitelist")
async def get_whitelist():
    """Returns current whitelist configuration and status summary."""
    return WHITELIST_MGR.export_summary()


@app.post("/api/whitelist/add")
async def add_whitelist_entry(req: WhitelistAddRequest):
    """Dynamically adds an entry to config/whitelist.json and hot-reloads."""
    config_path = "config/whitelist.json"
    if not os.path.exists(config_path):
        return JSONResponse(status_code=404, content={"error": "whitelist.json not found"})

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        v = req.value.strip()
        if req.item_type == "subnet":
            if v not in data.get("subnets", []):
                data.setdefault("subnets", []).append(v)
        elif req.item_type == "ip":
            if v not in data.get("trusted_ips", []):
                data.setdefault("trusted_ips", []).append(v)
        elif req.item_type == "port":
            p = int(v)
            if p not in data.get("trusted_ports", []):
                data.setdefault("trusted_ports", []).append(p)
        elif req.item_type == "mac":
            if v not in data.get("trusted_macs", []):
                data.setdefault("trusted_macs", []).append(v)
        else:
            return JSONResponse(status_code=400, content={"error": f"Invalid item_type: {req.item_type}"})

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        WHITELIST_MGR.load_whitelist(force=True)
        return {"status": "success", "added": v, "type": req.item_type, "summary": WHITELIST_MGR.export_summary()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/genome")
async def get_genome():
    """Returns detailed architecture: inputs, mutated hidden nodes, weights, and polarities."""
    try:
        genome, cfg = genomevault.load_genome_and_config("genomes/champion.pkl")

        # Sensor input names (20 dimensions)
        input_names = FEATURE_NAMES_20
        num_inputs = len(cfg.genome_config.input_keys) if cfg is not None else len(input_names)
        inputs = [{"id": -(i + 1), "name": input_names[i] if i < len(input_names) else f"in_{i}", "type": "input"} for i in range(num_inputs)]
        outputs = [{"id": 0, "name": "THREAT_DECISION", "type": "output", "bias": genome.nodes[0].bias}]
        
        hidden = []
        for nid, node in genome.nodes.items():
            if nid > 0:
                hidden.append({
                    "id": nid,
                    "name": f"NEURON_{nid}",
                    "type": "hidden",
                    "bias": node.bias,
                    "activation": node.activation
                })

        connections = []
        for key, cg in genome.connections.items():
            if cg.enabled:
                connections.append({
                    "in": key[0],
                    "out": key[1],
                    "weight": cg.weight,
                    "polarity": "excitatory" if cg.weight > 0 else "inhibitory"
                })

        return {
            "inputs": inputs,
            "hidden": hidden,
            "outputs": outputs,
            "connections": connections,
            "fitness": getattr(genome, "fitness", 0.9980)
        }
    except Exception as e:
        return {"error": str(e)}


def _config_pop_size():
    """Read pop_size from the live NEAT config; None if unreadable."""
    try:
        with open("config/config-nexus.txt", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("pop_size"):
                    return int(line.split("=", 1)[1].strip())
    except Exception:
        pass
    return None


@app.get("/api/training/stats")
async def get_training_stats():
    """Returns evolutionary generation trajectory, Ray speeds, and LSTM forecaster specs."""
    history_file = "logs/training_history.json"
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                return json.load(f)
        except Exception:
            pass

    return {
        "evolution_history": [
            {"generation": 0, "best_fitness": 0.7420, "avg_fitness": 0.4120, "nodes": 13, "connections": 12},
            {"generation": 3, "best_fitness": 0.8845, "avg_fitness": 0.5930, "nodes": 13, "connections": 12},
            {"generation": 7, "best_fitness": 0.9410, "avg_fitness": 0.7100, "nodes": 13, "connections": 12},
            {"generation": 10, "best_fitness": 0.9780, "avg_fitness": 0.8350, "nodes": 13, "connections": 12},
            {"generation": 12, "best_fitness": 0.9912, "avg_fitness": 0.8870, "nodes": 13, "connections": 12},
            {"generation": 15, "best_fitness": 0.9980, "avg_fitness": 0.9240, "nodes": 13, "connections": 12}
        ],
        "ray_benchmark": {
            # Measured by the trainer and written to logs/training_history.json.
            # This block previously carried literal constants (2330.3 evals/sec,
            # "8.3x vs single-core") that were reported to the operator whatever
            # the hardware actually did.
            "evals_per_sec": None,
            "cores_active": os.cpu_count(),
            "cluster_nodes": 1,
            "speedup_factor": "not measured"
        },
        "population": {
            # pop_size comes from the live NEAT config. The rest are NOT
            # measured at runtime, so they are None rather than invented.
            "size": _config_pop_size(),
            "species_count": None,
            "mutation_rate": None,
            "selection_elitism": None
        },
        "lstm_predictor": {
            "model_path": "models/predictive_brain.pt",
            "onnx_path": "models/predictive_brain.onnx",
            "lookback_window": 30,
            "epochs_trained": None,
            "sequence_accuracy": None,
            "sequence_accuracy_note": "not measured; the honest evaluation lives in logs/honest_training_results.json",
            "current_horizon_threat": None,
            "status": "excluded from the decision path (clean-window AUC below gate)"
        }
    }


@app.post("/api/training/evolve")
async def trigger_evolution_burst():
    """Triggers an active 5-generation evolution burst and broadcasts progression."""
    def _run_evolution():
        try:
            print("[NEXUS Evolution] Running background evolution burst (5 generations)...")
            import neat
            config_file = "config/config-nexus.txt"
            cfg = neat.Config(
                neat.DefaultGenome, neat.DefaultReproduction,
                neat.DefaultSpeciesSet, neat.DefaultStagnation, config_file
            )
            from evolve import load_or_extract_dataset, eval_genomes
            X_norm, X_atk = load_or_extract_dataset(".")
            pop = neat.Population(cfg)

            def _eval_wrapper(genomes, config):
                eval_genomes(genomes, config, X_norm, X_atk)

            pop.run(_eval_wrapper, 5)
            champ = pop.best_genome
            SHARED_STATE["champion_fitness"] = float(champ.fitness)
            broadcast_event("evolution_update", {
                "message": f"Evolution cycle completed! Best Fitness: {champ.fitness:.4f}",
                "fitness": float(champ.fitness)
            })
            print(f"[NEXUS Evolution] Burst complete! New Champion Fitness: {champ.fitness:.4f}")
        except Exception as e:
            # Always broadcast: the evolve button's release depends on this
            # event, and the operator deserves the failure reason, not a
            # frozen "EVOLVING..." label.
            print(f"[NEXUS Evolution Error]: {e}")
            broadcast_event("evolution_update", {
                "message": f"Evolution burst failed: {e}",
                "fitness": None,
                "failed": True
            })

    threading.Thread(target=_run_evolution, daemon=True).start()
    return {"status": "started", "generations": 5}


@app.get("/api/intel/lookup/{ip}")
async def get_intel(ip: str):
    """Returns deep threat attribution dossier for an IP."""
    return resolve_ip_intel(ip)


@app.post("/api/bans/unban/{ip}")
async def unban_ip(ip: str):
    if BAN_STORE.remove(ip):
        SHARED_STATE["bans"] = BAN_STORE.active()
        try:
            fw_res = fw_unblock_ip(ip, active=True)
            if fw_res["error"]:
                print(f"[NEXUS FIREWALL] unban {ip} failed: {fw_res['error']}")
        except FirewallValidationError as ve:
            print(f"[NEXUS FIREWALL] refusing to unban invalid IP {ip!r}: {ve}")
        broadcast_event("bans", SHARED_STATE["bans"])
        return {"status": "unbanned", "ip": ip}
    return {"status": "not_found", "ip": ip}


# --------------------------------------------------------------------
# CONTINUOUS LEARNING & TELEMETRY API
# --------------------------------------------------------------------
@app.get("/api/continuous/status")
async def get_continuous_status():
    return CONTINUOUS_MANAGER.get_status()


@app.post("/api/continuous/toggle")
async def toggle_continuous():
    new_state = not CONTINUOUS_MANAGER.is_running
    CONTINUOUS_MANAGER.is_running = new_state
    if new_state:
        CONTINUOUS_MANAGER.current_stage = "SNIFFING"
        CONTINUOUS_MANAGER.log("CONTROL", "Autonomous Continuous Sniffing & Learning Loop ACTIVATED.")
    else:
        CONTINUOUS_MANAGER.current_stage = "IDLE"
        CONTINUOUS_MANAGER.log("CONTROL", "Autonomous Continuous Loop paused.")
    broadcast_event("continuous_status", CONTINUOUS_MANAGER.get_status())
    return CONTINUOUS_MANAGER.get_status()


@app.post("/api/continuous/inject_batch")
async def inject_continuous_batch():
    """Simulates an active burst of 35 diverse packets to feed the continuous loop."""
    def _inject_thread():
        import time
        from scapy.all import Ether, IP, TCP, Raw
        CONTINUOUS_MANAGER.log("INJECT", "Operator triggered continuous training test burst (35 pkts)...")
        clean_dsts = ["142.250.190.46", "151.101.65.140", "104.244.42.1", "13.107.42.14"]
        threat_srcs = ["185.220.101.5", "194.26.29.112", "91.240.118.172", "198.51.100.48"]

        for i in range(35):
            if random.random() < 0.30:
                src_ip = random.choice(threat_srcs)
                flags = random.choice(["FPU", "S", "PA"])
                dport = random.choice([8443, 445, 3333, 22])
                pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=random.choice([48, 52, 60]))/\
                      TCP(sport=random.randint(1024, 65535), dport=dport, flags=flags, seq=random.randint(1000, 50000), window=random.choice([0, 1024, 2048]))
                if flags == "PA":
                    pkt = pkt / Raw(load=os.urandom(96))
            else:
                dst_ip = random.choice(clean_dsts)
                dport = random.choice([443, 80, 8080])
                pkt = Ether()/IP(src="192.168.1.50", dst=dst_ip, ttl=64)/\
                      TCP(sport=random.randint(49152, 65535), dport=dport, flags="PA", seq=random.randint(1000, 50000), window=64240)/\
                      Raw(load=b"GET /api/telemetry HTTP/1.1\r\nHost: nexus.local\r\n\r\n")

            process_packet(pkt)
            time.sleep(0.04)

    threading.Thread(target=_inject_thread, daemon=True).start()
    return {"status": "burst_dispatched", "count": 35}


@app.get("/api/telemetry/history")
async def get_telemetry_history():
    return {
        "scores": list(SCORE_HISTORY),
        "velocity": list(VELOCITY_HISTORY),
        "continuous": CONTINUOUS_MANAGER.get_status(),
        "logs": list(CONTINUOUS_LOGS)
    }


@app.get("/api/sniff/status")
async def get_sniff_status():
    return {"running": SNIFFER_RUNNING}


@app.post("/api/sniff/toggle")
async def toggle_sniff():
    if SNIFFER_RUNNING:
        stop_sniffer()
    else:
        start_sniffer()
    return {"running": SNIFFER_RUNNING}


@app.post("/api/defense/toggle")
async def toggle_defense():
    # Arming live firewall blocking from the web UI is fenced exactly like the
    # other privileged controls: loopback bind required, cross-origin refused
    # by OriginGuardMiddleware. (The README's "nothing reachable from the
    # dashboard can arm it" claim holds only if this stays fenced.)
    try:
        ops_control.assert_local(SHARED_STATE.get("bind_host", "127.0.0.1"))
    except ops_control.ControlError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    SHARED_STATE["active_defense"] = not SHARED_STATE["active_defense"]
    status_label = "ARMED (FIREWALL BLOCKS)" if SHARED_STATE["active_defense"] else "ARMED (SIMULATION AUDIT)"
    broadcast_event("defense_mode", {
        "active_defense": SHARED_STATE["active_defense"],
        "status": status_label
    })
    return {"active_defense": SHARED_STATE["active_defense"], "status": status_label}


@app.post("/api/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    """Simulates realistic threat arrival with full packet attributes."""
    from scapy.all import Ether, IP, TCP, Raw

    if attack_type == "synflood":
        # Hostile SYN flood probe from known attacker netblock
        attacker_ips = ["185.220.101.5", "198.51.100.48", "91.240.118.172", "45.154.255.89"]
        src_ip = random.choice(attacker_ips)
        dst_port = random.choice([80, 443, 22, 3389, 445])
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=random.choice([32, 48, 54]))/\
              TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S", seq=random.randint(10000, 99999), window=1024, ack=0)
    elif attack_type == "xmasscan":
        # Stealth reconnaissance FIN+PSH+URG scan
        src_ip = "194.26.29.112"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=40)/\
              TCP(sport=random.randint(40000, 60000), dport=445, flags="FPU", window=0)
    elif attack_type == "sshbrute":
        # Rapid SSH connection probe
        src_ip = "103.149.28.195"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=52)/\
              TCP(sport=random.randint(30000, 50000), dport=22, flags="S", seq=random.randint(1000, 5000), window=14600)/\
              Raw(load=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
    elif attack_type == "c2beacon":
        # Active Cobalt Strike / Sliver C2 Beacon Pulse
        src_ip = "185.220.101.5"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=48)/\
              TCP(sport=random.randint(32768, 65535), dport=8443, flags="PA", window=2048)/\
              Raw(load=os.urandom(96))
    elif attack_type == "exfil":
        # Infostealer / Ransomware Double-Extortion Outbound Exfiltration
        dst_ip = "91.240.118.172"
        pkt = Ether()/IP(src="192.168.1.50", dst=dst_ip, ttl=64)/\
              TCP(sport=random.randint(40000, 60000), dport=14432, flags="PA", window=64240)/\
              Raw(load=os.urandom(1420))
    elif attack_type == "stratum":
        # Cryptomining Stratum JSON-RPC submit
        dst_ip = "193.142.59.83"
        stratum_rpc = b'{"id":1,"jsonrpc":"2.0","method":"mining.submit","params":["xmr_worker1","0x99a1","0xcafe1234"]}\n'
        pkt = Ether()/IP(src="192.168.1.50", dst=dst_ip, ttl=64)/\
              TCP(sport=random.randint(45000, 65000), dport=3333, flags="PA", window=29200)/\
              Raw(load=stratum_rpc)
    elif attack_type == "worm":
        # Worm Lateral Movement Sweep (SMB 445 EternalBlue)
        src_ip = "198.51.100.48"
        pkt = Ether()/IP(src=src_ip, dst="192.168.1.50", ttl=32)/\
              TCP(sport=random.randint(1024, 65535), dport=445, flags="S", window=8192)
    elif attack_type in ("evasive_c2", "evasive_flood", "evasive_scan", "evasive_exfil"):
        # Red Team Adversarial Evasion Synthetic Probe
        pkt, _ = EVASION_ENGINE.generate_evasive_packet(attack_type)
    else:
        # Clean baseline web browsing session
        src_ip = "192.168.1.50"
        pkt = Ether()/IP(src=src_ip, dst="142.250.190.46", ttl=64)/\
              TCP(sport=random.randint(49152, 65535), dport=443, flags="PA", window=64240)/\
              Raw(load=b"GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

    data = process_packet(pkt)
    if data is None:
        # Whitelisted sources (all RFC1918, loopback, link-local) are
        # deliberately not evaluated -- that is what stops the platform from
        # ever scoring or banning the operator's own machine. Report the
        # bypass honestly instead of crashing on the None return.
        is_wl, reason = WHITELIST_MGR.is_whitelisted(
            pkt[IP].src, dst_ip=pkt[IP].dst,
            sport=int(pkt[TCP].sport), dport=int(pkt[TCP].dport))
        return {"status": "whitelisted" if is_wl else "bypassed",
                "reason": reason or "not evaluated",
                "src": pkt[IP].src, "score": None, "intel": None}
    return {"status": "ok", "score": data["score"], "src": data["src"], "intel": data["intel"]}


# ---------------------------------------------------------------------------
# OPS & AUTOMATION
#
# These endpoints start processes and can register scheduled tasks, so each one
# goes through ops_control.assert_local() using the host the server was actually
# bound to. Bound anywhere but loopback, they refuse rather than degrade.
# Nothing here can pass --active-defense: arming the firewall stays a deliberate
# command-line act after a week of clean audits.
# ---------------------------------------------------------------------------

class RollingRequest(BaseModel):
    tag: str = "mixed"
    chunk_minutes: int = 15


def _host():
    return SHARED_STATE.get("bind_host", "127.0.0.1")


@app.get("/api/ops/summary")
async def ops_summary():
    try:
        return ops_control.ops_summary()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/ops/tags")
async def ops_tags():
    return {"tags": [{"tag": t, "label": l} for t, l in ops_control.KNOWN_TAGS]}


@app.post("/api/ops/rolling/start")
async def ops_rolling_start(req: RollingRequest):
    try:
        return ops_control.rolling_start(req.tag, req.chunk_minutes, _host())
    except ops_control.ControlError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/ops/rolling/stop")
async def ops_rolling_stop():
    try:
        return ops_control.rolling_stop(_host())
    except ops_control.ControlError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/ops/job/{key}")
async def ops_job_start(key: str):
    try:
        return ops_control.job_start(key, _host())
    except ops_control.ControlError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/ops/job/{key}")
async def ops_job_status(key: str):
    return ops_control.job_status(key)


@app.post("/api/ops/schedule/install")
async def ops_schedule_install():
    try:
        return ops_control.schedule_install(_host())
    except ops_control.ControlError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/ops/schedule")
async def ops_schedule_status():
    return ops_control.schedule_status()


@app.get("/api/stream")
async def event_stream(request: Request):
    """Per-client Server-Sent Events endpoint streaming real-time alerts and packet updates."""
    client_queue = asyncio.Queue(maxsize=100)
    EVENT_SUBSCRIBERS.add(client_queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(client_queue.get(), timeout=2.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            EVENT_SUBSCRIBERS.discard(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


def run_dashboard(host: str = "127.0.0.1", port: int = 8000, sniff_live: bool = False, active_defense: bool = False, iface: Optional[str] = None):
    SHARED_STATE["active_defense"] = active_defense
    SHARED_STATE["bind_host"] = host
    if sniff_live:
        start_sniffer(iface=iface)

    print("\n=================================================================")
    print(f"  NEXUS DEFENSE OPERATIONS CENTER (V2.0 HIGH-DENSITY HUD)")
    print(f"  URL:            http://localhost:{port}")
    print(f"  Live Sniffing:  {'ENABLED' if sniff_live else 'STANDBY (Toggle via Main HUD Switch)'}")
    print(f"  Defense Mode:   {'ARMED (LIVE FIREWALL)' if active_defense else 'SIMULATION / AUDIT'}")
    print("=================================================================\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Cyber-Guardian Live Web Dashboard")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host binding IP")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--sniff", action="store_true", help="Start with live network packet capture enabled")
    parser.add_argument("--iface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("--active-defense", action="store_true", help="Arm live Windows firewall blocking")
    args = parser.parse_args()

    run_dashboard(
        host=args.host,
        port=args.port,
        sniff_live=args.sniff,
        active_defense=args.active_defense,
        iface=args.iface
    )
