# N.E.X.U.S: Neuro Evolutionary Xeno Unified Sentinals

**N.E.X.U.S** (*Neuro Evolutionary Xeno Unified Sentinals*) is an enterprise-grade autonomous network intrusion observability, neuroevolutionary defense, and adversarial sparring engine. It fuses **Passive TCP Flow Tracking (RFC 5961 compliance & Challenge-ACK detection)**, a **3-Specialist Mixture of Experts (MoE) NEAT Council**, a **PyTorch LSTM Predictive Brain** for horizon forecasting, and a **Minimax Red Team Co-Evolutionary Evasion Engine**. Defensive actions are enforced strictly via **authorized policy devices** (Windows Firewall / `nftables` / `iptables`), preserving forensic timeline artifacts without fragile third-party packet spoofing.


---

## Start here

**First run, once:**

1. **`SETUP.bat`** — creates `venv\` and installs dependencies. Takes a few
   minutes (torch is large). It finishes by running diagnostics.
2. Install **[Npcap](https://npcap.com)** if the diagnostics mention it. It is
   what lets scapy read packets off your adapter. Everything except live capture
   works without it.
3. **`CREATE_DESKTOP_SHORTCUT.bat`** — puts a NEXUS icon on your Desktop, with
   the run-as-administrator flag already set.

**Every time:** double-click the **NEXUS** desktop icon. Approve the elevation
prompt — packet capture needs it. The command center opens at
<http://localhost:8000>.

**Then, on DECK 4: OPS & AUTOMATION:**

- **INSTALL SCHEDULED TASKS** — once. Registers the daily audit (20:00) and the
  weekly cycle (Sundays 21:00) so neither depends on being remembered.
- **START CAPTURE** — pick the context tag the coverage panel suggests. Leave it
  running while you use the laptop normally.

That is the whole routine. Everything else on Deck 4 is there for when you want
it: RUN AUDIT, RECALIBRATE TIERS, WEEKLY CYCLE.

### What is deliberately not automatic

**Blocking is off.** The sensor runs in shadow mode: it alerts, it never writes a
Windows Firewall rule. Nothing reachable from the dashboard can arm it. Arming is
`python scripts/sniff_and_respond.py --active-defense`, and it is gated by the
audit-verified interlock: both `--active-defense` (dashboard or guardian) and
the dashboard's defense toggle refuse to arm unless the most recent regression
audit (`python scripts/ops.py audit`) ended **PASS** — WARN, FAIL, or a missing
report all refuse, fail closed, and leave the sensor in simulation mode.
See *Known limitations* below for why that matters more than it sounds.

**Dashboard controls are loopback-only.** Bound anywhere but `127.0.0.1`, the
buttons refuse to act rather than letting anyone on the network start captures or
register scheduled tasks on this machine.

### Daily, weekly, monthly

The full routine, with the reasoning behind each gate, is in the `nexus-ops`
skill. Short version:

| cadence | what | where |
|---|---|---|
| daily | leave rolling capture running; skim the event log | Deck 4 / `logs/nexus_events.log` |
| daily 20:00 | regression audit (scheduled) | `logs/audit_report.json` |
| weekly | rebuild, retrain, recalibrate tiers, audit | Deck 4 → WEEKLY CYCLE |
| monthly | adversarial re-test, archive check | see the skill |

**Capture hours are the bottleneck, not generations.** Fitness plateaus inside
~150 generations; 250 more bought +3pp TPR. The model is limited by how much of
your network it has seen, and while the baseline is ~99% ports 443/53/80 its
decision collapses onto two features. The coverage panel on Deck 4 tracks this
and names the next context worth capturing.

---


## 8-Plane Autonomous Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CAPTURE PLANE                                                            │
│    Reads live NIC packets or PCAPs via Scapy (with fast-path normalization) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. STATE PLANE (scripts/passive_flow_tracker.py)                            │
│    • Canonical 4-tuple hashing: ((ip_a, port_a), (ip_b, port_b))            │
│    • Dual-Leg Directional State: Leg A→B and Leg B→A (rolling history k=8)  │
│    • Expected Sequence Math: next_seq = seq + len + 1_SYN + 1_FIN           │
│    • State Machine: SYN_SEEN, ESTABLISHED_CONFIRMED, MIDSTREAM, CLOSING, etc│
└──────────────────┬───────────────────────────────────────────┬──────────────┘
                   │ Flow context & features                   │
                   ▼                                           ▼
┌──────────────────────────────────────┐    ┌─────────────────────────────────┐
│ 3. SPECIALIST COUNCIL (MoE) PLANE    │    │ 5. INVESTIGATION PLANE          │
│    • Volumetric Specialist (7-D)     │    │ • Forensic Timeline Exporter    │
│    • Recon Specialist (10-D)         │    │ • Flow Inspection CLI           │
│    • Payload Specialist (7-D)        │    │ • Structured JSON Evidence Dumps│
│    • Council Arbiter (Priority Veto) │    │   (logs/evidence/*.json)        │
│    • PyTorch LSTM Horizon Predictor  │    │ • MITRE ATT&CK Dossier Mapper   │
└──────────────────┬───────────────────┘    └─────────────────────────────────┘
                   │ Verified high-confidence consensus
                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. RESPONSE PLANE                                                           │
│    Authorized Policy Enforcement:                                           │
│    • Windows Firewall (`netsh advfirewall firewall add rule ...`)           │
│    • Linux `nftables` / `iptables` drop rules                               │
│    • SIEM Audit Logging (logs/nexus_events.log)                             │
│    • Dynamic TTL Auto-Expiring Ban Table                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                   ▲
                   │ Hot-Reloaded Hardened Genomes
┌──────────────────┴──────────────────────────────────────────────────────────┐
│ 6. DISTRIBUTED RAY ACCELERATION & 7. CONTINUOUS LEARNING PLANE              │
│    • Multi-core parallel genetic evaluations via Ray Plasma Store           │
│    • 60-second background capture ring buffers & generational hot-reload    │
└──────────────────┬──────────────────────────────────────────┬──────────────┘
                   ▲
                   │ Minimax Hardening
┌──────────────────┴──────────────────────────────────────────────────────────┐
│ 8. ADVERSARIAL RED TEAM SPARRING & CO-EVOLUTION PLANE                       │
│    • Synthetic Mutation: Jitter, Entropy Flattening, TTL/Flag Camouflage    │
│    • Minimax Co-Evolution: Defenders evolve against evasive red team strains│
│    • Hall of Fame Archive: Safeguards against catastrophic forgetting       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Neuroevolutionary Guardian Paradigm ("The Living Genome")

Traditional machine learning relies on rigid, static architectures trained on historical data, leaving them blind to novel zero-day attack patterns. NEXUS applies genetic algorithms to evolve neural networks dynamically:

1. **The Healthy Genome Pool**:
   - Captures baseline home server traffic (media streaming, web browsing, DNS queries, SSH sessions, local LAN file transfers).
   - Serves as the clean training baseline so the network learns the rhythm of your actual home network.
2. **Genetic Topology Mutation (NEAT-Python)**:
   - Genomes start minimal (12 inputs $\to$ 1 output) with zero hidden nodes.
   - Evolution organically mutates connections, node topologies, and activation functions over generations, growing complexity only where necessary.
3. **The "Fitness Function From Hell"**:
   - Ruthlessly weeds out genomes that trigger false alarms on legitimate home server traffic (Netflix binges, game updates, file shares).
   - Rewards high-confidence spikes on SYN floods, stealth port scans, and malformed probes.
4. **Autonomous Re-Evolution Loop**:
   - Continuously buffers newly observed normal and flagged traffic.
   - Periodically re-evolves genomes in the background seeded from the current champion, adapting like an immune system against new threat variants.
5. **Edge Deployment (Raspberry Pi / Cluster)**:
   - Deploy the lightweight winning champion (`champion.pkl`, <10KB) on a Raspberry Pi or home gateway for microsecond packet scoring.
   - Run heavy evolution cycles in the background or offload to workstation/Ray clusters.

---

## Directory Structure

```text
~/nexus/
├── config/
│   └── config-nexus.txt          # Validated NEAT configuration (12 inputs, 1 output)
├── data/
│   ├── normal_traffic/           # Clean traffic captures (.pcap)
│   ├── attack_samples/           # SYN flood, port scan captures (.pcap)
│   └── nexus_sequence.db         # SQLite multi-packet sequence store
├── genomes/
│   ├── champion.pkl              # Active deployed champion neural network
│   ├── candidate_champion.pkl    # Next-generation candidate
│   └── archive/                  # Historical champion checkpoints
├── models/
│   ├── predictive_brain.pt       # PyTorch LSTM predictive brain weights
│   └── predictive_brain.onnx     # Production ONNX optimized model
├── logs/
│   ├── nexus_events.log          # Security audit trail (IP, score, action)
│   ├── evidence/                 # Forensic flow timeline JSON artifacts
│   └── neat-checkpoint-*         # Evolution checkpoint files
├── scripts/
│   ├── passive_flow_tracker.py   # State plane: RFC 5961 & sequence correlation
│   ├── test_passive_tracker.py   # Unit test suite for State Plane
│   ├── feature_extractor.py      # Scapy 12-dimensional vector extractor
│   ├── evolve.py                 # NEAT evolutionary fitness engine
│   ├── sniff_and_respond.py      # Live guardian, hot-reloader & firewall enforcement
│   ├── continuous_loop.py        # Background evolution & promotion loop
│   ├── train_predictive.py       # Sequence dataset generator & LSTM trainer
│   ├── distributed_ray_evolve.py # Phase 4 Ray multi-core/cluster evolution
│   ├── launch_cluster_node.py    # Ray cluster head/worker node orchestrator
│   ├── dataset_downloader.py     # Real PCAP & NSL-KDD dataset ingester
│   └── dashboard.py              # FastAPI + SSE real-time web command server
├── web/
│   └── index.html                # Tactical command dashboard UI (Canvas + Tailwind)
└── README.md                     # Master operational runbook
```

---

## Phased Master Roadmap & Success Criteria

### Phase 0 – Foundation (Single Laptop)
- **Goal**: Everything runs on one machine.
- **Components**:
  - `config/config-nexus.txt`: Initialized with 12 input pins, 1 output pin, population size 100, sigmoid activation.
  - `scripts/feature_extractor.py`: Turns Scapy packets into normalized 12-D vectors: packet size, protocol, ports, SYN/ACK/FIN/RST flags, payload length, window size, TTL, inter-arrival time, and packet arrival rate.
  - `scripts/evolve.py`: Evolves NEAT population, rewarding high anomaly scores for attack packets and low scores for normal traffic, penalizing false positives. Saves `genomes/champion.pkl`.
- **Success Criterion**: Load champion and get anomaly scores from live/simulated packets. *(Status: COMPLETED. Note the 0.0000/0.9885 figures were on synthetic traffic; see the honest numbers below.)*

### Phase 1 – Live Detection + Demonic Response
- **Goal**: Watches network interface and dispatches demonic skull TCP RST on detected threats.
- **Components**:
  - `scripts/sniff_and_respond.py`: Sniffs traffic with Scapy, extracts features, scores via champion genome.
  - Demonic payload: Dispatches TCP RST packet loaded with the horned skull ASCII banner:
    ```text
          (                 )
          |\   _,,,---,,_   /|
          / /`--'        `--'\ \
         / /                  \ \
        | |    (o)      (o)    | |
        | |        /\          | |
         \ \     \______/     / /
          \ \                / /
           `--||||||||||||||--'
              |            |
              `------------'
    =======================================
         I'VE ALREADY TASTED YOUR IP
    =======================================
    ```
  - Automated blocking: Windows Firewall (`netsh advfirewall`) or Linux `iptables`.
  - Comprehensive logging to `logs/nexus_events.log`.
  - **Packet Crafting Mechanics**:
    - **Layer Stacking**: Built via Scapy layer operator `/`: `IP(...) / TCP(...) / Raw(...)`.
    - **Flags (`RA`)**: Reset + Acknowledge, forcing target socket teardown.
    - **Sequence & Ack Math**: 
      - If incoming packet has `ACK`, response `seq = incoming.ack`; otherwise `seq = 0`.
      - Response `ack = incoming.seq + consumed` where `consumed = 1` for SYN/FIN or `len(payload)`.
    - **Reliability Double-Shot**: Transmits with `count=2` to ensure delivery through noisy networks.
- **Success Criterion**: Trigger packet, see NEXUS score it, and dispatch demonic countermeasure. *(Status: COMPLETED - Validated with dry-run and live hooks)*.

### Phase 2 – Continuous Evolution Loop
- **Goal**: Background engine that evolves without human intervention and hot-reloads without downtime.
- **Components**:
  - `scripts/continuous_loop.py`: Continuously monitors traffic pools, seeds evolution from current champion, promotes when fitness margin $\Delta \ge 0.001$, archives checkpoints, and signals live sniffer.
  - Zero-downtime hot-reload in `sniff_and_respond.py`.
- **Success Criterion**: Leave running and automatically deploy stronger champion without dropping connections. *(Status: COMPLETED)*.

### Phase 3 – Predictive Layer ("Psychotic" Brain)
- **Goal**: Move from reactive defense to predictive threat forecasting.
- **Components**:
  - `data/nexus_sequence.db`: SQLite temporal sequence store.
  - `scripts/train_predictive.py`: 2-layer PyTorch LSTM taking sliding window of $(T=30, D=13)$ to forecast impending attack probability.
  - Exported to ONNX runtime (`models/predictive_brain.onnx`).
- **Success Criterion**: Forecast multi-packet reconnaissance buildup before full attack saturation occurs. *(Status: **NOT MET.** Retrained on real packet sequences by `train_predictive_honest.py`, the LSTM scores AUC 0.98 on windows that already contain an attack -- i.e. it re-detects what the champion has already seen -- and AUC 0.68 on clean windows, which are the only genuinely predictive cases. It does not forecast. `sniff_and_respond.py` therefore refuses to let it lower the blocking threshold until its clean-window AUC clears `MIN_PREDICTIVE_AUC`. The previous "COMPLETED" status came from a model trained on two disjoint uniform-noise distributions.)*

### Phase 4 – Multi-Machine Scaling (Distributed Ray Evolution)
- **Goal**: Move beyond one machine to distributed cluster evolution.
- **Components**:
  - `scripts/distributed_ray_evolve.py`: Distributes NEAT genome evaluations across multiple machines or CPU cores using Ray and zero-copy shared memory plasma object store.
  - `scripts/launch_cluster_node.py`: Orchestrates multi-node clusters (Head Node on primary coordinator; Worker nodes on secondary laptops/desktops or Raspberry Pis).
  - Dedicated permanent guardian node on sensor gateway while other machines run evolution when idle.
- **Success Criterion**: Evolution speed increases roughly linearly with the number of machines/cores. *(Status: Ray path implemented; throughput is whatever `distributed_ray_evolve.py` measures on your hardware. The previously quoted 2,330.3 evals/sec was a hardcoded constant in `train_for_real.py`, not a measurement. The vectorized evaluator in `neat_vectorized.py` now does ~450 genome-evals/sec against 23k vectors on a single core, which removes the need for a cluster at this data scale.)*

---

## Unified Decision Path & Test Gate

Every number that turns a score into a decision has exactly one home:

* `scripts/policy.py` owns the operating point (`THREAT_THRESHOLD`, env
  override `NEXUS_THRESHOLD`), the predictive-escalation ladder, the ban TTL,
  the loopback protection set, and the holdout FPR gate. `council_arbiter.py`
  re-exports `THREAT_THRESHOLD` for backward compatibility. The dashboard,
  live guardian, benchmarks, and training gates all import from here.
* `scripts/banstore.py` is the single lock-guarded ban table: TTL expiry is
  enforced on every access, records are copied in and out, loopback sources
  are refused at the door, and expired bans are swept by the dashboard's 1s
  ticker (which re-broadcasts so every deck drops them live).
* `scripts/webguard.py` holds the request-fencing and security-header logic,
  framework-free and unit-tested; `dashboard.py`'s middleware is a thin
  adapter. The CSP's `script-src` is `'self'` with NO `'unsafe-inline'`: all
  28 former inline `onclick=` handlers are now `data-action`/`data-arg`
  attributes handled by one delegated listener in `app.js`.
* Council verdicts carry `seat_provenance`: the held-out TPR/FPR that earned
  each specialist its chair (read from `genomes/council_manifest.json`,
  written by `train_honest.py`). The deck renders it under each specialist
  bar and in the council footer, so operator trust is traceable to a
  measurement.
* `pytest` (72 tests in `tests/`) is the regression gate. Notably,
  `tests/test_architecture.py` re-parses the whole `scripts/` tree with AST
  and FAILS if anyone reintroduces `shell=True`, `os.system`, a raw `0.85`
  in a decision-path file, inline event handlers, or a third-party resource
  origin. `tests/test_genomevault.py` caught a real bug in its first run: a
  corrupted HMAC tag crashed the verifier (TypeError on non-ASCII
  comparison) instead of cleanly rejecting the container.

Run the gate:

```bat
python -m pytest
```

## Offline-First Command Deck

The dashboard loads **zero third-party resources**: Tailwind is compiled once at
build time (`build_web.bat`), fonts are self-hosted WOFF2 under
`web/static/fonts/`, and the app script is `web/js/app.js`. The Content-Security-
Policy on every response allows only `'self'` origins -- and for scripts,
strictly `script-src 'self'` with no inline, since every handler migrated to
`data-action` -- so the deck renders identically in airplane mode and an
injected attribute cannot execute script. Rebuild the CSS after changing
Tailwind classes:

```bat
build_web.bat        REM npm install happens once, dev-only; runtime stays Python
```

Font note: the JetBrains Mono 300-latin face is intentionally absent (the CDN
stalled mid-download when it was vendored). The UI falls back to weight 400;
to restore exact 300, re-fetch per `web/static/fonts/fonts.css` and drop the
file beside it.

## Quickstart Runbook

### 1. Environment Activation
```powershell
cd ~/nexus
.\venv\Scripts\Activate.ps1
```

### 2. Generate Synthetic Baseline Data
```powershell
python scripts/feature_extractor.py --generate-synthetic
```

### 3. Run NEAT Evolution
```powershell
python scripts/evolve.py --generations 20 --output genomes/champion.pkl
```

### 4. Test Live Sniffer & Demonic Response
```powershell
# Safe Dry-Run Simulation:
python scripts/sniff_and_respond.py --test-packet

# Live Arming (Requires Administrator Privileges for Raw Sockets / Firewall):
python scripts/sniff_and_respond.py --active-defense --threshold 0.85
```

### 5. Launch Autonomous Continuous Evolution Loop
```powershell
python scripts/continuous_loop.py --interval 300 --generations 10 --margin 0.005
```

### 6. Train the Predictive Brain (PyTorch + ONNX)
```powershell
python scripts/train_predictive.py --epochs 15 --window 30
```

### 7. Run State Plane & RFC 5961 Unit Tests
```powershell
python scripts/test_passive_tracker.py
```

### 8. Passively Inspect PCAPs & Export Evidence
```powershell
python scripts/passive_flow_tracker.py --pcap data/attack_samples/synflood_portscan.pcap --evidence
```

### 9. Run Phase 4 Distributed Ray Evolution
```powershell
# Multi-Core Local Parallelism (e.g. 16 workers):
python scripts/distributed_ray_evolve.py --generations 20 --cpus 16

# Multi-Machine Cluster Run:
# On Head Node (Workstation):
python scripts/launch_cluster_node.py --head --port 6379

# On Worker Node (Secondary laptop / Pi):
python scripts/launch_cluster_node.py --worker --head-ip <HEAD_IP> --port 6379

# Dispatch distributed job to cluster:
python scripts/distributed_ray_evolve.py --address ray://<HEAD_IP>:10001 --generations 50
```

### 10. Launch Tactical Command Web Dashboard (Phase 2 & Sprint 2)
```powershell
# Run FastAPI server on port 8000:
python scripts/dashboard.py --port 8000

# With active defense (enforces live Windows firewall blocks for flagged threats).
# Refused with a loud warning (exit 2) unless the last audit verdict is PASS:
python scripts/dashboard.py --port 8000 --active-defense
```
Open `http://localhost:8000` in any web browser:
- **Live Anomaly Speedometer**: Real-time threat coefficient gauge ($0.0000 - 1.0000$) with dynamic green/yellow/crimson transitions.
- **Demonic Skull Alarm Banner**: Pulsing skull alert with audio chirp when threat score $\ge 0.85$.
- **Living NEAT Genome Canvas**: Live topology visualizer of the champion neural network's inputs, synapses, and output.
- **Real-Time Packet Stream & 20-D Feature Drawer**: Click any packet row to slide open all 20 normalized features (Shannon entropy, TTL divergence, flag anomalies, window ratio).
- **Active Ban Matrix & Live Countdown**: Real-time TTL countdown with one-click manual unban API (`POST /api/bans/unban/{ip}`).
- **RFC 5961 State Plane Feed**: Live feed for challenge-ACKs, out-of-window RSTs, and forensic dumps.
- **One-Click Simulation Triggers**: Test `⚡ SIMULATE SYN FLOOD` and `+ SIMULATE CLEAN WEB` directly from the top navigation bar.

### 11. Run Real Production Neuroevolution Tonight (16-Core Ray Distributed)
```powershell
# High-Intensity Run (30 Generations, ~2-3 Minutes on 16 CPUs):
python scripts/train_for_real.py --cpus 16 --generations 30 --live-sniff 150

# Deep Overnight Run (100 Generations, Multi-Species Evolution):
python scripts/train_for_real.py --cpus 16 --overnight --live-sniff 150

# Or double-click the one-click Windows batch launcher:
.\train_overnight.bat
```
Features of the production training engine:
- **Comprehensive Multi-Class Threat Corpus**: 6,300+ packets encompassing volumetric SYN floods, stealth XMAS/NULL/FIN port scans, high-entropy exploit payloads, SSH brute-force probes, and RFC 5961 RST attacks alongside real live local NIC baseline captures.
- **Ray Distributed Cluster Acceleration**: Automatically distributes genome evaluations across all 16 cores on your AMD Ryzen 9 processor with zero-copy shared memory plasma store.
- **Holdout Validation Safety Gate**: `train_honest.py` promotes only when the candidate clears $< 0.5\%$ False Positive Rate on a held-out *later time window of real captured traffic*. Each council specialist is gated separately, because the PRIORITY_VETO rule lets any one specialist carry a verdict alone -- an ungated expert with a 20% FPR makes the whole council worse than the monolith.
- **Hot-Reload Promotion**: Updates `genomes/champion.pkl`, archives the previous champion to `genomes/archive/`, and signals running guardians and the dashboard with zero downtime.
- **Simultaneous PyTorch LSTM Retraining**: Sequences temporal events ($T=30$) and updates `models/predictive_brain.pt` and production `models/predictive_brain.onnx`.
- **Live Dashboard Telemetry**: Writes real-time generational fitness to `logs/training_history.json`, animating the live curve on Deck 2 of the dashboard!

### 12. Train & Benchmark Specialist Council (Mixture of Experts - MoE)
```powershell
# Train all 3 specialists (Volumetric 7-D, Recon 10-D, Payload 7-D) across 24 Ray workers:
python scripts/train_council_moe.py --cpus 24 --generations 25

# Head-to-head benchmark (Monolith vs. Specialist Council):
python scripts/benchmark_moe_vs_monolith.py
```
Key performance metrics:
- **Specialist Council**: 2 of 3 specialists seated (recon 89.6% TPR / 0.00% FPR, volumetric 41.8% / 0.22%). The payload specialist is **rejected** by the holdout gate at 20.8% FPR -- its 7-feature slice cannot separate encrypted benign traffic from encrypted malicious payloads at single-packet granularity. Measured on a held-out window of 6,506 real captured packets, not on generated traffic.

  The earlier "100.0% / 0.0%" figure was measured against synthetic benign traffic produced by the same generator as the training set. Against real captured traffic that champion flagged 43-55% of packets as hostile.
- **Council Arbiter**: High-confidence veto priority ensuring that any specialist detecting its domain (>0.75 threshold) triggers swift, decisive defense.
- **HUD Deliberation Widget**: Live visual telemetry showing individual domain confidence bars (Volumetric, Recon, Payload) and consensus verdicts in real time.

### 13. Adversarial Red Team Sparring & Minimax Co-Evolution
```powershell
# Benchmark defenders against 5 tiers of adversarial evasion:
python scripts/benchmark_adversarial_stress.py

# Co-evolve defenders against evolving Red Team evasion strains:
python scripts/coevolve_adversarial.py --generations 20 --cpus 24 --pressure 0.45
```
Adversarial evasion vectors:
- **Entropy Flattening**: Padding payload bytes to match typical HTTPS/TLS distribution.
- **Micro-burst Jitter**: Injecting Poisson timing delays to fool sliding-window detectors.
- **TTL Masquerading**: Matching hop counts of legitimate operating systems (Windows, Linux, macOS).
- **Flag & Window Camouflage**: Emulating browser TCP handshake signatures.
- **Hall of Fame Archiving**: Hardened champions preserved in `genomes/archive/hall_of_fame.json` to prevent catastrophic forgetting.

---

## Prioritized High-Impact Improvements Roadmap

Ranked by **Value vs. Effort** for upcoming sprints:

### Top Priority (Sprint 1 - Immediate Focus)
1. **Real Training Data Ingestion** (Medium / Very High): Ingest real-world attack captures (CIC-IDS2017, NSL-KDD, Stratosphere CTU-13) alongside local home server PCAPs.
2. **Enhanced Feature Set** (Low-Medium / High): Expand from 12 to 20+ features (Shannon payload entropy, TTL variance, anomalous TCP flag combinations, window scaling ratios).
3. **Temporary IP Ban List (TTL Auto-Expiry)** (Low / High): Automatically unblock attacker IPs after 10–60 minutes to prevent firewall rule clutter.
4. **Response Cooldown & Rate Limiting** (Very Low / Medium-High): Token bucket rate-limiting per attacker IP (max 1 countermeasure / alert per 30–60s).
5. **Real-time Logging & Webhook Alerts** (Low / High): Alert dispatcher streaming to Discord/Telegram/Slack webhooks and structured JSON audit logs.
6. **Bidirectional RST (Lab Mode)** (Low / Medium): In simulation mode, dispatch RST packets to both client and server simultaneously.

### Strong Medium-Term Upgrades (Sprint 2)
- **Automatic Champion Promotion + Rollback**: Automatically revert to the previous champion if a candidate exhibits higher false alarm rates on validation data.
- **Live Web Dashboard**: FastAPI / WebSocket dashboard showing real-time threat scores, active flows, and firewall blocks.
- **Trusted Device & Subnet Whitelist**: Dedicated CIDR/IP/MAC configuration to safeguard local streaming, gaming, and development.
- **Predictive LSTM Integration**: Proactively adjust alert sensitivity before packet saturation occurs.



---

## Current Measured Performance

All figures from a held-out later time window of real captured traffic
(6,506 benign packets the evolver never saw), at the runtime operating point
of 0.85. Reproduce with `python scripts/build_corpus_v2.py && python scripts/train_honest.py`.

| | original champion | retrained |
|---|---|---|
| False positives, `home_live_baseline.pcap` (2,163 real packets) | 55.29% | **0.00%** |
| False positives, `continuous_baseline.pcap` (19,522 real packets) | 43.38% | **0.99%** |
| Detection, `massive_attacks.pcap` | 80.15% | **97.35%** |
| Holdout TPR / FPR | 33.8% / 61.2% | **91.7% / 0.00%** |

### Known limitations

**The champion is effectively a two-feature rule.** Permutation importance on
the holdout gives `src_port` 79pp of impact and `ttl_divergence` 39pp; every
other feature contributes under 3pp. It is a better rule than the original
single-TTL rule, but it is not the 20-dimensional detector the architecture
implies.

**The cause is baseline narrowness, not the model.** 100% of the benign capture
is ports 443, 53 and 80. The model has never seen legitimate traffic on a high
source port, so it treats "inbound, high source port" as hostile. Real P2P,
game, WebRTC and VoIP traffic would be flagged. `build_corpus_v2.py` now warns
when the baseline is this narrow. The fix is more diverse captures, not more
generations.

**Timing features are capture-dependent.** The two available captures differ by
two orders of magnitude in packet rate (0.3 pps over 16h vs 36 pps over 60s), so
`inter_arrival_time` and `stream_rate` mean different things in each. The corpus
builder splits each capture on its own timeline to keep both regimes on both
sides of the split.

**Adversarial tier FPRs are pending a re-run.** `benchmark_adversarial_stress.py`
now runs a benign pool inside every tier and reports the false-positive rate
alongside detection, but the committed `logs/adversarial_stress_results.json`
predates that change (its tiers carry no `moe_fpr`). Re-run the benchmark to
refresh the artifact; `docs/MEASURED-PERFORMANCE.md` renders whatever the
artifact honestly contains.

## Verification & tooling

- **`python tools/check.py`** — the full verification gate: pytest, compile
  checks, module self-tests (firewall, intel, policy, banstore, webguard,
  genomevault), `node --check`, Tailwind build freshness, and the offline
  audit (no third-party origins, no inline handlers, no inline styles,
  no threshold literals outside `policy.py`). CI runs the same gate:
  `.github/workflows/ci.yml` executes it on `windows-latest` on every push.
- **`docs/MEASURED-PERFORMANCE.md`** is generated from `logs/*.json` by
  `tools/gen_performance_doc.py` — never edit it by hand; CI fails if the
  document drifts from the measurement artifacts.
- **`CHANGELOG.md`** tracks the hardening campaign change by change.
- **`scripts/install-antigravity-ide.sh`** — reusable, idempotent installer for
  Google's Antigravity IDE (linux-x64): downloads the pinned release, verifies
  its SHA-256, extracts to `/opt/Antigravity IDE`, links the
  `antigravity-ide` CLI, and installs a desktop entry. Re-run safe; supports
  `--version`, `--install-dir`, `--force`, `--uninstall` and
  `ANTIGRAVITY_*` environment overrides (`--help` for details).
- Web build: `build_web.bat` (or `npm run build:web`). Tailwind is compiled
  at build time; `app.css` is committed so runtime never needs Node.
  The Tailwind config uses absolute content paths, so it builds correctly
  from any working directory.
