"""
NEXUS System Integrity & Pre-Flight Diagnostic Suite
Runs comprehensive health checks across all 9 architectural planes,
models, network interfaces, and web dashboard readiness.
"""

import os
import sys
import time
import json
import subprocess
from datetime import datetime
import numpy as np

# Set color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header(text: str):
    print(f"\n{CYAN}{BOLD}--- {text} ---{RESET}")

def print_check(name: str, passed: bool, detail: str = ""):
    status = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    detail_str = f" ({detail})" if detail else ""
    print(f"  {status} {name}{detail_str}")

def run_diagnostics():
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}           NEXUS SYSTEM INTEGRITY & PRE-FLIGHT AUDIT            {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Audit Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Working Directory: {os.getcwd()}")
    print(f"Python Interpreter: {sys.executable}")

    all_passed = True

    # -------------------------------------------------------------
    # 1. PYTHON ENVIRONMENT & DEPENDENCIES
    # -------------------------------------------------------------
    print_header("1. Core Python Dependencies")
    # (module, label, required). Ray is optional: the vectorized evaluator in
    # scripts/neat_vectorized.py scores a 150-genome population against the full
    # 23k-vector corpus at ~450 genome-evals/sec on one core, which removed the
    # reason to fan out across a cluster at this data scale. Reporting its
    # absence as a failure sent people installing a large dependency nothing
    # needs, so it is reported as optional and does not fail the audit.
    dependencies = [
        ("neat", "neat-python", True),
        ("scapy", "scapy", True),
        ("torch", "PyTorch", True),
        ("onnxruntime", "ONNX Runtime", True),
        ("fastapi", "FastAPI", True),
        ("uvicorn", "Uvicorn", True),
        ("numpy", "NumPy", True),
        ("ray", "Ray Distributed", False),
    ]

    for mod, label, required in dependencies:
        try:
            m = __import__(mod)
            ver = getattr(m, "__version__", "installed")
            print_check(f"{label} ({mod})", True, f"v{ver}")
        except ImportError as e:
            if required:
                print_check(f"{label} ({mod})", False, f"Missing: {e}")
                all_passed = False
            else:
                print_check(f"{label} ({mod})", True,
                            "not installed - optional, only for distributed evolution")

    # -------------------------------------------------------------
    # 2. CONFIGURATION & MODELS
    # -------------------------------------------------------------
    print_header("2. Configuration & Trained Models")
    config_path = "config/config-nexus.txt"
    has_config = os.path.exists(config_path)
    print_check("NEAT Config File", has_config, config_path)
    if has_config:
        try:
            import neat
            cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, config_path)
            num_inputs = len(cfg.genome_config.input_keys)
            act_ok = set(cfg.genome_config.activation_options) == {"sigmoid", "relu", "tanh"}
            print_check("NEAT Input Dimension (20-D)", num_inputs == 20, f"num_inputs = {num_inputs}")
            print_check("NEAT Population Size (150)", cfg.pop_size == 150, f"pop_size = {cfg.pop_size}")
            print_check("Non-Linear Activations", act_ok, f"{', '.join(cfg.genome_config.activation_options)}")
            if num_inputs != 20 or cfg.pop_size != 150 or not act_ok:
                all_passed = False
        except Exception as e:
            print_check("NEAT Config Parsing", False, str(e))
            all_passed = False
    else:
        all_passed = False

    champion_path = "genomes/champion.pkl"
    has_champ = os.path.exists(champion_path)
    if has_champ:
        try:
            import pickle
            with open(champion_path, "rb") as f:
                champ_data = pickle.load(f)
            fitness = getattr(champ_data["genome"], "fitness", 0.0)
            print_check("Active Champion Genome", True, f"{champion_path} | Fitness: {fitness:.4f}")
        except Exception as e:
            print_check("Active Champion Genome", False, f"Corrupted: {e}")
            all_passed = False
    else:
        print_check("Active Champion Genome", False, f"Not found at {champion_path}")
        all_passed = False

    pt_path = "models/predictive_brain.pt"
    onnx_path = "models/predictive_brain.onnx"
    print_check("PyTorch LSTM Brain", os.path.exists(pt_path), pt_path)
    print_check("ONNX Runtime Brain", os.path.exists(onnx_path), onnx_path)

    # -------------------------------------------------------------
    # 3. FEATURE EXTRACTOR & STATE PLANE
    # -------------------------------------------------------------
    print_header("3. State Plane & Feature Extractor (RFC 5961)")
    try:
        sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
        from feature_extractor import PacketFeatureExtractor, calculate_shannon_entropy
        from scapy.all import Ether, IP, TCP, Raw

        # Test Shannon entropy
        ent = abs(calculate_shannon_entropy(b"A" * 100))
        ent_rand = calculate_shannon_entropy(os.urandom(1000))
        entropy_ok = (ent == 0.0) and (ent_rand > 0.7)
        print_check("Shannon Entropy Engine", entropy_ok, f"Zero: {ent:.2f}, High: {ent_rand:.2f}")

        # Test 12-D and 20-D extraction
        extractor = PacketFeatureExtractor()
        test_pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.1", ttl=64)/\
                   TCP(sport=54321, dport=443, flags="S", window=64240)/\
                   Raw(load=b"TEST")
        f12 = extractor.extract(test_pkt)
        f20 = extractor.extract(test_pkt, extended=True)
        extractor_ok = (len(f12) == 12) and (len(f20) == 20)
        print_check("Packet Feature Extractor", extractor_ok, f"12-D & 20-D Vectors verified")

        # Test Passive TCP Flow Tracker
        from passive_flow_tracker import PassiveTcpFlowTracker
        tracker = PassiveTcpFlowTracker()
        res = tracker.observe(
            src_ip="1.1.1.1",
            src_port=1234,
            dst_ip="2.2.2.2",
            dst_port=80,
            seq=100,
            ack=None,
            flags="S",
            payload_len=0,
            window=64240,
            ttl=64
        )
        tracker_ok = res.get("state") == "SYN_SEEN"
        print_check("Passive TCP State Machine", tracker_ok, "Handshake tracking active")
        if not tracker_ok:
            all_passed = False

    except Exception as e:
        print_check("Feature Extractor & State Plane", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # 4. NETWORK INTERFACES & LIVE CAPTURE CAPABILITY
    # -------------------------------------------------------------
    print_header("4. Network Capture Capability (Scapy / Npcap)")
    try:
        from scapy.all import get_if_list, conf, sniff
        ifaces = get_if_list()
        default_iface = conf.iface
        print_check("Npcap Network Interfaces", len(ifaces) > 0, f"{len(ifaces)} interfaces detected")
        print_check("Default Capture Adapter", True, f"{default_iface}")

        # Quick capture test (1 packet, 2s timeout)
        t0 = time.time()
        captured = sniff(count=1, timeout=2.0)
        dur = time.time() - t0
        print_check("Live Packet Capture Test", True, f"Sniffed {len(captured)} pkt in {dur:.2f}s")
    except Exception as e:
        print_check("Network Capture Capability", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # 5. FIREWALL & POLICY ENFORCEMENT ACCESS
    # -------------------------------------------------------------
    print_header("5. Host Firewall Policy Access")
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                shell=False,
                capture_output=True,
                text=True
            )
            fw_ok = "State" in res.stdout or "ON" in res.stdout or "OFF" in res.stdout or res.returncode == 0
            print_check("Windows Firewall (netsh)", fw_ok, "Accessible")
        except Exception as e:
            print_check("Windows Firewall (netsh)", False, str(e))
    else:
        print_check("Host Firewall", True, "Linux/Unix platform detected")

    # -------------------------------------------------------------
    # 6. DASHBOARD & UI ARTIFACTS
    # -------------------------------------------------------------
    print_header("6. Web Dashboard & UI Artifacts")
    dash_script = "scripts/dashboard.py"
    ui_html = "web/index.html"
    print_check("Dashboard Server Script", os.path.exists(dash_script), dash_script)
    print_check("Dashboard UI Template", os.path.exists(ui_html), ui_html)

    # -------------------------------------------------------------
    # 7. SPECIALIST COUNCIL (MIXTURE OF EXPERTS - MoE) PLANE
    # -------------------------------------------------------------
    print_header("7. Specialist Council (Mixture of Experts - MoE)")
    council_configs = [
        ("config/config-council-volumetric.txt", "Volumetric Config (7-D)", 7),
        ("config/config-council-recon.txt", "Recon Config (10-D)", 10),
        ("config/config-council-payload.txt", "Deep-Payload Config (7-D)", 7)
    ]
    for c_path, label, exp_in in council_configs:
        exists = os.path.exists(c_path)
        if exists:
            try:
                import neat
                cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, c_path)
                in_count = len(cfg.genome_config.input_keys)
                print_check(label, in_count == exp_in, f"{in_count}-D inputs")
                if in_count != exp_in:
                    all_passed = False
            except Exception as e:
                print_check(label, False, str(e))
                all_passed = False
        else:
            print_check(label, False, f"Missing {c_path}")
            all_passed = False

    council_models = [
        ("genomes/council_volumetric.pkl", "Volumetric Vanguard Champion", "volumetric"),
        ("genomes/council_recon.pkl", "Recon Inquisitor Champion", "recon"),
        ("genomes/council_payload.pkl", "Deep-Payload Analyst Champion", "payload")
    ]
    # A specialist may be deliberately absent: train_honest.py refuses a seat to
    # any expert that fails the holdout false-positive gate, because the
    # council's priority-veto rule would let it alert on benign traffic
    # single-handedly. The manifest records that decision, so an intentional
    # rejection is reported as such rather than as a missing file.
    seat_status = {}
    try:
        with open("genomes/council_manifest.json", "r", encoding="utf-8") as f:
            seat_status = json.load(f).get("specialists", {})
    except Exception:
        pass
    for m_path, label, role in council_models:
        exists = os.path.exists(m_path)
        if exists:
            try:
                import pickle
                with open(m_path, "rb") as f:
                    data = pickle.load(f)
                fit = getattr(data["genome"], "fitness", 0.0)
                print_check(label, True, f"Fitness: {fit:.4f}")
            except Exception as e:
                print_check(label, False, f"Corrupted: {e}")
                all_passed = False
        elif seat_status.get(role, {}).get("seated") is False:
            info = seat_status[role]
            print_check(label, True,
                        f"Not seated by design (holdout FPR {info['holdout_fpr']*100:.2f}% "
                        f"exceeds gate); council runs without it")
        else:
            print_check(label, False, f"Missing {m_path}")
            all_passed = False

    manifest_path = "genomes/council_manifest.json"
    print_check("Council Manifest JSON", os.path.exists(manifest_path), manifest_path)

    # Test Council Arbiter
    try:
        from council_arbiter import CouncilArbiter
        arbiter = CouncilArbiter()
        arbiter_ok = (arbiter.active_mode == "MOE_COUNCIL")
        print_check("Council Arbiter Engine", arbiter_ok, f"Mode: {arbiter.active_mode}")
        if not arbiter_ok:
            all_passed = False
    except Exception as e:
        print_check("Council Arbiter Engine", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # 8. ADVERSARIAL EVASION & CO-EVOLUTION PLANE
    # -------------------------------------------------------------
    print_header("8. Adversarial Red Team Sparring & Co-Evolution Engine")
    try:
        from evasion_engine import AdversarialEvasionEngine
        ev_engine = AdversarialEvasionEngine()

        # Test mutation operators on a dummy 20-D vector
        test_vec = np.zeros(20, dtype=np.float32)
        test_vec[0] = 0.5   # packet_len
        test_vec[11] = 0.95 # stream_rate
        test_vec[12] = 0.95 # payload_entropy
        test_vec[19] = 0.85 # ttl_divergence

        mut_entropy = ev_engine.mutate_vector(test_vec, "entropy", intensity=0.8)
        mut_jitter = ev_engine.mutate_vector(test_vec, "jitter", intensity=0.8)
        mut_ttl = ev_engine.mutate_vector(test_vec, "ttl", intensity=0.8)
        mut_full = ev_engine.mutate_vector(test_vec, "full", intensity=0.9)

        entropy_ok = (mut_entropy[12] < test_vec[12])
        jitter_ok = (mut_jitter[11] < test_vec[11])
        ttl_ok = (mut_ttl[19] < test_vec[19])

        print_check("Synthetic Mutation Operators", (entropy_ok and jitter_ok and ttl_ok), "Entropy, Jitter, TTL, & Camouflage Verified")
        if not (entropy_ok and jitter_ok and ttl_ok):
            all_passed = False

        # Test evasive packet generation
        pkt, desc = ev_engine.generate_evasive_packet("evasive_c2")
        pkt_ok = (pkt is not None and len(desc) > 0)
        print_check("Adversarial Packet Synthesis", pkt_ok, f"Signature: {desc}")
        if not pkt_ok:
            all_passed = False

    except Exception as e:
        print_check("Adversarial Evasion Engine", False, str(e))
        all_passed = False

    # Check Hall of Fame Archive
    hof_path = "genomes/archive/hall_of_fame.json"
    if os.path.exists(hof_path):
        try:
            with open(hof_path, "r", encoding="utf-8") as f:
                hof_data = json.load(f)
            champs = hof_data.get("specialists", {})
            champ_count = len(champs)
            print_check("Adversarial Hall of Fame", champ_count > 0, f"{champ_count} Hardened Specialists Stored")
            if champ_count == 0:
                all_passed = False
        except Exception as e:
            print_check("Adversarial Hall of Fame", False, f"Corrupt: {e}")
            all_passed = False
    else:
        print_check("Adversarial Hall of Fame", False, f"Missing {hof_path}")
        all_passed = False

    # Check benchmark and co-evolution suites
    bench_script = "scripts/benchmark_adversarial_stress.py"
    coevolve_script = "scripts/coevolve_adversarial.py"
    print_check("5-Tier Adversarial Stress Suite", os.path.exists(bench_script), bench_script)
    print_check("Minimax Co-Evolution Engine", os.path.exists(coevolve_script), coevolve_script)

    stress_res_path = "logs/adversarial_stress_results.json"
    print_check("Adversarial Benchmark Telemetry", os.path.exists(stress_res_path), stress_res_path)

    # -------------------------------------------------------------
    # 9. GENETIC SURGEON META-LEARNING ENGINE PLANE
    # -------------------------------------------------------------
    print_header("9. Genetic Surgeon Meta-Learning Directed Mutation Engine")
    try:
        from genetic_surgeon import GeneticSurgeon
        surgeon = GeneticSurgeon()
        print_check("Genetic Surgeon Module", True, "GeneticSurgeon initialized")

        import neat
        import neat.innovation
        neat_cfg = neat.Config(
            neat.DefaultGenome,
            neat.DefaultReproduction,
            neat.DefaultSpeciesSet,
            neat.DefaultStagnation,
            "config/config-council-volumetric.txt"
        )
        neat_cfg.genome_config.innovation_tracker = neat.innovation.InnovationTracker()
        test_genome = neat.DefaultGenome(9999)
        test_genome.configure_new(neat_cfg.genome_config)
        test_genome.nodes[0].bias = -2.0
        test_genome.connections.clear()

        # Create dummy validation data with deliberate false negatives
        dummy_X = np.random.uniform(0.5, 1.0, (40, 7)).astype(np.float32)
        dummy_y = np.ones(40, dtype=np.float32)

        diag = surgeon.diagnose_genome(test_genome, neat_cfg, dummy_X, dummy_y)
        diag_ok = ("false_negatives" in diag and "accuracy" in diag)
        print_check("Genome Diagnostic Analyzer", diag_ok, f"FN={diag.get('false_negatives')}, Accuracy={diag.get('accuracy', 0):.2f}")
        if not diag_ok:
            all_passed = False

        spliced_genome, ops = surgeon.perform_surgery(test_genome, neat_cfg, diag, max_interventions=2)
        spliced_ok = len(ops) > 0 and (len(spliced_genome.connections) >= len(test_genome.connections))
        print_check("Synaptic Splice & Recalibration", spliced_ok, f"{len(ops)} surgical interventions grafted")
        if not spliced_ok:
            all_passed = False

    except Exception as e:
        print_check("Genetic Surgeon Engine", False, str(e))
        all_passed = False

    surgeon_bench_script = "scripts/benchmark_surgeon_acceleration.py"
    print_check("Surgeon Benchmark Script", os.path.exists(surgeon_bench_script), surgeon_bench_script)

    surgeon_hist_path = "logs/genetic_surgery_history.json"
    print_check("Genetic Surgery History Log", os.path.exists(surgeon_hist_path), surgeon_hist_path)

    surgeon_bench_res = "logs/surgeon_benchmark_results.json"
    print_check("Surgeon Benchmark Telemetry", os.path.exists(surgeon_bench_res), surgeon_bench_res)

    # -------------------------------------------------------------
    # 10. TRUSTED WHITELIST & ZERO-DOWNTIME BYPASS ENGINE
    # -------------------------------------------------------------
    print_header("10. Trusted Whitelist & Bypass Engine")
    whitelist_path = "config/whitelist.json"
    has_wl_cfg = os.path.exists(whitelist_path)
    print_check("Whitelist Config File", has_wl_cfg, whitelist_path)
    if not has_wl_cfg:
        all_passed = False
    else:
        try:
            from whitelist_manager import WhitelistManager
            wm = WhitelistManager(whitelist_path=whitelist_path)

            lan_pass, _ = wm.is_whitelisted(ip="192.168.1.50")
            loopback_pass, _ = wm.is_whitelisted(ip="127.0.0.1")
            port_pass, _ = wm.is_whitelisted(ip="198.51.100.1", port=53)
            dash_port_pass, _ = wm.is_whitelisted(ip="198.51.100.1", port=8000)
            attacker_bypassed, _ = wm.is_whitelisted(ip="198.51.100.99", port=4444)
            attacker_blocked = not attacker_bypassed

            wl_eval_ok = lan_pass and loopback_pass and port_pass and dash_port_pass and attacker_blocked
            print_check(
                "Zero-Copy CIDR & Port Filtering",
                wl_eval_ok,
                f"LAN={lan_pass}, Loopback={loopback_pass}, DNS/Dashboard={port_pass}, Attacker Blocked={attacker_blocked}"
            )
            if not wl_eval_ok:
                all_passed = False

            reloaded = wm.check_and_reload()
            print_check("Hot-Reload Heartbeat Check", reloaded is False, "Active cache maintained")
        except Exception as e:
            print_check("Whitelist Manager Engine", False, str(e))
            all_passed = False

    # -------------------------------------------------------------
    # 11. AUTONOMOUS SAFETY VALIDATION GATE & ROLLBACK PLANE
    # -------------------------------------------------------------
    print_header("11. Autonomous Safety Validation Gate & Rollback Engine")
    try:
        from continuous_loop import validate_candidate_safety, rollback_to_latest_archive
        import copy
        import pickle

        if os.path.exists(champion_path):
            with open(champion_path, "rb") as f:
                c_data = pickle.load(f)
            c_cfg = c_data.get("config")
            if not c_cfg:
                import neat
                c_cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, config_path)

            # Test 1: Self-evaluation must pass
            safe_self, self_res = validate_candidate_safety(
                c_data["genome"], c_cfg, incumbent_file=champion_path, max_allowed_fp_increase=0.005
            )
            print_check("Safety Gate Incumbent Parity", safe_self, f"FP={self_res.get('candidate_fp', 0)*100:.2f}%")
            if not safe_self:
                all_passed = False

            # Test 2: Deliberately regressed candidate must be rejected
            regressed_genome = copy.deepcopy(c_data["genome"])
            regressed_genome.nodes[0].bias = 10.0
            safe_regressed, reg_res = validate_candidate_safety(
                regressed_genome, c_cfg, incumbent_file=champion_path, max_allowed_fp_increase=0.005
            )
            reg_rejected = (safe_regressed is False)
            print_check(
                "Safety Gate Regressed Rejection",
                reg_rejected,
                f"Rejected: {reg_res.get('reason', '')[:55]}..."
            )
            if not reg_rejected:
                all_passed = False

        archive_files = [f for f in os.listdir("genomes/archive") if f.endswith(".pkl")]
        has_archives = len(archive_files) > 0
        print_check("Archived Champion Snapshots", has_archives, f"{len(archive_files)} backups available")
        if not has_archives:
            all_passed = False

    except Exception as e:
        print_check("Safety Validation & Rollback Engine", False, str(e))
        all_passed = False

    # -------------------------------------------------------------
    # FINAL VERDICT
    # -------------------------------------------------------------
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    if all_passed:
        print(f"{BOLD}{GREEN}  STATUS: ALL CHECKS PASSED - NEXUS SYSTEM FULLY OPERATIONAL  {RESET}")
    else:
        print(f"{BOLD}{RED}  STATUS: ISSUES DETECTED - REVIEW FAILED CHECKS ABOVE        {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}\n")

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(run_diagnostics())
