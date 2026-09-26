"""
NEXUS Adversarial Stress Benchmark Suite
Pits the Monolithic Champion and the Specialist Council (MoE) against
5 progressive tiers of adversarial evasion:
- Tier 0: Unmutated Standard Attacks
- Tier 1: Timing & Rate Shaping (Low-and-Slow Jitter)
- Tier 2: TTL Masquerading & OS Camouflage
- Tier 3: Entropy Flattening (Steganographic Padding)
- Tier 4: Blended Full-Spectrum Camouflage (Combined Evasions)

METHODOLOGY FIX (2026-09-21)
----------------------------
Earlier versions of this benchmark reported *detection rate only*, with no
benign traffic in any tier. A model that alerts on EVERYTHING scores 100%.
Every tier now also scores a benign suite (the NORMAL suites from
benchmark_moe_vs_monolith), reporting:

    *_detection   TPR on the (mutated) attack pool
    *_fpr         FPR on the pristine benign pool -- the operational cost
    *_precision   TP / (TP + FP): how much of each alert is real

The benign pool here is still SYNTHETIC (generated suites), so the operational
FPR gate remains the one in train_honest.py / calibrate_tiers.py, which run on
real captured traffic. This benchmark measures evasion resilience, not
deployment readiness.
"""

import os
import sys
import json
import pickle
from datetime import datetime
import numpy as np

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from council_arbiter import CouncilArbiter
from evasion_engine import AdversarialEvasionEngine
from benchmark_moe_vs_monolith import generate_benchmark_test_suites

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

import policy

THRESHOLD = policy.THREAT_THRESHOLD


def _pool_from_suites(suites, category):
    pool = []
    for name, (feats, cat) in suites.items():
        if cat == category:
            pool.extend(feats)
    return np.array(pool, dtype=np.float32)


def _monolith_scores(m_net, m_num_in, X):
    out = np.empty(len(X), dtype=np.float32)
    for i, x in enumerate(X):
        inp = x if m_num_in == 20 else x[:12]
        out[i] = float(m_net.activate(inp)[0])
    return out


def run_adversarial_stress_benchmark():
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}      NEXUS ADVERSARIAL STRESS TEST: MONOLITH vs. COUNCIL (MoE) {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. Load Defenders (via the GenomeVault -- sealed genomes preferred)
    from genomevault import load_genome_and_config, GenomeVaultError
    import neat
    monolith_path = "genomes/champion.pkl"
    if not (os.path.exists(monolith_path)
            or os.path.exists("genomes/champion.ngenome")):
        print(f"{RED}Error: Monolithic champion not found at {monolith_path}{RESET}")
        return
    try:
        m_genome, m_cfg = load_genome_and_config(monolith_path)
    except GenomeVaultError as exc:
        print(f"{RED}Error: GenomeVault refused the champion: {exc}{RESET}")
        return
    m_net = neat.nn.FeedForwardNetwork.create(m_genome, m_cfg)
    m_num_in = len(m_cfg.genome_config.input_keys)

    arbiter = CouncilArbiter()
    print(f"Defenders Online:")
    print(f"  - Monolithic Champion (20-D): Fitness {getattr(m_genome, 'fitness', 0.0):.4f}")
    print(f"  - Specialist Council (MoE):   Mode {arbiter.active_mode}")

    # 2. Pools: attacks to detect, benign to protect
    engine = AdversarialEvasionEngine()
    test_suites = generate_benchmark_test_suites()
    attack_vectors = _pool_from_suites(test_suites, "ATTACK")
    benign_vectors = _pool_from_suites(test_suites, "NORMAL")
    print(f"\n[Sparring Arena] Attack pool: {len(attack_vectors)} intrusion vectors "
          f"| Benign pool: {len(benign_vectors)} legitimate vectors "
          f"(FPR is now measured; detection alone is meaningless)")

    # 3. Benign baselines (pristine -- attacker mutations do not change victim
    #    traffic; the FPR cost is the same bar every tier must clear)
    benign_scores_m = _monolith_scores(m_net, m_num_in, benign_vectors)
    m_fp = int((benign_scores_m >= THRESHOLD).sum())
    moe_fp = 0
    for x in benign_vectors:
        if arbiter.evaluate(x)["is_threat"]:
            moe_fp += 1
    m_fpr = 100.0 * m_fp / len(benign_vectors)
    moe_fpr = 100.0 * moe_fp / len(benign_vectors)
    print(f"[Benign Baseline] Monolith FPR {m_fpr:.2f}% ({m_fp}/{len(benign_vectors)}) "
          f"| Council FPR {moe_fpr:.2f}% ({moe_fp}/{len(benign_vectors)})")

    # 4. Define 5 Adversarial Stress Tiers
    tiers = [
        ("Tier 0: Standard Unmutated Baseline", "none", 0.0),
        ("Tier 1: Timing Jitter & Rate Shaping", "jitter", policy.THREAT_THRESHOLD),
        ("Tier 2: TTL Masquerading & OS Camouflage", "ttl", 1.0),
        ("Tier 3: Entropy Flattening & JSON Padding", "entropy", 0.80),
        ("Tier 4: Blended Full-Spectrum Evasion", "full", 0.90)
    ]

    print(f"\n{BOLD}{CYAN}--- Tiered Adversarial Sparring Evaluation ---{RESET}")
    header = (f"{'Evasion Tier':<42} | {'Mono Det':<13} | {'Mono FPR':<9} "
              f"| {'MoE Det':<13} | {'MoE FPR':<9} | {'MoE Prec':<9} | Leading Expert")
    print(BOLD + header + RESET)
    print("-" * len(header))

    benchmark_summary = []

    for tier_name, strategy, intensity in tiers:
        if strategy == "none":
            perturbed_pool = attack_vectors
        else:
            perturbed_pool = np.array([
                engine.mutate_vector(v, strategy=strategy, intensity=intensity)
                for v in attack_vectors
            ])

        n_samples = len(perturbed_pool)

        # Monolith evaluation (vectorized over scores)
        m_scores = _monolith_scores(m_net, m_num_in, perturbed_pool)
        m_detected = int((m_scores >= THRESHOLD).sum())
        m_rate = 100.0 * m_detected / n_samples

        # MoE Council evaluation
        moe_detected = 0
        expert_votes = {}
        for x in perturbed_pool:
            res = arbiter.evaluate(x)
            if res["is_threat"]:
                moe_detected += 1
            lead = res["leading_expert"]
            expert_votes[lead] = expert_votes.get(lead, 0) + 1
        moe_rate = 100.0 * moe_detected / n_samples

        dominant_expert = max(expert_votes, key=expert_votes.get) if expert_votes else "NONE"

        # Precision: of everything each defender alerted on this tier
        # (mutated attacks + pristine benign), how much was real?
        m_prec = (100.0 * m_detected / (m_detected + m_fp)) if (m_detected + m_fp) else 0.0
        moe_prec = (100.0 * moe_detected / (moe_detected + moe_fp)) if (moe_detected + moe_fp) else 0.0

        def _color(rate, fpr):
            # Good = catches attacks AND keeps the FPR bar. A tier that
            # "detects" everything by alarming on benign traffic is not good.
            if rate >= 90.0 and fpr <= 1.0:
                return GREEN
            if rate >= 75.0 and fpr <= 5.0:
                return YELLOW
            return RED

        cm, cmo = _color(m_rate, m_fpr), _color(moe_rate, moe_fpr)
        print(f"{tier_name:<42} | {cm}{m_rate:>5.1f}%{RESET}      | {cm}{m_fpr:>4.1f}%{RESET}    "
              f"| {cmo}{moe_rate:>5.1f}%{RESET}      | {cmo}{moe_fpr:>4.1f}%{RESET}    "
              f"| {cmo}{moe_prec:>4.1f}%{RESET}    | {dominant_expert}")

        benchmark_summary.append({
            "tier": tier_name,
            "strategy": strategy,
            "intensity": intensity,
            "attack_samples": n_samples,
            "monolith_detection": round(m_rate, 2),
            "moe_detection": round(moe_rate, 2),
            "monolith_fpr": round(m_fpr, 2),
            "moe_fpr": round(moe_fpr, 2),
            "monolith_precision": round(m_prec, 2),
            "moe_precision": round(moe_prec, 2),
            "benign_samples": len(benign_vectors),
            "dominant_expert": dominant_expert
        })

    print("-" * len(header))

    # Resilience summary (detection drop, as before)
    m_base = benchmark_summary[0]["monolith_detection"]
    m_worst = benchmark_summary[4]["monolith_detection"]
    moe_base = benchmark_summary[0]["moe_detection"]
    moe_worst = benchmark_summary[4]["moe_detection"]
    m_drop = m_base - m_worst
    moe_drop = moe_base - moe_worst

    print(f"\n{BOLD}Adversarial Resilience Summary:{RESET}")
    print(f"  - Monolith Detection Drop (Tier 0 -> Tier 4):    -{m_drop:.1f}%   "
          f"(FPR held at {m_fpr:.2f}%)")
    print(f"  - MoE Council Detection Drop (Tier 0 -> Tier 4): -{moe_drop:.1f}%   "
          f"(FPR held at {moe_fpr:.2f}%)")

    # The honest verdict: resilience is only meaningful against a defender
    # that is not merely alarming. Compare (drop, FPR) pairs.
    if moe_drop < m_drop and moe_fpr <= max(1.0, m_fpr):
        advantage = m_drop - moe_drop
        print(f"  {GREEN}{BOLD}VERDICT: Council is more resilient AND at least as quiet "
              f"(+{advantage:.1f}% better retention at <= equal FPR).{RESET}")
    elif moe_fpr > max(1.0, m_fpr):
        print(f"  {YELLOW}VERDICT: Council retains more detection but flags MORE benign "
              f"traffic ({moe_fpr:.2f}% vs {m_fpr:.2f}%) -- resilience bought with "
              f"false alarms.{RESET}")
    else:
        print(f"  {YELLOW}VERDICT: comparable evasion resilience; compare FPR and "
              f"precision before concluding either defender is stronger.{RESET}")

    # Save to disk
    os.makedirs("logs", exist_ok=True)
    out_file = "logs/adversarial_stress_results.json"
    result_data = {
        "timestamp": datetime.now().isoformat(),
        "methodology": "detection (TPR, mutated attacks) AND fpr (pristine benign suite) per tier; benign pool is synthetic -- operational FPR gate is train_honest.py on real captures",
        "threshold": THRESHOLD,
        "benign_pool_size": len(benign_vectors),
        "attack_pool_size": len(attack_vectors),
        "tiers": benchmark_summary,
        "monolith_drop": round(m_drop, 2),
        "moe_drop": round(moe_drop, 2)
    }
    with open(out_file, "w") as f:
        json.dump(result_data, f, indent=2)
    print(f"\nDetailed stress results saved to: {out_file}\n")
    return result_data


if __name__ == "__main__":
    run_adversarial_stress_benchmark()
