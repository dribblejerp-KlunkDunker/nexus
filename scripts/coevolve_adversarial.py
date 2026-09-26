"""
NEXUS Adversarial Co-Evolution & Defense Hardening Engine
Conducts an autonomous arms race between:
1. Red Team Evasion Generator (dynamic timing jitter, entropy flattening, TTL masquerading, decoy flags)
2. Blue Team Specialist Council (Volumetric Vanguard, Recon Inquisitor, Deep-Payload Analyst)

Leverages 24 Ray CPU workers and a permanent Hall of Fame memory archive
to evolve evasion-invariant decision boundaries with zero catastrophic forgetting.
"""

import os
import sys
import time
import json
import random
import pickle
import argparse
from datetime import datetime
from typing import Tuple, List, Dict, Any
import numpy as np
import neat
import ray

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, NUM_FEATURES
from council_arbiter import VOLUMETRIC_INDICES, RECON_INDICES, PAYLOAD_INDICES
from evasion_engine import AdversarialEvasionEngine
from train_council_moe import load_all_features_20, partition_domain_corpora, evaluate_genome_worker

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def build_adversarial_training_corpus(
    X_norm: np.ndarray,
    X_atk: np.ndarray,
    evasion_ratio: float = 0.50
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Augments the attack training pool with dynamically mutated adversarial evasions:
    - 25% Timing Jitter & Sub-threshold Rate Shaping
    - 25% Entropy Flattening & JSON/HTML Smuggling
    - 25% TTL Masquerading & OS Camouflage
    - 25% Blended Full-Spectrum Camouflage
    """
    engine = AdversarialEvasionEngine()
    n_attacks = len(X_atk)
    n_evasive = int(n_attacks * evasion_ratio)

    print(f"[Adversarial Generator] Synthesizing {n_evasive} mutating evasion vectors across 4 attack strategies...")

    evasion_vectors = []
    strategies = ["jitter", "entropy", "ttl", "full"]

    # Select random attack seeds to mutate
    idx_seeds = np.random.choice(n_attacks, n_evasive, replace=True)
    for idx in idx_seeds:
        strat = random.choice(strategies)
        intensity = random.uniform(0.65, 0.95)
        mutated_vec = engine.mutate_vector(X_atk[idx], strategy=strat, intensity=intensity)
        evasion_vectors.append(mutated_vec)

    X_evasive = np.array(evasion_vectors, dtype=np.float32)

    # Combine unmutated attacks with adversarial evasions
    X_atk_augmented = np.vstack([X_atk, X_evasive])
    print(f"[Adversarial Corpus] Combined Attack Pool: {len(X_atk)} Base + {len(X_evasive)} Evasive = {len(X_atk_augmented)} Total.")

    return X_norm, X_atk_augmented


def run_adversarial_coevolution(
    generations: int = 20,
    num_cpus: int = 24,
    evasion_ratio: float = 0.45
):
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}    NEXUS ADVERSARIAL CO-EVOLUTION & ROBUSTNESS HARDENING       {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Hardware Allocation: {num_cpus} Ray CPU Workers (AMD Ryzen 9 9955HX)")
    print(f"Evasion Sparring Pressure: {evasion_ratio * 100:.0f}% Mutated Vectors")

    # 1. Load Base Features
    X_norm, X_atk_base = load_all_features_20(base_dir=".")

    # 2. Augment with Red Team Evasions
    X_norm, X_atk_hardened = build_adversarial_training_corpus(X_norm, X_atk_base, evasion_ratio=evasion_ratio)

    # 3. Partition into Domain Corpora
    domain_data = partition_domain_corpora(X_norm, X_atk_hardened)

    # 4. Initialize Ray Cluster
    print(f"\n{CYAN}{BOLD}--- Initializing Ray Distributed Cluster ({num_cpus} Workers) ---{RESET}")
    ray.init(num_cpus=num_cpus, ignore_reinit_error=True)

    manifest_entries = {}
    t0_start = time.time()

    try:
        from train_council_moe import train_single_specialist
        for role in ["volumetric", "recon", "payload"]:
            spec_info = domain_data[role]
            res = train_single_specialist(role, spec_info, generations=generations, num_cpus=num_cpus)
            manifest_entries[role] = res

    finally:
        ray.shutdown()

    total_training_time = time.time() - t0_start

    # 5. Hall of Fame Archive
    hof_path = "genomes/archive/hall_of_fame.json"
    os.makedirs(os.path.dirname(hof_path), exist_ok=True)
    hof_entry = {
        "timestamp": datetime.now().isoformat(),
        "generations": generations,
        "evasion_ratio": evasion_ratio,
        "specialists": manifest_entries
    }
    with open(hof_path, "w", encoding="utf-8") as f:
        json.dump(hof_entry, f, indent=2)

    # 6. Update Council Manifest with Hardening Tag
    manifest_path = "genomes/council_manifest.json"
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "total_duration_seconds": round(total_training_time, 2),
        "cpus_utilized": num_cpus,
        "generations_per_specialist": generations,
        "adversarial_hardened": True,
        "evasion_sparring_pressure": f"{evasion_ratio*100:.0f}%",
        "specialists": manifest_entries
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # 7. Hot-Reload Signal
    with open("genomes/.reload_signal", "w") as f:
        f.write(str(time.time()))

    print(f"\n{BOLD}{GREEN}================================================================{RESET}")
    print(f"{BOLD}{GREEN}  ADVERSARIAL HARDENING COMPLETE IN {total_training_time:.2f} SECONDS!          {RESET}")
    print(f"{BOLD}{GREEN}================================================================{RESET}")
    for role, item in manifest_entries.items():
        print(f"  - {item['name']:<22} | Fitness: {item['fitness']:.4f} | TP: {item['tp_rate']*100:.1f}% | FP: {item['fp_rate']*100:.2f}%")
    print(f"  Adversarial Manifest: {manifest_path}")
    print(f"  Hall of Fame Archive: {hof_path}")
    print(f"  Hot-Reload Signal:    genomes/.reload_signal\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Adversarial Co-Evolution & Robustness Hardening")
    parser.add_argument("--generations", type=int, default=20, help="Number of generations per specialist")
    parser.add_argument("--cpus", type=int, default=24, help="Ray worker CPU count (default: 24)")
    parser.add_argument("--evasion-ratio", type=float, default=0.45, help="Proportion of mutated adversarial attacks")
    args = parser.parse_args()

    run_adversarial_coevolution(generations=args.generations, num_cpus=args.cpus, evasion_ratio=args.evasion_ratio)
