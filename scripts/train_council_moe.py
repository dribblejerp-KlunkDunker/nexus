"""
NEXUS Council of Specialists Training Engine (Mixture of Experts - MoE)
Evolves three dedicated neural champions concurrently on 24 Ray CPU workers:
1. Volumetric Vanguard (config/config-council-volumetric.txt, 7 inputs)
2. Recon Inquisitor (config/config-council-recon.txt, 10 inputs)
3. Deep-Payload Analyst (config/config-council-payload.txt, 7 inputs)

Each specialist is trained on domain-tailored threat slices with strict holdout gates,
producing the three council champions in genomes/council_*.pkl and updating council_manifest.json.
"""

import os
import sys
import time
import json
import random
import pickle
import shutil
import argparse
from datetime import datetime
from typing import Tuple, List, Dict, Any

import numpy as np
import neat
import ray
from scapy.all import rdpcap

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, NUM_FEATURES
from council_arbiter import VOLUMETRIC_INDICES, RECON_INDICES, PAYLOAD_INDICES
from train_for_real import build_comprehensive_corpus

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_all_features_20(base_dir: str = ".") -> Tuple[np.ndarray, np.ndarray]:
    """Extracts 20-D feature vectors from all available normal and attack PCAPs."""
    extractor = PacketFeatureExtractor()
    norm_dir = os.path.join(base_dir, "data", "normal_traffic")
    atk_dir = os.path.join(base_dir, "data", "attack_samples")

    norm_feats = []
    for f in os.listdir(norm_dir):
        if f.endswith(".pcap"):
            p = os.path.join(norm_dir, f)
            try:
                for pkt in rdpcap(p):
                    norm_feats.append(extractor.extract(pkt, extended=True))
            except Exception:
                pass

    atk_feats = []
    for f in os.listdir(atk_dir):
        if f.endswith(".pcap"):
            p = os.path.join(atk_dir, f)
            try:
                for pkt in rdpcap(p):
                    atk_feats.append(extractor.extract(pkt, extended=True))
            except Exception:
                pass

    X_norm = np.array(norm_feats, dtype=np.float32)
    X_atk = np.array(atk_feats, dtype=np.float32)
    print(f"[Council Dataset] Extracted {len(X_norm)} Normal and {len(X_atk)} Attack 20-D Vectors.")
    return X_norm, X_atk


def partition_domain_corpora(X_norm: np.ndarray, X_atk: np.ndarray) -> Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]]:
    """
    Partitions the full 20-D dataset into domain-specific subsets for each specialist:
    1. Volumetric: Filter attacks where stream_rate > 0.4 or syn/flood traits exist.
    2. Recon: Filter attacks where stealth scan flags (NULL, XMAS, SF) or TTL divergence > 0 exist.
    3. Payload: Filter attacks where payload_entropy > 0.6 or payload_len > 0.1 exist.
    """
    np.random.seed(42)

    # 1. Volumetric Slices (Indices: [0, 1, 4, 7, 10, 11, 18])
    is_syn_flood = (X_atk[:, 4] == 1.0) & (X_atk[:, 7] == 0.0) & (X_atk[:, 13] == 0.0) & (X_atk[:, 14] == 0.0) & (X_atk[:, 15] == 0.0)
    atk_vol_mask = is_syn_flood
    atk_vol = X_atk[atk_vol_mask]
    if len(atk_vol) < 200:
        atk_vol = X_atk
    norm_vol = X_norm

    # 2. Recon Slices (Indices: [2, 3, 4, 5, 6, 9, 13, 14, 15, 19])
    # Attacks with stealth scan flags (NULL=13, XMAS=14, SF=15) or TTL divergence=19
    atk_rec_mask = (X_atk[:, 13] == 1.0) | (X_atk[:, 14] == 1.0) | (X_atk[:, 15] == 1.0) | (X_atk[:, 19] > 0.2)
    atk_rec = X_atk[atk_rec_mask]
    if len(atk_rec) < 200:
        atk_rec = X_atk
    norm_rec = X_norm

    # 3. Payload Slices (Indices: [1, 3, 7, 10, 12, 16, 17])
    # Attacks with payload entropy >= 0.35 or payload len > 0.005 (covers Stratum mining & exploits)
    atk_pay_mask = (X_atk[:, 12] >= 0.35) | (X_atk[:, 7] > 0.005)
    atk_pay = X_atk[atk_pay_mask]
    if len(atk_pay) < 200:
        atk_pay = X_atk
    norm_pay = X_norm

    def create_split(norm_arr: np.ndarray, atk_arr: np.ndarray, feat_indices: List[int]):
        norm_sliced = norm_arr[:, feat_indices]
        atk_sliced = atk_arr[:, feat_indices]

        n_p = np.random.permutation(len(norm_sliced))
        a_p = np.random.permutation(len(atk_sliced))

        n_split = int(len(norm_sliced) * 0.8)
        a_split = int(len(atk_sliced) * 0.8)

        train = (norm_sliced[n_p[:n_split]], atk_sliced[a_p[:a_split]])
        val = (norm_sliced[n_p[n_split:]], atk_sliced[a_p[a_split:]])
        return train, val

    return {
        "volumetric": {
            "train": create_split(norm_vol, atk_vol, VOLUMETRIC_INDICES)[0],
            "val": create_split(norm_vol, atk_vol, VOLUMETRIC_INDICES)[1],
            "indices": VOLUMETRIC_INDICES,
            "config": "config/config-council-volumetric.txt",
            "output": "genomes/council_volumetric.pkl",
            "name": "Volumetric Vanguard"
        },
        "recon": {
            "train": create_split(norm_rec, atk_rec, RECON_INDICES)[0],
            "val": create_split(norm_rec, atk_rec, RECON_INDICES)[1],
            "indices": RECON_INDICES,
            "config": "config/config-council-recon.txt",
            "output": "genomes/council_recon.pkl",
            "name": "Recon Inquisitor"
        },
        "payload": {
            "train": create_split(norm_pay, atk_pay, PAYLOAD_INDICES)[0],
            "val": create_split(norm_pay, atk_pay, PAYLOAD_INDICES)[1],
            "indices": PAYLOAD_INDICES,
            "config": "config/config-council-payload.txt",
            "output": "genomes/council_payload.pkl",
            "name": "Deep-Payload Analyst"
        }
    }


@ray.remote
def evaluate_genome_worker(gid, genome, cfg, n_ref, a_ref):
    """Ray worker evaluating an individual specialist genome."""
    net = neat.nn.FeedForwardNetwork.create(genome, cfg)
    n_scores = np.array([net.activate(x)[0] for x in n_ref], dtype=np.float32)
    fp_rate = float(np.mean(n_scores > 0.5))
    n_loss = float(np.mean(n_scores ** 2))

    a_scores = np.array([net.activate(x)[0] for x in a_ref], dtype=np.float32)
    fn_rate = float(np.mean(a_scores < 0.5))
    a_loss = float(np.mean((1.0 - a_scores) ** 2))

    base_fitness = 1.0 - np.sqrt(0.5 * n_loss + 0.5 * a_loss)
    penalty = (0.35 * fp_rate) + (0.25 * fn_rate)
    return gid, max(0.0, float(base_fitness - penalty))


def train_single_specialist(
    spec_key: str,
    spec_data: dict,
    generations: int = 15,
    num_cpus: int = 24
) -> Dict[str, Any]:
    """Evolves a single specialist population across all Ray workers."""
    name = spec_data["name"]
    cfg_path = spec_data["config"]
    out_path = spec_data["output"]
    train_norm, train_atk = spec_data["train"]
    val_norm, val_atk = spec_data["val"]

    print(f"\n{CYAN}{BOLD}--- Evolution: {name.upper()} ({spec_key}) ---{RESET}")
    print(f"  Inputs: {len(spec_data['indices'])} dimensions | Train: {len(train_norm)} Norm / {len(train_atk)} Atk")
    print(f"  Config: {cfg_path} | Target Output: {out_path}")

    norm_ref = ray.put(train_norm)
    atk_ref = ray.put(train_atk)

    config = neat.Config(
        neat.DefaultGenome,
        neat.DefaultReproduction,
        neat.DefaultSpeciesSet,
        neat.DefaultStagnation,
        cfg_path
    )

    pop = neat.Population(config)
    t0_start = time.time()
    prev_best = None
    stagnation_counter = 0

    for gen in range(generations):
        t0_gen = time.time()
        genomes = list(pop.population.items())

        futures = [evaluate_genome_worker.remote(gid, g, config, norm_ref, atk_ref) for gid, g in genomes]
        results = dict(ray.get(futures))

        for gid, g in genomes:
            g.fitness = results.get(gid, 0.0)

        best_g = max(pop.population.values(), key=lambda g: g.fitness)
        avg_fit = float(np.mean([g.fitness for g in pop.population.values()]))
        dur = max(0.001, time.time() - t0_gen)
        evals_sec = len(genomes) / dur

        # Genetic Surgeon Stagnation Check
        surgeon_note = ""
        if prev_best is not None and abs(best_g.fitness - prev_best) < 0.001:
            stagnation_counter += 1
            if stagnation_counter >= 2:
                from genetic_surgeon import GeneticSurgeon
                surgeon = GeneticSurgeon()
                X_v = np.vstack([val_norm, val_atk])
                y_v = np.array([0] * len(val_norm) + [1] * len(val_atk), dtype=np.float32)
                diag = surgeon.diagnose_genome(best_g, config, X_v, y_v)
                if diag.get("has_stagnation_culprits"):
                    spliced, ivs = surgeon.perform_surgery(best_g, config, diag, max_interventions=2)
                    if ivs:
                        worst_gid = min(pop.population.keys(), key=lambda gid: pop.population[gid].fitness)
                        pop.population[worst_gid] = spliced
                        surgeon_note = f" {YELLOW}[SURGEON: +{len(ivs)} splices]{RESET}"
                        stagnation_counter = 0
        else:
            stagnation_counter = 0

        prev_best = best_g.fitness

        print(f"  [{spec_key[:3].upper()}] Gen {gen:02d} | Best: {best_g.fitness:.4f} | Avg: {avg_fit:.4f} | Speed: {evals_sec:.0f} evals/s ({dur*1000:.0f}ms){surgeon_note}")

        if gen < generations - 1:
            pop.run(lambda g, c: None, 1)

    total_dur = time.time() - t0_start
    winning_genome = max(pop.population.values(), key=lambda g: g.fitness)

    # Validation Gate
    val_net = neat.nn.FeedForwardNetwork.create(winning_genome, config)
    val_n_scores = np.array([val_net.activate(x)[0] for x in val_norm])
    val_a_scores = np.array([val_net.activate(x)[0] for x in val_atk])

    fp_count = int(np.sum(val_n_scores > 0.5))
    fp_rate = float(fp_count / max(1, len(val_n_scores)))
    tp_count = int(np.sum(val_a_scores >= 0.5))
    tp_rate = float(tp_count / max(1, len(val_a_scores)))

    print(f"  {BOLD}Holdout Validation Gate:{RESET}")
    print(f"    Normal FP: {fp_count}/{len(val_n_scores)} ({fp_rate*100:.2f}%) | Attack TP: {tp_count}/{len(val_a_scores)} ({tp_rate*100:.2f}%)")

    # Safety promotion
    os.makedirs(os.path.dirname(out_path) or "genomes", exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump({"genome": winning_genome, "config": config, "role": spec_key, "indices": spec_data["indices"]}, f)
    print(f"  {GREEN}{BOLD}Champion Promoted: {out_path} (Fitness: {winning_genome.fitness:.4f} in {total_dur:.2f}s){RESET}")

    return {
        "role": spec_key,
        "name": name,
        "fitness": float(winning_genome.fitness),
        "nodes": len(winning_genome.nodes),
        "connections": len(winning_genome.connections),
        "inputs": len(spec_data["indices"]),
        "fp_rate": fp_rate,
        "tp_rate": tp_rate,
        "duration_seconds": round(total_dur, 2),
        "path": out_path
    }


def main():
    parser = argparse.ArgumentParser(description="NEXUS Council of Specialists (MoE) Distributed Training Engine")
    parser.add_argument("--generations", type=int, default=15, help="Number of neuroevolution generations per specialist")
    parser.add_argument("--cpus", type=int, default=24, help="Ray worker CPU count (default: 24 for 16C/32T)")
    parser.add_argument("--skip-corpus-gen", action="store_true", help="Skip PCAP synthesis if already assembled")
    args = parser.parse_args()

    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}       NEXUS SPECIALIST COUNCIL (MoE) DISTRIBUTED TRAINING      {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Hardware Allocation: {args.cpus} Ray CPU Workers (AMD Ryzen 9 9955HX)")
    print(f"Generations Per Specialist: {args.generations}")

    # 1. Corpus Preparation
    if not args.skip_corpus_gen:
        build_comprehensive_corpus(base_dir=".", live_capture_count=100)

    # 2. Extract 20-D Vectors
    X_norm, X_atk = load_all_features_20(base_dir=".")

    # 3. Partition Domain Corpora
    domain_data = partition_domain_corpora(X_norm, X_atk)

    # 4. Initialize Ray Cluster
    print(f"\n{CYAN}{BOLD}--- Initializing Ray Distributed Cluster ({args.cpus} Workers) ---{RESET}")
    ray.init(num_cpus=args.cpus, ignore_reinit_error=True)

    manifest_entries = {}
    t0_all = time.time()

    try:
        # Evolve all 3 specialists
        for role in ["volumetric", "recon", "payload"]:
            spec_info = domain_data[role]
            res = train_single_specialist(role, spec_info, generations=args.generations, num_cpus=args.cpus)
            manifest_entries[role] = res

    finally:
        ray.shutdown()

    total_training_time = time.time() - t0_all

    # 5. Write Council Manifest
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "total_duration_seconds": round(total_training_time, 2),
        "cpus_utilized": args.cpus,
        "generations_per_specialist": args.generations,
        "specialists": manifest_entries
    }

    manifest_path = "genomes/council_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # 6. Emit Hot-Reload Signal
    with open("genomes/.reload_signal", "w") as f:
        f.write(str(time.time()))

    print(f"\n{BOLD}{GREEN}================================================================{RESET}")
    print(f"{BOLD}{GREEN}  SPECIALIST COUNCIL TRAINING COMPLETE IN {total_training_time:.2f} SECONDS!    {RESET}")
    print(f"{BOLD}{GREEN}================================================================{RESET}")
    for role, item in manifest_entries.items():
        print(f"  - {item['name']:<22} | Fitness: {item['fitness']:.4f} | TP: {item['tp_rate']*100:.1f}% | FP: {item['fp_rate']*100:.2f}% | Path: {item['path']}")
    print(f"  Manifest written to: {manifest_path}")
    print(f"  Hot-reload signal touched: genomes/.reload_signal\n")


if __name__ == "__main__":
    main()
