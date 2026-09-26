"""
NEXUS - Phase 4 Distributed Neuroevolution Engine (Ray)
Distributes NEAT genome evaluations across multi-machine Ray clusters or high-core workstations.
Zero-copy shared memory datasets via Ray plasma object store.
"""

import os
import sys
import time
import pickle
import argparse
import numpy as np
import neat
import ray

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evolve import load_or_extract_dataset


@ray.remote
def eval_single_genome_remote(genome_id, genome, config, X_norm, X_atk):
    """
    Evaluates a single genome on remote Ray worker.
    Uses zero-copy reference to X_norm and X_atk in Ray object store.
    """
    net = neat.nn.FeedForwardNetwork.create(genome, config)

    # 1. Normal traffic evaluation (target = 0.0)
    norm_scores = np.array([net.activate(x)[0] for x in X_norm], dtype=np.float32)
    fp_rate = float(np.mean(norm_scores > 0.5))
    norm_loss = float(np.mean(norm_scores ** 2))

    # 2. Attack traffic evaluation (target = 1.0)
    atk_scores = np.array([net.activate(x)[0] for x in X_atk], dtype=np.float32)
    fn_rate = float(np.mean(atk_scores < 0.5))
    atk_loss = float(np.mean((1.0 - atk_scores) ** 2))

    # Combined fitness
    base_fitness = 1.0 - np.sqrt(0.5 * norm_loss + 0.5 * atk_loss)
    penalty = (0.3 * fp_rate) + (0.2 * fn_rate)
    fitness = max(0.0, float(base_fitness - penalty))

    return genome_id, fitness


class RayDistributedEvaluator:
    def __init__(self, config, X_norm, X_atk):
        self.config = config
        # Put datasets into Ray plasma object store for zero-copy parallel access
        self.X_norm_ref = ray.put(X_norm)
        self.X_atk_ref = ray.put(X_atk)

    def evaluate_population(self, genomes, config):
        # Dispatch remote evaluation tasks across Ray cluster
        futures = [
            eval_single_genome_remote.remote(
                gid, g, config, self.X_norm_ref, self.X_atk_ref
            )
            for gid, g in genomes
        ]

        # Gather all evaluated fitnesses
        results = ray.get(futures)
        fitness_map = dict(results)

        for gid, g in genomes:
            g.fitness = fitness_map.get(gid, 0.0)


def run_distributed_evolution(
    config_file: str = "config/config-nexus.txt",
    generations: int = 15,
    output_file: str = "genomes/champion_distributed.pkl",
    seed_champion: str = "genomes/champion.pkl",
    ray_address: str = None,
    num_cpus: int = None
):
    # Initialize Ray
    if ray_address:
        print(f"[NEXUS Ray] Connecting to existing Ray Cluster at: {ray_address}")
        ray.init(address=ray_address, ignore_reinit_error=True)
    else:
        print(f"[NEXUS Ray] Initializing local Ray cluster (CPUs: {num_cpus or 'auto'})...")
        ray.init(num_cpus=num_cpus, ignore_reinit_error=True)

    cluster_resources = ray.cluster_resources()
    print(f"[NEXUS Ray] Cluster Ready! Total Cluster CPUs: {cluster_resources.get('CPU', 0)}")

    config = neat.Config(
        neat.DefaultGenome,
        neat.DefaultReproduction,
        neat.DefaultSpeciesSet,
        neat.DefaultStagnation,
        config_file
    )

    X_norm, X_atk = load_or_extract_dataset(base_dir=".")

    # Initialize population
    p = neat.Population(config)

    # Seed from previous champion if present
    if seed_champion and os.path.exists(seed_champion):
        try:
            with open(seed_champion, "rb") as f:
                saved = pickle.load(f)
                seed_genome = saved["genome"] if isinstance(saved, dict) else saved
                p.population[1] = seed_genome
                print(f"[NEXUS Ray] Seeded population with {seed_champion}")
        except Exception as e:
            print(f"[NEXUS Ray] Warning: Could not seed champion: {e}")

    p.add_reporter(neat.StdOutReporter(True))
    stats = neat.StatisticsReporter()
    p.add_reporter(stats)

    evaluator = RayDistributedEvaluator(config, X_norm, X_atk)

    t_start = time.time()
    winner = p.run(evaluator.evaluate_population, generations)
    t_elapsed = time.time() - t_start

    total_evals = generations * config.pop_size
    evals_per_sec = total_evals / max(0.001, t_elapsed)

    print(f"\n[NEXUS Ray] DISTRIBUTED EVOLUTION COMPLETED in {t_elapsed:.2f}s!")
    print(f" -> Best Genome Fitness: {winner.fitness:.4f}")
    print(f" -> Total Evaluations: {total_evals} ({evals_per_sec:.1f} evals/sec)")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    payload = {
        "genome": winner,
        "fitness": winner.fitness,
        "config": config,
        "distributed_time_sec": t_elapsed,
        "evals_per_sec": evals_per_sec
    }
    with open(output_file, "wb") as f:
        pickle.dump(payload, f)
    print(f" -> Champion saved to: {output_file}")

    ray.shutdown()
    return winner, t_elapsed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Phase 4 Distributed Ray Evolution")
    parser.add_argument("--config", type=str, default="config/config-nexus.txt", help="NEAT config file")
    parser.add_argument("--generations", type=int, default=10, help="Generations to evolve")
    parser.add_argument("--output", type=str, default="genomes/champion_distributed.pkl", help="Output champion path")
    parser.add_argument("--seed", type=str, default="genomes/champion.pkl", help="Seed champion path")
    parser.add_argument("--address", type=str, default=None, help="Ray cluster address (e.g. auto, ray://<ip>:10001)")
    parser.add_argument("--cpus", type=int, default=None, help="CPUs to allocate (default: all available)")
    args = parser.parse_args()

    run_distributed_evolution(
        config_file=args.config,
        generations=args.generations,
        output_file=args.output,
        seed_champion=args.seed,
        ray_address=args.address,
        num_cpus=args.cpus
    )
