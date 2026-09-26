"""
NEXUS - NeuroEvolution Engine (NEAT)
Evolves lightweight, high-speed neural networks to detect network anomalies and attacks.
"""

import os
import copy
import glob
from itertools import count
import pickle
import argparse
import numpy as np
import neat
from feature_extractor import extract_from_pcap, NUM_FEATURES

CORPUS_PATH = os.path.join("data", "corpus_v2.npz")


def load_or_extract_dataset(base_dir: str = ".", split: str = "train"):
    """Loads the leak-free corpus. Falls back to raw PCAPs only if it is absent.

    This loader is shared by continuous_loop.py, dashboard.py and
    distributed_ray_evolve.py, so whatever it returns is what every background
    evolution path trains on.

    It used to glob data/normal_traffic/*.pcap and data/attack_samples/*.pcap.
    Those directories contain generated traffic whose benign class uses
    ttl in {64, 128} while real inbound packets arrive in the 46-54 band the
    attack class occupies. Any run seeded from those files re-learns
    "decremented TTL -> attack" and scores roughly half of real home traffic as
    hostile, which is how a champion promoted by the continuous loop could
    silently undo a corpus rebuild.

    It also used to CALL generate_synthetic_datasets() when the PCAPs were
    missing, so deleting the bad data simply recreated it. That path is gone:
    with no corpus and no captures this raises, because training on regenerated
    synthetic traffic is worse than not training.
    """
    corpus = os.path.join(base_dir, CORPUS_PATH)
    if os.path.exists(corpus):
        d = np.load(corpus, allow_pickle=True)
        X = d[f"X_{split}"]
        y = d[f"y_{split}"]
        X_norm, X_atk = X[y == 0], X[y == 1]
        print(f"[NEXUS Evolve] Corpus '{split}' split: {len(X_norm)} benign (real capture), "
              f"{len(X_atk)} attack.")
        return X_norm, X_atk

    normal_pcaps = glob.glob(os.path.join(base_dir, "data", "normal_traffic", "*.pcap"))
    attack_pcaps = glob.glob(os.path.join(base_dir, "data", "attack_samples", "*.pcap"))

    if not normal_pcaps or not attack_pcaps:
        raise FileNotFoundError(
            f"No corpus at {corpus} and no capture PCAPs to fall back on.\n"
            "Build the corpus first:  python scripts/build_corpus_v2.py\n"
            "Synthetic traffic is deliberately NOT generated here -- a model trained "
            "on it flags ~50% of real traffic as an attack."
        )

    print(f"[NEXUS Evolve] WARNING: no {corpus}; falling back to raw PCAP glob. "
          "Run build_corpus_v2.py -- PCAP-glob training has no holdout and no leak audit.")

    normal_list = [f for f in (extract_from_pcap(p) for p in normal_pcaps) if len(f) > 0]
    attack_list = [f for f in (extract_from_pcap(p) for p in attack_pcaps) if len(f) > 0]

    X_norm = np.vstack(normal_list) if normal_list else np.empty((0, NUM_FEATURES))
    X_atk = np.vstack(attack_list) if attack_list else np.empty((0, NUM_FEATURES))

    print(f"[NEXUS Evolve] Loaded {len(X_norm)} normal samples, {len(X_atk)} attack samples.")
    return X_norm, X_atk


def eval_genomes(genomes, config, X_norm, X_atk):
    """Population fitness, using the single shared definition.

    This previously scored at a 0.5 threshold with a 0.3 false-positive penalty,
    while the runtime blocks at 0.85 and the promotion gate checks at 0.85. A
    genome could therefore be evolved against one decision boundary and judged
    against another. There is now one fitness function and one operating point
    (council_arbiter.THREAT_THRESHOLD) for every evolution path in the project.
    """
    from train_honest import fitness_of
    from neat_vectorized import activate_batch

    X = np.vstack([X_norm, X_atk]).astype(np.float64)
    y = np.concatenate([np.zeros(len(X_norm), dtype=np.int8),
                        np.ones(len(X_atk), dtype=np.int8)])

    for _, genome in genomes:
        genome.fitness = fitness_of(activate_batch(genome, config, X), y)


def run_evolution(config_file: str, generations: int = 25, output_file: str = "genomes/champion.pkl", seed_champion: str = None):
    """
    Executes the NEAT evolution cycle.
    """
    print(f"[NEXUS Evolve] Loading config: {config_file}")
    config = neat.Config(
        neat.DefaultGenome,
        neat.DefaultReproduction,
        neat.DefaultSpeciesSet,
        neat.DefaultStagnation,
        config_file
    )

    X_norm, X_atk = load_or_extract_dataset(base_dir=".")

    # No subsampling.
    #
    # This used to cut both classes to 1000 random rows per run for speed, which
    # made fitness non-comparable across runs: continuous_loop.py compares a
    # candidate's fitness against the fitness stored in the champion pickle,
    # and that number was computed on the full training split by
    # train_honest.py. Comparing a 2000-row score to a 23000-row score with a
    # 0.001 promotion margin decides promotions on sampling noise.
    #
    # The vectorized evaluator makes the full split affordable (~0.3s per
    # generation for a 150-genome population), so every fitness in the project
    # is now measured on the same data.

    # Initialize population
    p = neat.Population(config)

    # If seeding from an existing champion:
    if seed_champion and os.path.exists(seed_champion):
        try:
            with open(seed_champion, "rb") as f:
                saved = pickle.load(f)
            seed_genome = saved["genome"] if isinstance(saved, dict) else saved

            # The genome must be filed under its OWN key.
            #
            # This used to be `p.population[1] = seed_genome`, which left the
            # genome's .key as whatever it was when it was saved (19685, say)
            # while it sat in slot 1. neat-python's speciation and reproduction
            # look genomes up by .key, so the first call to reproduce() raised
            # KeyError: 19685 -- swallowed by the broad `except` in
            # continuous_loop.py, which then logged "Error during evolution
            # cycle #1: 19685" and slept. Every seeded cycle failed this way, so
            # the continuous loop had never completed a generation with a
            # champion present.
            #
            # Copying the genome first keeps the on-disk champion immutable:
            # evolution mutates its population in place.
            seeded = copy.deepcopy(seed_genome)
            target_key = next(iter(p.population))
            seeded.key = target_key
            p.population[target_key] = seeded

            # Advance the node-ID allocator past the seeded genome's history.
            #
            # DefaultGenomeConfig.get_new_node_key() lazily seeds its counter
            # from the first genome it is asked about, then asserts that the id
            # it hands out is not already in that genome. A fresh population
            # starts at node {0}, so the counter begins near zero -- but this
            # champion carries nodes [0, 1686, 5556, 5663, 5960, 5978, 6097]
            # from its own evolutionary history. A few hundred generations in,
            # the counter reaches 1686, hands it to the seeded lineage, and
            # neat-python trips its own assertion. Short runs never got far
            # enough to hit it; long ones always would.
            max_node = max(
                (k for g in p.population.values() for k in g.nodes),
                default=config.genome_config.num_outputs
            )
            config.genome_config.node_indexer = count(max_node + 1)

            # Re-speciate so the species representatives refer to the genome now
            # actually in the population rather than the one it replaced.
            p.species.speciate(config, p.population, p.generation)
            print(f"[NEXUS Evolve] Successfully seeded population with {seed_champion} "
                  f"(genome {seed_genome.key} -> slot {target_key})")
        except Exception as e:
            print(f"[NEXUS Evolve] Warning: Could not seed champion: {type(e).__name__}: {e}")

    # Reporters
    p.add_reporter(neat.StdOutReporter(True))
    stats = neat.StatisticsReporter()
    p.add_reporter(stats)

    os.makedirs("logs", exist_ok=True)
    p.add_reporter(neat.Checkpointer(5, filename_prefix="logs/neat-checkpoint-"))

    # Evolutionary loop
    def eval_wrapper(genomes, cfg):
        eval_genomes(genomes, cfg, X_norm, X_atk)

    winner = p.run(eval_wrapper, generations)

    # Save champion
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    payload = {
        "genome": winner,
        "fitness": winner.fitness,
        "config": config,
        "num_inputs": config.genome_config.num_inputs,
        "num_outputs": config.genome_config.num_outputs
    }
    with open(output_file, "wb") as f:
        pickle.dump(payload, f)

    print(f"\n[NEXUS Evolve] EVOLUTION COMPLETE!")
    print(f" -> Best Genome Fitness: {winner.fitness:.4f}")
    print(f" -> Champion saved to: {output_file}")
    return winner, config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS NEAT Evolution Engine")
    parser.add_argument("--config", type=str, default="config/config-nexus.txt", help="Path to NEAT config")
    parser.add_argument("--generations", type=int, default=20, help="Number of evolution generations")
    parser.add_argument("--output", type=str, default="genomes/champion.pkl", help="Output path for champion genome")
    parser.add_argument("--seed", type=str, default=None, help="Path to champion genome to seed from")
    args = parser.parse_args()

    run_evolution(
        config_file=args.config,
        generations=args.generations,
        output_file=args.output,
        seed_champion=args.seed
    )
