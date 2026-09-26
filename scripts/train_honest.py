"""
NEXUS Honest Trainer

Evolves the monolithic champion and the three council specialists against
data/corpus_v2.npz, where the benign class is real captured traffic and the
holdout is a capture session the evolver never sees.

Differences from train_for_real.py that matter to the resulting numbers:

* Fitness penalises false positives ~20x harder than misses. On a home sensor a
  false positive puts a real CDN into the firewall; a miss costs one packet of
  detection on a flood that will send thousands more.
* The reported operating point is the one the runtime actually uses (0.85),
  not 0.5.
* Promotion is gated on the held-out capture, and the gate is the number the
  README quotes.
* Throughput is measured, never written as a constant.
"""

import os
import sys
import time
import json
import pickle
import argparse
from datetime import datetime

import numpy as np
import neat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neat_vectorized import activate_batch
from council_arbiter import VOLUMETRIC_INDICES, RECON_INDICES, PAYLOAD_INDICES, THREAT_THRESHOLD

CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
BOLD = "\033[1m"; RESET = "\033[0m"

# A false positive firewalls a real host. A false negative costs one packet of
# detection on an attack that is, by nature, repetitive.
FP_WEIGHT = 20.0

SPECIALISTS = {
    "volumetric": (VOLUMETRIC_INDICES, "config/config-council-volumetric.txt", "genomes/council_volumetric.pkl"),
    "recon":      (RECON_INDICES,      "config/config-council-recon.txt",      "genomes/council_recon.pkl"),
    "payload":    (PAYLOAD_INDICES,    "config/config-council-payload.txt",    "genomes/council_payload.pkl"),
}


def rates(scores: np.ndarray, y: np.ndarray, thr: float = THREAT_THRESHOLD):
    """True/false positive rate at the runtime operating point."""
    pred = scores >= thr
    fpr = float(pred[y == 0].mean()) if (y == 0).any() else 0.0
    tpr = float(pred[y == 1].mean()) if (y == 1).any() else 0.0
    return tpr, fpr


# Benign scores are pushed below this, attack scores above it, so the
# population keeps a gradient instead of stalling on a step at THREAT_THRESHOLD.
SAFE_BAND = 0.35


def fitness_of(scores: np.ndarray, y: np.ndarray) -> float:
    b, a = scores[y == 0], scores[y == 1]

    # Margin terms. A step function at the operating point gives every genome
    # on the same side of it an identical score, which is what stalled the
    # earlier runs for 30 generations at a time. These stay differentiable.
    margin_clean = 1.0 - float(np.mean(np.clip((b - SAFE_BAND) / (1.0 - SAFE_BAND), 0.0, 1.0)))
    margin_catch = float(np.mean(np.clip((a - SAFE_BAND) / (1.0 - SAFE_BAND), 0.0, 1.0)))
    soft = 0.5 * margin_clean + 0.5 * margin_catch

    # Hard term: the decision the operator actually lives with.
    tpr, fpr = rates(scores, y)
    hard = float(np.clip(tpr - FP_WEIGHT * fpr, 0.0, 1.0))
    return float(max(0.0, 0.35 * soft + 0.65 * hard))


def evolve(X: np.ndarray, y: np.ndarray, config_path: str, generations: int, label: str):
    cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction,
                      neat.DefaultSpeciesSet, neat.DefaultStagnation, config_path)
    n_in = len(cfg.genome_config.input_keys)
    assert X.shape[1] == n_in, f"{label}: config expects {n_in} inputs, data has {X.shape[1]}"

    pop = neat.Population(cfg)
    Xd = X.astype(np.float64)
    history, best_ever, best_fit = [], None, -1.0
    t_start = time.time()
    evals = 0

    def eval_genomes(genomes, config):
        nonlocal best_ever, best_fit, evals
        for _, genome in genomes:
            s = activate_batch(genome, config, Xd)
            genome.fitness = fitness_of(s, y)
            evals += 1
            if genome.fitness > best_fit:
                best_fit, best_ever = genome.fitness, genome

    for gen in range(generations):
        t0 = time.time()
        pop.run(eval_genomes, 1)
        best = max(pop.population.values(), key=lambda g: g.fitness or 0.0)
        s = activate_batch(best, cfg, Xd)
        tpr, fpr = rates(s, y)
        dur = max(1e-6, time.time() - t0)
        print(f"  [{label}] gen {gen:02d} | fit {best.fitness:.4f} | train TPR {tpr*100:5.1f}% "
              f"FPR {fpr*100:5.2f}% | nodes {len(best.nodes)} conns {len(best.connections)} "
              f"| {len(pop.population)/dur:.0f} genome-evals/s")
        history.append({"generation": gen, "best_fitness": round(float(best.fitness), 4),
                        "train_tpr": round(tpr, 4), "train_fpr": round(fpr, 4),
                        "nodes": len(best.nodes), "connections": len(best.connections)})

    elapsed = time.time() - t_start
    measured = evals / max(1e-6, elapsed)
    print(f"  [{label}] {evals} genome evaluations in {elapsed:.1f}s = {measured:.1f} evals/sec (measured)")
    return best_ever, cfg, history, measured


def report(name, genome, cfg, X, y, indices=None):
    Xs = X[:, indices] if indices else X
    s = activate_batch(genome, cfg, Xs.astype(np.float64))
    tpr, fpr = rates(s, y)
    print(f"  {name:22s} TPR {tpr*100:6.2f}%   FPR {fpr*100:6.2f}%   "
          f"({int((s[y==0] >= THREAT_THRESHOLD).sum())} of {int((y==0).sum())} benign flagged)")
    return tpr, fpr


def main():
    ap = argparse.ArgumentParser(description="NEXUS honest trainer")
    ap.add_argument("--corpus", default="data/corpus_v2.npz")
    ap.add_argument("--generations", type=int, default=40)
    ap.add_argument("--max-fpr", type=float, default=0.005,
                    help="Holdout FPR gate for promotion (default 0.5%%, matching the README)")
    ap.add_argument("--no-promote", action="store_true")
    args = ap.parse_args()

    d = np.load(args.corpus, allow_pickle=True)
    X_tr, y_tr, X_va, y_va = d["X_train"], d["y_train"], d["X_val"], d["y_val"]

    print(f"{BOLD}{CYAN}================= NEXUS HONEST TRAINING ================={RESET}")
    print(f"  train   {len(y_tr):6d} vectors  ({int((y_tr==0).sum())} real benign / {int(y_tr.sum())} attack)")
    print(f"  holdout {len(y_va):6d} vectors  ({int((y_va==0).sum())} real benign / {int(y_va.sum())} attack)")
    print(f"  benign sources: {', '.join(d['benign_sources'])} (temporal split {float(d['train_fraction'][0]):.0%}/{1-float(d['train_fraction'][0]):.0%})")
    print(f"  operating point {THREAT_THRESHOLD}, false positives weighted {FP_WEIGHT}x\n")

    results = {"timestamp": datetime.now().isoformat(), "operating_point": THREAT_THRESHOLD}

    print(f"{BOLD}--- Monolith (20-D) ---{RESET}")
    mono, mono_cfg, mono_hist, mono_speed = evolve(
        X_tr, y_tr, "config/config-nexus.txt", args.generations, "monolith")

    print(f"\n{BOLD}--- Council specialists ---{RESET}")
    spec = {}
    for role, (idx, cfg_path, out_path) in SPECIALISTS.items():
        g, c, h, sp = evolve(X_tr[:, idx], y_tr, cfg_path, args.generations, role)
        spec[role] = (g, c, out_path, idx, h)

    print(f"\n{BOLD}================= HOLDOUT (unseen later window) ================={RESET}")
    m_tpr, m_fpr = report("monolith", mono, mono_cfg, X_va, y_va)
    spec_scores = {}
    for role, (g, c, _, idx, _) in spec.items():
        spec_scores[role] = report(f"specialist:{role}", g, c, X_va, y_va, idx)

    results["monolith"] = {"holdout_tpr": round(m_tpr, 4), "holdout_fpr": round(m_fpr, 4),
                           "measured_evals_per_sec": round(mono_speed, 1),
                           "history": mono_hist}

    # Per-specialist gate.
    #
    # The council's PRIORITY_VETO rule lets any single specialist carry the
    # verdict alone. That makes the council exactly as safe as its worst member:
    # one expert with a 35% false positive rate flags a third of all benign
    # traffic no matter how clean the other two are. A specialist that cannot
    # clear the gate on held-out traffic does not get a seat.
    print(f"\n{BOLD}--- Council seats ---{RESET}")
    seated = {}
    for role, (tpr, fpr) in spec_scores.items():
        if fpr <= args.max_fpr:
            seated[role] = (tpr, fpr)
            print(f"{GREEN}  SEATED   {role:12s} TPR {tpr*100:6.2f}%  FPR {fpr*100:5.2f}%{RESET}")
        else:
            print(f"{RED}  REJECTED {role:12s} TPR {tpr*100:6.2f}%  FPR {fpr*100:5.2f}% "
                  f"> gate {args.max_fpr*100:.2f}% -- would veto on benign traffic{RESET}")
    results["specialists"] = {r: {"holdout_tpr": round(t, 4), "holdout_fpr": round(f, 4),
                                  "seated": r in seated} for r, (t, f) in spec_scores.items()}

    promoted = False
    print()
    if args.no_promote:
        print(f"{YELLOW}  --no-promote set; models not written.{RESET}")
    elif m_fpr <= args.max_fpr:
        os.makedirs("genomes/archive", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        for src in ["genomes/champion.pkl"] + [v[2] for v in SPECIALISTS.values()]:
            if os.path.exists(src):
                os.replace(src, f"genomes/archive/{os.path.basename(src)[:-4]}_{ts}.pkl")
        with open("genomes/champion.pkl", "wb") as f:
            pickle.dump({"genome": mono, "config": mono_cfg}, f)
        for role, (g, c, out_path, _, _) in spec.items():
            if role in seated:
                with open(out_path, "wb") as f:
                    pickle.dump({"genome": g, "config": c}, f)
        with open("genomes/council_manifest.json", "w") as f:
            json.dump({"generated": datetime.now().isoformat(),
                       "operating_point": THREAT_THRESHOLD,
                       "holdout_gate_fpr": args.max_fpr,
                       "monolith": {"holdout_tpr": round(m_tpr, 4), "holdout_fpr": round(m_fpr, 4)},
                       "specialists": results["specialists"]}, f, indent=2)
        with open("genomes/.reload_signal", "w") as f:
            f.write(str(time.time()))
        promoted = True
        print(f"{GREEN}{BOLD}  PROMOTED: monolith holdout FPR {m_fpr*100:.2f}% <= gate "
              f"{args.max_fpr*100:.2f}%; {len(seated)}/3 specialists seated{RESET}")
    else:
        print(f"{RED}{BOLD}  NOT PROMOTED: holdout FPR {m_fpr*100:.2f}% exceeds gate "
              f"{args.max_fpr*100:.2f}%. Previous champion retained.{RESET}")
        print(f"{YELLOW}  This is the gate doing its job. Fix the model, not the gate.{RESET}")

    results["promoted"] = promoted
    os.makedirs("logs", exist_ok=True)
    with open("logs/honest_training_results.json", "w") as f:
        json.dump(results, f, indent=2)
    with open("logs/training_history.json", "w") as f:
        json.dump({"evolution_history": mono_hist,
                   "ray_benchmark": {"evals_per_sec": round(mono_speed, 1),
                                     "cores_active": 1, "cluster_nodes": 1,
                                     "measured": True},
                   "population": {"size": mono_cfg.pop_size, "species_count": 0}}, f, indent=2)
    print(f"\n  wrote logs/honest_training_results.json")


if __name__ == "__main__":
    main()
