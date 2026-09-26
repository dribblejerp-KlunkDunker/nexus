"""
NEXUS - Continuous Evolution & Hot-Reload Loop
Orchestrates autonomous background evolution cycles, seeds from the current champion,
enforces safety validation gates (FP regression threshold), promotes superior genomes,
and supports automated rollback to archived champions.
"""

import os
import sys
import glob
import time
import shutil
import pickle
import argparse
import logging
import traceback
from datetime import datetime
import numpy as np
import neat

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evolve import run_evolution, load_or_extract_dataset
from neat_vectorized import activate_batch
from council_arbiter import THREAT_THRESHOLD

# Absolute ceiling on held-out false positives, checked in addition to the
# relative regression test below. Without it the gate only compares a candidate
# to the incumbent, so once the incumbent is bad every equally bad successor
# passes -- the gate ratchets nothing. 0.5% matches train_honest.py and README.
MAX_ABSOLUTE_FP_RATE = 0.005

logger = logging.getLogger("NEXUS_EVOLVE_LOOP")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] [CONTINUOUS LOOP] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(ch)

RELOAD_SIGNAL_FILE = "genomes/.reload_signal"
ARCHIVE_DIR = "genomes/archive"


def get_current_champion_fitness(champion_file: str) -> float:
    """Safely extracts fitness score from an active champion pickle."""
    if not os.path.exists(champion_file):
        return -1.0
    try:
        with open(champion_file, "rb") as f:
            data = pickle.load(f)
            if isinstance(data, dict):
                if "fitness" in data and data["fitness"] is not None:
                    return float(data["fitness"])
                if "genome" in data and hasattr(data["genome"], "fitness"):
                    return float(data["genome"].fitness)
            elif hasattr(data, "fitness"):
                return float(data.fitness)
            return -1.0
    except Exception as e:
        logger.warning(f"Failed to read champion fitness from {champion_file}: {e}")
        return -1.0


def trigger_hot_reload():
    """Touches reload signal file to notify live guardians."""
    os.makedirs(os.path.dirname(RELOAD_SIGNAL_FILE), exist_ok=True)
    with open(RELOAD_SIGNAL_FILE, "w") as f:
        f.write(str(time.time()))
    logger.info("Signaled live guardians via .reload_signal.")


def rollback_to_latest_archive(
    champion_file: str = "genomes/champion.pkl",
    archive_dir: str = ARCHIVE_DIR
) -> str | None:
    """
    Rolls back the active champion to the newest valid archive in archive_dir.
    Touches .reload_signal so the sniffer immediately reverts.
    """
    if not os.path.exists(archive_dir):
        logger.error(f"Archive directory '{archive_dir}' does not exist. Cannot rollback.")
        return None

    archive_files = glob.glob(os.path.join(archive_dir, "*.pkl"))
    # Filter for champion pickle archives
    archive_files = [f for f in archive_files if os.path.isfile(f) and os.path.getsize(f) > 0]

    if not archive_files:
        logger.warning(f"No archive pickle files found in '{archive_dir}'. Cannot rollback.")
        return None

    # Sort archives by modification time descending (newest first)
    archive_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    latest_archive = archive_files[0]

    try:
        # Validate that the archive can be loaded
        with open(latest_archive, "rb") as f:
            arch_data = pickle.load(f)
        arch_fit = 0.0
        if isinstance(arch_data, dict):
            arch_fit = arch_data.get("fitness") or getattr(arch_data.get("genome"), "fitness", 0.0)
        elif hasattr(arch_data, "fitness"):
            arch_fit = arch_data.fitness

        logger.info(f"Found latest valid archive: {latest_archive} (Archived Fitness: {float(arch_fit):.4f})")

        # Create emergency backup of current failing champion if present
        if os.path.exists(champion_file):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            regressed_bak = os.path.join(archive_dir, f"rolled_back_champion_{ts}.pkl")
            shutil.copy2(champion_file, regressed_bak)
            logger.info(f"Backed up pre-rollback champion to {regressed_bak}")

        # Overwrite champion with latest archive
        shutil.copy2(latest_archive, champion_file)
        trigger_hot_reload()
        logger.info(f"SUCCESS: Rolled back active champion to {latest_archive}")
        return latest_archive

    except Exception as e:
        logger.error(f"CRITICAL: Failed to execute rollback from {latest_archive}: {e}")
        return None


def validate_candidate_safety(
    candidate_genome,
    candidate_config,
    incumbent_file: str = "genomes/champion.pkl",
    max_allowed_fp_increase: float = 0.005,
    max_allowed_fn_increase: float = 0.02,
    validation_data: tuple = None
) -> tuple[bool, dict]:
    """
    Autonomous Safety Validation Gate:
    Tests candidate genome against holdout validation data.
    Rejects candidate if False Positive rate increases more than max_allowed_fp_increase (0.5%),
    or if False Negative rate increases more than max_allowed_fn_increase (2.0%).
    """
    logger.info("--- [Autonomous Safety Validation Gate] ---")

    # 1. Acquire validation dataset.
    #    This must be the HELD-OUT split. It previously called
    #    load_or_extract_dataset() with no split argument, which returned the
    #    same data the candidate had just been evolved on, so the "validation"
    #    gate was scoring training performance.
    if validation_data is not None:
        X_norm, X_atk = validation_data
    else:
        try:
            X_norm, X_atk = load_or_extract_dataset(base_dir=".", split="val")
        except Exception as e:
            logger.error(f"Failed to load validation dataset: {e}")
            return False, {"passed": False, "reason": f"Validation dataset error: {e}"}

    if len(X_norm) == 0 or len(X_atk) == 0:
        logger.warning("Empty validation dataset. Cannot verify safety; rejecting candidate.")
        return False, {"passed": False, "reason": "Empty validation dataset"}

    # Use up to 6000 samples per class for a deterministic check. The whole
    # split is affordable now that scoring is vectorized.
    np.random.seed(42)
    val_norm = X_norm[np.random.choice(len(X_norm), min(len(X_norm), 6000), replace=False)]
    val_atk = X_atk[np.random.choice(len(X_atk), min(len(X_atk), 6000), replace=False)]

    # 2. Evaluate candidate at the RUNTIME operating point.
    #    Rates were previously measured at 0.5 while sniff_and_respond.py blocks
    #    at THREAT_THRESHOLD, so the gate was not measuring the behaviour that
    #    ships.
    try:
        cand_fp = float(np.mean(activate_batch(candidate_genome, candidate_config,
                                               val_norm.astype(np.float64)) >= THREAT_THRESHOLD))
        cand_fn = float(np.mean(activate_batch(candidate_genome, candidate_config,
                                               val_atk.astype(np.float64)) < THREAT_THRESHOLD))
    except Exception as e:
        logger.error(f"Candidate network evaluation error: {e}")
        return False, {"passed": False, "reason": f"Evaluation exception: {e}"}

    # 3. Evaluate incumbent champion (if present)
    has_incumbent = os.path.exists(incumbent_file)
    inc_fp = 0.0
    inc_fn = 0.0

    if has_incumbent:
        try:
            with open(incumbent_file, "rb") as f:
                inc_data = pickle.load(f)
            inc_genome = inc_data["genome"] if isinstance(inc_data, dict) else inc_data
            inc_config = inc_data.get("config", candidate_config) if isinstance(inc_data, dict) else candidate_config

            inc_fp = float(np.mean(activate_batch(inc_genome, inc_config,
                                                  val_norm.astype(np.float64)) >= THREAT_THRESHOLD))
            inc_fn = float(np.mean(activate_batch(inc_genome, inc_config,
                                                  val_atk.astype(np.float64)) < THREAT_THRESHOLD))
        except Exception as e:
            logger.warning(f"Could not evaluate incumbent champion ({e}). Falling back to baseline check.")
            has_incumbent = False

    # 4. Comparative Safety Checks
    fp_delta = cand_fp - inc_fp
    fn_delta = cand_fn - inc_fn

    metrics = {
        "candidate_fp": cand_fp,
        "candidate_fn": cand_fn,
        "incumbent_fp": inc_fp if has_incumbent else None,
        "incumbent_fn": inc_fn if has_incumbent else None,
        "fp_delta": fp_delta if has_incumbent else 0.0,
        "fn_delta": fn_delta if has_incumbent else 0.0,
        "max_allowed_fp_increase": max_allowed_fp_increase,
        "max_allowed_fn_increase": max_allowed_fn_increase,
    }

    metrics["max_absolute_fp_rate"] = MAX_ABSOLUTE_FP_RATE
    metrics["operating_point"] = THREAT_THRESHOLD

    # Absolute ceiling first. A candidate that is merely no worse than a bad
    # incumbent is still a bad candidate, and the relative test alone would
    # promote it.
    if cand_fp > MAX_ABSOLUTE_FP_RATE:
        reason = (
            f"Candidate false positive rate {cand_fp*100:.2f}% exceeds the absolute ceiling of "
            f"{MAX_ABSOLUTE_FP_RATE*100:.2f}% on held-out real traffic (at threshold {THREAT_THRESHOLD}), "
            f"regardless of the incumbent's {inc_fp*100:.2f}%."
        )
        logger.warning(reason)
        metrics["passed"] = False
        metrics["reason"] = reason
        return False, metrics

    if has_incumbent:
        logger.info(f"Validation Comparison -> FP Rate: Candidate={cand_fp*100:.2f}% | Incumbent={inc_fp*100:.2f}% (Delta: {fp_delta*100:+.2f}%)")
        logger.info(f"Validation Comparison -> FN Rate: Candidate={cand_fn*100:.2f}% | Incumbent={inc_fn*100:.2f}% (Delta: {fn_delta*100:+.2f}%)")

        if fp_delta > max_allowed_fp_increase:
            reason = (
                f"Candidate False Positive rate regressed by {fp_delta*100:+.2f}% "
                f"(cand: {cand_fp*100:.2f}%, inc: {inc_fp*100:.2f}%), "
                f"exceeding max allowed increase of {max_allowed_fp_increase*100:.2f}%."
            )
            metrics["passed"] = False
            metrics["reason"] = reason
            return False, metrics

        if fn_delta > max_allowed_fn_increase:
            reason = (
                f"Candidate False Negative rate regressed by {fn_delta*100:+.2f}% "
                f"(cand: {cand_fn*100:.2f}%, inc: {inc_fn*100:.2f}%), "
                f"exceeding max allowed increase of {max_allowed_fn_increase*100:.2f}%."
            )
            metrics["passed"] = False
            metrics["reason"] = reason
            return False, metrics

        reason = (
            f"Safety Gate Passed: FP={cand_fp*100:.2f}% (delta: {fp_delta*100:+.2f}%), "
            f"FN={cand_fn*100:.2f}% (delta: {fn_delta*100:+.2f}%)"
        )
        metrics["passed"] = True
        metrics["reason"] = reason
        return True, metrics

    else:
        # First-time candidate: same ceiling as everyone else. This branch
        # previously allowed 5.0%, ten times the documented gate, which let a
        # weak model install itself as the incumbent that all later candidates
        # were then compared against.
        if cand_fp > MAX_ABSOLUTE_FP_RATE:
            reason = (f"Candidate FP rate too high for initial champion "
                      f"({cand_fp*100:.2f}% > {MAX_ABSOLUTE_FP_RATE*100:.2f}%)")
            metrics["passed"] = False
            metrics["reason"] = reason
            return False, metrics

        reason = f"Initial Candidate Passed: FP={cand_fp*100:.2f}%, FN={cand_fn*100:.2f}%"
        metrics["passed"] = True
        metrics["reason"] = reason
        return True, metrics


def run_continuous_evolution(
    config_file: str = "config/config-nexus.txt",
    champion_file: str = "genomes/champion.pkl",
    cycle_interval: int = 300,
    generations_per_cycle: int = 10,
    promotion_margin: float = 0.005,
    max_allowed_fp_increase: float = 0.005,
    max_cycles: int = 0  # 0 means infinite
):
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    cycle = 0

    logger.info("Initializing NEXUS Autonomous Continuous Evolution Loop...")
    logger.info(f"Cycle Interval: {cycle_interval}s | Gen/Cycle: {generations_per_cycle} | Margin: {promotion_margin} | Max FP Incr: {max_allowed_fp_increase*100:.2f}%")

    while True:
        cycle += 1
        logger.info(f"\n========== BEGINNING EVOLUTION CYCLE #{cycle} ==========")

        current_fitness = get_current_champion_fitness(champion_file)
        logger.info(f"Current Active Champion Fitness: {current_fitness:.4f}")

        candidate_file = "genomes/candidate_champion.pkl"

        try:
            winner, config = run_evolution(
                config_file=config_file,
                generations=generations_per_cycle,
                output_file=candidate_file,
                seed_champion=champion_file if os.path.exists(champion_file) else None
            )

            new_fitness = float(winner.fitness)
            logger.info(f"Candidate Genome Evolved with Fitness: {new_fitness:.4f}")

            # 1. Check promotion criteria
            if (new_fitness - current_fitness) >= promotion_margin or current_fitness < 0:
                logger.info(f"*** CANDIDATE MET FITNESS CRITERIA! (+{new_fitness - current_fitness:.4f}) ***")

                # 2. Enforce Autonomous Safety Validation Gate
                is_safe, safety_metrics = validate_candidate_safety(
                    candidate_genome=winner,
                    candidate_config=config,
                    incumbent_file=champion_file,
                    max_allowed_fp_increase=max_allowed_fp_increase
                )

                if is_safe:
                    logger.info(f"*** SAFETY GATE PASSED! *** -> {safety_metrics['reason']}")

                    # Archive existing champion
                    if os.path.exists(champion_file):
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        archive_path = os.path.join(ARCHIVE_DIR, f"champion_cycle{cycle}_{ts}.pkl")
                        shutil.copy2(champion_file, archive_path)
                        logger.info(f"Archived previous champion to: {archive_path}")

                    # Promote candidate
                    shutil.copy2(candidate_file, champion_file)
                    trigger_hot_reload()
                    logger.info(f"PROMOTED NEW CHAMPION -> {champion_file}")
                else:
                    logger.warning(f"*** PROMOTION REJECTED BY SAFETY GATE! ***")
                    logger.warning(f"Reason: {safety_metrics['reason']}")
                    logger.warning("Active champion retained without change.")
            else:
                logger.info(f"Candidate did not exceed promotion margin (+{promotion_margin:.4f}). Champion retained.")

        except Exception as e:
            # Log the traceback. A bare `{e}` here printed "19685" for a
            # KeyError and hid a seeding bug that broke every cycle.
            logger.error(f"Error during evolution cycle #{cycle}: {type(e).__name__}: {e}")
            logger.error(traceback.format_exc())
            logger.info("Attempting automatic safety verification of active champion...")
            if not os.path.exists(champion_file):
                logger.warning("Active champion missing! Triggering emergency rollback...")
                rollback_to_latest_archive(champion_file=champion_file)

        if max_cycles > 0 and cycle >= max_cycles:
            logger.info(f"Completed requested {max_cycles} evolution cycles. Exiting loop.")
            break

        logger.info(f"Sleeping for {cycle_interval}s until next evolution cycle...")
        time.sleep(cycle_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Continuous Evolution Loop")
    parser.add_argument("--config", type=str, default="config/config-nexus.txt", help="NEAT config file")
    parser.add_argument("--champion", type=str, default="genomes/champion.pkl", help="Champion genome file")
    parser.add_argument("--interval", type=int, default=60, help="Interval in seconds between cycles")
    parser.add_argument("--generations", type=int, default=5, help="Generations per cycle")
    parser.add_argument("--margin", type=float, default=0.001, help="Fitness margin required to promote")
    parser.add_argument("--max-fp-increase", type=float, default=0.005, help="Max allowed validation FP rate increase (default: 0.005 = 0.5%%)")
    parser.add_argument("--cycles", type=int, default=1, help="Number of cycles to run (0=infinite)")
    parser.add_argument("--rollback", action="store_true", help="Perform emergency rollback to latest archived champion and exit")
    parser.add_argument("--test-safety", action="store_true", help="Run safety validation on the current champion against itself")
    args = parser.parse_args()

    if args.rollback:
        restored = rollback_to_latest_archive(champion_file=args.champion)
        if restored:
            print(f"[NEXUS] Emergency rollback successful. Active champion restored from {restored}")
            sys.exit(0)
        else:
            print("[NEXUS] Emergency rollback failed: No archives found.")
            sys.exit(1)

    if args.test_safety:
        if not os.path.exists(args.champion):
            print(f"[NEXUS] Cannot test safety: Champion {args.champion} not found.")
            sys.exit(1)
        with open(args.champion, "rb") as f:
            data = pickle.load(f)
        cfg = data.get("config")
        if not cfg:
            cfg = neat.Config(neat.DefaultGenome, neat.DefaultReproduction, neat.DefaultSpeciesSet, neat.DefaultStagnation, args.config)
        safe, res = validate_candidate_safety(data["genome"], cfg, incumbent_file=args.champion, max_allowed_fp_increase=args.max_fp_increase)
        print(f"[NEXUS Safety Test Result]: Safe={safe}, Details={res}")
        sys.exit(0 if safe else 1)

    run_continuous_evolution(
        config_file=args.config,
        champion_file=args.champion,
        cycle_interval=args.interval,
        generations_per_cycle=args.generations,
        promotion_margin=args.margin,
        max_allowed_fp_increase=args.max_fp_increase,
        max_cycles=args.cycles
    )
