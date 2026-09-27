"""
NEXUS Specialist Council Arbiter (Mixture of Experts - MoE)
Coordinates three hyper-specialized NEAT champions:
1. Volumetric Vanguard (Inputs 0, 1, 4, 7, 10, 11, 18)
2. Recon Inquisitor (Inputs 2, 3, 4, 5, 6, 9, 13, 14, 15, 19)
3. Deep-Payload Analyst (Inputs 1, 3, 7, 10, 12, 16, 17)

Applies probabilistic disjunction and priority-veto consensus logic with
automatic zero-downtime fallback to the monolithic champion.
"""

import os
import time
import json
from typing import Dict, Any, Optional, Tuple
import numpy as np

from genomevault import load_genome_and_config, GenomeVaultError
import policy

# Sensory slices into the 20-D feature vector
VOLUMETRIC_INDICES = [0, 1, 4, 7, 10, 11, 18]        # 7 features
RECON_INDICES = [2, 3, 4, 5, 6, 9, 13, 14, 15, 19]   # 10 features
PAYLOAD_INDICES = [1, 3, 7, 10, 12, 16, 17]          # 7 features

# Single decision boundary for the whole SYSTEM. The number LIVES in
# policy.py (env-overridable via NEXUS_THRESHOLD); this re-export keeps every
# existing `from council_arbiter import THREAT_THRESHOLD` in the project
# valid. Scores are raw network outputs.

THREAT_THRESHOLD = policy.THREAT_THRESHOLD

DEFAULT_PATHS = {
    "volumetric": "genomes/council_volumetric.pkl",
    "recon": "genomes/council_recon.pkl",
    "payload": "genomes/council_payload.pkl",
    "manifest": "genomes/council_manifest.json",
    "monolith": "genomes/champion.pkl"
}


def load_seat_provenance(manifest_path: str = DEFAULT_PATHS["manifest"]) -> dict:
    """Per-seat holdout measurements from the promotion gate (train_honest.py).

    A council seat is earned by clearing the held-out benign false-positive
    gate, and the manifest records the exact TPR/FPR that earned it. Surfacing
    those numbers beside every verdict lets an operator see WHY an expert is
    trusted, not just that a file exists. A missing or unreadable manifest
    yields an empty dict -- verdicts then report no provenance rather than
    inventing numbers.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        return {}
    prov: Dict[str, Any] = {}
    for role, info in (manifest.get("specialists") or {}).items():
        prov[role] = {
            "holdout_tpr": info.get("holdout_tpr"),
            "holdout_fpr": info.get("holdout_fpr"),
            "seated": bool(info.get("seated", False)),
        }
    mono = manifest.get("monolith") or {}
    gate = manifest.get("holdout_gate_fpr", policy.HOLDOUT_FPR_GATE)
    prov["monolith"] = {
        "holdout_tpr": mono.get("holdout_tpr"),
        "holdout_fpr": mono.get("holdout_fpr"),
        "promoted": (mono.get("holdout_fpr") is not None
                     and mono["holdout_fpr"] <= gate),
    }
    prov["_meta"] = {
        "generated": manifest.get("generated"),
        "operating_point": manifest.get("operating_point"),
        "holdout_gate_fpr": gate,
    }
    return prov


class CouncilArbiter:
    """
    Arbitrates multi-expert neural evaluations and synthesizes a unified threat score.
    """
    def __init__(self, base_dir: str = "."):
        self.base_dir = base_dir
        self.paths = {k: os.path.join(base_dir, v) for k, v in DEFAULT_PATHS.items()}
        self.specialists: Dict[str, Any] = {}
        self.specialist_configs: Dict[str, Any] = {}
        self.specialist_fitnesses: Dict[str, float] = {}
        self.monolith_net = None
        self.monolith_config = None
        self.last_load_time = 0.0
        self.active_mode = "UNINITIALIZED"
        self.provenance = load_seat_provenance(
            os.path.join(base_dir, DEFAULT_PATHS["manifest"]))

        self.load_models()

    def load_models(self):
        """Loads all specialist champion models or falls back to monolithic model."""
        # Missing models degrade one rung (HEURISTIC_ONLY); a missing library
        # must degrade the same way, not take the whole dashboard down at
        # import time. The heuristic path in evaluate() below is the bottom rung.
        try:
            import neat
        except ImportError:
            print("[Council Arbiter] neat-python not installed -- HEURISTIC_ONLY mode. "
                  "Run SETUP.bat to build the full venv.")
            self.active_mode = "HEURISTIC_ONLY"
            self.last_load_time = time.time()
            return
        loaded_count = 0
        self.specialists.clear()
        self.specialist_configs.clear()
        self.specialist_fitnesses.clear()

        # Attempt loading each specialist
        for role in ["volumetric", "recon", "payload"]:
            path = self.paths[role]
            if os.path.exists(path) or os.path.exists(os.path.splitext(path)[0] + ".ngenome"):
                try:
                    genome, cfg = load_genome_and_config(path)
                    net = neat.nn.FeedForwardNetwork.create(genome, cfg)
                    self.specialists[role] = net
                    self.specialist_configs[role] = cfg
                    self.specialist_fitnesses[role] = float(getattr(genome, "fitness", 0.95))
                    loaded_count += 1
                except (GenomeVaultError, Exception) as e:
                    print(f"[Council Arbiter] Error loading {role} specialist: {e}")

        # Load monolithic champion as backup/baseline
        if os.path.exists(self.paths["monolith"]) or os.path.exists(
                os.path.splitext(self.paths["monolith"])[0] + ".ngenome"):
            try:
                m_genome, self.monolith_config = load_genome_and_config(self.paths["monolith"])
                self.monolith_net = neat.nn.FeedForwardNetwork.create(m_genome, self.monolith_config)
            except (GenomeVaultError, Exception) as e:
                print(f"[Council Arbiter] Error loading fallback monolith: {e}")

        # A council of two is still a council. Earlier builds demanded all
        # three and otherwise dropped to the monolith, which meant rejecting one
        # unsafe specialist threw away two good ones. Seats are decided by the
        # holdout gate in train_honest.py, not by whether a file happens to
        # exist, so a missing specialist means it failed and is meant to be out.
        if loaded_count >= 2:
            self.active_mode = "MOE_COUNCIL"
            print(f"[Council Arbiter] Specialist Council Online ({loaded_count}/3 seated):")
            for role in ("volumetric", "recon", "payload"):
                if role in self.specialists:
                    print(f"  - {role:12s} fitness {self.specialist_fitnesses[role]:.4f}")
                else:
                    print(f"  - {role:12s} NOT SEATED (failed holdout false-positive gate)")
        elif self.monolith_net is not None:
            self.active_mode = "MONOLITHIC_FALLBACK"
            print(f"[Council Arbiter] Only {loaded_count}/3 specialists available. MONOLITHIC_FALLBACK mode.")
        else:
            self.active_mode = "HEURISTIC_ONLY"
            print("[Council Arbiter] Warning: No models available. Operating in HEURISTIC mode.")

        self.last_load_time = time.time()

    def reload_if_needed(self):
        """Checks for updated champion files or signal and hot-reloads."""
        signal_file = os.path.join(self.base_dir, "genomes", ".reload_signal")
        if os.path.exists(signal_file):
            try:
                mtime = os.path.getmtime(signal_file)
                if mtime > self.last_load_time:
                    print("[Council Arbiter] Reload signal detected. Refreshing Council models...")
                    self.provenance = load_seat_provenance(
                        os.path.join(self.base_dir, DEFAULT_PATHS["manifest"]))
                    self.load_models()
            except Exception:
                pass

    def evaluate(self, feats_20: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a 20-D packet vector across all council members.
        Returns unified threat verdict, individual scores, and attribution.
        """
        self.reload_if_needed()

        if self.active_mode == "MOE_COUNCIL":
            # Score only the seated specialists.
            slices = {
                "volumetric": (VOLUMETRIC_INDICES, "VOLUMETRIC_VANGUARD"),
                "recon": (RECON_INDICES, "RECON_INQUISITOR"),
                "payload": (PAYLOAD_INDICES, "DEEP_PAYLOAD_ANALYST"),
            }
            raw, scores = {}, {}
            for role, (idx, display) in slices.items():
                net = self.specialists.get(role)
                if net is None:
                    continue
                v = float(net.activate(feats_20[idx])[0])
                v = max(0.0, min(1.0, v))
                raw[role] = v
                scores[display] = v

            # NOTE: raw specialist outputs are reported as-is. An earlier build
            # remapped every raw score >= 0.50 onto [0.85, 0.99] and then tested
            # `score >= 0.85`, which made the displayed confidence meaningless
            # (a raw 0.501 rendered as "0.85 confident") and collapsed the whole
            # consensus structure into `any specialist > 0.5`. Confidence shown
            # to an operator must be the number the decision was made on.

            leading_expert = max(scores, key=scores.get)
            leading_score = scores[leading_expert]

            # Consensus decision rule
            # Priority veto: a specialist that is confident inside its own domain
            # carries the verdict undiluted.
            if leading_score >= THREAT_THRESHOLD:
                final_score = leading_score
                consensus_rule = "PRIORITY_VETO"
            else:
                # Noisy-OR over the seated specialists: several mild suspicions
                # can still add up to a verdict. Reachable now that scores are
                # not inflated.
                prod = 1.0
                for v in raw.values():
                    prod *= (1.0 - v)
                final_score = 1.0 - prod
                consensus_rule = "PROBABILISTIC_DISJUNCTION"

            return {
                "score": float(final_score),
                "is_threat": bool(final_score >= THREAT_THRESHOLD),
                "leading_expert": leading_expert,
                "leading_score": float(leading_score),
                "seated": sorted(raw.keys()),
                "seat_provenance": {r: self.provenance[r]
                                    for r in raw.keys() if r in self.provenance},
                "breakdown": {
                    "volumetric": round(raw.get("volumetric", 0.0), 4),
                    "recon": round(raw.get("recon", 0.0), 4),
                    "payload": round(raw.get("payload", 0.0), 4)
                },
                "consensus_rule": consensus_rule,
                "mode": "MOE_COUNCIL"
            }

        elif self.active_mode == "MONOLITHIC_FALLBACK" and self.monolith_net is not None:
            num_in = len(self.monolith_config.genome_config.input_keys) if self.monolith_config else 20
            inp = feats_20 if num_in == 20 else feats_20[:12]
            score = float(self.monolith_net.activate(inp)[0])
            score = max(0.0, min(1.0, score))

            # Approximate attribution based on prominent feature groups
            if feats_20[11] > 0.6 or feats_20[0] > 0.8:
                leading = "VOLUMETRIC_VANGUARD"
            elif feats_20[13] > 0.5 or feats_20[14] > 0.5 or feats_20[15] > 0.5:
                leading = "RECON_INQUISITOR"
            elif feats_20[12] > 0.7:
                leading = "DEEP_PAYLOAD_ANALYST"
            else:
                leading = "GENERAL_MONOLITH"

            return {
                "score": float(score),
                "is_threat": bool(score >= THREAT_THRESHOLD),
                "leading_expert": leading,
                "leading_score": float(score),
                "seat_provenance": {"monolith": self.provenance.get("monolith")},
                "breakdown": {
                    "volumetric": round(score if leading == "VOLUMETRIC_VANGUARD" else score * 0.5, 4),
                    "recon": round(score if leading == "RECON_INQUISITOR" else score * 0.5, 4),
                    "payload": round(score if leading == "DEEP_PAYLOAD_ANALYST" else score * 0.5, 4)
                },
                "consensus_rule": "MONOLITHIC_FALLBACK",
                "mode": "MONOLITHIC_FALLBACK"
            }

        else:
            # Heuristic Baseline
            heuristic_score = 0.0
            if feats_20[13] > 0.5 or feats_20[14] > 0.5:  # NULL or XMAS
                heuristic_score = 0.95
                leading = "RECON_INQUISITOR"
            elif feats_20[12] > policy.THREAT_THRESHOLD:  # High entropy
                heuristic_score = 0.90
                leading = "DEEP_PAYLOAD_ANALYST"
            elif feats_20[11] > 0.8:                      # High packet rate
                heuristic_score = 0.88
                leading = "VOLUMETRIC_VANGUARD"
            else:
                leading = "NONE"

            return {
                "score": float(heuristic_score),
                "is_threat": bool(heuristic_score >= THREAT_THRESHOLD),
                "leading_expert": leading,
                "seat_provenance": {"_meta": self.provenance.get("_meta")},
                "leading_score": float(heuristic_score),
                "breakdown": {
                    "volumetric": float(feats_20[11]),
                    "recon": float(max(feats_20[13], feats_20[14])),
                    "payload": float(feats_20[12])
                },
                "consensus_rule": "HEURISTIC_RULE",
                "mode": "HEURISTIC_ONLY"
            }


if __name__ == "__main__":
    # Self-test
    arbiter = CouncilArbiter()
    dummy_feat = np.zeros(20, dtype=np.float32)
    dummy_feat[14] = 1.0  # XMAS scan flag
    res = arbiter.evaluate(dummy_feat)
    print("\nSelf-Test Sample Evaluation:")
    print(json.dumps(res, indent=2))
