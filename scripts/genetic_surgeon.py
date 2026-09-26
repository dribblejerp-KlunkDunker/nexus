"""
N.E.X.U.S - Genetic Surgeon (Meta-Learning Directed Mutation Engine)
Analyzes neural genome misclassifications on holdout validation datasets,
diagnoses neglected sensory dimensions, and performs directed synaptic splices
(excitatory attack links, inhibitory shielding, intermediary combiner nodes)
to accelerate convergence and break through evolutionary stagnation.
"""

import os
import sys
import time
import json
import copy
import pickle
import random
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import FEATURE_NAMES_20, PacketFeatureExtractor

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


class GeneticSurgeon:
    """
    AI Meta-Learning Agent that inspects candidate neural genomes,
    diagnoses why they fail on specific validation samples, and performs
    targeted architectural surgery rather than waiting for blind random mutations.
    """

    def __init__(self, history_file: str = "logs/genetic_surgery_history.json"):
        self.history_file = history_file
        self.history = self._load_history()

    def _load_history(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_history(self):
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history[-100:], f, indent=2)
        except Exception as e:
            print(f"[Genetic Surgeon] Warning: Failed to save surgery history: {e}")

    def diagnose_genome(
        self,
        genome: Any,
        config: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        threshold: float = 0.50
    ) -> Dict[str, Any]:
        """
        Runs validation inference on the candidate genome, isolates False Negatives
        and False Positives, and identifies which input features are being neglected.
        """
        import neat
        net = neat.nn.FeedForwardNetwork.create(genome, config)
        num_inputs = len(config.genome_config.input_keys)

        preds = []
        for x in X_val:
            x_in = x[:num_inputs]
            out = net.activate(x_in)[0]
            preds.append(out)
        preds = np.array(preds, dtype=np.float32)

        binary_preds = (preds >= threshold).astype(int)
        y_int = y_val.astype(int)

        # Identify misclassifications
        fn_indices = np.where((y_int == 1) & (binary_preds == 0))[0]  # Missed attacks
        fp_indices = np.where((y_int == 0) & (binary_preds == 1))[0]  # False alarms
        tp_indices = np.where((y_int == 1) & (binary_preds == 1))[0]
        tn_indices = np.where((y_int == 0) & (binary_preds == 0))[0]

        total = len(y_val)
        accuracy = (len(tp_indices) + len(tn_indices)) / max(total, 1)

        # Analyze existing connectivity and effective excitatory strength
        connected_inputs = set()
        effective_attack_inputs = set()
        for (in_node, out_node), cg in genome.connections.items():
            if cg.enabled and in_node < 0:
                sensor_idx = abs(in_node) - 1
                connected_inputs.add(sensor_idx)
                if cg.weight >= 0.8:
                    effective_attack_inputs.add(sensor_idx)

        # Contrast vectors between attacks and baseline normal traffic
        attack_mask = (y_val == 1)
        normal_mask = (y_val == 0)
        X_attack = X_val[attack_mask]
        X_normal = X_val[normal_mask]

        mean_attack = np.mean(X_attack, axis=0) if len(X_attack) > 0 else np.zeros(num_inputs)
        mean_normal = np.mean(X_normal, axis=0) if len(X_normal) > 0 else np.zeros(num_inputs)

        attack_contrast = mean_attack - mean_normal
        normal_contrast = mean_normal - mean_attack

        # Diagnostic feature attribution for False Negatives (Missed Attacks)
        neglected_attack_features = []
        if len(fn_indices) > 0:
            fn_vectors = X_val[fn_indices]
            fn_means = np.mean(fn_vectors, axis=0)
            for idx in range(num_inputs):
                feat_name = FEATURE_NAMES_20[idx] if idx < len(FEATURE_NAMES_20) else f"in_{idx}"
                contrast = float(attack_contrast[idx])
                signal_strength = float(fn_means[idx])
                is_effective = idx in effective_attack_inputs

                if (contrast >= 0.20 or signal_strength >= 0.50) and not is_effective:
                    neglected_attack_features.append({
                        "sensor_index": idx,
                        "sensor_node": -(idx + 1),
                        "feature_name": feat_name,
                        "contrast": round(contrast, 4),
                        "signal_strength": round(signal_strength, 4),
                        "status": "UNCONNECTED_CRITICAL" if idx not in connected_inputs else "WEAK_WEIGHT_CRITICAL"
                    })
            neglected_attack_features.sort(key=lambda x: max(x["contrast"], x["signal_strength"]), reverse=True)

        # Diagnostic feature attribution for False Positives (False Alarms)
        neglected_shield_features = []
        if len(fp_indices) > 0:
            fp_vectors = X_val[fp_indices]
            fp_means = np.mean(fp_vectors, axis=0)
            for idx in range(num_inputs):
                feat_name = FEATURE_NAMES_20[idx] if idx < len(FEATURE_NAMES_20) else f"in_{idx}"
                contrast = float(normal_contrast[idx])
                signal_strength = float(fp_means[idx])
                is_connected = idx in connected_inputs

                if (contrast >= 0.20 or idx in (8, 18)) and not is_connected:
                    neglected_shield_features.append({
                        "sensor_index": idx,
                        "sensor_node": -(idx + 1),
                        "feature_name": feat_name,
                        "contrast": round(contrast, 4),
                        "signal_strength": round(signal_strength, 4),
                        "status": "SHIELD_UNCONNECTED"
                    })
            neglected_shield_features.sort(key=lambda x: x["contrast"], reverse=True)

        # Check if output bias is in extreme saturation
        out_bias = genome.nodes[0].bias if 0 in genome.nodes else 0.0
        bias_issue = None
        if len(fp_indices) > 0.6 * max(len(X_normal), 1) and out_bias > 0.0:
            bias_issue = "OVER_EXCITATORY_BIAS"
        elif len(fn_indices) > 0.6 * max(len(X_attack), 1) and out_bias < -1.5:
            bias_issue = "OVER_DEPRESSED_BIAS"

        return {
            "accuracy": round(accuracy, 4),
            "false_negatives": int(len(fn_indices)),
            "false_positives": int(len(fp_indices)),
            "connected_inputs": sorted(list(connected_inputs)),
            "neglected_attack_sensors": neglected_attack_features,
            "neglected_shield_sensors": neglected_shield_features,
            "bias_issue": bias_issue,
            "has_stagnation_culprits": len(neglected_attack_features) > 0 or len(neglected_shield_features) > 0 or bias_issue is not None
        }

    def _create_connection_gene(self, config: Any, in_node: int, out_node: int, weight: float) -> Any:
        innovation = None
        if hasattr(config.genome_config, "innovation_tracker") and config.genome_config.innovation_tracker:
            try:
                innovation = config.genome_config.innovation_tracker.get_innovation_number(in_node, out_node, 'add_connection')
            except Exception:
                pass
        if innovation is None:
            innovation = abs(hash((in_node, out_node))) % 10000000 + 1

        cg = config.genome_config.connection_gene_type((in_node, out_node), innovation=innovation)
        cg.init_attributes(config.genome_config)
        cg.weight = weight
        cg.enabled = True
        return cg

    def _create_node_gene(self, config: Any, node_id: int, bias: float = 0.0, activation: str = "relu") -> Any:
        ng = config.genome_config.node_gene_type(node_id)
        ng.init_attributes(config.genome_config)
        ng.bias = bias
        ng.activation = activation
        ng.response = 1.0
        ng.aggregation = "sum"
        return ng

    def perform_surgery(
        self,
        genome: Any,
        config: Any,
        diagnosis: Dict[str, Any],
        max_interventions: int = 2
    ) -> Tuple[Any, List[Dict[str, Any]]]:
        """
        Executes targeted, directed topological modifications to the candidate genome:
        1. Grafts excitatory synapses from high-signal neglected attack sensors directly into the decision core or hidden layer.
        2. Grafts inhibitory shielding synapses from benign indicators to eliminate false alarms.
        3. Inserts intermediary combiner nodes if multi-modal sensor synergy is missing.
        """
        mutated_genome = copy.deepcopy(genome)
        interventions = []

        # Strategy 0: Output Bias Recalibration
        bias_issue = diagnosis.get("bias_issue")
        if bias_issue and 0 in mutated_genome.nodes:
            old_bias = float(mutated_genome.nodes[0].bias)
            if bias_issue == "OVER_EXCITATORY_BIAS":
                mutated_genome.nodes[0].bias = -0.5
                interventions.append({
                    "action": "RECALIBRATED_OUTPUT_BIAS",
                    "old_bias": round(old_bias, 3),
                    "new_bias": -0.5,
                    "rationale": "Reset over-excitatory bias causing chronic false alarms"
                })
            elif bias_issue == "OVER_DEPRESSED_BIAS":
                mutated_genome.nodes[0].bias = -0.5
                interventions.append({
                    "action": "RECALIBRATED_OUTPUT_BIAS",
                    "old_bias": round(old_bias, 3),
                    "new_bias": -0.5,
                    "rationale": "Reset over-depressed bias causing chronic false negatives"
                })

        # Strategy 1: Splice Neglected Attack Sensors (Excitatory)
        attack_sensors = diagnosis.get("neglected_attack_sensors", [])
        for feat in attack_sensors[:max_interventions]:
            sensor_node = feat["sensor_node"]
            target_node = 0  # Default to output node

            # If hidden nodes exist, optionally route through the most active hidden neuron
            hidden_nodes = [nid for nid in mutated_genome.nodes.keys() if nid > 0]
            if hidden_nodes and random.random() < 0.40:
                target_node = random.choice(hidden_nodes)

            conn_key = (sensor_node, target_node)
            weight = random.uniform(2.0, 3.2)  # Strong decisive excitatory weight

            if conn_key in mutated_genome.connections:
                mutated_genome.connections[conn_key].enabled = True
                mutated_genome.connections[conn_key].weight = max(mutated_genome.connections[conn_key].weight + 1.5, 2.5)
                action = "REINFORCED_CONNECTION"
            else:
                cg = self._create_connection_gene(config, sensor_node, target_node, weight)
                mutated_genome.connections[conn_key] = cg
                action = "GRAFTED_EXCITATORY_SYNAPSE"

            detail = {
                "action": action,
                "sensor_node": sensor_node,
                "sensor_name": feat["feature_name"],
                "target_node": target_node,
                "weight": round(weight, 4),
                "rationale": f"Resolve False Negatives on high-signal sensor ({feat['signal_strength']})"
            }
            interventions.append(detail)

        # Strategy 2: Splice Inhibitory Shielding for False Positives
        shield_sensors = diagnosis.get("neglected_shield_sensors", [])
        if diagnosis.get("false_positives", 0) > 0 and shield_sensors and len(interventions) < max_interventions:
            feat = shield_sensors[0]
            sensor_node = feat["sensor_node"]
            target_node = 0
            conn_key = (sensor_node, target_node)
            weight = random.uniform(-2.8, -1.8)  # Strong inhibitory weight

            if conn_key in mutated_genome.connections:
                mutated_genome.connections[conn_key].enabled = True
                mutated_genome.connections[conn_key].weight = min(mutated_genome.connections[conn_key].weight - 1.5, -2.0)
                action = "REINFORCED_INHIBITORY"
            else:
                cg = self._create_connection_gene(config, sensor_node, target_node, weight)
                mutated_genome.connections[conn_key] = cg
                action = "GRAFTED_INHIBITORY_SHIELD"

            interventions.append({
                "action": action,
                "sensor_node": sensor_node,
                "sensor_name": feat["feature_name"],
                "target_node": target_node,
                "weight": round(weight, 4),
                "rationale": f"Inhibit False Alarms using benign baseline feature"
            })

        # Strategy 3: Intermediary Node Grafting (if network is too shallow)
        hidden_count = len([nid for nid in mutated_genome.nodes.keys() if nid > 0])
        sensor_candidates = [it["sensor_node"] for it in interventions if "sensor_node" in it]
        if not sensor_candidates and attack_sensors:
            sensor_candidates = [attack_sensors[0]["sensor_node"]]
        elif not sensor_candidates and hasattr(config.genome_config, "input_keys"):
            sensor_candidates = list(config.genome_config.input_keys)

        if hidden_count == 0 and sensor_candidates and random.random() < 0.50:
            existing_node_keys = [k for k in mutated_genome.nodes.keys() if k > 0]
            new_node_id = (max(existing_node_keys) + 1) if existing_node_keys else 1

            ng = self._create_node_gene(config, new_node_id, bias=random.uniform(-0.5, 0.5), activation="relu")
            mutated_genome.nodes[new_node_id] = ng

            # Connect input -> new_node -> output
            sensor_node = sensor_candidates[0]
            c1 = self._create_connection_gene(config, sensor_node, new_node_id, random.uniform(1.5, 2.5))
            mutated_genome.connections[(sensor_node, new_node_id)] = c1

            c2 = self._create_connection_gene(config, new_node_id, 0, random.uniform(1.8, 2.8))
            mutated_genome.connections[(new_node_id, 0)] = c2

            interventions.append({
                "action": "GRAFTED_INTERMEDIARY_NODE",
                "node_id": new_node_id,
                "activation": "relu",
                "sensor_source": sensor_node,
                "rationale": "Add non-linear abstraction layer for complex multi-sensor synergy"
            })

        # Record operation
        record = {
            "timestamp": datetime.now().isoformat(),
            "interventions": interventions,
            "pre_accuracy": diagnosis.get("accuracy", 0.0),
            "pre_fn": diagnosis.get("false_negatives", 0),
            "pre_fp": diagnosis.get("false_positives", 0),
        }
        self.history.append(record)
        self._save_history()

        return mutated_genome, interventions

    def apply_population_surgery(
        self,
        population: Any,
        config: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        stagnation_generation: int,
        target_species_ratio: float = 0.30
    ) -> List[Dict[str, Any]]:
        """
        Inspects an entire NEAT population during evolutionary stagnation,
        diagnoses the top stagnating species champions, and performs targeted
        surgeries on a subset of the population to seed rapid breakthrough.
        """
        operations = []
        species_list = list(population.species.species.values())
        target_count = max(1, int(len(species_list) * target_species_ratio))

        # Sort species by representative fitness
        species_list.sort(key=lambda s: getattr(s.fitness, "fitness", 0.0) if s.fitness is not None else 0.0)

        for sp in species_list[:target_count]:
            if not sp.members:
                continue

            # Pick the top member in the species
            champ_id = max(sp.members.keys(), key=lambda gid: sp.members[gid].fitness if sp.members[gid].fitness is not None else -1e9)
            champ_genome = sp.members[champ_id]

            diagnosis = self.diagnose_genome(champ_genome, config, X_val, y_val)
            if diagnosis.get("has_stagnation_culprits", False):
                spliced_genome, interventions = self.perform_surgery(champ_genome, config, diagnosis)
                if interventions:
                    # Replace a weaker member or the champion with the surgically enhanced genome
                    weakest_id = min(sp.members.keys(), key=lambda gid: sp.members[gid].fitness if sp.members[gid].fitness is not None else 1e9)
                    sp.members[weakest_id] = spliced_genome

                    op_summary = {
                        "species_id": sp.id,
                        "generation": stagnation_generation,
                        "interventions": interventions,
                        "pre_fn": diagnosis["false_negatives"],
                        "pre_fp": diagnosis["false_positives"]
                    }
                    operations.append(op_summary)

        return operations


if __name__ == "__main__":
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}       N.E.X.U.S - GENETIC SURGEON SELF-TEST & VALIDATION       {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")

    # Load active champion and config
    with open("genomes/champion.pkl", "rb") as f:
        data = pickle.load(f)
    test_genome = data["genome"]
    test_config = data["config"]

    surgeon = GeneticSurgeon()

    # Generate synthetic validation split
    from benchmark_moe_vs_monolith import generate_benchmark_test_suites
    suites = generate_benchmark_test_suites()

    X_list, y_list = [], []
    for name, (feats, category) in suites.items():
        label = 1 if category == "ATTACK" else 0
        X_list.extend(feats[:40])
        y_list.extend([label] * len(feats[:40]))

    X_val = np.array(X_list, dtype=np.float32)
    y_val = np.array(y_list, dtype=np.float32)

    print(f"\n1. Running Genetic Surgeon Diagnosis on Active Champion...")
    diagnosis = surgeon.diagnose_genome(test_genome, test_config, X_val, y_val)

    print(f"  - Validation Accuracy:  {diagnosis['accuracy'] * 100:.2f}%")
    print(f"  - False Negatives:      {diagnosis['false_negatives']}")
    print(f"  - False Positives:      {diagnosis['false_positives']}")
    print(f"  - Connected Inputs:     {len(diagnosis['connected_inputs'])} / 20 sensors")
    print(f"  - Neglected Sensors:    {len(diagnosis['neglected_attack_sensors'])} identified")

    for feat in diagnosis["neglected_attack_sensors"][:3]:
        print(f"    * Neglected Sensor: {feat['feature_name']} (Node {feat['sensor_node']}, Signal: {feat['signal_strength']:.2f})")

    print(f"\n2. Executing Targeted Synaptic Surgery...")
    mut_genome, interventions = surgeon.perform_surgery(test_genome, test_config, diagnosis, max_interventions=2)

    print(f"  - Surgical Interventions Performed: {len(interventions)}")
    for iv in interventions:
        print(f"    [SPLICE] {iv['action']}: Sensor {iv.get('sensor_name', 'N/A')} ({iv.get('sensor_node')}) -> Node {iv.get('target_node')} (Weight: {iv.get('weight', 0.0):+.2f})")
        print(f"             Rationale: {iv['rationale']}")

    # Verify that the mutated genome has new connections
    assert len(mut_genome.connections) >= len(test_genome.connections), "Surgical splice failed to expand connections"

    print(f"\n3. Simulating Stagnant Infant Genome & Verifying Directed Surgery...")
    # Create an infant genome with only 2 non-diagnostic connections
    infant_genome = copy.deepcopy(test_genome)
    infant_genome.connections.clear()
    infant_genome.nodes[0].bias = -1.5  # Typical dormant negative threshold
    c1 = surgeon._create_connection_gene(test_config, -3, 0, 0.2)  # src_port -> out
    infant_genome.connections[(-3, 0)] = c1

    c2 = surgeon._create_connection_gene(test_config, -4, 0, 0.2)  # dst_port -> out
    infant_genome.connections[(-4, 0)] = c2

    infant_diag = surgeon.diagnose_genome(infant_genome, test_config, X_val, y_val)
    print(f"  - Infant Pre-Surgery Accuracy:  {infant_diag['accuracy'] * 100:.2f}%")
    print(f"  - Infant False Negatives:       {infant_diag['false_negatives']}")
    print(f"  - Infant Neglected Sensors:     {len(infant_diag['neglected_attack_sensors'])} identified")

    surg_infant, infant_ivs = surgeon.perform_surgery(infant_genome, test_config, infant_diag, max_interventions=3)
    print(f"  - Surgical Interventions Grafted: {len(infant_ivs)}")
    for iv in infant_ivs:
        print(f"    * [SURGERY] {iv['action']}: {iv.get('sensor_name')} ({iv.get('sensor_node')}) -> Node {iv.get('target_node')} (Weight: {iv.get('weight', 0.0):+.2f})")

    post_diag = surgeon.diagnose_genome(surg_infant, test_config, X_val, y_val)
    print(f"  - Infant Post-Surgery Accuracy: {post_diag['accuracy'] * 100:.2f}% (Acc Delta: +{(post_diag['accuracy'] - infant_diag['accuracy']) * 100:.2f}%)")
    print(f"  - Infant False Negatives Drop:  {infant_diag['false_negatives']} -> {post_diag['false_negatives']}")

    assert post_diag['accuracy'] > infant_diag['accuracy'], "Surgeon failed to improve infant accuracy"
    print(f"\n{BOLD}{GREEN}[PASS] Genetic Surgeon Engine fully operational, verified, and accelerating convergence!{RESET}\n")

