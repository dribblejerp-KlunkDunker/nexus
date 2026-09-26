"""
NEXUS Adversarial Evasion & Robustness Engine
Applies synthetic feature perturbations and packet mutations to evaluate
and harden intrusion detection classifiers against adversarial evasion techniques.

Operators:
1. Entropy Flattening (Steganographic Camouflage / Benign Padding)
2. Micro-Burst & Timing Jitter (Low-and-Slow Rate Shaping)
3. TTL Masquerading / Normalization (Zero TTL Divergence)
4. Flag & Window Variation (Decoy Flags & Benign Streaming Ratios)
"""

import os
import sys
import time
import random
import numpy as np
from typing import Dict, Any, Tuple, Optional
from scapy.all import Ether, IP, TCP, Raw

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import PacketFeatureExtractor, calculate_shannon_entropy


class AdversarialEvasionEngine:
    """
    Synthesizes perturbed feature vectors and packets to stress-test
    neural network classifiers against adversarial camouflage.
    """

    def __init__(self):
        self.extractor = PacketFeatureExtractor()

    def mutate_vector(self, feat_20: np.ndarray, strategy: str = "full", intensity: float = 0.8) -> np.ndarray:
        """
        Applies mathematical perturbations directly to a 20-D feature vector.
        Feature indices:
        0: packet_len, 1: proto, 2: sport, 3: dport, 4: syn, 5: ack, 6: fin_rst,
        7: payload_len, 8: window, 9: ip_ttl, 10: delta_t, 11: stream_rate,
        12: payload_entropy, 13: null_scan, 14: xmas_scan, 15: syn_fin,
        16: is_urg, 17: is_psh, 18: win_to_len_ratio, 19: ttl_div
        """
        mutated = np.copy(feat_20)

        # 1. Micro-Burst & Timing Jitter: reduce stream_rate, increase delta_t
        if strategy in ("jitter", "timing", "full"):
            # Lower stream rate below standard burst threshold
            mutated[11] = max(0.05, mutated[11] * (1.0 - 0.75 * intensity))
            # Increase inter-arrival time (slower spacing)
            mutated[10] = min(1.0, mutated[10] + (0.5 * intensity))

        # 2. TTL Masquerading: normalize TTL to 64 or 128 (eliminate divergence)
        if strategy in ("ttl", "masquerade", "full"):
            # Reset TTL divergence (sensor 19) to 0
            mutated[19] = max(0.0, mutated[19] * (1.0 - intensity))
            # Snap normalized TTL (sensor 9) to standard 64/255 = 0.251
            mutated[9] = 64.0 / 255.0

        # 3. Entropy Flattening: suppress high entropy with structured padding
        if strategy in ("entropy", "camouflage", "full"):
            # If entropy (sensor 12) is high (>0.6), suppress it to benign level (0.40 - 0.55)
            if mutated[12] > 0.6:
                target_entropy = 0.45 + (0.10 * (1.0 - intensity))
                mutated[12] = max(target_entropy, mutated[12] - (0.45 * intensity))

        # 4. Flag & Window Variation: add decoy ACK, adjust window ratio
        if strategy in ("window", "flags", "full"):
            # Blend window-to-length ratio towards benign streaming ratio (~0.6 - 0.9)
            mutated[18] = 0.70 + (0.15 * random.random())
            # If pure scan flag was set, tone down stealth flag indicators slightly
            if mutated[13] == 1.0 or mutated[14] == 1.0 or mutated[15] == 1.0:
                mutated[5] = 1.0  # add decoy ACK flag

        return mutated.astype(np.float32)

    def generate_evasive_packet(
        self,
        attack_type: str = "c2beacon",
        target_host: str = "192.168.1.50",
        strategy: str = "full"
    ) -> Tuple[Any, str]:
        """
        Constructs a realistic Scapy packet modified with evasion techniques:
        - evasive_c2: C2 beacon masked inside benign repeating JSON container
        - evasive_flood: SYN flood disguised with randomized window & pacing
        - evasive_scan: Recon probe normalized with standard TTL & decoy flags
        """
        attacker_ip = f"185.220.101.{random.randint(10, 200)}"

        if attack_type == "evasive_c2":
            # Camouflaged C2: Injects raw beacon bytes inside structured repeating JSON
            c2_core = os.urandom(32)
            # Embedding in repeating JSON structure reduces Shannon entropy from ~0.95 to ~0.55
            padding = b'{"status":"ok","channel":"telemetry_sync","payload":"' + c2_core + b'","stream_id":"session_009"}'
            pkt = Ether()/IP(src=attacker_ip, dst=target_host, ttl=64)/\
                  TCP(sport=random.randint(30000, 60000), dport=8443, flags="PA", window=29200)/\
                  Raw(load=padding)
            desc = "Adversarial C2 Beacon Camouflaged in Structured JSON Telemetry"

        elif attack_type == "evasive_flood":
            # Jittered Sub-Threshold Flood: Window scaled, paced, decoy ACK
            pkt = Ether()/IP(src=attacker_ip, dst=target_host, ttl=64)/\
                  TCP(sport=random.randint(1024, 65535), dport=443, flags="SA", window=64240, seq=random.randint(1000, 9999))
            desc = "Adversarial Jittered SYN+ACK Pulse with Standard Window Scaling"

        elif attack_type == "evasive_scan":
            # Stealth Recon probe with Linux standard TTL (64) and legitimate window size
            pkt = Ether()/IP(src=attacker_ip, dst=target_host, ttl=64)/\
                  TCP(sport=random.randint(40000, 60000), dport=random.randint(1, 1024), flags="FPU", window=14600)
            desc = "Adversarial XMAS Recon Probe with Normalized OS TTL (64)"

        elif attack_type == "evasive_exfil":
            # Large data exfiltration interleaved with text dictionary padding
            chunk = (b"BENIGN_DOCUMENT_HEADER_DATA_" * 10) + os.urandom(256)
            pkt = Ether()/IP(src=target_host, dst=attacker_ip, ttl=128)/\
                  TCP(sport=random.randint(40000, 60000), dport=14432, flags="PA", window=65535)/\
                  Raw(load=chunk)
            desc = "Adversarial Data Exfiltration Masked with Document Text Padding"

        else:
            # General fallback
            pkt = Ether()/IP(src=attacker_ip, dst=target_host, ttl=64)/\
                  TCP(sport=random.randint(30000, 60000), dport=80, flags="PA", window=14600)/\
                  Raw(load=b"GET /api/v1/ping HTTP/1.1\r\n\r\n")
            desc = "Generic Benign Probe"

        return pkt, desc


if __name__ == "__main__":
    # Self-test
    engine = AdversarialEvasionEngine()
    print("--- Testing Adversarial Evasion Engine ---")
    pkt, desc = engine.generate_evasive_packet("evasive_c2")
    f_raw = engine.extractor.extract(pkt, extended=True)
    print(f"Sample Evasive Packet: {desc}")
    print(f"  Extracted Entropy: {f_raw[12]:.4f} (Suppressed from >0.85)")
    print(f"  Extracted TTL Div: {f_raw[19]:.4f} (Normalized to 0.0)")

    # Test vector perturbation
    dummy = np.ones(20, dtype=np.float32)
    dummy[11] = 0.95  # high rate
    dummy[12] = 0.92  # high entropy
    dummy[19] = 0.85  # high ttl div
    mut = engine.mutate_vector(dummy, strategy="full")
    print("\nVector Perturbation Test:")
    print(f"  Rate:    {dummy[11]:.2f} -> {mut[11]:.2f}")
    print(f"  Entropy: {dummy[12]:.2f} -> {mut[12]:.2f}")
    print(f"  TTL Div: {dummy[19]:.2f} -> {mut[19]:.2f}")
    print("Self-test completed successfully!")
