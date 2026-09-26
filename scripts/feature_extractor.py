"""
NEXUS - High-Speed Packet Feature Extractor
Extracts normalized 12-dimensional and extended 20-dimensional feature vectors from Scapy packets.
Includes Shannon entropy, TCP flag anomaly detectors (XMAS, NULL, SYN+FIN), and timing variance.
"""

import time
import os
import math
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, wrpcap, rdpcap

# Standard 12-feature vector (Backward compatible with Phase 0-3 models)
FEATURE_NAMES_12 = [
    "packet_len",          # 0: Normalized packet length (0-1500 MTU)
    "protocol",            # 1: Protocol category (TCP=0.6, UDP=0.17, ICMP=0.01, other=0.0)
    "src_port",            # 2: Normalized source port (0-65535)
    "dst_port",            # 3: Normalized destination port (0-65535)
    "is_syn",              # 4: Pure SYN packet flag (potential scan / SYN flood)
    "is_ack",              # 5: ACK packet flag
    "is_fin_rst",          # 6: FIN or RST packet flag (teardown or rejection)
    "payload_len",         # 7: Normalized raw payload size (0-1500)
    "tcp_window",          # 8: Normalized TCP window size (0-65535)
    "ip_ttl",              # 9: Normalized IP Time To Live (0-255)
    "inter_arrival_time",  # 10: Delta time since previous packet on interface
    "stream_rate",         # 11: Exponential moving average packet rate
]

# Extended 20-feature vector (Advanced threat intelligence)
FEATURE_NAMES_20 = FEATURE_NAMES_12 + [
    "payload_entropy",     # 12: Shannon entropy of payload (0.0=zero variance, 1.0=encrypted/compressed C2)
    "is_null_scan",        # 13: TCP NULL scan probe (flags == 0)
    "is_xmas_scan",        # 14: TCP XMAS scan probe (FIN + PSH + URG)
    "is_syn_fin",          # 15: Illegal TCP flag combo (SYN + FIN simultaneously)
    "is_urgent",           # 16: TCP URG flag set
    "is_push",             # 17: TCP PSH flag set
    "win_to_len_ratio",    # 18: Ratio of advertised window to packet length
    "ttl_divergence",      # 19: Absolute divergence from standard baseline (64)
]

# Packets/sec mapped to stream_rate = 1.0 on a log scale.
RATE_CEILING = 20000.0

FEATURE_NAMES = FEATURE_NAMES_20
NUM_FEATURES = len(FEATURE_NAMES_20)


def calculate_shannon_entropy(payload_bytes: bytes) -> float:
    """Calculates normalized Shannon entropy [0.0 - 1.0] of byte payload."""
    if not payload_bytes:
        return 0.0
    length = len(payload_bytes)
    byte_counts = np.bincount(np.frombuffer(payload_bytes, dtype=np.uint8), minlength=256)
    probabilities = byte_counts[byte_counts > 0] / length
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return float(entropy / 8.0)  # Max entropy is 8.0 bits per byte


class PacketFeatureExtractor:
    def __init__(self, ema_alpha: float = 0.2):
        self.last_timestamp = None
        self.ema_alpha = ema_alpha
        self.packet_rate_ema = 0.0

    def reset(self):
        self.last_timestamp = None
        self.packet_rate_ema = 0.0

    def extract(self, packet, current_time: float = None, extended: bool = False) -> np.ndarray:
        """
        Converts a Scapy packet into a normalized feature vector:
        - extended=False: 12-dim vector (standard)
        - extended=True:  20-dim vector (including Shannon entropy and flag anomalies)
        """
        if current_time is None:
            current_time = float(getattr(packet, 'time', time.time()))

        raw_len = len(packet)
        f_len = min(1.0, float(raw_len) / 1500.0)

        # IP Protocol and TTL
        f_proto = 0.0
        f_ttl = 0.5
        raw_ttl = 64
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            raw_ttl = int(ip_layer.ttl)
            f_ttl = float(raw_ttl) / 255.0
            if ip_layer.proto == 6:
                f_proto = 0.6
            elif ip_layer.proto == 17:
                f_proto = 0.17
            elif ip_layer.proto == 1:
                f_proto = 0.01
            else:
                f_proto = float(ip_layer.proto % 100) / 100.0

        # Transport layer & flags
        f_sport = 0.0
        f_dport = 0.0
        f_syn = 0.0
        f_ack = 0.0
        f_fin_rst = 0.0
        f_window = 0.0
        raw_window = 0

        # Extended flag signals
        f_null = 0.0
        f_xmas = 0.0
        f_syn_fin = 0.0
        f_urg = 0.0
        f_psh = 0.0

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            raw_window = int(tcp.window)
            f_sport = float(tcp.sport) / 65535.0
            f_dport = float(tcp.dport) / 65535.0
            f_window = float(raw_window) / 65535.0

            flags = int(tcp.flags)
            is_syn_flag = bool(flags & 0x02)
            is_ack_flag = bool(flags & 0x10)
            is_rst_flag = bool(flags & 0x04)
            is_fin_flag = bool(flags & 0x01)
            is_psh_flag = bool(flags & 0x08)
            is_urg_flag = bool(flags & 0x20)

            f_syn = 1.0 if (is_syn_flag and not is_ack_flag) else 0.0
            f_ack = 1.0 if is_ack_flag else 0.0
            f_fin_rst = 1.0 if (is_rst_flag or is_fin_flag) else 0.0

            # Extended flag anomalies
            f_null = 1.0 if flags == 0 else 0.0
            f_xmas = 1.0 if (is_fin_flag and is_psh_flag and is_urg_flag) else 0.0
            f_syn_fin = 1.0 if (is_syn_flag and is_fin_flag) else 0.0
            f_urg = 1.0 if is_urg_flag else 0.0
            f_psh = 1.0 if is_psh_flag else 0.0

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            f_sport = float(udp.sport) / 65535.0
            f_dport = float(udp.dport) / 65535.0

        # Payload metrics & Shannon entropy
        f_payload = 0.0
        raw_payload_bytes = b""
        if packet.haslayer(Raw):
            raw_payload_bytes = bytes(packet[Raw].load)
            f_payload = min(1.0, float(len(raw_payload_bytes)) / 1500.0)

        f_entropy = calculate_shannon_entropy(raw_payload_bytes)

        # Timing & Rate
        if self.last_timestamp is None:
            delta_t = 0.1
            instant_rate = 1.0
        else:
            delta_t = max(0.000001, current_time - self.last_timestamp)
            instant_rate = min(1000.0, 1.0 / delta_t)

        self.last_timestamp = current_time
        self.packet_rate_ema = (self.ema_alpha * instant_rate) + ((1.0 - self.ema_alpha) * self.packet_rate_ema)

        f_delta_t = min(1.0, delta_t)
        # Log-scaled rate. Linear normalisation (ema / 200.0) pinned this
        # feature at 1.0 for 87% of packets on a real home network -- any
        # link busier than 200pps saturated it permanently, leaving the
        # volumetric specialist blind to the one signal it exists to read.
        # Log scale spreads 1..RATE_CEILING pps across the full 0..1 range.
        f_rate = min(1.0, math.log10(1.0 + self.packet_rate_ema) / math.log10(1.0 + RATE_CEILING))

        base_features = [
            f_len, f_proto, f_sport, f_dport,
            f_syn, f_ack, f_fin_rst, f_payload,
            f_window, f_ttl, f_delta_t, f_rate
        ]

        if not extended:
            return np.array(base_features, dtype=np.float32)

        # Additional 8 features for extended 20-D vector
        f_win_ratio = min(1.0, float(raw_window) / max(1.0, float(raw_len)))
        f_ttl_div = min(1.0, abs(raw_ttl - 64) / 64.0)

        extended_features = base_features + [
            f_entropy, f_null, f_xmas, f_syn_fin,
            f_urg, f_psh, f_win_ratio, f_ttl_div
        ]
        return np.array(extended_features, dtype=np.float32)

    def observe_timing(self, current_time: float) -> None:
        """Advance the timing state for a packet that will not be scored.

        inter_arrival_time and stream_rate describe the INTERFACE, not one flow,
        so every packet on the wire has to advance them -- including the ones the
        whitelist exempts from scoring. sniff_and_respond.py returns early on a
        whitelisted packet, which on this network is 47.6% of all TCP traffic; the
        packets that did get scored therefore carried a mean delta_t of 0.0975
        against the 0.0663 the training corpus was built with, a 47% shift in a
        feature the model relies on. Calling this on the skipped packets keeps the
        live feature distribution equal to the training one.
        """
        if self.last_timestamp is None:
            instant_rate = 1.0
        else:
            delta_t = max(0.000001, current_time - self.last_timestamp)
            instant_rate = min(1000.0, 1.0 / delta_t)
        self.last_timestamp = current_time
        self.packet_rate_ema = ((self.ema_alpha * instant_rate)
                               + ((1.0 - self.ema_alpha) * self.packet_rate_ema))

    def extract_extended(self, packet, current_time: float = None) -> np.ndarray:
        return self.extract(packet, current_time=current_time, extended=True)


def extract_from_pcap(pcap_file: str, extended: bool = True) -> np.ndarray:
    """Reads a PCAP file and returns an (N, D) numpy matrix."""
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
    packets = rdpcap(pcap_file)
    extractor = PacketFeatureExtractor()
    features = []
    for pkt in packets:
        features.append(extractor.extract(pkt, extended=extended))
    if not features:
        dim = len(FEATURE_NAMES_20) if extended else len(FEATURE_NAMES_12)
        return np.empty((0, dim), dtype=np.float32)
    return np.vstack(features)


def generate_synthetic_datasets(base_dir: str = "."):
    import random

    normal_dir = os.path.join(base_dir, "data", "normal_traffic")
    attack_dir = os.path.join(base_dir, "data", "attack_samples")
    os.makedirs(normal_dir, exist_ok=True)
    os.makedirs(attack_dir, exist_ok=True)

    normal_pcap = os.path.join(normal_dir, "baseline_traffic.pcap")
    attack_pcap = os.path.join(attack_dir, "synflood_portscan.pcap")

    print("[NEXUS Extractor] Synthesizing baseline normal network traffic...")
    normal_pkts = []
    cur_time = time.time()
    for _ in range(300):
        cur_time += random.uniform(0.02, 0.25)
        proto_choice = random.random()
        if proto_choice < 0.6:
            p = Ether()/IP(src="192.168.1.50", dst="142.250.190.46", ttl=64)/\
                TCP(sport=random.randint(49152, 65535), dport=443, flags="PA", window=64240)/\
                Raw(load=b"X" * random.randint(50, 800))
        elif proto_choice < 0.85:
            p = Ether()/IP(src="192.168.1.50", dst="8.8.8.8", ttl=64)/\
                UDP(sport=random.randint(49152, 65535), dport=53)/\
                Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
        else:
            p = Ether()/IP(src="192.168.1.50", dst="192.168.1.1", ttl=64)/\
                ICMP(type=8, code=0)/\
                Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
        p.time = cur_time
        normal_pkts.append(p)
    wrpcap(normal_pcap, normal_pkts)
    print(f" -> Wrote {len(normal_pkts)} normal packets to {normal_pcap}")

    print("[NEXUS Extractor] Synthesizing malicious attack traffic (scans + floods)...")
    attack_pkts = []
    cur_time = time.time()
    for target_port in range(20, 150):
        cur_time += random.uniform(0.0005, 0.003)
        p = Ether()/IP(src="10.0.0.99", dst="192.168.1.50", ttl=48)/\
            TCP(sport=random.randint(40000, 60000), dport=target_port, flags="S", window=1024)
        p.time = cur_time
        attack_pkts.append(p)

    # High-Rate SYN Flood
    for _ in range(200):
        cur_time += random.uniform(0.0001, 0.001)
        spoofed_ip = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
        p = Ether()/IP(src=spoofed_ip, dst="192.168.1.50", ttl=32)/\
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S", window=512)
        p.time = cur_time
        attack_pkts.append(p)

    # Malformed XMAS and NULL scans
    for _ in range(30):
        cur_time += random.uniform(0.001, 0.005)
        p = Ether()/IP(src="10.0.0.66", dst="192.168.1.50", ttl=40)/\
            TCP(sport=random.randint(40000, 60000), dport=445, flags="FPU", window=0)
        p.time = cur_time
        attack_pkts.append(p)

    wrpcap(attack_pcap, attack_pkts)
    print(f" -> Wrote {len(attack_pkts)} attack packets to {attack_pcap}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NEXUS Packet Feature Extractor")
    parser.add_argument("--generate-synthetic", action="store_true", help="Generate synthetic baseline & attack PCAPs")
    parser.add_argument("--pcap", type=str, help="Extract features from a specific PCAP file")
    parser.add_argument("--extended", action="store_true", help="Extract 20-D extended feature vector")
    args = parser.parse_args()

    if args.generate_synthetic:
        generate_synthetic_datasets(base_dir=".")
    elif args.pcap:
        feats = extract_from_pcap(args.pcap, extended=args.extended)
        dim = 20 if args.extended else 12
        print(f"Extracted {dim}-D feature matrix shape: {feats.shape}")
        if len(feats) > 0:
            names = FEATURE_NAMES_20 if args.extended else FEATURE_NAMES_12
            print("Sample feature vector (packet #0):")
            for name, val in zip(names, feats[0]):
                print(f"  {name:20s}: {val:.4f}")
    else:
        generate_synthetic_datasets(base_dir=".")
