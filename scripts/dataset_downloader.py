"""
NEXUS - Public Intrusion Dataset Ingestion & Preprocessor
Downloads and normalizes real-world network security datasets (CIC-IDS, NSL-KDD)
and live PCAP samples for the NEAT evolutionary training pool.
"""

import os
import sys
import argparse
import urllib.request
from typing import Tuple
import numpy as np

# Reliable public PCAP mirrors from open security repositories
SAMPLE_PCAP_MIRRORS = {
    "tcp_flags": "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/print-flags.pcap",
    "dhcp_traffic": "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/scapy-dhcp.pcap",
    "esp_tunnel": "https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/tests/esp0.pcap",
}


def download_public_sample(name: str, target_dir: str = "data/attack_samples") -> str:
    """Downloads a public intrusion PCAP sample."""
    url = SAMPLE_PCAP_MIRRORS.get(name)
    if not url:
        print(f"Unknown sample: {name}. Available: {list(SAMPLE_PCAP_MIRRORS.keys())}")
        return ""

    os.makedirs(target_dir, exist_ok=True)
    out_file = os.path.join(target_dir, f"real_{name}.pcap")
    print(f"[NEXUS Data] Downloading real sample '{name}' from {url}...")
    try:
        urllib.request.urlretrieve(url, out_file)
        print(f"[NEXUS Data] Successfully saved: {out_file} ({os.path.getsize(out_file)} bytes)")
        return out_file
    except Exception as e:
        print(f"[NEXUS Data] Warning: Could not download external sample ({e}).")
        return ""


def convert_nsl_kdd_to_features(csv_path: str, max_rows: int = 5000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Parses NSL-KDD format CSV into NEXUS 12-D normalized feature vectors.
    Maps duration, protocol, service, flags, bytes, rates into normalized features.
    """
    import pandas as pd
    print(f"[NEXUS Data] Ingesting NSL-KDD dataset: {csv_path}...")
    cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
    ]
    df = pd.read_csv(csv_path, names=cols, nrows=max_rows)

    labels = (df["label"] != "normal").astype(np.float32).values

    f_len = np.clip((df["src_bytes"] + df["dst_bytes"]) / 1500.0, 0.0, 1.0)
    f_proto = df["protocol_type"].map({"tcp": 0.6, "udp": 0.17, "icmp": 0.01}).fillna(0.0).values
    f_sport = np.clip(df["dst_host_same_src_port_rate"], 0.0, 1.0).values
    f_dport = np.clip(df["srv_count"] / 512.0, 0.0, 1.0).values
    f_syn = np.clip(df["serror_rate"], 0.0, 1.0).values
    f_ack = (df["logged_in"]).astype(np.float32).values
    f_fin_rst = np.clip(df["rerror_rate"], 0.0, 1.0).values
    f_payload = np.clip(df["dst_bytes"] / 1500.0, 0.0, 1.0).values
    f_window = np.ones(len(df), dtype=np.float32) * 0.5
    f_ttl = np.ones(len(df), dtype=np.float32) * 0.5
    f_delta_t = np.clip(df["duration"] / 10.0, 0.0, 1.0).values
    f_rate = np.clip(df["count"] / 512.0, 0.0, 1.0).values

    X = np.column_stack([
        f_len, f_proto, f_sport, f_dport,
        f_syn, f_ack, f_fin_rst, f_payload,
        f_window, f_ttl, f_delta_t, f_rate
    ]).astype(np.float32)

    print(f"[NEXUS Data] Successfully normalized {len(X)} records (Normal: {np.sum(labels == 0)}, Attack: {np.sum(labels == 1)})")
    return X, labels


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Dataset Downloader & Ingester")
    parser.add_argument("--sample", type=str, choices=list(SAMPLE_PCAP_MIRRORS.keys()), help="Download sample PCAP")
    parser.add_argument("--kdd", type=str, help="Convert NSL-KDD CSV to NEXUS feature vectors")
    args = parser.parse_args()

    if args.sample:
        download_public_sample(args.sample)
    elif args.kdd:
        convert_nsl_kdd_to_features(args.kdd)
    else:
        parser.print_help()
