"""
NEXUS - Real-Time Ambient Home Network Baseline Recorder
Captures live ambient network traffic on the local physical network adapter,
validates integrity, computes 20-D feature profiles, and writes to
data/normal_traffic/home_live_baseline.pcap for NEAT calibration.
"""

import os
import sys
import time
import logging
import argparse
from datetime import datetime
from collections import Counter

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Visual formatting
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def capture_home_baseline(
    duration: int = 60,
    output_path: str = "data/normal_traffic/home_live_baseline.pcap",
    iface: str = None,
    max_packets: int = 50000
):
    """
    Captures live traffic for specified duration or until Ctrl+C.
    """
    from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, conf
    from feature_extractor import PacketFeatureExtractor, calculate_shannon_entropy

    adapter = iface or conf.iface
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}      NEXUS HOME NETWORK AMBIENT BASELINE RECORDER              {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}")
    print(f"Timestamp:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target Duration:  {duration} seconds")
    print(f"Target Adapter:   {adapter}")
    print(f"Destination:      {output_path}")
    print(f"Max Packet Cap:   {max_packets:,}")
    print(f"Press {YELLOW}Ctrl+C{RESET} at any time to finish early and save.\n")

    captured_packets = []
    total_bytes = 0
    start_time = time.time()
    last_print = start_time
    protocol_counts = Counter()
    ip_sources = Counter()

    def packet_callback(pkt):
        nonlocal total_bytes, last_print
        if not pkt.haslayer(IP):
            return

        captured_packets.append(pkt)
        pkt_len = len(pkt)
        total_bytes += pkt_len

        ip_src = pkt[IP].src
        ip_sources[ip_src] += 1

        if pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1
        else:
            protocol_counts["OTHER"] += 1

        now = time.time()
        if now - last_print >= 1.0:
            elapsed = now - start_time
            remaining = max(0.0, duration - elapsed)
            pps = len(captured_packets) / max(0.1, elapsed)
            kbps = (total_bytes * 8.0 / 1024.0) / max(0.1, elapsed)
            pct = min(100.0, (elapsed / duration) * 100.0)
            bar_len = 24
            filled = int(bar_len * (pct / 100.0))
            bar = "=" * filled + "-" * (bar_len - filled)

            sys.stdout.write(
                f"\r{CYAN}[{bar}] {pct:5.1f}%{RESET} | "
                f"Elapsed: {elapsed:4.1f}s / {duration}s | "
                f"Pkts: {BOLD}{len(captured_packets):5d}{RESET} | "
                f"Rate: {pps:5.1f} pps ({kbps:6.1f} kbps)  "
            )
            sys.stdout.flush()
            last_print = now

    # Stop filter function for Scapy sniff
    def stop_filter(pkt):
        if len(captured_packets) >= max_packets:
            return True
        if time.time() - start_time >= duration:
            return True
        return False

    print(f"{GREEN}[RECORDING STARTED]{RESET} Listening for ambient home network packets...")
    try:
        sniff(
            iface=adapter,
            prn=packet_callback,
            stop_filter=stop_filter,
            timeout=duration + 2,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[USER INTERRUPT]{RESET} Finalizing baseline capture early...")
    except Exception as e:
        print(f"\n{RED}[CAPTURE ERROR]{RESET} An error occurred during capture: {e}")

    total_time = max(0.01, time.time() - start_time)
    print(f"\n\n{BOLD}{CYAN}--- [Capture Complete] Finalizing Dataset ---{RESET}")
    print(f"Total Elapsed Time:  {total_time:.2f} seconds")
    print(f"Packets Captured:    {len(captured_packets):,}")
    print(f"Total Volume:        {format_bytes(total_bytes)}")
    print(f"Protocol Breakdown:  TCP: {protocol_counts['TCP']}, UDP: {protocol_counts['UDP']}, Other: {protocol_counts['OTHER']}")

    if not captured_packets:
        print(f"{YELLOW}[WARNING]{RESET} No IP packets were captured. Ensure your adapter has network activity.")
        return False

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save to PCAP
    print(f"[NEXUS Baseline] Writing raw pcap to {output_path}...")
    wrpcap(output_path, captured_packets)

    # Verify PCAP file integrity
    print(f"[NEXUS Baseline] Verifying PCAP integrity...")
    try:
        verified_pkts = rdpcap(output_path)
        assert len(verified_pkts) == len(captured_packets)
        print(f"{GREEN}[INTEGRITY CHECK PASS]{RESET} Successfully verified {len(verified_pkts)} packets in {output_path}")
    except Exception as e:
        print(f"{RED}[INTEGRITY CHECK FAIL]{RESET} Failed to verify {output_path}: {e}")
        return False

    # 20-D Feature extraction profile
    print(f"\n{CYAN}{BOLD}--- [20-D Forensic Baseline Analysis] ---{RESET}")
    extractor = PacketFeatureExtractor()
    entropies = []
    ttls = []
    windows = []
    sample_size = min(len(captured_packets), 500)

    for p in captured_packets[:sample_size]:
        f20 = extractor.extract(p, extended=True)
        # f20: [len, proto, sport, dport, syn, ack, fin_rst, payload, win, ttl, iat, rate, entropy, null, xmas, syn_fin, urg, psh, win_ratio, ttl_div]
        entropies.append(f20[12])
        ttls.append(f20[9] * 255.0)
        windows.append(f20[8] * 65535.0)

    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    avg_ttl = sum(ttls) / len(ttls) if ttls else 0.0
    avg_win = sum(windows) / len(windows) if windows else 0.0

    print(f"  * Sample Analyzed:      {sample_size} packets")
    print(f"  * Mean Payload Entropy: {avg_entropy:.4f} (Normal baseline is < 0.50)")
    print(f"  * Mean IP TTL:          {avg_ttl:.1f}")
    print(f"  * Mean TCP Window:      {avg_win:.0f}")

    top_ips = ip_sources.most_common(5)
    print(f"\n  * Top Active IP Endpoints in Home Baseline:")
    for ip, count in top_ips:
        print(f"      - {ip:18s} : {count:5d} packets ({count/len(captured_packets)*100:.1f}%)")

    print(f"\n{BOLD}{GREEN}[SUCCESS] Home baseline successfully captured and saved for training.{RESET}\n")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture 60-Second Home Network Baseline for NEXUS")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60)")
    parser.add_argument("--output", type=str, default="data/normal_traffic/home_live_baseline.pcap", help="Output PCAP path")
    parser.add_argument("--iface", type=str, default=None, help="Interface identifier (default: Scapy default)")
    parser.add_argument("--max-packets", type=int, default=50000, help="Maximum packets to capture")

    args = parser.parse_args()
    success = capture_home_baseline(
        duration=args.duration,
        output_path=args.output,
        iface=args.iface,
        max_packets=args.max_packets
    )
    sys.exit(0 if success else 1)
