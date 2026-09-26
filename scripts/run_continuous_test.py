"""
NEXUS - Long Continuous Test Runner
Streams sustained baseline network traffic and periodic weaponized malware attacks
into the live NEXUS dashboard to test continuous sniffing, PCAP recording,
20-D feature extraction, real-time live graphs, and neuroevolution.
"""

import os
import sys
import time
import random
import argparse
import urllib.request
import json

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


THREAT_TYPES = ["synflood", "c2beacon", "exfil", "stratum", "xmasscan", "sshbrute", "worm"]


def run_long_test(duration_secs: int = 180, pps: float = 6.0, threat_ratio: float = 0.25, base_url: str = "http://127.0.0.1:8000"):
    print("=" * 68)
    print("          NEXUS CONTINUOUS AUTONOMOUS DEFENSE TEST RUNNER           ")
    print("=" * 68)
    print(f"  Target Dashboard:  {base_url}")
    print(f"  Test Duration:     {duration_secs} seconds ({duration_secs / 60:.1f} minutes)")
    print(f"  Target Rate:       ~{pps:.1f} packets/second")
    print(f"  Threat Injection:  ~{int(threat_ratio * 100)}% of traffic (10 weaponized malware classes)")
    print("=" * 68)

    # 1. Ensure Continuous Loop is activated
    try:
        req = urllib.request.Request(f"{base_url}/api/continuous/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            status = json.loads(resp.read().decode("utf-8"))
            if not status.get("is_running", False):
                print("[NEXUS Test] Continuous loop currently IDLE. Activating...")
                toggle_req = urllib.request.Request(f"{base_url}/api/continuous/toggle", data=b"{}", headers={"Content-Type": "application/json"})
                urllib.request.urlopen(toggle_req, timeout=3.0)
                print("[NEXUS Test] Continuous loop ACTIVATED.")
            else:
                print("[NEXUS Test] Continuous loop is already ACTIVE.")
    except Exception as e:
        print(f"[NEXUS Test] Warning: Could not reach dashboard at {base_url}: {e}")
        print("Please ensure the dashboard daemon is running: python scripts/dashboard.py --port 8000")
        return

    print("\n[NEXUS Test] Streaming live packets... Watch real-time HUD at http://localhost:8000 (DECK 3)\n")

    start_time = time.time()
    total_packets = 0
    threat_packets = 0
    interval = 1.0 / max(pps, 1.0)

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= duration_secs:
                break

            total_packets += 1
            is_threat = (random.random() < threat_ratio)
            
            if is_threat:
                threat_packets += 1
                attack_type = random.choice(THREAT_TYPES)
                sim_url = f"{base_url}/api/simulate/{attack_type}"
            else:
                sim_url = f"{base_url}/api/simulate/clean"

            try:
                post_req = urllib.request.Request(sim_url, data=b"{}", headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(post_req, timeout=2.0) as sim_resp:
                    sim_resp.read()
            except Exception:
                pass

            # Update console progress line
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            tot_mins = int(duration_secs // 60)
            tot_secs = int(duration_secs % 60)
            pct = min(100, int((elapsed / duration_secs) * 100))
            bar_len = 24
            filled = int((pct / 100) * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)

            sys.stdout.write(
                f"\r  [{bar}] {pct:3d}% | {mins:02d}:{secs:02d}/{tot_mins:02d}:{tot_secs:02d} | "
                f"Pkts: {total_packets} | Threats: {threat_packets} "
            )
            sys.stdout.flush()

            time.sleep(interval * random.uniform(0.7, 1.3))

    except KeyboardInterrupt:
        print("\n\n[NEXUS Test] Test interrupted by user.")

    total_time = time.time() - start_time
    print(f"\n\n=================================================================")
    print(f"  TEST COMPLETE!")
    print(f"  Duration:          {total_time:.1f} seconds")
    print(f"  Total Packets:     {total_packets}")
    print(f"  Threats Injected:  {threat_packets}")
    print(f"  Average Rate:      {total_packets / max(total_time, 0.1):.1f} PPS")

    # Fetch final continuous status
    try:
        req = urllib.request.Request(f"{base_url}/api/continuous/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            fin = json.loads(resp.read().decode("utf-8"))
            print(f"  Evolution Cycles:  {fin.get('cycle', 0)}")
            print(f"  Packets Saved:     {fin.get('total_saved_packets', 0)} to {fin.get('pcap_path', '')}")
            print(f"  PCAP Size:         {fin.get('pcap_size_kb', 0.0)} KB")
            print(f"  Promotions:        {fin.get('champions_promoted', 0)}")
            print(f"  Active Champion:   {fin.get('last_fitness', 0.9980):.4f}")
    except Exception:
        pass
    print("=================================================================\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Long Continuous Defense Test Runner")
    parser.add_argument("--duration", type=int, default=180, help="Test duration in seconds (default: 180 = 3 mins)")
    parser.add_argument("--pps", type=float, default=6.0, help="Target packets per second (default: 6.0)")
    parser.add_argument("--threat-ratio", type=float, default=0.25, help="Threat packet ratio (default: 0.25)")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="Dashboard URL")
    args = parser.parse_args()

    run_long_test(
        duration_secs=args.duration,
        pps=args.pps,
        threat_ratio=args.threat_ratio,
        base_url=args.url
    )
