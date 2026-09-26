"""
NEXUS - Phase 4 Multi-Machine Cluster Launcher
Orchestrates multi-machine Ray clusters for distributed cyber-guardian evolution.
Supports Head Node (Coordinator) and Worker Nodes (Edge nodes / Laptops / Raspberry Pis).
"""

import sys
import subprocess
import argparse


def start_head_node(port: int = 6379, dashboard_host: str = "0.0.0.0", dashboard_port: int = 8265):
    print("\n=======================================================")
    print(f"  STARTING NEXUS RAY HEAD NODE ON PORT {port}")
    print("=======================================================\n")
    cmd = [
        sys.executable, "-m", "ray.scripts.scripts", "start",
        "--head",
        f"--port={port}",
        f"--dashboard-host={dashboard_host}",
        f"--dashboard-port={dashboard_port}",
        "--disable-usage-stats"
    ]
    print(f"Executing: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd, check=True)
        print("\n[+] Head Node running! Worker machines can join with:")
        print(f"    python scripts/launch_cluster_node.py --worker --head-ip <THIS_MACHINE_IP> --port {port}\n")
    except Exception as e:
        print(f"[-] Error launching Head Node: {e}")


def start_worker_node(head_ip: str, port: int = 6379, num_cpus: int = None):
    print("\n=======================================================")
    print(f"  JOINING NEXUS RAY CLUSTER AT {head_ip}:{port}")
    print("=======================================================\n")
    cmd = [
        sys.executable, "-m", "ray.scripts.scripts", "start",
        f"--address={head_ip}:{port}",
        "--disable-usage-stats"
    ]
    if num_cpus:
        cmd.append(f"--num-cpus={num_cpus}")

    print(f"Executing: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd, check=True)
        print(f"\n[+] Successfully joined Ray cluster at {head_ip}:{port}!")
    except Exception as e:
        print(f"[-] Error joining cluster: {e}")


def stop_node():
    print("\nStopping Ray instance on this node...")
    cmd = [sys.executable, "-m", "ray.scripts.scripts", "stop"]
    try:
        subprocess.run(cmd, check=True)
        print("[+] Ray stopped.")
    except Exception as e:
        print(f"[-] Error stopping Ray: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Ray Multi-Machine Cluster Launcher")
    parser.add_argument("--head", action="store_true", help="Launch this machine as the Ray Cluster Head Node")
    parser.add_argument("--worker", action="store_true", help="Launch this machine as a Worker Node joining a cluster")
    parser.add_argument("--stop", action="store_true", help="Stop the Ray instance on this machine")
    parser.add_argument("--head-ip", type=str, default=None, help="IP address of the Head Node (required for workers)")
    parser.add_argument("--port", type=int, default=6379, help="Ray Redis port (default: 6379)")
    parser.add_argument("--cpus", type=int, default=None, help="CPUs to allocate on this worker node")
    args = parser.parse_args()

    if args.stop:
        stop_node()
    elif args.head:
        start_head_node(port=args.port)
    elif args.worker:
        if not args.head_ip:
            print("Error: --head-ip is required when launching as a worker.")
            sys.exit(1)
        start_worker_node(head_ip=args.head_ip, port=args.port, num_cpus=args.cpus)
    else:
        parser.print_help()
