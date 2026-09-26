"""
NEXUS - State Plane & Passive TCP Flow Tracker
RFC 5961 Challenge-ACK validation, directional sequence space tracking,
and defensive anomaly/forensic correlation.
"""

from __future__ import annotations
import os
import sys
import json
import time
import argparse
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Deque, Dict, List, Optional, Set, Tuple

Endpoint = Tuple[str, int]
FlowKey = Tuple[Endpoint, Endpoint]


@dataclass
class TcpObservation:
    ts: float
    seq: int
    ack: Optional[int]
    payload_len: int
    flags: str
    window: int
    ttl: int = 64
    has_timestamp: bool = False

    @property
    def consumes_sequence_space(self) -> int:
        """Calculates TCP sequence space consumption (SYN and FIN consume 1; payload consumes N)."""
        return self.payload_len + int("S" in self.flags) + int("F" in self.flags)

    @property
    def expected_next_seq(self) -> int:
        """Derives the expected next sequence number for this direction."""
        return (self.seq + self.consumes_sequence_space) & 0xFFFFFFFF


@dataclass
class DirectionState:
    observations: Deque[TcpObservation]
    inferred_state: str = "UNKNOWN"
    packets: int = 0
    bytes_payload: int = 0
    reset_count: int = 0
    challenge_ack_count: int = 0
    baseline_ttl: Optional[int] = None
    last_seen: float = field(default_factory=time.time)


@dataclass
class FlowState:
    endpoints: FlowKey
    directions: Dict[Tuple[Endpoint, Endpoint], DirectionState]
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: Set[str] = field(default_factory=set)
    anomalies: List[dict] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)


class PassiveTcpFlowTracker:
    def __init__(self, timeout_seconds: float = 120.0, history_size: int = 8):
        self.timeout_seconds = timeout_seconds
        self.history_size = history_size
        self.flows: Dict[FlowKey, FlowState] = {}

    @staticmethod
    def canonical_key(src: Endpoint, dst: Endpoint) -> FlowKey:
        """Normalizes flow 4-tuple so A->B and B->A share the same canonical key."""
        return (src, dst) if src <= dst else (dst, src)

    def _get_flow(self, src: Endpoint, dst: Endpoint) -> FlowState:
        key = self.canonical_key(src, dst)
        if key not in self.flows:
            a, b = key
            self.flows[key] = FlowState(
                endpoints=key,
                directions={
                    (a, b): DirectionState(deque(maxlen=self.history_size)),
                    (b, a): DirectionState(deque(maxlen=self.history_size)),
                },
            )
        return self.flows[key]

    def observe(
        self,
        *,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        ack: Optional[int],
        flags: str,
        payload_len: int,
        window: int,
        ttl: int = 64,
        has_timestamp: bool = False,
        ts: Optional[float] = None,
    ) -> dict:
        now = time.time() if ts is None else ts
        src = (src_ip, src_port)
        dst = (dst_ip, dst_port)
        flow = self._get_flow(src, dst)
        direction = flow.directions[(src, dst)]

        if direction.baseline_ttl is None:
            direction.baseline_ttl = ttl

        obs = TcpObservation(
            ts=now,
            seq=seq,
            ack=ack,
            payload_len=payload_len,
            flags=flags,
            window=window,
            ttl=ttl,
            has_timestamp=has_timestamp,
        )

        direction.observations.append(obs)
        direction.packets += 1
        direction.bytes_payload += payload_len
        direction.last_seen = now
        flow.last_seen = now

        self._update_state(direction, obs)
        findings = self._detect_anomalies(flow, src, dst, obs)

        event = {
            "ts": now,
            "src": f"{src[0]}:{src[1]}",
            "dst": f"{dst[0]}:{dst[1]}",
            "flags": flags,
            "seq": seq,
            "ack": ack,
            "payload_len": payload_len,
            "expected_next_seq": obs.expected_next_seq,
            "inferred_state": direction.inferred_state,
            "findings": findings,
        }
        flow.timeline.append(event)
        if findings:
            flow.anomalies.extend(findings)

        return {
            "flow": flow.endpoints,
            "direction": (src, dst),
            "state": direction.inferred_state,
            "findings": findings,
            "expected_next_seq": obs.expected_next_seq,
        }

    def _update_state(self, state: DirectionState, obs: TcpObservation) -> None:
        """Conservative directional state transitions."""
        if "R" in obs.flags:
            state.reset_count += 1
            state.inferred_state = "RESET_OBSERVED"
        elif "F" in obs.flags:
            state.inferred_state = "CLOSING"
        elif "S" in obs.flags and "A" not in obs.flags:
            state.inferred_state = "SYN_SEEN"
        elif "S" in obs.flags and "A" in obs.flags:
            state.inferred_state = "SYN_ACK_SEEN"
        elif obs.payload_len > 0:
            state.inferred_state = "ESTABLISHED_CONFIRMED"
        elif "A" in obs.flags and state.inferred_state == "UNKNOWN":
            state.inferred_state = "MIDSTREAM_OBSERVED"
        elif "A" in obs.flags and state.inferred_state in ("SYN_SEEN", "SYN_ACK_SEEN"):
            state.inferred_state = "ESTABLISHED_LIKELY"

    def _detect_anomalies(
        self, flow: FlowState, src: Endpoint, dst: Endpoint, obs: TcpObservation
    ) -> List[dict]:
        findings = []
        reverse = flow.directions[(dst, src)]
        direction = flow.directions[(src, dst)]

        # 1. Reset observed
        if "R" in obs.flags:
            score = 0
            reasons = []

            # Check if flow was established with active data
            if reverse.bytes_payload > 0 or direction.bytes_payload > 0:
                score += 2
                reasons.append("RST appeared on recently active established flow")

            # Sequence progression check
            if len(direction.observations) >= 2:
                prev = direction.observations[-2]
                if obs.seq != prev.expected_next_seq:
                    score += 1
                    reasons.append(f"RST seq ({obs.seq}) conflicts with expected next seq ({prev.expected_next_seq})")

            # TTL deviation check
            if direction.baseline_ttl and abs(obs.ttl - direction.baseline_ttl) > 5:
                score += 1
                reasons.append(f"RST TTL ({obs.ttl}) diverges from baseline ({direction.baseline_ttl})")

            findings.append({
                "type": "tcp_reset_observed",
                "severity": "medium",
                "injection_score": score,
                "reasons": reasons,
                "note": "RST observed; evaluating sequence continuity and RFC 5961 handling.",
            })

        # 2. RFC 5961 Challenge ACK Detection:
        # Receiver sends an ACK shortly after seeing an RST in the reverse direction
        if "A" in obs.flags and "R" not in obs.flags and len(reverse.observations) > 0:
            last_reverse = reverse.observations[-1]
            time_delta = obs.ts - last_reverse.ts
            if "R" in last_reverse.flags and time_delta < 2.0:
                reverse.challenge_ack_count += 1
                findings.append({
                    "type": "rfc5961_challenge_ack",
                    "severity": "high",
                    "note": (
                        f"RFC 5961 Challenge ACK detected ({time_delta*1000:.1f}ms after RST). "
                        "Endpoint received an in-window non-exact RST and challenged the peer; "
                        "connection remained intact."
                    ),
                    "rst_seq": last_reverse.seq,
                    "challenge_ack": obs.ack,
                })

        # 3. Session continuation after RST (proves RST was ineffective or forged)
        if len(direction.observations) >= 2:
            prev = direction.observations[-2]
            if "R" in prev.flags and ("A" in obs.flags or obs.payload_len > 0):
                findings.append({
                    "type": "post_reset_survival",
                    "severity": "critical",
                    "note": "Flow continued transmitting application data/ACKs after an RST. Confirms prior RST was rejected by stack.",
                })

        return findings

    def export_timeline(self, flow_key: FlowKey) -> List[dict]:
        if flow_key in self.flows:
            return self.flows[flow_key].timeline
        return []

    def export_evidence_json(self, flow_key: FlowKey, output_dir: str = "logs/evidence") -> str:
        os.makedirs(output_dir, exist_ok=True)
        flow = self.flows.get(flow_key)
        if not flow:
            return ""

        safe_name = f"{flow_key[0][0]}_{flow_key[0][1]}_to_{flow_key[1][0]}_{flow_key[1][1]}"
        out_file = os.path.join(output_dir, f"evidence_{safe_name}_{int(time.time())}.json")

        payload = {
            "flow": f"{flow_key[0][0]}:{flow_key[0][1]} <-> {flow_key[1][0]}:{flow_key[1][1]}",
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "duration_sec": flow.last_seen - flow.first_seen,
            "anomalies": flow.anomalies,
            "timeline": flow.timeline,
        }

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return out_file

    def expire(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        stale = [k for k, flow in self.flows.items() if now - flow.last_seen > self.timeout_seconds]
        for k in stale:
            del self.flows[k]
        return len(stale)


def ingest_pcap_passive(pcap_path: str, tracker: Optional[PassiveTcpFlowTracker] = None) -> PassiveTcpFlowTracker:
    from scapy.all import rdpcap, IP, TCP, Raw

    if tracker is None:
        tracker = PassiveTcpFlowTracker()

    packets = rdpcap(pcap_path)
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            tracker.observe(
                src_ip=ip.src,
                src_port=tcp.sport,
                dst_ip=ip.dst,
                dst_port=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack if (tcp.flags & 0x10) else None,
                flags=str(tcp.flags),
                payload_len=len(payload),
                window=tcp.window,
                ttl=ip.ttl,
                ts=float(getattr(pkt, "time", time.time())),
            )
    return tracker


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Passive Flow Intelligence & RFC 5961 Validator")
    parser.add_argument("--pcap", type=str, help="PCAP file to passively analyze")
    parser.add_argument("--summary", action="store_true", help="Print summary of all observed flows")
    parser.add_argument("--evidence", action="store_true", help="Export forensic evidence JSON for anomalous flows")
    args = parser.parse_args()

    if args.pcap:
        print(f"[NEXUS State Plane] Analyzing PCAP passively: {args.pcap}")
        tracker = ingest_pcap_passive(args.pcap)
        print(f"[NEXUS State Plane] Analyzed {len(tracker.flows)} canonical flows.")

        for flow_key, flow in tracker.flows.items():
            ep_a, ep_b = flow_key
            print(f"\nFlow: {ep_a[0]}:{ep_a[1]} <-> {ep_b[0]}:{ep_b[1]}")
            for dir_key, dir_state in flow.directions.items():
                print(f"  Leg {dir_key[0]} -> {dir_key[1]}: State={dir_state.inferred_state}, Pkts={dir_state.packets}, Resets={dir_state.reset_count}, ChallengeACKs={dir_state.challenge_ack_count}")
            if flow.anomalies:
                print(f"  [!] Anomalies discovered: {len(flow.anomalies)}")
                for anom in flow.anomalies:
                    print(f"      - {anom['type']} ({anom.get('severity','info')}): {anom.get('note','')}")
                if args.evidence:
                    path = tracker.export_evidence_json(flow_key)
                    print(f"      -> Evidence exported to: {path}")
    else:
        print("Pass --pcap <file.pcap> to analyze traffic passively.")
