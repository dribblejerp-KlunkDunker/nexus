"""
NEXUS - Test Suite for State Plane & RFC 5961 Validation
Validates handshake tracking, sequence progression, challenge-ACK discovery,
and forensic evidence exports.
"""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from passive_flow_tracker import PassiveTcpFlowTracker, TcpObservation

class TestPassiveTcpFlowTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = PassiveTcpFlowTracker(timeout_seconds=5.0, history_size=8)
        self.client_ip = "192.168.1.100"
        self.client_port = 49152
        self.server_ip = "203.0.113.10"
        self.server_port = 443

    def test_handshake_and_established_progression(self):
        """Tests SYN -> SYN-ACK -> ACK -> Data state progression."""
        t0 = time.time()

        # 1. Client sends SYN (seq=1000)
        res1 = self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1000, ack=None, flags="S", payload_len=0, window=64240, ts=t0
        )
        self.assertEqual(res1["state"], "SYN_SEEN")
        self.assertEqual(res1["expected_next_seq"], 1001)

        # 2. Server sends SYN-ACK (seq=5000, ack=1001)
        res2 = self.tracker.observe(
            src_ip=self.server_ip, src_port=self.server_port,
            dst_ip=self.client_ip, dst_port=self.client_port,
            seq=5000, ack=1001, flags="SA", payload_len=0, window=65535, ts=t0 + 0.02
        )
        self.assertEqual(res2["state"], "SYN_ACK_SEEN")
        self.assertEqual(res2["expected_next_seq"], 5001)

        # 3. Client sends ACK (seq=1001, ack=5001)
        res3 = self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1001, ack=5001, flags="A", payload_len=0, window=64240, ts=t0 + 0.04
        )
        self.assertEqual(res3["state"], "ESTABLISHED_LIKELY")

        # 4. Client sends HTTP Application Data (len=250 bytes)
        res4 = self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1001, ack=5001, flags="PA", payload_len=250, window=64240, ts=t0 + 0.05
        )
        self.assertEqual(res4["state"], "ESTABLISHED_CONFIRMED")
        self.assertEqual(res4["expected_next_seq"], 1251)

    def test_rfc5961_challenge_ack_and_post_reset_survival(self):
        """
        Simulates an attacker injecting an in-window non-exact sequence RST.
        Modern endpoint rejects it, transmits an RFC 5961 Challenge ACK,
        and connection continues cleanly.
        """
        t0 = time.time()
        # Establish session first
        self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1000, ack=None, flags="S", payload_len=0, window=64240, ts=t0
        )
        self.tracker.observe(
            src_ip=self.server_ip, src_port=self.server_port,
            dst_ip=self.client_ip, dst_port=self.client_port,
            seq=5000, ack=1001, flags="SA", payload_len=0, window=65535, ts=t0 + 0.02
        )
        self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1001, ack=5001, flags="PA", payload_len=500, window=64240, ts=t0 + 0.05
        )

        # Attacker injects a non-exact RST (seq=1200 instead of 1501)
        res_rst = self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1200, ack=None, flags="R", payload_len=0, window=0, ts=t0 + 0.08
        )
        self.assertEqual(res_rst["state"], "RESET_OBSERVED")
        self.assertTrue(any(f["type"] == "tcp_reset_observed" for f in res_rst["findings"]))

        # Server responds with RFC 5961 Challenge ACK (acknowledging 1501) 30ms later
        res_chal = self.tracker.observe(
            src_ip=self.server_ip, src_port=self.server_port,
            dst_ip=self.client_ip, dst_port=self.client_port,
            seq=5001, ack=1501, flags="A", payload_len=0, window=65535, ts=t0 + 0.11
        )
        challenge_findings = [f for f in res_chal["findings"] if f["type"] == "rfc5961_challenge_ack"]
        self.assertEqual(len(challenge_findings), 1, "Should discover RFC 5961 Challenge ACK!")

        # Client continues sending data on the unbroken connection
        res_cont = self.tracker.observe(
            src_ip=self.client_ip, src_port=self.client_port,
            dst_ip=self.server_ip, dst_port=self.server_port,
            seq=1501, ack=5001, flags="PA", payload_len=300, window=64240, ts=t0 + 0.15
        )
        post_survival = [f for f in res_cont["findings"] if f["type"] == "post_reset_survival"]
        self.assertEqual(len(post_survival), 1, "Should detect post-reset session survival!")

        # Verify evidence export
        key = self.tracker.canonical_key((self.client_ip, self.client_port), (self.server_ip, self.server_port))
        evidence_file = self.tracker.export_evidence_json(key, output_dir="logs/test_evidence")
        self.assertTrue(os.path.exists(evidence_file))
        print(f"\n[Test] Forensic evidence exported to: {evidence_file}")


if __name__ == "__main__":
    unittest.main()
