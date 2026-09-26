"""
NEXUS - High-Performance Trusted Device, Subnet & Protocol Whitelist Engine
Provides CIDR, IP, MAC, and Port bypass evaluation with zero-downtime hot-reloading.
Guarantees local LAN gaming, streaming, NAS access, and local dev are never blocked.
"""

import os
import sys
import json
import time
import ipaddress
import logging
from typing import Set, List, Dict, Tuple, Optional

logger = logging.getLogger("NEXUS_WHITELIST")


class WhitelistManager:
    def __init__(self, config_path: str = "config/whitelist.json", whitelist_path: Optional[str] = None):
        self.config_path = whitelist_path or config_path
        self.enabled = True
        self.networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.trusted_ips: Set[str] = set()
        self.trusted_macs: Set[str] = set()
        self.trusted_ports: Set[int] = set()
        self.bypass_local_lan = True
        self.bypass_multicast = True

        self.last_mtime = 0.0
        # Fast query cache: IP string -> (is_whitelisted, reason)
        self._ip_cache: Dict[str, Tuple[bool, str]] = {}
        self._cache_max_size = 4096

        self.load_whitelist()

    def load_whitelist(self, force: bool = False):
        """Loads or reloads whitelist configuration from JSON."""
        if not os.path.exists(self.config_path):
            self._apply_fallback_defaults()
            return

        try:
            mtime = os.path.getmtime(self.config_path)
            if not force and mtime == self.last_mtime:
                return

            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.enabled = data.get("enabled", True)
            self.bypass_local_lan = data.get("bypass_local_lan", True)
            self.bypass_multicast = data.get("bypass_multicast_and_broadcast", True)

            # Parse subnets
            raw_subnets = data.get("subnets", [])
            parsed_nets = []
            for s in raw_subnets:
                try:
                    parsed_nets.append(ipaddress.ip_network(s.strip(), strict=False))
                except Exception as e:
                    logger.warning(f"[WHITELIST] Invalid CIDR '{s}': {e}")
            self.networks = parsed_nets

            # Parse trusted IPs
            self.trusted_ips = {ip.strip().lower() for ip in data.get("trusted_ips", [])}

            # Parse trusted MACs (normalized to lower colon format)
            self.trusted_macs = {self._normalize_mac(m) for m in data.get("trusted_macs", []) if m}

            # Parse trusted ports
            self.trusted_ports = {int(p) for p in data.get("trusted_ports", [])}

            self.last_mtime = mtime
            self._ip_cache.clear()
            logger.info(
                f"[WHITELIST] Loaded {len(self.networks)} subnets, {len(self.trusted_ips)} IPs, "
                f"{len(self.trusted_macs)} MACs, and {len(self.trusted_ports)} ports from {self.config_path}."
            )
        except Exception as e:
            logger.error(f"[WHITELIST ERROR] Failed to load {self.config_path}: {e}")
            if not self.networks:
                self._apply_fallback_defaults()

    def _apply_fallback_defaults(self):
        """Fallback in-memory defaults if config file is absent."""
        self.enabled = True
        self.trusted_ips = {"127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"}
        self.networks = [
            ipaddress.ip_network("127.0.0.0/8", strict=False),
            ipaddress.ip_network("192.168.0.0/16", strict=False),
            ipaddress.ip_network("10.0.0.0/8", strict=False),
            ipaddress.ip_network("172.16.0.0/12", strict=False),
            ipaddress.ip_network("fe80::/10", strict=False),
        ]
        self.trusted_ports = {53, 67, 68, 123, 8000}
        self.trusted_macs = set()
        self._ip_cache.clear()

    def _normalize_mac(self, mac: str) -> str:
        """Normalizes MAC address to lowercase colon format: 00:11:22:33:44:55."""
        clean = mac.replace("-", ":").replace(".", "").lower()
        if len(clean) == 12 and ":" not in clean:
            return ":".join(clean[i:i+2] for i in range(0, 12, 2))
        return clean

    def check_for_reload(self) -> bool:
        """Checks file mtime and triggers reload if modified on disk. Returns True if reloaded."""
        if os.path.exists(self.config_path):
            try:
                mtime = os.path.getmtime(self.config_path)
                if mtime > self.last_mtime:
                    self.load_whitelist(force=True)
                    return True
            except Exception:
                pass
        return False

    def check_and_reload(self) -> bool:
        """Alias for check_for_reload."""
        return self.check_for_reload()

    def is_ip_whitelisted(self, ip_str: str) -> Tuple[bool, str]:
        """Fast evaluation of IP against trusted list and subnets."""
        if not self.enabled or not ip_str:
            return False, ""

        clean_ip = ip_str.strip().lower()

        # Check in-memory cache first
        cached = self._ip_cache.get(clean_ip)
        if cached is not None:
            return cached

        # 1. Exact IP match
        if clean_ip in self.trusted_ips:
            res = (True, "TRUSTED_HOST_IP")
            self._set_cache(clean_ip, res)
            return res

        # 2. Subnet range match
        try:
            addr = ipaddress.ip_address(clean_ip)

            # Multicast / Loopback / Private shortcuts
            if self.bypass_multicast and addr.is_multicast:
                res = (True, "MULTICAST_TRAFFIC")
                self._set_cache(clean_ip, res)
                return res

            if addr.is_loopback:
                res = (True, "LOOPBACK_INTERFACE")
                self._set_cache(clean_ip, res)
                return res

            # Explicit configured subnets (e.g. 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)
            if self.bypass_local_lan:
                for net in self.networks:
                    if addr in net:
                        res = (True, f"WHITELISTED_CIDR_{net}")
                        self._set_cache(clean_ip, res)
                        return res

        except ValueError:
            pass

        res = (False, "")
        self._set_cache(clean_ip, res)
        return res

    def _set_cache(self, key: str, value: Tuple[bool, str]):
        if len(self._ip_cache) >= self._cache_max_size:
            # Simple eviction
            self._ip_cache.clear()
        self._ip_cache[key] = value

    def is_whitelisted(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_mac: Optional[str] = None,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Full-packet whitelist audit covering IP, MAC, and Port dimensions.
        Returns (is_bypassed, reason).
        """
        self.check_for_reload()

        if not self.enabled:
            return False, ""

        actual_ip = src_ip or ip or ""
        actual_sport = sport or port
        actual_dport = dport or (port if sport is not None else None)

        # 1. Port bypass (DNS, DHCP, NTP, Dashboard)
        if actual_sport is not None and actual_sport in self.trusted_ports:
            return True, f"TRUSTED_SOURCE_PORT_{actual_sport}"
        if actual_dport is not None and actual_dport in self.trusted_ports:
            return True, f"TRUSTED_DEST_PORT_{actual_dport}"

        # 2. MAC address bypass
        if src_mac:
            norm_mac = self._normalize_mac(src_mac)
            if norm_mac in self.trusted_macs:
                return True, f"TRUSTED_MAC_{norm_mac}"

        # 3. Source IP audit (Attacker candidate)
        src_ok, src_reason = self.is_ip_whitelisted(actual_ip)
        if src_ok:
            return True, f"SRC_{src_reason}"

        # 4. Destination IP audit (if internal broadcast/multicast)
        if dst_ip:
            dst_ok, dst_reason = self.is_ip_whitelisted(dst_ip)
            if dst_ok and ("MULTICAST" in dst_reason or "LOOPBACK" in dst_reason):
                return True, f"DST_{dst_reason}"

        return False, ""

    def export_summary(self) -> Dict:
        """Returns JSON-serializable whitelist status dictionary."""
        return {
            "enabled": self.enabled,
            "bypass_local_lan": self.bypass_local_lan,
            "bypass_multicast": self.bypass_multicast,
            "subnets": [str(net) for net in self.networks],
            "trusted_ips": sorted(list(self.trusted_ips)),
            "trusted_macs": sorted(list(self.trusted_macs)),
            "trusted_ports": sorted(list(self.trusted_ports)),
            "cached_entries": len(self._ip_cache),
            "config_path": self.config_path
        }


if __name__ == "__main__":
    print("\n--- Testing NEXUS Whitelist Manager ---")
    wm = WhitelistManager("config/whitelist.json")
    print("Summary:", json.dumps(wm.export_summary(), indent=2))

    test_cases = [
        ("127.0.0.1", None, None, None, None, True),
        ("192.168.1.105", None, None, 443, 55555, True),
        ("10.0.0.25", None, None, 80, 50000, True),
        ("172.16.5.10", None, None, 8080, 60000, True),
        ("198.51.100.77", None, None, 55555, 80, False),  # External attacker
        ("203.0.113.19", None, None, 4444, 22, False),    # External scanner
        ("198.51.100.77", None, None, 53, 10000, True),   # DNS source port bypass
    ]

    for sip, dip, mac, sp, dp, expected in test_cases:
        ok, reason = wm.is_whitelisted(sip, dst_ip=dip, src_mac=mac, sport=sp, dport=dp)
        match = (ok == expected)
        status = "[PASS]" if match else "[FAIL]"
        print(f"  {status} IP: {sip:<15} Port: {str(sp):<5} -> Whitelisted: {ok} ({reason})")
        assert match, f"Expected {expected} for {sip}:{sp}"

    print("\nAll Whitelist Manager Tests PASSED!\n")
