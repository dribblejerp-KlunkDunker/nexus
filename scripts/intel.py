"""
NEXUS Intel Enrichment Layer
============================

Replaces the inline enrichment that used to live in dashboard.py, with a
strict honesty contract:

 1. NO fabricated attribution. If a GeoIP lookup fails, the dossier says
    "attribution unavailable" -- it NEVER invents a threat actor, malware
    family, or city. A failed lookup is not a measurement of hostile.
 2. HTTPS only for third-party lookups. A failed HTTPS lookup is better
    than a successful HTTP one that an on-path attacker can rewrite.
 3. Responses are schema-validated: only whitelisted fields enter the
    dossier, and strings are length-capped before display.
 4. Every record carries "provenance" naming where each fact came from:
    "live:<host>", "cache:threat_intel", "heuristic:rfc1918",
    "heuristic:ttl-window", "lookup:port", or "unavailable".
 5. "risk": "CRITICAL" is asserted ONLY on a verified intel-cache match.
    Heuristic OS guessing stays explicitly labelled as speculative and
    never sets risk.

The default provider (ipwho.is) is free, keyless HTTPS. Override with
NEXUS_GEO_URL (a template containing {ip}); an http:// override is refused.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import urllib.parse
import urllib.request
from typing import Dict, Optional

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

DEFAULT_GEO_URL = "https://ipwho.is/{ip}"
GEO_TIMEOUT_SEC = 2.0
USER_AGENT = "NEXUS-Defense/1.1"

# IANA documentation ranges (RFC 5737). Modern Python already calls these
# is_private, but they deserve their own honest label: they are neither LAN
# hosts nor attack infrastructure, and MUST NOT be attributed.
DOCUMENTATION_NETS = [
    ipaddress.ip_network(n) for n in
    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
     "2001:db8::/32")
]

# Service classification for target ports (pure lookup, no enrichment).
SERVICE_MAP = {
    80: "HTTP Web Server (Layer 7 DoS Target)",
    443: "HTTPS TLS Endpoint (SSL Handshake Exhaustion)",
    22: "SSH Secure Shell (Brute-Force & Credential Stuffing)",
    3389: "RDP Remote Desktop (BlueKeep Exploit Probe)",
    445: "SMB / Windows File Sharing (EternalBlue MS17-010 Vector)",
    53: "DNS Core Resolver (Reflection / Amplification Staging)",
    8080: "HTTP Alternate / Web Management (Mirai IoT Vector)",
}


class IntelError(RuntimeError):
    """Raised for configuration problems (e.g. an insecure provider URL)."""


# --------------------------------------------------------------------------
# Response schema validation
# --------------------------------------------------------------------------

def _cap(value, limit: int) -> str:
    """Coerce to a length-capped string."""
    s = str(value) if value is not None else ""
    return s[:limit]


def _validate_geo_payload(payload: dict, source_host: str) -> dict:
    """Whitelist + cap fields from a third-party GeoIP response."""
    conn = payload.get("connection") or {}
    code = _cap(payload.get("country_code") or payload.get("countryCode") or "", 2)
    flag = "".join(chr(127397 + ord(c)) for c in code.upper()) if len(code) == 2 else "🌐"
    return {
        "country": _cap(payload.get("country"), 64) or "Unknown",
        "code": code or "??",
        "flag": flag,
        "city": _cap(payload.get("city"), 64) or "Unknown",
        "asn": _cap(conn.get("asn") and f"AS{conn['asn']} {conn.get('org') or conn.get('isp') or ''}"
                    or conn.get("org") or conn.get("isp") or payload.get("as"), 128) or "Unknown ASN",
        "org": _cap(conn.get("org") or conn.get("isp") or payload.get("org"), 128) or "Unknown ISP",
        "provenance": f"live:{source_host}",
    }


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class IntelService:
    """Threat-intel enrichment with an honesty contract. Thread-safe caches."""

    def __init__(self, threat_intel_file: str = "data/threat_intel_cache.json",
                 geo_url: Optional[str] = None, timeout: float = GEO_TIMEOUT_SEC):
        self.geo_url = geo_url or os.environ.get("NEXUS_GEO_URL") or DEFAULT_GEO_URL
        if not self.geo_url.startswith("https://"):
            raise IntelError(
                f"GeoIP provider must be HTTPS (got {self.geo_url!r}). "
                f"An on-path attacker must not be able to rewrite attribution "
                f"shown to the operator.")
        if "{ip}" not in self.geo_url:
            raise IntelError("GeoURL template must contain '{ip}'")
        self.timeout = timeout

        self._geo_cache: Dict[str, dict] = {}
        self._lock = threading.Lock()

        self.threat_intel: Dict[str, dict] = {}
        self._load_threat_intel(threat_intel_file)

    # ------------------------------------------------------------ loaders --
    def _load_threat_intel(self, path: str) -> None:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.threat_intel = data.get("ips", {}) or {}
                print(f"[NEXUS Intel] Loaded {len(self.threat_intel)} verified "
                      f"C2/botnet indicators from {path}")
            except Exception as exc:  # corrupt cache must not kill the sensor
                print(f"[NEXUS Intel] Error loading threat cache: {exc}")

    # ------------------------------------------------------------- lookup --
    def lookup(self, ip: str, ttl: int = 64, window: int = 1024,
               dport: int = 80) -> dict:
        """Build the dossier for one IP. Never raises for data problems."""
        intel: dict = {"ip": ip}

        # 1. Local-address short-circuit (precise, not string-prefix guessing)
        try:
            addr = ipaddress.ip_address(ip)
            is_doc = any(addr in net for net in DOCUMENTATION_NETS)
            is_local = (not is_doc and
                        (addr.is_private or addr.is_loopback
                         or addr.is_link_local or addr.is_reserved))
        except ValueError:
            is_doc = False
            is_local = False

        if is_doc:
            intel.update({
                "country": "Reserved Range", "code": "RSV", "flag": "🧪",
                "city": "RFC 5737 documentation block",
                "asn": "IANA special-purpose",
                "org": "Documentation range",
                "threat_actor": "Not attributed (reserved range)",
                "risk": "UNKNOWN",
                "provenance": "heuristic:rfc5737",
            })
        elif is_local:
            intel.update({
                "country": "Local LAN", "code": "LAN", "flag": "🏠",
                "city": "Internal Subnet",
                "asn": "RFC 1918 / loopback / link-local",
                "org": "Local Trusted Host",
                "threat_actor": "Not attributed (local address)",
                "risk": "LOW",
                "provenance": "heuristic:rfc1918",
            })
        else:
            intel.update(self._geo_with_cache(ip))

        # 2. Reverse DNS (best-effort; may be slow on some resolvers)
        try:
            rdns = socket.getfqdn(ip)
            intel["rdns"] = rdns if rdns != ip else "No PTR Record"
        except Exception:
            intel["rdns"] = "No PTR Record"

        # 3. Passive OS guess -- explicitly a heuristic, never risk
        if ttl <= 32:
            intel["os_guess"] = "Aggressive Scanner (ZMap / Masscan / Scapy Raw)"
        elif ttl == 64 and window in (5840, 29200, 64240, 65535):
            intel["os_guess"] = "Linux Kernel 3.x - 6.x (Ubuntu / Debian / CentOS)"
        elif ttl == 128 and window in (8192, 64240, 65535):
            intel["os_guess"] = "Windows NT 10 / 11 / Server 2022"
        elif ttl >= 200:
            intel["os_guess"] = "Cisco IOS / Network Hardware / BSD"
        else:
            intel["os_guess"] = f"Custom TCP Stack (TTL={ttl}, Win={window})"
        intel["os_guess_provenance"] = "heuristic:ttl-window (speculative)"

        # 4. Target service classification
        intel["target_service"] = SERVICE_MAP.get(
            dport, f"TCP Port {dport}")
        intel["service_provenance"] = "lookup:port"

        # 5. Verified intel match -- the ONLY path to CRITICAL
        c2 = self.threat_intel.get(ip)
        if c2:
            intel["c2_match"] = True
            intel["threat_actor"] = f"{c2.get('malware', 'Unknown malware')} " \
                                    f"({c2.get('threat_type', 'unknown type')})"
            intel["malware_family"] = c2.get("malware", "")
            intel["confidence"] = c2.get("confidence_level", 95)
            mitre_id = c2.get("mitre_id", "")
            intel["mitre"] = {
                "id": mitre_id,
                "name": c2.get("mitre_name", ""),
                "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
            }
            intel["risk"] = "CRITICAL"
            intel["risk_provenance"] = "verified:threat_intel_cache"

        return intel

    # ---------------------------------------------------------------- geo --
    def _geo_with_cache(self, ip: str) -> dict:
        with self._lock:
            hit = self._geo_cache.get(ip)
        if hit:
            d = dict(hit)
            d["provenance"] = d.get("provenance", "live") + "+cache"
            return d
        fresh = self._geo_live(ip)
        with self._lock:
            self._geo_cache[ip] = fresh
        return dict(fresh)

    def _geo_live(self, ip: str) -> dict:
        """HTTPS lookup with strict failure semantics.

        On ANY failure the record states attribution is unavailable. It does
        not fabricate an actor, a city, or a risk level -- that is the whole
        point of this module.
        """
        try:
            url = self.geo_url.format(ip=ip)
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = json.loads(resp.read().decode("utf-8", errors="replace"))

            host = urllib.parse.urlparse(url).hostname or "provider"
            # ipwho.is nests connection fields; flat providers (ip-api pro)
            # use top-level keys -- _validate_geo_payload handles both.
            if raw.get("success") is False:
                raise ValueError("provider reported lookup failure")
            return _validate_geo_payload(raw, host)
        except Exception:
            return {
                "country": "Unknown", "code": "??", "flag": "🌐",
                "city": "Unknown",
                "asn": "Lookup unavailable",
                "org": "Lookup unavailable",
                "threat_actor": "Attribution unavailable",
                "risk": "UNKNOWN",
                "provenance": "unavailable:lookup_failed_or_offline",
            }


# --------------------------------------------------------------------------
# MITRE ATT&CK technique classification (moved verbatim from dashboard.py)
# --------------------------------------------------------------------------

def classify_mitre_technique(dport: int, flags: str, entropy: float,
                             score: float, intel: dict,
                             raw_payload: bytes = b"") -> dict:
    """Classifies anomalous packet behavior into MITRE ATT&CK Enterprise techniques."""
    if intel.get("mitre"):
        return intel["mitre"]

    if dport in (3333, 4444, 5555, 7777) or b"mining." in raw_payload:
        return {
            "id": "T1496",
            "name": "Resource Hijacking: Stratum Cryptomining",
            "url": "https://attack.mitre.org/techniques/T1496/"
        }
    if flags in ("FPU", "F", "SF", "") or flags == "0":
        return {
            "id": "T1046",
            "name": "Network Service Discovery: Stealth TCP Scan",
            "url": "https://attack.mitre.org/techniques/T1046/"
        }
    if dport in (445, 139):
        return {
            "id": "T1021.002",
            "name": "Remote Services: SMB/Windows Admin Shares",
            "url": "https://attack.mitre.org/techniques/T1021/002/"
        }
    if dport in (22, 3389):
        return {
            "id": "T1110.001",
            "name": "Brute Force: Password Guessing (SSH/RDP)",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        }
    if entropy >= 0.85 and len(raw_payload) >= 800:
        return {
            "id": "T1048.003",
            "name": "Exfiltration Over Alternative Protocol (Encrypted)",
            "url": "https://attack.mitre.org/techniques/T1048/003/"
        }
    if dport in (8443, 8000, 4444, 8888, 9001) and entropy >= 0.80:
        return {
            "id": "T1071.001",
            "name": "Command and Control: Web Protocols (Malleable C2 Beacon)",
            "url": "https://attack.mitre.org/techniques/T1071/001/"
        }
    if raw_payload.startswith(b"MZ") or raw_payload.startswith(b"\x7fELF"):
        return {
            "id": "T1105",
            "name": "Ingress Tool Transfer: Executable Dropper / Stager",
            "url": "https://attack.mitre.org/techniques/T1105/"
        }
    if "S" in flags and score >= 0.80:
        return {
            "id": "T1498.001",
            "name": "Network Denial of Service: Direct Network Flood",
            "url": "https://attack.mitre.org/techniques/T1498/001/"
        }
    return {
        "id": "T1046",
        "name": "Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/"
    }


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    failures = []

    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            failures.append(name)

    svc = IntelService(threat_intel_file="data/__no_such_cache__.json")

    # Local addresses are recognised precisely, without fabrication
    rec = svc.lookup("192.168.1.50", ttl=64, window=64240, dport=443)
    check("LAN recognised", rec["code"] == "LAN")
    check("LAN not attributed to an actor", "Not attributed" in rec["threat_actor"])

    # RFC 5737 documentation ranges get their own honest label
    rec = svc.lookup("203.0.113.42", ttl=128, window=8192, dport=445)
    check("TEST-NET labelled reserved", rec["code"] == "RSV")
    check("TEST-NET never attributed to an actor",
          "Not attributed" in rec["threat_actor"] and rec["risk"] == "UNKNOWN")

    # A private-ish looking but invalid string must not crash the sensor
    rec = svc.lookup("999.999.1.1")
    check("invalid IP tolerated", isinstance(rec, dict) and rec.get("ip") == "999.999.1.1")

    # Deterministic lookup failure: unroutable HTTPS endpoint. The dossier
    # must say "unavailable", never invent attribution.
    svc_offline = IntelService(threat_intel_file="data/__no_such_cache__.json",
                               geo_url="https://127.0.0.1:1/{ip}", timeout=0.5)
    rec = svc_offline.lookup("93.184.216.34", ttl=128, window=8192, dport=445)
    check("failed lookup says unavailable",
          rec.get("threat_actor") == "Attribution unavailable" and
          rec.get("provenance") == "unavailable:lookup_failed_or_offline")
    check("failed lookup never fabricates a named actor",
          "APT" not in json.dumps(rec) and "Lazarus" not in json.dumps(rec))
    check("failed lookup risk is UNKNOWN, not CRITICAL", rec["risk"] == "UNKNOWN")

    # OS heuristic labelled as speculative
    check("os heuristic labelled", "speculative" in rec["os_guess_provenance"])

    # MITRE mapping sanity (pure function)
    m = classify_mitre_technique(445, "PA", 0.4, 0.9, intel={}, raw_payload=b"")
    check("mitre smb mapping", m["id"] == "T1021.002")
    m = classify_mitre_technique(80, "", 0.1, 0.9, intel={}, raw_payload=b"")
    check("mitre null-flag mapping", m["id"] == "T1046")

    # Insecure provider configuration is refused
    try:
        IntelService(geo_url="http://ip-api.com/json/{ip}")
        check("http provider refused", False)
    except IntelError:
        check("http provider refused", True)

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILURES'}")
    sys.exit(1 if failures else 0)
