"""
NEXUS Firewall Enforcement Layer
================================

Every privileged firewall mutation in NEXUS routes through this module.

Why this module exists
----------------------
Before this module, block/unban paths interpolated packet-derived values (the
source IP) directly into `netsh`/`iptables` command strings executed with
`shell=True`. An attacker who can put bytes on the wire must never be able to
shape a command string. `ops_control.py` already fixed this class of bug for
capture control by whitelisting values and using argument lists; this module
applies the same standard to the firewall paths.

Design rules:
  1. No `shell=True`. Ever. Commands are argv lists.
  2. Every IP is validated by `ipaddress.ip_address()` *before* it can be
     embedded in any command. An invalid IP raises `FirewallValidationError`.
  3. Rule names are generated here from a validated IP, so the rule name is
     always a fixed-shape string.
  4. Platform dispatch is explicit (win32 / Linux); anything else raises
     rather than guessing.
  5. Dry-run is a first-class concept: with `active=False` the same functions
     return the command that *would* run, so the UI and logs can show intent
     without touching the firewall.
"""

from __future__ import annotations

import ipaddress
import subprocess
import sys
from typing import Optional

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

class FirewallValidationError(ValueError):
    """Raised when a value destined for a firewall command fails validation."""


def validate_ip(ip: str) -> str:
    """Return a canonicalized IP string or raise.

    `ipaddress.ip_address()` rejects shell metacharacters, whitespace, and
    anything that is not a valid IPv4/IPv6 address, so passing the *canonical*
    form into a command is safe even if the string originated on the wire.
    """
    if isinstance(ip, (bytes, bytearray)):
        raise FirewallValidationError("IP must be a str, not bytes")
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError as exc:
        raise FirewallValidationError(f"Invalid IP {ip!r}: {exc}") from exc


def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number."""
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise FirewallValidationError(f"Invalid port {port!r}") from exc
    if not (0 <= p <= 65535):
        raise FirewallValidationError(f"Invalid port {port!r}")
    return p


# --------------------------------------------------------------------------
# Rule-name construction (pure, testable)
# --------------------------------------------------------------------------

def rule_name_for(ip: str) -> str:
    """Stable, fixed-shape rule name for a validated IP.

    IPv6 colons become underscores; netsh names are arbitrary strings, so this
    is cosmetic -- but it keeps `NEXUS_BLOCK_*` greppable in firewall dumps.
    """
    ip = validate_ip(ip)
    return "NEXUS_BLOCK_" + ip.replace(":", "_").replace(".", "_")


# --------------------------------------------------------------------------
# Command builders (pure functions -- unit-testable without a firewall)
# --------------------------------------------------------------------------

def build_block_argv(ip: str, platform: Optional[str] = None) -> list:
    """argv that adds a block rule for `ip` on the current (or given) platform."""
    ip = validate_ip(ip)
    platform = platform or sys.platform
    if platform == "win32":
        return ["netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + rule_name_for(ip),
                "dir=in", "action=block", "remoteip=" + ip]
    if platform.startswith("linux"):
        return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    raise FirewallValidationError(
        f"No firewall strategy for platform {platform!r}; refusing to guess")


def build_unblock_argv(ip: str, platform: Optional[str] = None) -> list:
    """argv that removes the block rule for `ip`."""
    ip = validate_ip(ip)
    platform = platform or sys.platform
    if platform == "win32":
        return ["netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name_for(ip)]
    if platform.startswith("linux"):
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    raise FirewallValidationError(
        f"No firewall strategy for platform {platform!r}; refusing to guess")


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def apply_command(argv: list, active: bool, timeout: float = 20.0) -> dict:
    """Run (or dry-run) an argv, returning a structured result.

    Returns: {"active": bool, "argv": [...], "returncode": int|None,
              "error": str|None}
    """
    result = {"active": bool(active), "argv": argv,
              "returncode": None, "error": None}
    if not active:
        return result
    try:
        proc = subprocess.run(argv, shell=False, capture_output=True,
                              text=True, timeout=timeout)
        result["returncode"] = proc.returncode
        if proc.returncode != 0:
            result["error"] = (proc.stderr or proc.stdout or "").strip()[:500]
    except FileNotFoundError:
        result["error"] = f"tool not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        result["error"] = f"timed out after {timeout}s"
    except OSError as exc:
        result["error"] = str(exc)
    return result


def block_ip(ip: str, active: bool = False) -> dict:
    """Block an IP. Validates before anything else; never shells out."""
    argv = build_block_argv(ip)
    return apply_command(argv, active)


def unblock_ip(ip: str, active: bool = False) -> dict:
    """Remove an existing block for an IP."""
    argv = build_unblock_argv(ip)
    return apply_command(argv, active)


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

if __name__ == "__main__":
    failures = []

    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            failures.append(name)

    # Validation positives
    check("ipv4 canonical", validate_ip(" 192.168.1.50 ") == "192.168.1.50")
    check("ipv6 canonical", validate_ip("::1") == "::1")

    # Validation negatives -- the injection class this module exists to kill
    for bad in ("8.8.8.8; rm -rf /", "8.8.8.8 & whoami", "1.2.3.4\njunk",
                "", "999.999.999.999", b"bytes-ip", "1.2.3.4 | net user"):
        try:
            validate_ip(bad)
            check(f"reject {bad!r}", False)
        except FirewallValidationError:
            check(f"reject {bad!r}", True)

    # argv shape: no shell, everything is a single token derived from a
    # validated IP.
    argv = build_block_argv("203.0.113.9", platform="win32")
    check("win32 block argv", argv[:4] == ["netsh", "advfirewall", "firewall",
                                           "add"] and "remoteip=203.0.113.9" in argv)
    argv = build_block_argv("203.0.113.9", platform="linux")
    check("linux block argv", argv == ["iptables", "-A", "INPUT", "-s",
                                       "203.0.113.9", "-j", "DROP"])

    # Rule name shape
    check("rule name", rule_name_for("203.0.113.9") == "NEXUS_BLOCK_203_0_113_9")

    # Dry-run result shape
    r = block_ip("203.0.113.9", active=False)
    check("dry-run does not execute", r["active"] is False and r["returncode"] is None)

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILURES'}")
    sys.exit(1 if failures else 0)
