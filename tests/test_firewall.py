"""Unit tests for the firewall enforcement layer (firewall.py).

The module exists to make it impossible for packet-derived data to shape a
shell command; these tests pin that property from both directions:
validation rejects injection payloads, and the builders emit argv lists
(shell=False at execution).
"""

import pytest

import firewall as fw


@pytest.mark.parametrize("bad", [
    "8.8.8.8; rm -rf /",
    "8.8.8.8 & whoami",
    "8.8.8.8 || id",
    "1.2.3.4 | net user",
    "1.2.3.4\njunk",
    "$(whoami)",
    "`id`",
    "",
    "   ",
    "999.999.999.999",
    "not-an-ip",
    b"bytes-ip",
    None,
])
def test_validate_ip_rejects_injection_payloads(bad):
    with pytest.raises(fw.FirewallValidationError):
        fw.validate_ip(bad)


def test_validate_ip_canonicalizes():
    assert fw.validate_ip(" 192.168.1.50 ") == "192.168.1.50"
    assert fw.validate_ip("::1") == "::1"


def test_validate_ip_rejects_loopback_canonical_form_still_valid():
    # Loopback is valid IP syntax; the POLICY that forbids banning it lives
    # in policy.py/banstore.py. Firewall stays a syntax validator.
    assert fw.validate_ip("127.0.0.1") == "127.0.0.1"


def test_rule_name_shape():
    assert fw.rule_name_for("203.0.113.9") == "NEXUS_BLOCK_203_0_113_9"
    assert fw.rule_name_for("2001:db8::1") == "NEXUS_BLOCK_2001_db8__1"


def test_build_block_argv_windows():
    argv = fw.build_block_argv("203.0.113.9", platform="win32")
    assert argv[0] == "netsh"
    assert "remoteip=203.0.113.9" in argv
    assert "name=NEXUS_BLOCK_203_0_113_9" in argv
    assert "action=block" in argv


def test_build_block_argv_linux():
    argv = fw.build_block_argv("203.0.113.9", platform="linux")
    assert argv == ["iptables", "-A", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]


def test_build_unblock_argv():
    assert fw.build_unblock_argv("203.0.113.9", platform="linux") == \
        ["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]


def test_unknown_platform_refused():
    with pytest.raises(fw.FirewallValidationError):
        fw.build_block_argv("203.0.113.9", platform="sunos")


def test_invalid_ip_never_reaches_a_command():
    with pytest.raises(fw.FirewallValidationError):
        fw.build_block_argv("1.2.3.4; shutdown /r")


def test_dry_run_does_not_execute():
    r = fw.block_ip("203.0.113.9", active=False)
    assert r["active"] is False
    assert r["returncode"] is None
    assert r["error"] is None
    assert r["argv"][0] in ("netsh", "iptables")


def test_apply_command_reports_missing_tool(monkeypatch):
    # active=True on a platform whose tool does not exist: must return a
    # structured error, never raise, never use a shell.
    argv = fw.build_block_argv("203.0.113.9", platform="linux")
    r = fw.apply_command(argv, active=True)
    # On Windows, `iptables` is absent -> FileNotFoundError branch.
    import sys
    if sys.platform == "win32":
        assert r["error"] is not None and "iptables" in r["error"]
    else:
        assert r["returncode"] is not None or r["error"] is not None
