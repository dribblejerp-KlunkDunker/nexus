"""Unit tests for the decision policy owner (policy.py)."""

import pytest

import policy


def test_operating_point_in_valid_range():
    assert 0.0 < policy.THREAT_THRESHOLD < 1.0


def test_default_operating_point_is_085():
    assert policy.DEFAULT_THREAT_THRESHOLD == 0.85
    assert policy.THREAT_THRESHOLD == policy.DEFAULT_THREAT_THRESHOLD


def test_is_threat_boundary_is_inclusive():
    thr = policy.THREAT_THRESHOLD
    assert policy.is_threat(thr) is True
    assert policy.is_threat(thr - 0.0001) is False
    assert policy.is_threat(1.0) is True


def test_is_threat_explicit_threshold():
    assert policy.is_threat(0.65, threshold=0.60) is True
    assert policy.is_threat(0.55, threshold=0.60) is False


def test_loopback_protection_set():
    for ip in ("127.0.0.1", "::1", "0.0.0.0"):
        assert policy.is_loopback_ip(ip)
    assert not policy.is_loopback_ip("203.0.113.7")
    # the dashboard consumes the same set
    assert policy.LOOPBACK_IPS == frozenset({"127.0.0.1", "::1", "0.0.0.0"})


def test_escalation_ladder_is_ordered():
    assert policy.PREDICTIVE_ESCALATION_THRESHOLD < \
        policy.PREDICTIVE_ESCALATION_TRIGGER < policy.THREAT_THRESHOLD


def test_predictive_gates_present():
    assert 0.5 < policy.MIN_PREDICTIVE_AUC <= 1.0
    assert policy.MIN_PREDICTIVE_POSITIVES >= 30


def test_holdout_gate_is_five_tenths_percent():
    assert policy.HOLDOUT_FPR_GATE == 0.005


def test_ban_ttl_is_thirty_minutes():
    assert policy.BAN_TTL_SEC == 1800.0


def test_env_override_mechanics(monkeypatch):
    monkeypatch.setenv("NEXUS_THRESHOLD", "0.90")
    assert policy._load_threshold() == pytest.approx(0.90)

    monkeypatch.setenv("NEXUS_THRESHOLD", "1.5")
    with pytest.raises(ValueError):
        policy._load_threshold()

    monkeypatch.setenv("NEXUS_THRESHOLD", "abc")
    with pytest.raises(ValueError):
        policy._load_threshold()

    monkeypatch.setenv("NEXUS_THRESHOLD", "")
    assert policy._load_threshold() == policy.DEFAULT_THREAT_THRESHOLD


def test_council_arbiter_reexports_policy():
    import council_arbiter
    assert council_arbiter.THREAT_THRESHOLD is policy.THREAT_THRESHOLD
