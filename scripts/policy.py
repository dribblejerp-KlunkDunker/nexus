"""
NEXUS Decision Policy
=====================

The single owner of every number that turns a score into a decision.

Before this module the operating threshold (0.85) existed as a hardcoded
literal in the council arbiter, the dashboard scoring loop (twice), the live
guardian (four times), and two benchmark harnesses. Numbers that decide
blocking must have one definition and one home: an operator should be able to
change the operating point in exactly one place and have every consumer --
training gates, runtime blocking, benchmarks, audits -- follow, and an auditor
should be able to read one file to know what the system's decision bar is.

Constants live here; consumers import. `council_arbiter.THREAT_THRESHOLD` is
now a re-export of `policy.THREAT_THRESHOLD`, so existing imports keep working
while grep-ability stays with the old name.

Env override: `NEXUS_THRESHOLD` may move the operating point (validated float
in (0, 1)). A warning is printed once at import when it differs from the
default, and `train_honest.py` writes the point actually used into
`genomes/council_manifest.json`, which `ops_audit.py` compares against this
module -- so drift between the promotion gate and the runtime is detected, not
silent.

Self-test:
    python scripts/policy.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional, Tuple

# --------------------------------------------------------------------------
# The operating point
# --------------------------------------------------------------------------
# Raw specialist/monolith scores are in [0, 1]. A score >= THREAT_THRESHOLD
# raises a threat verdict in the council arbiter, the dashboard scoring loop,
# and the live guardian. This is the bar the holdout gate in train_honest.py
# measures against -- change it and re-run the holdout, never one without the
# other.
DEFAULT_THREAT_THRESHOLD = 0.85


def _load_threshold() -> float:
    raw = os.environ.get("NEXUS_THRESHOLD")
    if raw is None or raw.strip() == "":
        return DEFAULT_THREAT_THRESHOLD
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(
            f"NEXUS_THRESHOLD must be a number in (0, 1), got {raw!r}") from None
    if not 0.0 < val < 1.0:
        raise ValueError(
            f"NEXUS_THRESHOLD must be in (0, 1) exclusive, got {val}")
    return val


try:
    THREAT_THRESHOLD: float = _load_threshold()
except ValueError as _e:
    # A bad override must never keep the dashboard or guardian from booting:
    # fall back loudly (stderr) and let ops_audit surface the real point.
    print(f"[NEXUS policy] {_e}", file=sys.stderr)
    print("[NEXUS policy] falling back to the default operating point "
          f"{DEFAULT_THREAT_THRESHOLD}", file=sys.stderr)
    THREAT_THRESHOLD = DEFAULT_THREAT_THRESHOLD

if THREAT_THRESHOLD != DEFAULT_THREAT_THRESHOLD:
    print(f"[NEXUS policy] operating point override active: "
          f"{THREAT_THRESHOLD} (default {DEFAULT_THREAT_THRESHOLD}). "
          f"Re-run train_honest.py at this point before trusting the gate.")

# --------------------------------------------------------------------------
# Predictive escalation (live guardian)
# --------------------------------------------------------------------------
# When the ONNX predictive brain is VALIDATED (AUC + positives floor below)
# it may drop the blocking bar to PREDICTIVE_ESCALATION_THRESHOLD once the
# forecast probability passes PREDICTIVE_ESCALATION_TRIGGER. Both numbers were
# previously literals inside NexusGuardian.__init__ defaults.
PREDICTIVE_ESCALATION_THRESHOLD = 0.70
PREDICTIVE_ESCALATION_TRIGGER = 0.75

# The bar the predictive brain must clear before it is allowed to move the
# threshold (mirrored from sniff_and_respond.py; one definition now).
MIN_PREDICTIVE_AUC = 0.75
MIN_PREDICTIVE_POSITIVES = 100

# --------------------------------------------------------------------------
# Enforcement policy
# --------------------------------------------------------------------------
# Ban TTL for an automated verdict. 30 minutes, previously a magic literal in
# dashboard.py (1800) and NexusGuardian's default (1800).
BAN_TTL_SEC = 1800.0

# A score at or above the threshold never blocks loopback / unspecified
# sources. One set, previously re-typed at every decision site.
LOOPBACK_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0"})

# --------------------------------------------------------------------------
# Holdout promotion gate (train_honest.py / train_council_moe.py)
# --------------------------------------------------------------------------
# Mirrors the README claim: a specialist or monolith may only take a seat if
# its held-out benign false-positive rate is at most 0.5%.
HOLDOUT_FPR_GATE = 0.005

# --------------------------------------------------------------------------
# Audit-verified enforcement interlock
# --------------------------------------------------------------------------
# Live firewall blocking is the one action in this platform that can drop
# packets from a real host, so it may only be armed while the most recent
# regression audit (ops.py audit -> ops_audit.py -> logs/audit_report.json)
# ended PASS. WARN means the measured evidence has a hole (narrow capture
# baseline, stale calibration) and blocking stays in simulation mode until a
# clean run; FAIL means a benign host would be firewalled. A missing or
# unreadable report is an unknown safety state and is refused too: the
# interlock fails closed.
AUDIT_REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "audit_report.json")


def audit_verdict(report_path: str = None) -> Optional[str]:
    """The verdict of the most recent regression audit, or None.

    None means never audited (or the report is unreadable / carries an
    unknown verdict string) -- an unknown safety state, which the arming
    interlock treats exactly like a failure.
    """
    path = report_path or AUDIT_REPORT_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            verdict = json.load(f).get("verdict")
    except Exception:
        return None
    return verdict if verdict in ("PASS", "WARN", "FAIL") else None


def enforcement_may_arm(report_path: str = None) -> Tuple[bool, str]:
    """(allowed, reason) for arming live firewall enforcement right now.

    Reads the same report ops_audit.py writes; PASS is the only verdict that
    permits arming. The reason string is operator-facing in both the CLI
    refusal and the /api/defense/toggle 409.
    """
    verdict = audit_verdict(report_path)
    if verdict is None:
        return False, (
            "no audit verdict found (logs/audit_report.json is missing or "
            "unreadable). Run 'python scripts/ops.py audit' first -- blocking "
            "never arms on an unknown safety state.")
    if verdict == "PASS":
        return True, "last audit verdict PASS"
    if verdict == "WARN":
        return False, (
            "last audit verdict is WARN -- the measured evidence has a hole "
            "and blocking stays in simulation mode. Run "
            "'python scripts/ops.py audit' after fixing the warning checks "
            "in logs/audit_report.json.")
    return False, (
        f"last audit verdict is {verdict} -- a benign host would be "
        f"firewalled. Resolve the failing checks in logs/audit_report.json "
        f"and re-run 'python scripts/ops.py audit'.")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def is_threat(score: float, threshold: float = None) -> bool:
    """True when a raw council score crosses the operating point (inclusive)."""
    if threshold is None:
        threshold = THREAT_THRESHOLD
    return bool(float(score) >= threshold)


def is_loopback_ip(ip: str) -> bool:
    """True for sources automated blocking must never touch.

    Membership in LOOPBACK_IPS, not heuristics: the loopback set is a policy
    list, and policy lists should be greppable. (firewall.validate_ip still
    does full `ipaddress` validation for anything that reaches the OS.)
    """
    return str(ip) in LOOPBACK_IPS


def operating_point() -> float:
    """The threshold the runtime is actually using (single read point)."""
    return THREAT_THRESHOLD


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _selftest() -> int:
    failures = []

    def check(name, cond):
        status = "PASS" if cond else "FAIL"
        print(f"  [{status}] {name}")
        if not cond:
            failures.append(name)

    print("NEXUS policy self-test")

    check("operating point within (0, 1)",
          0.0 < THREAT_THRESHOLD < 1.0)
    check("escalation threshold below operating point",
          PREDICTIVE_ESCALATION_THRESHOLD < THREAT_THRESHOLD)
    check("escalation trigger above escalation threshold",
          PREDICTIVE_ESCALATION_TRIGGER > PREDICTIVE_ESCALATION_THRESHOLD)
    check("escalation trigger below operating point",
          PREDICTIVE_ESCALATION_TRIGGER < THREAT_THRESHOLD)

    check("is_threat inclusive at the boundary",
          is_threat(THREAT_THRESHOLD) is True)
    check("is_threat exclusive below the boundary",
          is_threat(THREAT_THRESHOLD - 0.001) is False)
    check("is_threat honors explicit threshold",
          is_threat(0.65, threshold=0.60) is True)

    for ip in ("127.0.0.1", "::1", "0.0.0.0"):
        check(f"loopback protected: {ip}", is_loopback_ip(ip))
    check("public IP not loopback", not is_loopback_ip("203.0.113.7"))

    check("holdout gate below operating point sanity",
          0.0 < HOLDOUT_FPR_GATE <= 0.05)

    # Interlock mechanics against throwaway reports, never the live one.
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="nexus_policy_selftest_")
    for verdict, expected in (("PASS", True), ("WARN", False), ("FAIL", False)):
        p = os.path.join(tmpdir, f"report_{verdict}.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"verdict": verdict}, f)
        allowed, _ = enforcement_may_arm(p)
        check(f"interlock verdict {verdict} -> {'arm' if expected else 'refuse'}",
              allowed is expected)
    missing = os.path.join(tmpdir, "absent.json")
    check("interlock missing report -> refuse (fail closed)",
          enforcement_may_arm(missing)[0] is False)
    p = os.path.join(tmpdir, "report_garbage.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{not json")
    check("interlock unreadable report -> refuse (fail closed)",
          enforcement_may_arm(p)[0] is False)

    # Env override mechanics (tested through _load_threshold, which reads the
    # environment at call time -- no module reload gymnastics needed).
    saved = os.environ.pop("NEXUS_THRESHOLD", None)
    try:
        os.environ["NEXUS_THRESHOLD"] = "0.90"
        check("env override parses 0.90", abs(_load_threshold() - 0.90) < 1e-9)
        os.environ["NEXUS_THRESHOLD"] = "1.5"
        try:
            _load_threshold()
            check("out-of-range override rejected", False)
        except ValueError:
            check("out-of-range override rejected", True)
        os.environ["NEXUS_THRESHOLD"] = "abc"
        try:
            _load_threshold()
            check("non-numeric override rejected", False)
        except ValueError:
            check("non-numeric override rejected", True)
        os.environ["NEXUS_THRESHOLD"] = ""
        check("empty override means default",
              abs(_load_threshold() - DEFAULT_THREAT_THRESHOLD) < 1e-9)
    finally:
        if saved is not None:
            os.environ["NEXUS_THRESHOLD"] = saved
        else:
            os.environ.pop("NEXUS_THRESHOLD", None)

    print()
    if failures:
        print(f"{len(failures)} FAILURES: {failures}")
        return 1
    print("All policy self-tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(_selftest())
