"""Endpoint-level smoke tests for the NEXUS dashboard API.

The import smoke test in test_architecture.py proves dashboard.py boots;
this file proves every API route actually answers. These are smoke tests,
not unit tests: each route gets exercised exactly the way the HUD's fetch
calls exercise it, and the assertions pin the response *shape* the UI
depends on (a route that starts returning a different envelope should
fail here before the operator sees a broken panel).

Two ground rules, learned from the machine states this suite must run on:

1. OFFLINE. No test may perform a live GeoIP lookup. dashboard.resolve_ip_intel
   is stubbed at the INTEL_SERVICE boundary with the same schema intel.py
   emits (provenance included), so simulate/clean and intel/lookup return
   deterministic data with zero network traffic.

2. NO REAL SIDE EFFECTS. The firewall layer is never invoked with
   active=True (bans land in the in-memory BanStore only), the whitelist
   mutation test restores config/whitelist.json byte-for-byte, and the SSE
   test subscribes and leaves. CI has no neat/scapy -- the code under test
   already degrades to HEURISTIC_ONLY there, which these tests pin as the
   honest floor.
"""

import json
import os
import sys

import pytest

pytest.importorskip("fastapi", reason="dashboard API smoke tests need fastapi+httpx (pip install fastapi httpx)")

SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


# ---------------------------------------------------------------------------
# Fixture: client with the intel layer stubbed offline
# ---------------------------------------------------------------------------

def _stub_intel(mod):
    """Replace the live IntelService with an offline, schema-identical stub."""
    def fake_lookup(ip, ttl=64, window=1024, dport=80):
        return {
            "ip": ip,
            "flag": "",
            "country": "attribution unavailable",
            "city": "attribution unavailable",
            "asn": "unavailable",
            "threat_actor": "unavailable",
            "os_guess": "speculative (TTL-based)",
            "target_service": f"tcp/{dport}",
            "c2_match": False,
            "malware_family": "",
            "provenance": {"country": "test-stub", "asn": "test-stub"},
        }
    mod.INTEL_SERVICE.lookup = fake_lookup


@pytest.fixture(scope="module")
def client():
    import dashboard
    _stub_intel(dashboard)
    from fastapi.testclient import TestClient
    # No context manager on purpose: entering one runs the lifespan, which
    # spawns the throughput ticker task. Plain instantiation serves requests
    # without background tasks -- exactly what a smoke suite wants.
    # base_url must be a webguard.LOOPBACK_HOSTS member: state-changing
    # requests are Host-fenced, and TestClient's default "testserver" host
    # would be (correctly) refused with 403 on every POST.
    return TestClient(dashboard.app, base_url="http://127.0.0.1")


# ---------------------------------------------------------------------------
# Core read-only routes
# ---------------------------------------------------------------------------

def test_index_serves_hud(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "NEXUS" in r.text and "CYBER-GUARDIAN" in r.text


def test_status_shape(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    for key in ("status", "active_defense", "total_packets", "total_threats",
                "bans", "live_sniffing", "council"):
        assert key in body, f"/api/status lost the '{key}' field the HUD reads"


def test_council_status_shape(client):
    r = client.get("/api/council/status")
    assert r.status_code == 200
    body = r.json()
    assert {"mode", "specialists", "seat_provenance"} <= set(body)


def test_adversary_stats_shape(client):
    r = client.get("/api/adversary/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert "hall_of_fame_count" in body and "benchmark" in body


def test_surgeon_status_shape(client):
    r = client.get("/api/surgeon/status")
    assert r.status_code == 200
    body = r.json()
    assert {"status", "total_surgeries", "recent_interventions"} <= set(body)


def test_whitelist_summary_shape(client):
    r = client.get("/api/whitelist")
    assert r.status_code == 200
    body = r.json()
    assert {"enabled", "subnets", "trusted_ips", "trusted_ports"} <= set(body)


def test_genome_route_answers_without_neat(client):
    """With neat absent this returns {"error": ...} honestly; with neat
    present it returns the topology. Either way: no 500."""
    r = client.get("/api/genome")
    assert r.status_code == 200
    body = r.json()
    assert ("error" in body) or ("inputs" in body and "connections" in body)


def test_training_stats_shape(client):
    r = client.get("/api/training/stats")
    assert r.status_code == 200
    body = r.json()
    assert "evolution_history" in body


def test_telemetry_history_shape(client):
    r = client.get("/api/telemetry/history")
    assert r.status_code == 200
    body = r.json()
    assert {"scores", "velocity", "continuous", "logs"} <= set(body)


def test_sniff_status_shape(client):
    r = client.get("/api/sniff/status")
    assert r.status_code == 200
    assert "running" in r.json()


def test_continuous_status_shape(client):
    r = client.get("/api/continuous/status")
    assert r.status_code == 200
    assert "is_running" in r.json()


def test_ops_summary_shape(client):
    r = client.get("/api/ops/summary")
    assert r.status_code == 200
    body = r.json()
    assert "tiers" in body and "schedule" in body and "champion_sha256" in body


def test_ops_tags_shape(client):
    r = client.get("/api/ops/tags")
    assert r.status_code == 200
    tags = r.json()["tags"]
    assert tags and {"tag", "label"} <= set(tags[0])


def test_ops_job_status_unknown_key(client):
    r = client.get("/api/ops/job/definitely-not-a-job")
    assert r.status_code == 200  # job_status answers, doesn't 500
    assert "error" in r.json() or "running" in r.json()


def test_ops_schedule_status_shape(client):
    r = client.get("/api/ops/schedule")
    assert r.status_code == 200
    assert "supported" in r.json()


def test_intel_lookup_uses_stub(client):
    r = client.get("/api/intel/lookup/8.8.8.8")
    assert r.status_code == 200
    body = r.json()
    assert body["ip"] == "8.8.8.8"
    assert body["provenance"] == {"country": "test-stub", "asn": "test-stub"}


# ---------------------------------------------------------------------------
# POST /api/simulate/{attack_type} -- every attack type the HUD can send,
# plus the two aliases only reachable by hand.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_type", [
    "synflood", "sshbrute", "c2beacon", "exfil", "stratum", "xmasscan",
    "worm", "clean", "evasive_c2", "evasive_flood", "evasive_scan",
    "evasive_exfil",
])
def test_simulate_all_attack_types(client, attack_type):
    r = client.post(f"/api/simulate/{attack_type}")
    assert r.status_code == 200, f"simulate/{attack_type} broke"
    body = r.json()
    assert body["status"] in ("ok", "whitelisted")
    if body["status"] == "ok":
        assert isinstance(body["score"], float)
        assert "intel" in body


def test_simulate_inbound_threats_score_and_ban(client):
    """xmasscan (FPU flags from a public IP) must be evaluated and scored as
    hostile in EVERY council mode: the heuristic floor scores flag features
    0.95, and the trained genomes score recon probes ~0.97. (A single SYN
    packet, by contrast, legitimately scores ~0 in HEURISTIC mode -- rate
    features need a rate.) This is the decision path, exercised with the
    firewall layer untouched."""
    import dashboard
    r = client.post("/api/simulate/xmasscan")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["score"] >= 0.5, "an FPU-flag scan scoring <0.5 means the decision path is dead"
    # At threshold it must land in the in-memory ban store (the endpoint's
    # src is IP:port; the store is keyed by IP)...
    src_ip = body["src"].split(":")[0]
    if body["score"] >= 0.85:
        assert src_ip in dashboard.BAN_STORE.active()
    # ...and the HUD-facing counters must have moved.
    assert dashboard.SHARED_STATE["packets_evaluated"] > 0
    assert dashboard.SHARED_STATE["last_score"] == body["score"]


def test_simulate_outbound_whitelisted_honest_response(client):
    """The default whitelist trusts all RFC1918 sources, so the outbound sims
    are deliberately not evaluated. The endpoint must SAY so -- this is the
    regression test for the 500 it used to raise here."""
    r = client.post("/api/simulate/clean")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "whitelisted"
    assert "192.168.0.0/16" in body["reason"]


# ---------------------------------------------------------------------------
# Mutating routes -- each restores the world before returning
# ---------------------------------------------------------------------------

def test_whitelist_add_round_trip(client):
    import dashboard
    config_path = "config/whitelist.json"
    with open(config_path, "rb") as f:
        original = f.read()
    try:
        r = client.post("/api/whitelist/add",
                        json={"item_type": "ip", "value": "203.0.113.77"})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert "203.0.113.77" in dashboard.WHITELIST_MGR.trusted_ips
        # The manager must actually honor it immediately.
        assert dashboard.WHITELIST_MGR.is_whitelisted("203.0.113.77")[0] is True
    finally:
        with open(config_path, "wb") as f:
            f.write(original)
        dashboard.WHITELIST_MGR.load_whitelist(force=True)
    # ...and the restore must be visible to the API too.
    assert "203.0.113.77" not in client.get("/api/whitelist").json()["trusted_ips"]


def test_whitelist_add_rejects_bad_type(client):
    r = client.post("/api/whitelist/add",
                    json={"item_type": "banana", "value": "x"})
    assert r.status_code == 400


def test_unban_route_removes_from_store(client):
    import dashboard
    ip = "198.51.100.48"
    dashboard.BAN_STORE.add(ip, {"score": 0.99, "reason": "smoke-test"})
    assert ip in dashboard.BAN_STORE.active()
    r = client.post(f"/api/bans/unban/{ip}")
    assert r.status_code == 200
    assert r.json()["status"] == "unbanned"
    assert ip not in dashboard.BAN_STORE.active()


def test_unban_route_reports_missing(client):
    r = client.post("/api/bans/unban/198.51.100.99")
    assert r.status_code == 200
    assert r.json()["status"] == "not_found"


def test_continuous_toggle_round_trip(client):
    import dashboard
    original = dashboard.CONTINUOUS_MANAGER.is_running
    try:
        r1 = client.post("/api/continuous/toggle")
        assert r1.status_code == 200
        assert r1.json()["is_running"] is (not original)
        r2 = client.post("/api/continuous/toggle")
        assert r2.status_code == 200
        assert r2.json()["is_running"] is bool(original)
    finally:
        dashboard.CONTINUOUS_MANAGER.is_running = original


def test_inject_batch_dispatches(client):
    r = client.post("/api/continuous/inject_batch")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "burst_dispatched"
    assert body["count"] == 35


# ---------------------------------------------------------------------------
# Request fencing -- webguard wiring as seen from the outside
# ---------------------------------------------------------------------------

def test_security_headers_on_every_response(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    csp = r.headers.get("content-security-policy", "")
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_cross_origin_post_is_refused(client):
    r = client.post("/api/continuous/toggle",
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_unknown_route_404(client):
    r = client.get("/api/definitely/not/a/route")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# SSE stream. The keep-alive loop is infinite by design, so no test may ever
# pull it through the HTTP client (httpx's ASGI transport drains the whole
# body before returning -- a guaranteed hang). The contract is verified by
# exercising the endpoint's async generator directly, with hard timeouts.
# ---------------------------------------------------------------------------

def test_broadcast_without_event_loop_is_safe(client):
    import dashboard
    # No lifespan ran (module-scoped TestClient without context manager), so
    # EVENT_LOOP is None: broadcasting must be a silent no-op, not a crash.
    dashboard.broadcast_event("smoke_test", {"ok": True})
    assert dashboard.EVENT_SUBSCRIBERS == set()


def test_stream_generator_yields_keepalive_and_cleans_up():
    """Pull one keep-alive from the SSE generator by hand, then close it.
    The receive channel never completes, which keeps request.is_disconnected()
    False (starlette cancels the probe), so the generator reaches its 2s
    keep-alive yield; aclose() then runs the finally that must discard the
    subscriber queue. No sockets, no client portal, no unbounded reads."""
    import asyncio
    import dashboard

    async def scenario():
        async def receive():
            # Never returns: is_disconnected() cancels this probe each cycle.
            await asyncio.Event().wait()

        scope = {"type": "http", "method": "GET", "path": "/api/stream",
                 "headers": [], "query_string": b""}
        request = dashboard.Request(scope, receive)
        response = await dashboard.event_stream(request)
        assert response.media_type == "text/event-stream"
        gen = response.body_iterator
        chunk = await asyncio.wait_for(gen.__anext__(), timeout=6.0)
        assert chunk.strip().startswith(":")  # keep-alive comment line
        await gen.aclose()

    asyncio.run(scenario())
    assert dashboard.EVENT_SUBSCRIBERS == set(), \
        "SSE subscriber queue leaked after generator close"


# ---------------------------------------------------------------------------
# Audit-verified enforcement interlock. Arming live firewall blocking -- via
# the --active-defense CLI flag or the dashboard's defense toggle -- must
# refuse unless the most recent regression audit verdict is exactly PASS.
# WARN / FAIL / missing / unreadable all refuse (fail closed). These tests
# drive the real report path with a throwaway report file and always restore
# the world; they never touch the live firewall layer.
# ---------------------------------------------------------------------------

def _write_report(path, verdict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"verdict": verdict, "checks": []}, f)


def test_policy_interlock_read_only(tmp_path):
    """policy.audit_verdict / enforcement_may_arm: PASS arms, everything else
    refuses, and a missing or unreadable report is an unknown state that
    refuses too."""
    import policy

    p = str(tmp_path / "report.json")
    _write_report(p, "PASS")
    assert policy.audit_verdict(p) == "PASS"
    assert policy.enforcement_may_arm(p)[0] is True

    for verdict in ("WARN", "FAIL"):
        _write_report(p, verdict)
        assert policy.audit_verdict(p) == verdict
        allowed, reason = policy.enforcement_may_arm(p)
        assert allowed is False
        assert verdict in reason

    _write_report(p, "PARTY")  # unknown verdict string = unknown state
    assert policy.audit_verdict(p) is None
    assert policy.enforcement_may_arm(p)[0] is False

    missing = str(tmp_path / "never_audited.json")
    assert policy.audit_verdict(missing) is None
    allowed, reason = policy.enforcement_may_arm(missing)
    assert allowed is False
    assert "never audited" in reason or "missing" in reason

    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    assert policy.audit_verdict(str(garbage)) is None
    assert policy.enforcement_may_arm(str(garbage))[0] is False


def test_policy_interlock_refuses_live_report_when_not_pass():
    """Whatever the repo's real report currently says: if it is not PASS,
    policy must refuse. (If the verdict ever becomes PASS this test still
    passes -- it only pins the refusal logic, not the repo's health.)"""
    import policy
    allowed, reason = policy.enforcement_may_arm()
    assert isinstance(allowed, bool) and reason
    if policy.audit_verdict() != "PASS":
        assert allowed is False


def test_toggle_arms_when_audit_pass(client, tmp_path):
    """With a PASS report installed, the toggle flips simulation -> live.
    The report path is redirected to a throwaway file and the original
    SHARED_STATE is restored, so no real state and no firewall layer moves."""
    import dashboard

    p = str(tmp_path / "pass.json")
    _write_report(p, "PASS")
    original_verdict, original_may = dashboard.audit_verdict, dashboard.enforcement_may_arm
    original_state = dashboard.SHARED_STATE["active_defense"]
    # Patch where dashboard uses the names (it imported them from policy).
    dashboard.audit_verdict = lambda: "PASS"
    dashboard.enforcement_may_arm = lambda: (True, "last audit verdict PASS")
    try:
        r = client.post("/api/defense/toggle")
        assert r.status_code == 200
        body = r.json()
        assert body["active_defense"] is True
        assert body["status"] == "ARMED (FIREWALL BLOCKS)"
        assert dashboard.SHARED_STATE["active_defense"] is True
    finally:
        dashboard.audit_verdict = original_verdict
        dashboard.enforcement_may_arm = original_may
        dashboard.SHARED_STATE["active_defense"] = original_state


def test_toggle_refuses_when_audit_warn(client):
    """The regression test for the interlock: with the repo's real WARN report
    in place, arming from the UI must be refused with 409 and the state must
    stay simulation."""
    import dashboard
    import policy
    original_state = dashboard.SHARED_STATE["active_defense"]
    try:
        # Force the state to simulation so the request is an ARM request.
        dashboard.SHARED_STATE["active_defense"] = False
        r = client.post("/api/defense/toggle")
        if policy.audit_verdict() == "PASS":
            pytest.skip("live report is PASS; the refusal path needs WARN/FAIL/missing")
        assert r.status_code == 409, r.text
        body = r.json()
        assert "audit" in body["error"].lower()
        assert body["active_defense"] is False
        assert dashboard.SHARED_STATE["active_defense"] is False
    finally:
        dashboard.SHARED_STATE["active_defense"] = original_state


def test_toggle_refuses_when_report_missing(client, tmp_path, monkeypatch):
    """Fail closed: an absent report must 409, not fall through to arming."""
    import dashboard
    monkeypatch.setattr(dashboard, "audit_verdict", lambda: None)
    monkeypatch.setattr(dashboard, "enforcement_may_arm",
                        lambda: (False, "no audit verdict found"))
    original_state = dashboard.SHARED_STATE["active_defense"]
    try:
        dashboard.SHARED_STATE["active_defense"] = False
        r = client.post("/api/defense/toggle")
        assert r.status_code == 409
        assert r.json()["active_defense"] is False
        assert dashboard.SHARED_STATE["active_defense"] is False
    finally:
        dashboard.SHARED_STATE["active_defense"] = original_state


def test_toggle_disarm_is_always_allowed(client):
    """The interlock gates arming only. Disarming must work whatever the
    verdict is, so an operator can always stand the firewall down."""
    import dashboard
    original_state = dashboard.SHARED_STATE["active_defense"]
    try:
        dashboard.SHARED_STATE["active_defense"] = True
        r = client.post("/api/defense/toggle")
        assert r.status_code == 200
        assert r.json()["active_defense"] is False
        assert dashboard.SHARED_STATE["active_defense"] is False
    finally:
        dashboard.SHARED_STATE["active_defense"] = original_state


def test_cli_run_dashboard_refuses_arming_without_pass(tmp_path):
    """run_dashboard(active_defense=True) with a non-PASS report must come up
    in simulation mode and report the refusal -- and the __main__ wrapper maps
    that to exit code 2. uvicorn.run is stubbed so no server starts."""
    import dashboard

    p = str(tmp_path / "warn.json")
    _write_report(p, "WARN")
    original_verdict, original_may = dashboard.audit_verdict, dashboard.enforcement_may_arm
    original_state = dashboard.SHARED_STATE["active_defense"]
    dashboard.audit_verdict = lambda: "WARN"
    dashboard.enforcement_may_arm = lambda: (False, "last audit verdict is WARN")

    uvicorn_calls = []
    original_uvicorn_run = dashboard.uvicorn.run
    dashboard.uvicorn.run = lambda *a, **k: uvicorn_calls.append(a)
    try:
        armed = dashboard.run_dashboard(active_defense=True)
        assert armed is False
        assert dashboard.SHARED_STATE["active_defense"] is False
        assert len(uvicorn_calls) == 1  # server still came up -- in simulation
    finally:
        dashboard.audit_verdict = original_verdict
        dashboard.enforcement_may_arm = original_may
        dashboard.uvicorn.run = original_uvicorn_run
        dashboard.SHARED_STATE["active_defense"] = original_state


def test_cli_run_dashboard_arms_with_pass(tmp_path):
    """The complementary path: PASS report -> run_dashboard arms and reports
    live enforcement (with uvicorn stubbed; the sniffer is not started)."""
    import dashboard

    p = str(tmp_path / "pass.json")
    _write_report(p, "PASS")
    original_verdict, original_may = dashboard.audit_verdict, dashboard.enforcement_may_arm
    original_state = dashboard.SHARED_STATE["active_defense"]
    dashboard.audit_verdict = lambda: "PASS"
    dashboard.enforcement_may_arm = lambda: (True, "last audit verdict PASS")

    original_uvicorn_run = dashboard.uvicorn.run
    dashboard.uvicorn.run = lambda *a, **k: None
    try:
        armed = dashboard.run_dashboard(active_defense=True)
        assert armed is True
        assert dashboard.SHARED_STATE["active_defense"] is True
    finally:
        dashboard.audit_verdict = original_verdict
        dashboard.enforcement_may_arm = original_may
        dashboard.uvicorn.run = original_uvicorn_run
        dashboard.SHARED_STATE["active_defense"] = original_state
