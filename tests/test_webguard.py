"""Unit tests for the request-fencing core (webguard.py)."""

import webguard as wg


def test_host_name_parsing():
    assert wg.host_name("127.0.0.1") == "127.0.0.1"
    assert wg.host_name("localhost:8000") == "localhost"
    assert wg.host_name("[::1]:8000") == "::1"
    assert wg.host_name("") == ""


def test_safe_methods_always_pass():
    for m in ("GET", "HEAD", "OPTIONS", "get"):
        assert wg.check_request(m, {"host": "evil.example"}) is None


def test_non_loopback_host_refused():
    assert wg.check_request("POST", {"host": "attacker.example"}) == wg.ERR_HOST
    assert wg.check_request("POST", {"host": "192.168.1.50:8000"}) == wg.ERR_HOST


def test_loopback_hosts_accepted():
    assert wg.check_request("POST", {"host": "127.0.0.1:8000"}) is None
    assert wg.check_request("POST", {"host": "localhost"}) is None
    assert wg.check_request("POST", {"host": "[::1]:8000"}) is None


def test_cross_origin_refused():
    headers = {"host": "127.0.0.1:8000", "origin": "https://evil.example"}
    assert wg.check_request("POST", headers) == wg.ERR_ORIGIN


def test_rebind_lookalike_origin_refused():
    headers = {"host": "127.0.0.1:8000",
               "origin": "http://127.0.0.1.evil.example:8000"}
    assert wg.check_request("POST", headers) == wg.ERR_ORIGIN


def test_null_origin_refused():
    headers = {"host": "127.0.0.1:8000", "origin": "null"}
    assert wg.check_request("POST", headers) == wg.ERR_ORIGIN


def test_loopback_origin_accepted():
    headers = {"host": "127.0.0.1:8000", "origin": "http://127.0.0.1:8000"}
    assert wg.check_request("POST", headers) is None


def test_referer_fallback():
    assert wg.check_request("POST", {"host": "127.0.0.1:8000",
                                     "referer": "https://evil.example/x"}) == wg.ERR_REFERER
    assert wg.check_request("POST", {"host": "127.0.0.1:8000",
                                     "referer": "http://127.0.0.1:8000/"}) is None


def test_security_headers_complete():
    import copy
    resp = {}
    wg.apply_security_headers(resp)
    assert set(resp) == set(wg.SECURITY_HEADERS)
    assert resp["X-Frame-Options"] == "DENY"
    assert resp["X-Content-Type-Options"] == "nosniff"
    # setdefault semantics: an explicit value wins
    resp2 = {"Referrer-Policy": "same-origin"}
    wg.apply_security_headers(resp2)
    assert resp2["Referrer-Policy"] == "same-origin"
