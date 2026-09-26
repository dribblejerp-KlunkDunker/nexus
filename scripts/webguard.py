"""
NEXUS Web Guard
===============

Request-fencing and security-header logic for the control API, extracted from
dashboard.py so it can be unit-tested WITHOUT fastapi/starlette installed.

Threat model
------------
The control API (start captures, toggle defense, unban IPs, register ops
tasks) is loopback-only by policy. A loopback BIND alone does not stop other
pages in the browser from POSTing to http://127.0.0.1:8000 -- any webpage can
attempt CSRF via form post, or DNS rebinding (an attacker domain resolving to
127.0.0.1, which gives the Host header an attacker-chosen name). This module
is the decision logic that refuses those requests:

  1. Safe methods (GET/HEAD/OPTIONS) pass -- they must stay side-effect free,
     and the SSE event stream depends on GET.
  2. A non-loopback Host header is refused outright (DNS-rebinding defense).
  3. A state-changing request whose Origin or Referer names a non-loopback
     host is refused (CSRF defense).

The fastapi adapter in dashboard.py is a thin shell around `check_request`
and `apply_security_headers`; all policy lives here.

CSP note: script-src carries no 'unsafe-inline' since the onclick ->
data-action migration (app.js); style-src carries none since the inline
style="" attributes were migrated to utility classes. No inline script,
style attribute, or style element can execute against this policy.

Self-test:
    python scripts/webguard.py
"""

from __future__ import annotations

import urllib.parse
from typing import Mapping, Optional

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Applied to every response (see apply_security_headers).
CSP = ("default-src 'self'; "
       "script-src 'self'; "
       "style-src 'self'; "
       "font-src 'self' data:; "
       "connect-src 'self'; img-src 'self' data:; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
       "form-action 'self'")

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# Error strings are stable contract for the API responses.
ERR_HOST = "control API refuses non-loopback Host header"
ERR_ORIGIN = "cross-origin control request refused"
ERR_REFERER = "cross-site control request refused"


def count_inline_styles(html_path: str = None) -> int:
    """Count style=" attributes in the deck markup. The CSP ships without
    style-src 'unsafe-inline', so any reintroduced inline style silently
    breaks the element it styles -- count and fail loudly instead."""
    import os
    path = html_path or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "web", "index.html")
    if not os.path.exists(path):
        return -1  # markup not present (packaged deployments): nothing to scan
    with open(path, "r", encoding="utf-8") as f:
        return f.read().count('style="')


def host_name(header_value: str) -> str:
    """Extract the hostname from a raw Host header value.

    Handles bracketed IPv6 ("[::1]:8000" -> "::1") and host:port. Lowercased.
    """
    if not header_value:
        return ""
    if header_value.startswith("["):
        end = header_value.find("]")
        return header_value[1:end].lower() if end > 0 else ""
    if ":" in header_value:
        return header_value.rsplit(":", 1)[0].lower()
    return header_value.lower()


def origin_host(url: str) -> str:
    """Extract the hostname from an Origin/Referer URL. Unparseable -> ""."""
    if not url:
        return ""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def is_loopback_host(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def check_request(method: str, headers: Mapping[str, str]) -> Optional[str]:
    """Decide whether a state-changing request may proceed.

    Returns None when allowed, or the reason string when refused. `headers`
    is any case-insensitive mapping (Starlette's request.headers qualifies;
    plain dicts should use lowercase keys).
    """
    if method.upper() in SAFE_METHODS:
        return None

    raw_host = headers.get("host", "") or ""
    host = host_name(raw_host)
    if host and not is_loopback_host(host):
        return ERR_HOST

    origin = headers.get("origin", "") or ""
    if origin:
        if not is_loopback_host(origin_host(origin)):
            return ERR_ORIGIN
    else:
        referer = headers.get("referer", "") or ""
        if referer and not is_loopback_host(origin_host(referer)):
            return ERR_REFERER
    return None


def apply_security_headers(target: Mapping[str, str]) -> None:
    """setdefault every security header onto a response header mapping."""
    for key, value in SECURITY_HEADERS.items():
        try:
            target.setdefault(key, value)
        except Exception:
            pass


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

    print("NEXUS web guard self-test")

    # Host header parsing
    check("bare ipv4 host", host_name("127.0.0.1") == "127.0.0.1")
    check("host with port", host_name("localhost:8000") == "localhost")
    check("bracketed ipv6", host_name("[::1]:8000") == "::1")
    check("empty host", host_name("") == "")

    # Safe methods always pass
    for m in ("GET", "HEAD", "OPTIONS", "get"):
        check(f"safe method {m} passes",
              check_request(m, {"host": "evil.example"}) is None)

    # Host fencing
    check("non-loopback host refused",
          check_request("POST", {"host": "attacker.example"}) == ERR_HOST)
    check("rebind-style public host refused",
          check_request("POST", {"host": "192.168.1.50:8000"}) == ERR_HOST)
    check("loopback host accepted",
          check_request("POST", {"host": "127.0.0.1:8000"}) is None)
    check("localhost accepted",
          check_request("POST", {"host": "localhost"}) is None)
    check("bracketed v6 loopback accepted",
          check_request("POST", {"host": "[::1]:8000"}) is None)

    # Origin fencing
    check("cross-origin POST refused",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "origin": "https://evil.example"}) == ERR_ORIGIN)
    check("attacker-origin unban refused",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "origin": "http://127.0.0.1.evil.example:8000"})
          == ERR_ORIGIN)
    check("null origin refused",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "origin": "null"}) == ERR_ORIGIN)
    check("loopback origin accepted",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "origin": "http://127.0.0.1:8000"}) is None)
    check("localhost origin accepted",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "origin": "http://localhost:8000"}) is None)

    # Referer fallback
    check("cross-site referer refused",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "referer": "https://evil.example/x"}) == ERR_REFERER)
    check("loopback referer accepted",
          check_request("POST", {"host": "127.0.0.1:8000",
                                 "referer": "http://127.0.0.1:8000/"}) is None)

    # CSP tightening regression: script-src must not trust inline scripts
    check("script-src has no unsafe-inline",
          "script-src 'self';" in CSP.replace("script-src 'self' ;", "script-src 'self';")
          and "script-src 'self' 'unsafe-inline'" not in CSP)
    check("style-src has no unsafe-inline",
          "style-src 'self';" in CSP and "style-src 'self' 'unsafe-inline'" not in CSP)
    check("markup carries zero inline style attributes",
          count_inline_styles() == 0)

    print()
    if failures:
        print(f"{len(failures)} FAILURES: {failures}")
        return 1
    print("All web guard self-tests passed.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
