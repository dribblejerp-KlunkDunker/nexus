"""Regression gate: the security properties NEXUS must never lose.

This suite exists so the classes of bug removed during the hardening sprints
cannot quietly return. Each test pins an architecture invariant:

  * no firewall command is ever executed through a shell (subprocess calls
    must use argv lists; os.system / os.popen are BANNED)
  * the operating threshold lives in policy.py alone -- no raw 0.85
    score comparisons in the decision path
  * no inline event handlers in the markup (CSP script-src has no
    'unsafe-inline')
  * no inline style attributes either (CSP style-src has no 'unsafe-inline')
  * no third-party resource loads (fonts, CSS, JS are all self-hosted)

The Python scans are AST-based: docstrings and comments that DOCUMENT the
rules (e.g. firewall.py's rationale) are not code and must not fire the gate.
"""

import ast
import os

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(PROJECT_ROOT, "scripts")
WEB = os.path.join(PROJECT_ROOT, "web")


def _py_sources():
    for name in sorted(os.listdir(SCRIPTS)):
        if name.endswith(".py"):
            with open(os.path.join(SCRIPTS, name), "r", encoding="utf-8") as f:
                yield name, f.read()


def test_no_shell_execution_in_scripts():
    """No subprocess call may pass shell=True, and os.system/os.popen are
    banned outright. Docstrings mentioning them do not count -- only calls."""
    offenders = []
    for name, src in _py_sources():
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute):
                callee = fn.attr
            elif isinstance(fn, ast.Name):
                callee = fn.id
            else:
                continue
            if callee in ("system", "popen"):
                offenders.append(f"{name}:{node.lineno}: {callee}() call")
            if callee == "run" and isinstance(fn, ast.Attribute):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        val = kw.value
                        if isinstance(val, ast.Constant) and val.value is True:
                            offenders.append(
                                f"{name}:{node.lineno}: subprocess shell=True")
    assert not offenders, "shell execution reintroduced:\n" + "\n".join(offenders)


# Files allowed to contain a literal 0.85 WITHOUT it being a threat-score
# decision. Every entry is a DIFFERENT quantity that happens to equal 0.85:
#   benchmark_surgeon_acceleration: mutation intensity parameter
#   build_corpus_v2:              corpus coverage ratio
#   evasion_engine:               synthetic red-team feature vector value
#   feature_extractor:            protocol-choice synthesis ratio
#   intel:                        payload-entropy heuristic (MITRE T1048),
#                                 a different measurement than the alert bar
#   ops_audit:                    port-diversity concentration heuristic
#   verify_system:                synthetic test-vector feature value
# The DECISION path (dashboard, arbiter, guardian, training gates) holds zero:
# any score-vs-threshold comparison must import policy.
_THRESHOLD_OK_FILES = {
    "benchmark_surgeon_acceleration.py",
    "build_corpus_v2.py",
    "evasion_engine.py",
    "feature_extractor.py",
    "intel.py",
    "ops_audit.py",
    "verify_system.py",
}


def test_no_threshold_literals_in_decision_path():
    """A raw 0.85 outside policy.py is a decision made outside the decision
    owner. Float literals equal to 0.85 are banned in decision-path files;
    unrelated magnitudes (1.85, 18.5) never match."""
    offenders = []
    for name, src in _py_sources():
        if name == "policy.py" or name in _THRESHOLD_OK_FILES:
            continue
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, float) \
                    and node.value == 0.85:
                offenders.append(f"{name}:{node.lineno}: literal 0.85")
    assert not offenders, "threshold literal outside policy.py:\n" + "\n".join(offenders)


def test_threshold_helpers_exist_for_consumers():
    """The consumers of the operating point import it; nothing redefines it."""
    import council_arbiter
    import policy
    assert policy.THREAT_THRESHOLD == pytest.approx(0.85)
    assert council_arbiter.THREAT_THRESHOLD == policy.THREAT_THRESHOLD


def test_no_inline_event_handlers():
    for fname in ("index.html", os.path.join("js", "app.js")):
        path = os.path.join(WEB, fname)
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        assert "onclick=" not in src, f"inline handler reintroduced in {fname}"
        assert "onload=" not in src, f"inline handler reintroduced in {fname}"
        assert "onerror=" not in src, f"inline handler reintroduced in {fname}"


def test_csp_has_no_unsafe_inline_for_scripts():
    import webguard
    script_dir = webguard.CSP.split("script-src")[1].split(";")[0]
    assert "'unsafe-inline'" not in script_dir
    assert "script-src 'self';" in webguard.CSP


def test_csp_has_no_unsafe_inline_for_styles():
    import webguard
    style_dir = webguard.CSP.split("style-src")[1].split(";")[0]
    assert "'unsafe-inline'" not in style_dir, \
        "style-src trusted inline styles again; migrate them to classes first"


def test_markup_has_zero_inline_style_attributes():
    import webguard
    count = webguard.count_inline_styles()
    assert count == 0, \
        f"{count} inline style attributes reintroduced; CSP style-src has no 'unsafe-inline'"


def test_no_third_party_resource_origins():
    offenders = []
    cdns = ("fonts.googleapis.com", "fonts.gstatic.com", "cdn.tailwindcss.com",
            "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com")
    for fname in ("index.html", os.path.join("js", "app.js")):
        with open(os.path.join(WEB, fname), "r", encoding="utf-8") as f:
            src = f.read()
        for origin in cdns:
            if origin in src:
                offenders.append(f"web/{fname}: {origin}")
    assert not offenders, "third-party resource origin reintroduced:\n" + "\n".join(offenders)


def test_dashboard_routes_requests_through_webguard():
    with open(os.path.join(SCRIPTS, "dashboard.py"), "r", encoding="utf-8") as f:
        src = f.read()
    assert "_wg_check_request(" in src, "middleware must delegate to webguard.check_request"
    assert "LOOPBACK_NAMES = {" not in src, "loopback set duplicated in dashboard (owner: webguard)"


def test_dashboard_imports_and_boots():
    """The product's entry point must import cleanly.

    This file is the entire product surface -- the HUD, the API, the decision
    engine -- yet it is only grep-checked elsewhere in this suite. A module-
    level NameError (e.g. an import sitting below its first use) is a total
    launch failure that source-grep tests cannot see, so we import it here.
    """
    import importlib.util
    path = os.path.join(SCRIPTS, "dashboard.py")
    spec = importlib.util.spec_from_file_location("dashboard_audit", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # pragma: no cover - failure path
        pytest.fail(f"dashboard.py failed to import: {e!r}")
    assert mod.app is not None, "FastAPI app object missing"
    routes = {getattr(r, "path", None) for r in mod.app.routes}
    assert "/api/status" in routes and "/api/stream" in routes
