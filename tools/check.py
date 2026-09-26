"""NEXUS verification gate: one command that runs everything CI would.

    python tools/check.py            # full gate
    python tools/check.py --fast     # skip module self-tests and npm audit

Stages (each stage failure aborts with its exit code):
  1. pytest suite (unit + architecture regression gate)
  2. py_compile across scripts/ and tools/
  3. module self-tests (firewall, intel, policy, banstore, webguard, vault)
  4. web deck: node --check on app.js, Tailwind build freshness
  5. offline audit: no third-party origins, no inline handlers,
     no inline styles, no threshold literals outside policy.py

This is the same gate .github/workflows/ci.yml runs, so "check.py green"
locally means CI green.
"""
import argparse
import compileall
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
TOOLS = os.path.join(ROOT, "tools")
WEB = os.path.join(ROOT, "web")
PY = sys.executable or "python"

SELF_TESTS = ["firewall", "intel", "policy", "banstore", "webguard", "genomevault"]

CDN_ORIGINS = (
    "fonts.googleapis.com", "fonts.gstatic.com", "cdn.tailwindcss.com",
    "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
)


def run(cmd, cwd=None):
    print(f"\n>>> {' '.join(cmd)}" + (f"   (cwd={os.path.relpath(cwd, ROOT)})" if cwd else ""))
    proc = subprocess.run(cmd, cwd=cwd or ROOT)
    return proc.returncode


def stage_pytest() -> int:
    return run([PY, "-m", "pytest", "tests/", "-q"])


def stage_compile() -> int:
    ok = compileall.compile_dir(SCRIPTS, quiet=2) and compileall.compile_dir(TOOLS, quiet=2)
    if not ok:
        print("compileall FAILED")
        return 1
    print("compileall OK")
    return 0


def stage_selftests() -> int:
    for mod in SELF_TESTS:
        code = run([PY, os.path.join(SCRIPTS, f"{mod}.py")])
        if code:
            print(f"self-test FAILED: {mod}")
            return code
    return 0


def stage_web() -> int:
    code = run(["node", "--check", os.path.join("web", "js", "app.js")])
    if code:
        return code
    built = os.path.join(WEB, "static", "css", "app.css")
    if not os.path.exists(built):
        print("app.css missing -- run build_web.bat")
        return 1
    digest = _file_digest(built)
    tmp = os.path.join(WEB, "static", "css", "app.css.check")
    build = subprocess.run(
        ["node", os.path.join("..", "node_modules", "tailwindcss", "lib", "cli.js"),
         "-c", "tailwind.config.js", "-i", "static/css/input.css",
         "-o", "static/css/app.css.check", "--minify"],
        cwd=WEB, capture_output=True)
    try:
        if build.returncode != 0:
            print("Tailwind freshness build FAILED:", build.stderr.decode()[-400:])
            return 1
        if _file_digest(tmp) != digest:
            print("app.css is STALE -- committed CSS does not match sources; run build_web.bat")
            return 1
        print("app.css fresh")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if os.path.exists(built + ".map"):
        os.remove(built + ".map")
    return 0


def _file_digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def stage_offline_audit() -> int:
    failures = []
    for rel in (os.path.join("web", "index.html"), os.path.join("web", "js", "app.js"),
                os.path.join("web", "static", "css", "input.css")):
        with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
            src = f.read()
        for origin in CDN_ORIGINS:
            if origin in src:
                failures.append(f"{rel}: third-party origin {origin}")
        for attr in ("onclick=", "onerror=", "onload="):
            if attr in src:
                failures.append(f"{rel}: inline handler {attr}")
        if rel.endswith("index.html") and 'style="' in src:
            failures.append(f"{rel}: inline style attribute (CSP style-src has no unsafe-inline)")
    code = run([PY, "-c",
                "import sys; sys.path.insert(0, 'scripts');"
                "import policy, council_arbiter;"
                "assert council_arbiter.THREAT_THRESHOLD == policy.THREAT_THRESHOLD"])
    if code:
        failures.append("threshold owner mismatch (policy vs arbiter)")
    if failures:
        print("OFFLINE AUDIT FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("offline audit OK (no CDN origins, no inline handlers, no inline styles)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="NEXUS verification gate")
    ap.add_argument("--fast", action="store_true",
                    help="skip module self-tests (pytest still runs)")
    args = ap.parse_args()

    stages = [("pytest", stage_pytest), ("compile", stage_compile)]
    if not args.fast:
        stages.append(("selftests", stage_selftests))
    stages += [("web", stage_web), ("offline-audit", stage_offline_audit)]

    for name, fn in stages:
        print(f"\n===== STAGE: {name} =====")
        code = fn()
        if code:
            print(f"\nGATE FAILED at stage '{name}' (exit {code})")
            return code
    print("\nALL STAGES PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
