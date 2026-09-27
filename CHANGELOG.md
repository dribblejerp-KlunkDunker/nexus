# Changelog

All notable changes from the hardening campaign. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project has no runtime
version scheme yet, so everything below is "Unreleased" until the first tag.

## [Unreleased]

### Added

- **`tests/test_dashboard_api.py`** (41 tests): endpoint-level smoke coverage
  of the dashboard API -- every route the HUD calls, exercised through
  FastAPI's TestClient with the intel layer stubbed offline (zero network).
  Pins the response shapes the UI depends on, all 12 attack-simulation
  routes (including the honest `whitelisted` answer for outbound sims), the
  xmasscan decision path through to the in-memory ban store, whitelist
  mutation with byte-exact restore, the unban round-trip, the loopback
  Host fence (403 on spoofed Origin, security headers on every response),
  and the SSE generator's disconnect cleanup. CI now installs
  `fastapi httpx uvicorn scapy` so the real API surface is under test;
  heavier deps stay out and the HEURISTIC_ONLY degradation is the pinned
  honest floor.

### Fixed (full-project audit, live-fire verified)

- **`scripts/dashboard.py` crashed at import** (`NameError: banstore`): its
  security-module imports sat ~40 lines below first use at module scope. The
  product's entire entry point failed to launch and no test imported it. Fixed
  by moving the import block to the top and adding
  `test_dashboard_imports_and_boots`, which imports the module and asserts the
  FastAPI routes exist, so a launch regression can never hide again.
- **Missing `neat-python` took the whole dashboard down**: the degradation
  ladder (COUNCIL → MONOLITHIC_FALLBACK → HEURISTIC_ONLY) handled missing
  model files but a missing *library* was a bare module-level `import neat`.
  Now degrades to HEURISTIC_ONLY with a pointer to SETUP.bat, like any other
  missing input.
- **Outbound attack simulations 500'd**: the default whitelist trusts all
  RFC1918 sources (correct -- it stops the platform banning your own machine),
  so sims sourced from 192.168.1.50 were silently skipped and `simulate_attack`
  crashed on the `None` return. The endpoint now reports
  `{status: "whitelisted", reason: ...}` honestly.
- **`scripts/build_corpus_v2.py` NameError** (`base_dir` used undefined in
  `main()`): broke the weekly cycle's corpus step on every machine. The weekly
  cycle now runs corpus → training → holdout gates → promotion end to end.
- **Corrupt self-hosted font**: `tDbV2o-...D7OwE.woff2` (JetBrains Mono basic
  latin, referenced at 4 weights) failed OTS parsing; replaced with the
  canonical copy. HUD mono text actually renders in JetBrains Mono now.
- **`M 50 NaN` SVG path spam**: honest training histories store `null` fitness
  for unmeasured generations; three renderers fed the nulls into path math.
  All fitness values are clamped before plotting now.
- **Fabricated LSTM accuracy removed**: Deck 2 claimed "SEQUENCE ACCURACY:
  100.0% (Validation Pass)" in markup while the backend payload says
  `sequence_accuracy: null -- not measured`. Now renders NOT MEASURED until a
  real number exists.
- **Surgeon log `undefined` spam**: renderer assumed every intervention had
  sensor/weight fields; bias recalibrations and intermediary-node grafts have
  different shapes. Renders per action type now.
- **Evolve button could strand as "EVOLVING..."**: label only reset via a
  success broadcast; a failed burst froze it, and nothing stopped double-click
  bursts. Backend now broadcasts failures, the guard is re-entrancy safe, and
  `null` fitness is handled.
- **`ops_audit` died without onnxruntime**: the predictive-escalation audit
  needs two constants from `sniff_and_respond`, whose module-level
  `import onnxruntime` broke the import on machines without the ML runtime.
  Import is now lazy at the single use site.
- **`web/js/app.js` XSS sink**: continuous audit log rows were built with
  `innerHTML` from server log strings (which can embed exception text).
  Rebuilt with `textContent`.
- **Stray build artifact**: `web/app.css.check` (a stale Tailwind
  freshness-probe output) was tracked in git; untracked and ignored now.

### Security

- **`scripts/firewall.py`** (new): validated firewall layer. Packet-derived IPs
  are canonicalized through `ipaddress` before touching a command; all
  block/unban paths use argv lists with `shell=False`. Closes the
  network-driven command-injection class where a packet's source string
  reached an admin shell (`8.8.8.8; rm -rf /` is rejected in tests).
- **`scripts/genomevault.py`** (new): HMAC-sealed canonical-JSON genome
  containers (`.ngenome`). Replaces raw `pickle.load` on every runtime load
  path (dashboard champion/surgeon/topology, council arbiter, guardian
  hot-reload). Tampered genomes are rejected, not executed. Ships with
  `migrate` / `verify` / `selftest` CLI. A corrupted HMAC tag is cleanly
  rejected instead of crashing the verifier.
- **`scripts/webguard.py`** (new): framework-free request-fencing core.
  `OriginGuardMiddleware` refuses non-loopback Host/Origin/Referer on
  state-changing requests (CSRF + DNS-rebinding defense). Security headers on
  every response: CSP, `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`.
- **CSP is now `'self'`-only**: `script-src 'self'` (after the inline-handler
  migration) and `style-src 'self'` (after the inline-style migration). Zero
  `'unsafe-inline'` anywhere; zero third-party origins.
- **`verify_system.py`**: last `shell=True` in the codebase converted to an
  argv list.
- Defense toggle fenced through `ops_control.assert_local` so the dashboard
  cannot arm the active-defense script from a spoofable context.

### Honesty

- **`scripts/intel.py`** (new): HTTPS-only GeoIP with per-field provenance.
  The fabricated `SIMULATED_THREAT_ACTORS` table is gone: a failed lookup
  reports "Attribution unavailable" with `risk: UNKNOWN` instead of inventing
  "APT28" for an unresolvable IP. CRITICAL risk exists only on a verified
  intel-cache match.
- `policy.py` (new) is the single owner of decision constants
  (threshold 0.85, escalation ladder, ban TTL, gates). The arbiter re-exports
  `THREAT_THRESHOLD`; consumers import from policy. No raw 0.85 comparison
  remains in the decision path (architecture-tested).
- `/api/training/stats` reports only measured values: unmeasured fields are
  `null` with pointers to `logs/honest_training_results.json`.
- Pre-poll UI theater scrubbed: seeded "100.0% Det" adversarial spans and
  stale width percentages removed from markup; bars render honestly empty
  until the first real benchmark poll.
- `docs/MEASURED-PERFORMANCE.md` (generated): rendered from the `logs/*.json`
  artifacts by `tools/gen_performance_doc.py`; CI fails if the doc drifts.

### Architecture

- **`scripts/policy.py`** (new): threshold/constant ownership (see Honesty).
- **`scripts/banstore.py`** (new): RLock-guarded ban table with TTL purge and
  copy-in/copy-out records. Kills the delete-vs-add race and the
  "dict changed size during iteration" hazard inside SSE sends; loopback is
  refused at the door. A 1s ticker sweep re-broadcasts expirations live.
- Seat provenance: arbiter verdicts carry the per-specialist holdout TPR/FPR
  that `train_honest.py`'s promotion gate measured, surfaced in the council UI.
- Inline `onclick=` handlers migrated to `data-action`/`data-arg` +
  one delegated listener (`tools/codemod_onclick.py`).
- Inline `style=""` attributes migrated to utility classes
  (`tools/strip_inline_styles.py`).

### Offline-first deck

- Fonts self-hosted in `web/static/fonts/` (fonts.googleapis.com and
  fonts.gstatic.com are gone from the codebase).
- Tailwind compiled at build time into `web/static/css/app.css`; the
  `cdn.tailwindcss.com` runtime JIT is gone. The Tailwind config uses
  cwd-independent absolute content paths (a root-cwd build previously
  produced a utility-free CSS silently).
- The ~1,500-line inline script extracted to `web/js/app.js`; index.html
  halved (138 KB -> 71 KB).
- `build_web.bat` fixed: it invoked a `.bin` shim this install does not
  create, and built from the wrong cwd. `npm run build:web` fixed likewise.

### Verification

- **`tests/`** pytest gate: unit tests for firewall, intel, policy, banstore,
  webguard, genomevault, plus an architecture suite (AST-based) that fails on
  reintroduced `shell=True`/`os.system`, threshold literals outside policy,
  inline handlers, inline styles, and third-party origins.
- **`tools/check.py`** (new): one command that runs CI's gate locally
  (pytest, compileall, module self-tests, `node --check`, Tailwind freshness,
  offline audit).
- **`.github/workflows/ci.yml`** (new): runs `tools/check.py` on
  `windows-latest` (the netsh argv path is Windows-only) plus performance-doc
  freshness.
- `requirements.txt` fully upper-bounded.
- Self-tests: firewall 13/13, intel 12/12, policy 16/16, banstore 15/15,
  webguard 22/22, genomevault 9/9.
