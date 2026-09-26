# Changelog

All notable changes from the hardening campaign. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project has no runtime
version scheme yet, so everything below is "Unreleased" until the first tag.

## [Unreleased]

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
