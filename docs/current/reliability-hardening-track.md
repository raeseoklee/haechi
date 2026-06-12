# Reliability Hardening Track

- Status: Plan (pinned 2026-06-12; grounded in a 5-lens read-only audit of the 1.1.1 core)
- Target line: 1.1.2 (patch) → 1.2.0 (minor); no new product surface
- Purpose: raise Haechi to **commercial-solution-level reliability** — the trust, operability, and detection-quality density a production AI-security gateway is expected to have. This is a quality objective, not a commercialization plan. Every item **tightens, measures, or documents what already exists**; none adds a new feature.

## 1. Why this track

A 5-lens audit of the 1.1.1 core (detection quality, horizontal-scale/state, operability, security residuals, correctness/consistency) returned **47 findings (16 high / 20 medium / 11 low)**, each grounded in code, a config rule, a doc claim, or a missing artifact. The recurring theme is not missing features — it is **missing density**: the core is correct for a single self-hosted replica but unmeasured, under-instrumented, and partly under-documented for production trust.

A telling signal: the project's own current design draft (`docs/current/privacy-filtering-policy-draft.md`) already specifies `minConfidence` thresholds, a false-positive allowlist, and FP/FN measurement — controls the shipped code does **not** implement. So the largest single gap is closing the distance between the *designed* core and the *shipped* core, not extending scope.

This track deliberately **excludes** new features: external Redis/DB shared-state implementations, ML-based detection, and new inference backends are out of scope. Where horizontal scale needs production state, the track adds an **injection seam + honest documentation**, not a built-in distributed store.

## 2. Workstreams

Each workstream tightens existing behavior. Effort is per the audit (S/M/L).

### WS1 — Honesty & consistency sweep (1.1.2 patch)
The governing docs have drifted behind the shipped 1.1.1 line, which directly erodes trust in a security product.
- Correct stale claims: README + `configuration.md` "the proxy has no client authentication yet (planned for 0.6)" (bearer auth shipped in 0.6); `SECURITY.md` (describes a 0.3.x product — no streaming inspection, validation-only plugins); the `Target version: 0.6.0` / `Draft 0.1 / Target 1.0.0` headers on `configuration.md` / `threat-model.md` / `risk-register-release-gate.md`; the risk-register §1/§7 maturity language; the "0.1 crypto provider" label in README Security Notes.
- Add a **doc-freshness preflight gate** — extend the stale-name scanner (or a small new check) to fail CI on stale version banners and known-stale phrases (`planned for 0.6`, `Target version: 0.6.0`, `Only the current 0.3.x`, …). Haechi has shipped three stale-string fixes already; this prevents recurrence.
- Document honest scope explicitly (EN + KO): the multi-replica state contract (rate/audit/vault are single-process), single-host concurrency scoping, the unicode/base64 detection exclusions, and non-UTF-8 lossy decode.

### WS2 — Detection quality (1.2.0; highest leverage)
Detection precision/recall **is** the product for a security gateway, and it is currently unmeasured.
- **WS2a — Measure first (L):** a labeled fixture corpus (positive PII/secret samples per type + a benign/hard-negative set) and a `bench:detection` script reporting per-type precision/recall, wired as a CI regression gate alongside `release:preflight`. Everything else in WS2 is measured against this baseline.
- **WS2b — Coverage (M):** high-precision, well-anchored rules for the common credential formats the audit reproduced as MISS — AWS (`AKIA`/`ASIA`), GitHub (`ghp_`/`gho_`/`ghs_`), Google (`AIza`), Slack (`xox[baprs]-`), JWT (three-segment), PEM private-key headers — plus an expanded `assignment-secret` key vocabulary (`client_secret`, `private_key`, `aws_secret_access_key`, …). International PII (US SSN, IBAN mod-97, E.164) is either added with validators or **explicitly documented as KR-locale-only**.
- **WS2c — Precision control (M):** implement the *already-designed* `filters.minConfidence` gate (the `confidence` field is currently recorded but never gates anything) and a `filters.allowlist` exception mechanism with the documented invariant that it **cannot** suppress hard-block types (`secret`/`api_key`/`kr_rrn`/`card`). Add context anchors to the high-FP rules the audit reproduced (Luhn-passing order numbers → `card`; "Bearer …" in prose → `secret`).
- **WS2d — Evasion (M):** Unicode NFKC normalization of string leaves before matching (full-width/confusable evasion currently defeats all rules); optionally a bounded base64/percent-decode-and-rescan pass for long string leaves.

### WS3 — Horizontal-scale & state safety (1.2.0; injection seam + honest docs)
The rate limiter, audit chain, token vault, and auth store are single-process / local-file designs that **silently** weaken with 2+ replicas behind a load balancer.
- Make the rate limiter an **injectable collaborator** (`providers.rateLimiter`, mirroring `auditSink`/`cryptoProvider`) so a shared-store implementation is *replaceable* rather than absent — no built-in distributed store.
- Prune the rate-limiter window `Map` (currently unbounded memory growth keyed by identity).
- Document the multi-replica reality honestly (EN + KO + risk register): per-process rate limit, audit hash-chain forking on a shared file, whole-file-rewrite vault scaling limits, NFS file-lock caveats, single-writer anchor stream. Add a "horizontal scale / multiple replicas" subsection to `shared-responsibility.md`.

### WS4 — Operability / Day-2 (1.2.0)
A paying operator cannot run + monitor this in production today.
- **Health:** split `/__haechi/health` into `/__haechi/live` (process liveness) and `/__haechi/ready` (audit-sink writability + provider load + optional cached upstream probe → 503 when not ready), with a version field.
- **Telemetry:** a minimal `/metrics` surface (requests by decision/route/mode, blocks, `auth_denied`, `rate_limited`, `upstream_timeout`, response-unprotected, request/response latency histograms) via an injectable seam; a dedicated audit-write-failure signal (today it is a per-request 500 with one stderr line). Structured JSON logs for startup/shutdown/errors with a correlation id that also appears in the audit event. **Invariant guard:** no metric label or log field may carry plaintext/PII (the no-plaintext-in-audit invariant extends to telemetry).
- **Resilience:** graceful shutdown that drains in-flight requests and closes keep-alive connections within a grace period; a configurable global max-in-flight ceiling returning 503 + `Retry-After` (backpressure); tuned `requestTimeout`/`headersTimeout`.
- **Deploy:** an env-var configuration overlay for non-secret operational keys (`HAECHI_PROXY_PORT`/`HAECHI_UPSTREAM`/`HAECHI_MODE`/…), fail-closed; a hardened reference `Dockerfile` (non-root, pinned Node 22, read-only root fs + writable `.haechi` volume) + a `compose` example (fronting TLS/auth proxy) + an operations runbook; a chain-aware audit log rotation/retention procedure; a `configVersion` stamp + upgrade-notes map.

### WS5 — Core robustness bugs (1.1.2 patch)
- **`collectStringEntries` unbounded recursion (M):** a deeply nested JSON payload within `maxRequestBytes` can overflow the stack → uncaught crash. Add a configurable max-nesting-depth guard (fail-closed 4xx, mirroring the byte-limit path) + a deep-nesting test.
- Non-UTF-8 request body: today decoded lossily to U+FFFD before detection. Either reject fail-closed (`Buffer`/`isUtf8` check) or document as an accepted exclusion.
- Add deep-nesting + high-fan-out cases to `bench-payload.mjs` and reflect the honest worst-case in the P1-OPS-004 row.

### WS6 — Trust assets (commercial security review)
- **Proxy TLS / remote-bind hardening (M):** apply the dashboard's fail-closed remote-bind pattern to the proxy — when `--allow-remote-bind` is set, require an explicit TLS context (or a trusted-hop `X-Forwarded-Proto`) before accepting, so a remote bind cannot expose bearer tokens + payloads in plaintext. This is a real security control, not just docs.
- A security whitepaper mapping existing controls to OWASP LLM Top 10 (2025) and NIST AI RMF (frameworks already cited), plus a documented structured self-pentest.
- A vulnerability-disclosure channel: `SECURITY.md` reporting path + `security.txt` + GitHub private vulnerability reporting + a triage/response-time target.
- A compliance control mapping and a DSAR/retention operational workflow doc.

## 3. Sequencing

1. **WS1 + WS5 → 1.1.2 (patch).** Low-risk, immediate trust gain (honest docs + a real crash-bug fix + a doc-freshness gate). Warm-up.
2. **WS2 → the core of 1.2.0.** WS2a (measurement) lands first as a gate; WS2b/c/d are then developed *against the corpus* so every change has a precision/recall signal.
3. **WS3** (injection seam + honest multi-replica docs).
4. **WS4** (operability: health/metrics/logging/deploy).
5. **WS6** (trust assets).

WS2–WS6 land under **1.2.0** as additive, opt-in tightenings (API freeze preserved: new config keys are additive; `minConfidence`/`allowlist` change policy *behavior* but only additively and behind defaults that preserve 1.1 behavior — verified against `tests/api-contract.test.mjs`).

## 4. Guardrails (do not regress)
- **Zero runtime dependency** in core stays. Any shared-state/metrics implementation is an injection seam or a satellite, never a core dependency.
- **No plaintext/PII in audit** extends to all new telemetry (metrics labels, structured logs).
- **Fail-closed** posture holds for every new path (depth guard, backpressure, readiness, env overlay).
- **EN + KO docs** move together; the new KO content is written in 합쇼체.
- Each workstream is workflow-built and adversarially verified before merge; each ships with test + `check:types` + `release:preflight` evidence.

## 5. Explicit non-goals
- A built-in distributed rate limiter / audit sink / token vault (Redis/DB). The track adds the **seam + honest docs**; a production shared-store is a future satellite.
- ML/embedding-based detection. Detection stays regex + validators; the work is measurement + precision control + coverage of well-known formats.
- New inference backends or new plugin kinds. This track does not expand product surface.
- A compliance *certification*. WS6 produces a control **mapping** and disclosure assets, not a certification claim.
