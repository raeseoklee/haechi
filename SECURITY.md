# Security Policy

## Scope

This repository is a self-hosted security toolkit. It is not a compliance certification, legal opinion, or assurance report.

Release risk tracking is maintained in `docs/current/risk-register-release-gate.md`. npm release checks must pass `npm run release:preflight`; actual npm publication additionally requires `npm run release:preflight:npm` from an authenticated npm account.

## Supported Versions

Only the current `1.x` stable line is considered in scope. From 1.0 the public API is a frozen contract under strict semver, with a documented deprecation policy and a single in-minor security exception for disclosed vulnerabilities (see `docs/current/api-stability.md`). The four `haechi-*` satellites are pre-1.0 and version independently of core.

## Reporting

**Preferred channel: GitHub private vulnerability reporting.** Open a private report through the repository's Security Advisories at <https://github.com/raeseoklee/haechi/security/advisories> (the "Report a vulnerability" button). This keeps the report confidential until a fix is coordinated. The machine-readable disclosure metadata is published at [`/.well-known/security.txt`](.well-known/security.txt) (RFC 9116; mirrored at the repo root).

Do not include real secrets, production prompts, customer data, or personal information in reports — describe the issue and a minimal, sanitized reproduction instead.

**Triage target (best-effort, not an SLA for a pre-1.0/OSS project):** we aim to **acknowledge a report within 3 business days** and to share an initial assessment (accepted / needs-info / out-of-scope) within **10 business days**. A disclosed, in-scope vulnerability is eligible for an in-minor security fix under the `1.x` stability exception (`docs/current/api-stability.md`).

A control mapping (OWASP LLM Top 10 2025 / NIST AI RMF) and a structured self-pentest are documented in [`docs/current/security-whitepaper.md`](docs/current/security-whitepaper.md). This is a self-assessment, not an independent audit or certification.

## Security Invariants

- Audit output must not contain raw sensitive payload values; `FORBIDDEN_KEYS` guards against plaintext prompt, tool-result, secret, or PII values reaching the audit log.
- Audit output must carry a SHA-256 hash chain for local tamper detection; `audit.anchor` head-hash anchoring on append-only/separate media detects tail truncation back to the last anchor.
- Encryption must bind ciphertext to canonical AAD; the local crypto provider uses AES-256-GCM over a software-key file, and `keys.provider: external` requires an injected `cryptoProvider`.
- Policy enforcement must prefer blocking over leaking plaintext when configuration is invalid (fail-closed), including an unknown `target.type`.
- Policies only get stronger: preset/action merges and privacy profiles may strengthen but never weaken an explicit action (`ACTION_STRENGTH`).
- Proxy listeners must stay loopback-only unless remote binding is explicitly enabled (`--allow-remote-bind`) and the deployment supplies network access controls.
- Streaming responses are inspected only within bounds and opt-in: `streaming.requestMode: "inspect"` stream-filters SSE/NDJSON with a bounded cross-frame sliding buffer; the default `block` refuses streaming fail-closed, and `pass-through` is an explicit, audited opt-out.
- Response protection fails closed for non-JSON, invalid JSON, compressed, or oversized responses unless an explicit allow policy is configured.
- Client authentication is available: `auth.provider` of `bearer` (built-in hashed token store), `external` (injected `authProvider`), or `plugin` (a signed, sandboxed `authProvider`); identity in the audit log is keyed-HMAC, never raw subject/issuer. The default `none` leaves the proxy unauthenticated. The built-in rate limit is single-process (per-process).
- Token reveal must be disabled by default and enabled only for explicit local development workflows; reveal/purge decisions are audited by token id, never plaintext.
- Dynamic plugin execution is lifted **narrowly** for `authProvider` plugins only, gated by an Ed25519 signature, an operator trust-anchor allowlist, version pin/floor, revocation, and a validity window. The plugin runs in a sandbox: `worker_threads`-isolated (1.0, memory/crash isolation + data-minimization) or, opt-in, `process-isolated` (1.1, a child under the Node `--permission` model with kernel-enforced fs/net/exec/worker denial on a `--allow-net` Node, fail-closed otherwise). Plugin manifests declare capabilities (e.g. credential reads, network egress). All other plugin/provider kinds stay dependency-injection-only.

## Local Development Keys

`haechi init` creates `.haechi/dev.keys.json` for local development. Treat this file as a disposable development secret. Do not reuse it for production data, shared environments, compliance evidence, or internet-facing gateways.
