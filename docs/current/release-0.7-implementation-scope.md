# Haechi 0.7 Implementation Scope

- Status: Final
- Date: 2026-06-10
- Target version: 0.7.0 (after 0.6.0)
- Type: ops hardening
- Shipped: 2026-06-10 — PRs #22 (audit anchoring), #23 (cryptoProvider contract + reference KMS), #24 (signed release artifacts)

## 1. Release Goal

Harden the operational story that 1.0 ("stable", developer-preview label removed) blocks on: audit integrity beyond a single local file, external key custody, and verifiable release artifacts. This is the first of the two 1.0-blocker releases.

**Scope decision (2026-06-10):** 0.7 is focused on **ops hardening** — audit integrity, key custody contract, signed artifacts. The **ecosystem** items previously grouped here (npm org `@haechi/*`, publishing `@haechi/crypto-kms` / `@haechi/auth-oidc`, `@haechi/dashboard`, npm workspaces) move to **0.8**, which also removes the duplicate 0.7 roadmap row.

Core's **zero runtime dependency** posture is non-negotiable: everything in 0.7 ships with `node:` builtins only. Heavy adapters (AWS KMS, Vault) are satellites/examples, never core.

## 2. Scope

### 2.1 Audit tail-truncation defense: head-hash anchoring (built-in, zero-dep)

The audit hash chain detects tampering and reordering but **not** deletion of the last N records — the shortened chain still verifies. 0.7 closes this for the common case with periodic anchoring.

- After appending, the JSONL sink writes the current chain head to a separate **append-only anchor stream**: one JSON line `{ sequence, eventHash, timestamp }`.
- Config `audit.anchor`:
  - `mode`: `none` (default — current behavior) | `file` | `stdout`.
  - `path`: anchor file when `mode: file` (created `0600`). `stdout` writes anchor lines to stdout for capture by a long-running command's supervisor — not for JSON-emitting commands, whose output it would interleave.
  - `everyRecords`: anchor cadence (default `1` — anchor every record; raise to batch). Anchor lines are tiny.
- `verifyAuditChain(path, { anchorPath })` cross-checks: the latest anchor's `sequence` must not exceed the chain length, and the chain record at the anchored `sequence` must hash to the anchored `eventHash`. A chain shorter than the latest anchor → **truncation detected** (records after the last anchor were removed). A partial trailing anchor line (from a crash) is tolerated.
- `haechi audit-verify --anchor <path>` surfaces this; `haechi status` reports anchor mode + last anchored sequence.
- **Threat-model boundary (required, not optional):** the anchor adds tamper-evidence **only when it lives on append-only or physically separate media** (append-only-flagged FS, S3/GCS object-lock, syslog, a different host). On the **same writable filesystem** an attacker who truncates `audit.jsonl` can truncate `audit.anchor.jsonl` to match and verification passes — so file-mode on the same disk is a convenience, not a guarantee. The CLI (`status`, `audit-verify`, `config`) states this explicitly.
- **Bounded guarantee:** even on proper media, truncation is detected only back to the **last anchor**; records written after the last anchor and before truncation can still be lost silently. With `everyRecords: 1` that window is one record. Documented.

### 2.2 External append-only audit sink contract

- Formalize the injected `auditSink` contract (already supported via `createRuntime(config, { auditSink })`): `record(event)` is append-only and order-preserving; an external sink either implements the hash chain itself or wraps the built-in sink. Capability flags (`writesAudit`, `integrity`, `appendOnly`) are documented.
- A reference HTTP/syslog/object-lock forwarding sink is a **0.8 satellite/example**; 0.7 ships the contract + the built-in anchoring as the zero-dep answer.

### 2.3 cryptoProvider contract hardening + reference KMS adapter

- Tighten and document the `cryptoProvider` contract for `keys.provider: external`: a provider always implements `encrypt`/`decrypt`, binds canonical AAD, and selects keys by `kid`; the envelope **base shape** is `{ v, alg, kid, iv, ct, tag, aadHash }` and adapters **may add provider-specific fields** (e.g. a KMS adapter's `wrappedKey`). `hmac` is required **only by features that use it** — bearer auth and deterministic tokenization — and `createRuntime` fails closed at construction when one of those is configured without `hmac` (an encrypt-only provider is otherwise valid). Policy-bundle signing uses the local key file directly via the CLI, not the injected provider.
- Ship `assertCryptoProviderConformance(provider, { requireHmac = true })` (an exported test helper): encrypt→decrypt round-trip (distinct plaintexts), AAD-mismatch rejection, **tampered-ciphertext rejection (real AEAD authentication)**, and `hmac` determinism + data-dependency + domain separation + invalid-domain rejection. Satellite adapters self-test against it; pass `requireHmac: false` for an encrypt-only provider.
- Ship a **reference adapter** under `examples/crypto-kms-reference/` (its own `package.json`, AWS/Vault SDK as an *optional* dependency; the in-process `createInMemoryKms` is explicitly non-production) demonstrating envelope-encryption injection. It is the source that becomes the published **`@haechi/crypto-kms`** satellite in 0.8 (gated on the npm org).

### 2.4 Signed release artifacts

- npm provenance (SLSA attestation) already ships via trusted publishing (since 0.4). 0.7 adds **GitHub release asset integrity**: the release workflow runs `npm pack`, emits `SHA256SUMS`, and attaches the tarball + checksums (and, where available, a sigstore/cosign signature) to each GitHub release.
- Lets users verify a downloaded tarball before install and gives the release assets a tamper-evident manifest beyond the registry.

## 3. Explicit non-scope (deferred to 0.8)

- Create npm org `@haechi/*`; publish `@haechi/crypto-kms`, `@haechi/auth-oidc`, `@haechi/auth-jwt`.
- `@haechi/dashboard` (read-only audit viewer) and npm workspaces conversion.
- Real AWS KMS / HashiCorp Vault SDK integration as a published package (0.7 ships the contract + reference example only).
- Distributed/shared audit or rate state.

## 4. Config schema summary

```json
"audit": {
  "sink": "jsonl",
  "path": ".haechi/audit.jsonl",
  "anchor": { "mode": "none", "path": ".haechi/audit.anchor.jsonl", "everyRecords": 1 }
}
```
Fail-closed validation: unknown `anchor.mode`; `mode: file` without a `path`; non-positive `everyRecords`.

## 5. 1.0 exit-criteria progress

0.7 advances three of the five 1.0 ("remove developer-preview label") blockers:

| 1.0 blocker | 0.7 contribution |
|---|---|
| Operational key custody | cryptoProvider contract hardened + conformance test + reference adapter (published package in 0.8) |
| External / tamper-evident audit | Built-in anchoring closes tail-truncation; external sink contract documented |
| Verifiable release artifacts | Signed/checksummed GitHub release assets |
| API stability freeze | (1.0) |
| Plugin sandbox + real-environment validation | (1.0) |

## 6. Test criteria (for implementation)

- Anchoring: anchor lines written per `everyRecords`; `verifyAuditChain` with an anchor detects truncation (chain shorter than last anchor) and passes an intact chain; `mode: none` keeps 0.6 behavior byte-for-byte.
- `audit-verify --anchor` exit code + output; `status` reports anchor mode/last sequence.
- cryptoProvider conformance helper passes the local provider and fails a provider missing `hmac` / mismatching AAD.
- Config validation for the `audit.anchor` block.
- Release workflow produces `SHA256SUMS` matching the packed tarball (CI-verifiable).

## 7. Suggested PR breakdown (stacked)

1. Audit anchoring (sink writes anchors) + `verifyAuditChain` anchor cross-check + config + `audit-verify --anchor` / `status`.
2. cryptoProvider contract doc + `assertCryptoProviderConformance` + `examples/crypto-kms-reference/`.
3. Signed release artifacts (release workflow + verification doc).
4. 0.7.0 release cut (version, docs EN/KO, threat-model/risk-register/api-stability, wiki).
