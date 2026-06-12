# Compliance Control Mapping & DSAR/Retention Workflow

- Status: Living document (WS6 — reliability-hardening-track §WS6)
- Nature of this document: a **control mapping**, NOT a compliance **certification**. The reliability-hardening-track §5 lists a certification as an explicit non-goal, and `SECURITY.md` Scope states this repository is not a compliance certification, legal opinion, or assurance report. This document maps Haechi controls to the *obligation categories* they help an operator satisfy — it does not assert that deploying Haechi makes a system compliant with any regulation.

## 0. How to read this

A regulatory obligation (e.g. "data minimization", "access logging", "subject rights") is satisfied by a *program* — people, process, and technology. Haechi is one **technical control** an operator wires into that program at the LLM/MCP gateway boundary. Below, each obligation **category** is mapped to the Haechi control(s) that support it, with the boundary of what Haechi does and does not do. The authoritative control definitions are in the code and `docs/current/threat-model.md`; this maps them, it does not restate them.

## 1. Control → obligation-category mapping

| Obligation category | Haechi control(s) | What Haechi contributes | Operator still owns |
|---|---|---|---|
| **Data minimization** | Detection + redact/mask/tokenize/encrypt/block pipeline (`packages/core`, `packages/filter`, `packages/policy`); privacy profiles (`kr-pipa`/`eu-gdpr`/`us-general`) | Strips or pseudonymizes PII/secrets before they reach the model, tools, or logs — so the minimum necessary data flows downstream. Tokenization replaces a value with a reversible reference held only in the vault. | Choosing the lawful-basis policy, the regional profile, and which fields are truly necessary. |
| **Access logging / auditability** | Audit JSONL with SHA-256 hash chain + head anchoring (`packages/audit`); per-request `correlationId`; PII-free events (`FORBIDDEN_KEYS`) | A tamper-evident record of *what category* was detected, *what action* was enforced, *which* (keyed-hashed) identity, and *when* — without storing the sensitive value itself. | Append-only/immutable storage media, log shipping, and the retention schedule (see §3). |
| **Purpose limitation / access control** | Auth gate before body-read; named policy profiles; model allowlist; per-identity rate limit (`packages/proxy`, `packages/auth`) | Constrains who may use the gateway and which models/operations/quotas each identity gets, enforced before any payload is read. | Identity lifecycle, token issuance/revocation policy, and the authorization model beyond the gateway. |
| **Storage limitation / retention** | Token-vault retention (`tokenVault.retentionDays`, expiry pruned on mutation); chain-aware audit rotation/retention procedure (`operations-runbook.md` §6) | Bounded token lifetime and a documented, hash-chain-preserving rotation/retention procedure for the audit log. | Setting the retention window per legal requirement and operating the rotation schedule. |
| **Subject rights (access / erasure)** | Token-vault reveal governance (`revealPolicy`) + purge, both audited by token id; the DSAR workflow in §2 | The reveal/purge primitives and their governance/audit are the technical building blocks of a DSAR response (see §2). | The legal intake, identity verification, decision, and recordkeeping of each request. |
| **Confidentiality in transit** | Proxy TLS / remote-bind hardening (`proxy.tls` / `proxy.trustForwardedProto`); loopback-by-default (`packages/proxy`) | A remote bind cannot serve bearer tokens + payloads in plaintext — it must terminate TLS or sit behind a verified `X-Forwarded-Proto: https` hop, else it fails closed at startup. | Certificate issuance/rotation and the network perimeter. |
| **Integrity & tamper evidence** | Audit hash chain + anchoring; canonical-AAD-bound encryption (`packages/crypto`); policies-only-get-stronger (`ACTION_STRENGTH`) | Tamper-evident audit, AEAD-bound ciphertext, and a policy lattice that cannot silently weaken. | Key custody (a production KMS/HSM is an injected `cryptoProvider`, never core), and incident response. |
| **Security of processing / resilience** | Fail-closed enforcement; depth/byte/encoding guards; readiness (`/__haechi/ready`) + backpressure (`packages/proxy`, `packages/core`) | Inline enforcement and fail-closed availability controls reduce the chance of an unprotected payload or an unbounded-consumption event. | Capacity planning, monitoring, and the broader security program. |

## 2. DSAR / retention operational workflow

A **Data Subject Access/erasure Request (DSAR)** is a legal/process workflow; Haechi provides the technical operations it bottoms out on. The flow below maps a request to concrete Haechi primitives. **All reveal/purge operations are audited by token id (never plaintext)** and are governed by `tokenVault.revealPolicy`.

### 2.1 Access request (the subject asks "what data of mine do you hold / process?")
1. **Locate.** Use the audit log to find the events touching the subject — match on the keyed-HMAC `subjectHash` (the audit never stores a raw subject), the `correlationId`, the time window, and the detection summary. The audit tells you *that* a category was processed and *which action* was taken, without the value.
2. **Resolve tokens, if and only if governed.** If a value was **tokenized**, the reversible reference lives in the token vault. Revealing it is gated by `tokenVault.revealPolicy`:
   - `disabled` (the default): reveal is refused. This is the production-safe posture — a DSAR access response is assembled from the audit metadata + the operator's upstream records, not from a live reveal.
   - `local-dev`: reveal is permitted only for explicit local-development workflows (`haechi token-reveal <token> --allow-dev-reveal`). **Do not** use `--allow-dev-reveal` as a production DSAR procedure (see `shared-responsibility.md` §2).
   Every reveal decision is written to the audit log by token id.
3. **Respond** through your legal/process channel. Haechi supplies the technical evidence; the operator owns identity verification and the response.

### 2.2 Erasure request (the subject asks "delete my data")
1. **Purge the token mapping.** `haechi token-purge` removes the vault mapping so the tokenized value can no longer be revealed; expired tokens are also pruned automatically on vault mutations. The purge decision is audited by token id.
2. **Expire the audit segments** that fall outside the retention window. Per `operations-runbook.md` §6, the audit log rotates into segments; retention **expires whole segments** (never partial lines, which would break the hash chain). The audit deliberately holds **no plaintext PII** — so an erasure obligation against the *content* is largely satisfied by the upstream/operator store, while the audit holds only keyed-hashed identifiers and category metadata.
3. **Erase upstream copies.** The model provider's logs, your application database, and any backups are **outside Haechi** — the operator must erase those per their own data map.

### 2.3 Retention operation (ongoing)
- **Token vault:** set `tokenVault.retentionDays`; expiry is pruned on vault mutations.
- **Audit log:** operate the chain-aware rotation in `operations-runbook.md` §6 — rotate at a maintenance boundary, keep each rotated segment **and its anchor** for the retention window so the history still verifies, then expire whole segments. Token-vault retention and audit retention are independent; rotating the audit does not purge tokens.

## 3. Boundaries & non-goals (honest)
- This is a **mapping**, not a certification or legal advice. Deploying Haechi does not make a system "GDPR/PIPA/etc. compliant."
- Haechi controls the **gateway boundary** only. The model provider's retention, your application store, and backups are the operator's responsibility (`shared-responsibility.md`).
- Detection is regex + validators (no ML); documented exclusions stand (`threat-model.md` §4). A DSAR/erasure program must not assume Haechi caught *every* instance of a value.

## 4. Cross-references
- `docs/current/shared-responsibility.md` — the Haechi-vs-operator responsibility matrix (the DSAR/retention split is called out there).
- `docs/current/operations-runbook.md` — §6 chain-aware audit rotation & retention.
- `docs/current/security-whitepaper.md` — the OWASP-LLM / NIST-AI-RMF control mapping + self-pentest.
- `docs/current/threat-model.md` — exclusions and accepted residuals.
