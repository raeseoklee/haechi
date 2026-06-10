# Haechi Shared Responsibility

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: 0.3.2

## 1. Responsibility Matrix

| Area | Haechi provides | User/operator responsibility |
|---|---|---|
| Local development | CLI, default config, dev key generation | Do not reuse dev keys in production or shared environments |
| Policy enforcement | redact/mask/tokenize/encrypt/block pipeline | Select actions appropriate to regulatory and organizational policy |
| HTTP proxy | Loopback default, remote bind guard, body/response limits | Authentication, TLS termination, firewall, upstream auth |
| Streaming | Blocked by default | Accept the risk of no protection when using pass-through |
| TokenVault | Encrypted storage, reveal blocked by default, purge | Reveal approval workflow, DSAR/retention operations |
| Audit | Plaintext removal, hash chain | Append-only storage, backup, retention period, external signing |
| Key custody | Local dev key, external crypto provider contract | KMS/HSM/Vault adapter implementation, rotation, access review |
| Plugin | Manifest validation, dynamic runtime blocked | Plugin code review, do not execute before sandbox is available |
| MCP | JSON-RPC/method allowlist | MCP server auth, resource consent, env secret allowlist |
| Privacy profile | KR/EU/US baseline actions | Legal review, data residency, cross-border transfer evidence |

## 2. Prohibited default usage

- Using `--allow-remote-bind` without network controls
- Using `.haechi/dev.keys.json` with production data
- Treating `streaming.requestMode: "pass-through"` as an applied protection
- Using `responseProtection.failureMode: "allow"` on sensitive data paths
- Using `token-reveal --allow-dev-reveal` as a production recovery procedure

## 3. Production transition checklist

1. Connect an external crypto provider or KMS/HSM/Vault adapter.
2. Place authentication, TLS, a firewall, and rate limiting in front of the proxy.
3. Enable responseProtection and keep it fail-closed.
4. Block streaming endpoints until a dedicated stream-aware gateway is ready.
5. Send the audit sink to an append-only or externally signed storage backend.
6. Document the TokenVault reveal approval, retention, and deletion procedures.
7. Calibrate privacy profiles based on legal review findings.
