# Haechi Shared Responsibility

- Status: Living document (tracks core 1.3.x)
- Date: 2026-06-10

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
| Plugin | Manifest validation; dynamic loading lifted narrowly for signed + sandboxed `authProvider` plugins (worker-isolated 1.0 / process-isolated 1.1) | Curate trust anchors/pins/revocation; prefer `process-isolated`; review plugin code |
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
8. For more than one replica, supply the shared infrastructure in §4 (front-door rate limit, per-replica audit paths, shared token vault).

## 4. Horizontal scale / multiple replicas

Haechi's stateful controls are single-process by design. Running 2+ replicas behind a load balancer **silently weakens** them unless the operator supplies shared infrastructure:

- **Rate limit** is per-process and in-memory — total throughput multiplies by the replica count. Enforce a per-identity limit at a shared front door, or inject a shared-store `rateLimiter` via `createRuntime(config, { rateLimiter })` (the seam satisfies the `allow(key, limit)` contract, which may return `boolean` or `Promise<boolean>`; see [`configuration.md` → Rate limiter injection](./configuration.md#rate-limiter-injection)). The [`haechi-ratelimit-redis`](https://github.com/raeseoklee/haechi/tree/main/satellites/ratelimit-redis) satellite is the reference shared-store (Redis-backed) implementation — a fixed-window counter over an injected client. The default per-process limiter also bounds its window map (no unbounded memory growth keyed by identity).
- **Audit hash chain + anchor** are single-writer. Give each replica its **own** `audit.path` (and anchor path); never share one audit file across replicas, or the chain forks into an unverifiable state.
- **TokenVault and the auth store** are whole-file local stores — correct for one host, but not a shared multi-writer store. For multi-replica tokenization, inject a shared `tokenVault`.
- File locking relies on `O_EXCL` + atomic rename, which do not hold on NFS / shared filesystems — keep these stores on local disk.
