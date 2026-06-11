# `haechi-dashboard`

A **zero-dependency, read-only** audit viewer for Haechi. A `node:http` server that
serves a single self-contained static page (vanilla JS, no framework, no build
step) plus a read-only JSON API over the audit log and its hash-chain status.
`node:` builtins + the `haechi/audit` / `haechi/proxy` peer imports only — it adds
**no runtime dependency** to core. It takes **paths** (`auditPath`/`anchorPath`),
not a full runtime.

## Usage

### Programmatic

```js
import { createDashboardServer } from "haechi-dashboard";

const server = createDashboardServer({
  auditPath: "./.haechi/audit.jsonl",
  anchorPath: "./.haechi/audit.anchor.jsonl", // optional
  host: "127.0.0.1",                            // default
  port: 1018                                     // default; port 0 = OS-assigned ephemeral port
});

const { host, port } = await server.listen();
console.log(`http://${host}:${port}`);
// ... later
await server.close();
```

### CLI

```bash
haechi-dashboard --audit ./.haechi/audit.jsonl --anchor ./.haechi/audit.anchor.jsonl
# or via env: HAECHI_AUDIT_PATH / HAECHI_ANCHOR_PATH / HAECHI_HOST / HAECHI_PORT
```

The CLI binds loopback only; a remote bind requires TLS + a `sessionGuard`, which
are injected programmatically (not from the CLI).

## API (all `GET`/`HEAD`, read-only)

- `GET /` — the static HTML shell (references same-origin `/assets/app.js` + `/assets/app.css`).
- `GET /api/events?cursor=&limit=` — newest-first, bounded-window page of audit
  events. `limit` is an integer in `[1,200]`; `cursor` is the opaque
  `auditIntegrity.sequence` (never an fs offset). Pages older than the retained
  tail window return `{ windowExceeded: true }`. Each event is projected through a
  recursive key-by-key allowlist — never the raw record.
- `GET /api/chain` — derived from `verifyAuditChain`: `{ valid:true, records,
  headHash, anchored? }` on success, or `{ valid:false, records, truncationDetected }`
  on failure. The raw `reason` is never surfaced. Bounded compute (single
  serialized job, `mtime+size`-cached); above a hard size cap returns `413` /
  `{ valid:null }`. `HEAD` forces no fresh walk.
- `GET /api/summary` — aggregates the window's `byType` / `byAction` / `detectionCount`.
- `GET /healthz` — liveness only (no audit data/paths); reachable without a session.

## Security (these are guarantees, not options)

- **Loopback by default.** Reuses core's `assertSafeProxyBind`; a non-loopback bind
  without `allowRemoteBind` is refused. A remote bind additionally requires a
  `sessionGuard` **and** that the dashboard itself terminate TLS — a valid
  `tlsContext` carrying `(key && cert)` or `pfx`; an empty `{}` is rejected at
  construction. `trustProxy` (a non-empty trusted-proxy address/CIDR string)
  describes a fronting TLS terminator that reaches the dashboard over loopback;
  it **does not** authorize a non-loopback plaintext listener. `Strict-Transport-Security`
  is emitted **only** when the dashboard actually serves https (a valid
  `tlsContext`) — never over plaintext http. Fail-closed throughout.
- **Anti-DNS-rebinding.** Every request (incl. `/api/*` and `/healthz`) is rejected
  `403` unless the `Host` header host-portion is in the allowlist
  `{localhost, 127.0.0.1, ::1, ::ffff:127.0.0.1, the configured host}`. `Access-Control-Allow-Origin`
  is never emitted; `CORP`/`COOP` are `same-origin`.
- **No XSS.** The client builds the DOM with `createElement` + `textContent` only
  (never `innerHTML` with interpolation); a strict CSP with
  `require-trusted-types-for 'script'` makes any stray sink throw in-browser. The
  attacker-influenced `detections[].path` is rendered inert as text.
- **No plaintext / no field leak.** Events pass through a recursive key-by-key
  allowlist projection (defense in depth over core's `FORBIDDEN_KEYS`); identity is
  shown as `subjectHash`/`issuerHash`/`id` only — never `scopes`/`labels`/a raw subject.
- **Read-only.** Only `GET`/`HEAD`; anything else is `405`. No `POST`/`DELETE`
  surface (no reveal/purge/policy edit). Assets are served from a fixed in-code map
  (no `fs` path derived from the URL — path traversal is structurally impossible).
- **Generic errors.** Handler errors return `{ error: "internal" }` — never a stack,
  message, OS code, or an absolute path (`auditPath`/`anchorPath` are sensitive).
- **Bounded DoS surface.** Event reads tail a bounded byte window (never the whole
  file); `/api/chain` is `mtime+size`-cached and size-capped; `/api/*` is rate-limited.

## `sessionGuard` seam (interactive auth)

The dashboard gates every `/api/*` behind an injected `sessionGuard`:

```js
{ authenticate(request) -> session | null, handlers: { "/auth/login": fn, ... } }
```

An unauthenticated `/api/*` returns `401` (never a `302`; the static shell performs
the redirect). Handler keys are a **fixed allowlist** — only `/auth/login`,
`/auth/callback`, `/auth/logout` may be declared; any other key (notably an
`/api/*` path, `/healthz`, or `/`) is **rejected at construction**, so a guard can
never exempt an audit-data route from the gate. The auth-exempt set is the exact
intersection of that fixed list and the declared handlers; `/healthz` is always
reachable. On loopback with no guard, the dashboard serves unauthenticated (the
only unauthenticated mode). `haechi-auth-oidc`'s `createOidcSessionBroker` satisfies
this contract.

## Scope (0.9)

Audit viewer only — the event stream, the `verifyAuditChain` chain status, and
decision/action aggregates. Token-vault and policy visualization, and any write
action, are out of scope.
