# haechi-auth-oidc

An **interactive OIDC session broker** for [Haechi](https://github.com/raeseoklee/haechi): the authorization-code + PKCE flow that lets a human log in through a browser and obtain an opaque **server-side session**. It is the dashboard's human-login mechanism.

It is **not** a per-request bearer validator — that role stays with [`haechi-auth-jwt`](../auth-jwt). The broker reuses `haechi-auth-jwt`'s `createJwtVerifier` (and its `isBlockedAddress` SSRF guard) for ID-token signature + claim verification, then layers the OIDC-specific `aud`/`azp` profile on top.

## Install

```bash
npm install haechi haechi-auth-jwt haechi-auth-oidc   # peers: haechi >=0.8.0 <2.0.0, haechi-auth-jwt >=0.2.0
```

**`haechi` (the core) must be installed** — it is a peer dependency, not bundled (and so is `haechi-auth-jwt`, whose verifier this broker reuses). Zero runtime dependency — `node:` builtins (`crypto`, `dns`, `fetch`) plus the two peer imports only.

## Usage

```js
import { createOidcSessionBroker } from "haechi-auth-oidc";
import { createDashboardServer } from "haechi-dashboard";

const broker = createOidcSessionBroker({
  cryptoProvider,                                  // must implement hmac()
  issuer: "https://idp.example.com",               // https only
  clientId: "haechi-dashboard",
  clientSecret: process.env.OIDC_CLIENT_SECRET,    // omit for a public (PKCE-only) client
  redirectUri: "https://dash.example.com/auth/callback", // same-origin, path === /auth/callback
  scopes: ["openid", "profile"],                   // "openid" forced in, "offline_access" stripped
  returnToAllowlist: ["/", "/events"],
  sessionTtlSeconds: 28800,
  idleTtlSeconds: 1800,
  auditSink
});

createDashboardServer({ auditPath, host: "0.0.0.0", allowRemoteBind: true, tlsContext, sessionGuard: broker });
```

`createOidcSessionBroker(options)` returns the dashboard `sessionGuard` contract:

```
{
  authenticate(req) -> session | null,   // read-only; reads the session cookie; never throws
  handlers: {
    "/auth/login":    async (req, res) => {},   // 302 to the IdP authorize endpoint
    "/auth/callback": async (req, res) => {},   // token exchange + ID-token verify + session mint
    "/auth/logout":   async (req, res) => {}    // destroys the server-side session
  }
}
```

Each handler owns the full Node `http` response (status, headers incl. `Set-Cookie`, body).

## Security posture (acceptance criteria)

- **SSRF-hardened, single-origin discovery.** `GET <issuer>/.well-known/openid-configuration` over HTTPS only, bounded body, `metadata.issuer` must string-equal the configured issuer, and every endpoint must share the issuer host. Every egress (discovery, JWKS via the verifier, the token POST) runs a `lookup`→`isBlockedAddress` re-check immediately before the request (post-DNS rebinding guard) with `redirect:"error"`, a bounded body, and a timeout.
- **State-first short-circuit.** `/auth/callback` atomically `take()`s the pending record and asserts `state` **before any outbound request**; a missing/used/mismatched state denies with no IdP round-trip.
- **PKCE S256**, CSPRNG `state`/`nonce`/`code_verifier`, nonce binding on the ID token, RFC 9207 `iss` check, and an OIDC `aud`/`azp` profile (`aud` must contain `clientId`; multi-valued `aud` requires `azp === clientId`).
- **Server-side sessions; tokens never reach the browser.** The session cookie carries only an opaque ≥256-bit id. The access token is **discarded**. Two hardened cookies (`__Host-haechi_preauth`, `__Host-haechi_session`): `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` + `__Host-` whenever the externally-visible scheme is https.
- **PII-safe audit.** `oidc.login.{start,success,failure}` / `oidc.logout` / `oidc.session.evict` carry only `subjectHash`/`issuerHash`/`sessionIdHash` (keyed-HMAC), `provider:"oidc"`, a coarse `reasonCode`, and a timestamp — never a raw token, secret, `state`, `nonce`, or `sub`.
- **Fail-closed everywhere.** Every callback failure returns the same generic deny, no IdP detail echoed. Open-redirect prevention via `returnToAllowlist`; logout is non-GET + custom-header CSRF protected; a hard pending-auth cap rejects new logins with a generic 429 rather than evicting an in-flight auth.

See `docs/current/release-0.9-implementation-scope.md` §2.2 for the full specification.
