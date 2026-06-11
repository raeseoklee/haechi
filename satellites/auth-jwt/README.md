# `haechi-auth-jwt`

A **headless** JWKS bearer (JWT) `authProvider` for Haechi. It verifies an `Authorization: Bearer <jwt>` against an issuer's JWKS and resolves a **PII-safe identity** — using `node:` builtins only (no `jose`). Published independently as `haechi-auth-jwt`; it adds **no runtime dependency** to core.

## Usage

```js
import { createRuntime } from "haechi/runtime";
import { createJwtAuthProvider } from "haechi-auth-jwt";

const runtime = createRuntime(
  { auth: { provider: "external" }, /* ... */ },
  {
    cryptoProvider, // required (also satisfies the PII-safe identity hmac)
    authProvider: createJwtAuthProvider({
      issuer: "https://idp.example.com",
      audience: "haechi-gateway",
      jwksUri: "https://idp.example.com/.well-known/jwks.json",
      cryptoProvider,
      algorithms: ["RS256", "ES256"],     // server-side allowlist (default)
      clockSkewSeconds: 60,                // max 300
      claimMappings: { scope: "scp", labels: { team: "groups" } }
    })
  }
);
```

Wired via **injection** (`auth.provider: "external"`); dynamic loading stays banned until the 1.0 plugin sandbox.

## Security (these are guarantees, not options)

- **The token never picks the algorithm.** The verifier uses the configured `algorithms` allowlist and the JWK type. `alg: "none"` is rejected; HMAC (`HS*`) is not allowed (alg-confusion defence); a JWKS public key is only ever used with its matching asymmetric algorithm. ES256 uses `dsaEncoding: "ieee-p1363"` (a JWS ES256 signature is raw R‖S, which `node:crypto` otherwise mis-verifies).
- **`kid` required**, key selected by `kid`. **RSA ≥ 2048 bits.** JWK `use` must be `sig`; `key_ops` must not include `encrypt`/`decrypt`. Only JWS is accepted (`typ: "JWE"` rejected).
- **Claims fully validated:** `iss` exact match; `aud` (string or array) must contain the configured audience; `sub` required non-empty; `exp`/`nbf` required and checked with a bounded `clockSkewSeconds` (default 60, **max 300**).
- **JWKS fetching is SSRF-hardened:** `issuer` and `jwksUri` must be **HTTPS** and share a host (single-origin issuers only in 0.8); requests to private/loopback/link-local/metadata addresses are refused (literal host + resolved IPs); fetch has a timeout and a 1 MiB response cap; JSON parsing is depth-bounded; JWT segments are strict base64url.
- **JWKS cache is bounded:** TTL-cached; an unknown `kid` triggers at most one refetch per cooldown (no fetch-storm against the IdP).
- **Identity is PII-safe (fail-closed):** a `cryptoProvider` with `hmac()` is required; `subjectHash`/`issuerHash` are keyed HMAC-SHA-256 (`haechi:identity:hash:v1`, built by core's `buildExternalIdentity`) — raw `sub`/`iss` are never stored or logged. `scopes` from the configured scope claim; `labels` from an allowlisted claim mapping.
- **Fail-closed everywhere:** any verification error → `authenticate` returns `null` (deny), never throws into the request path, and echoes no token detail.

## `createJwtVerifier` (the reusable primitive)

`createJwtVerifier(options)` is the standalone, audited JWS/JWKS verification path that `createJwtAuthProvider` is built on. It takes the verification-only options (`issuer`, `audience`, `jwksUri`, `algorithms`, `clockSkewSeconds`, JWKS cache/fetch knobs, `now`) — **no `cryptoProvider`, `claimMappings`, or `allowedLabelKeys`** (those stay in the provider) — and returns `{ verify }`:

```js
const verifier = createJwtVerifier({ issuer, audience, jwksUri /* ... */ });
const claims = await verifier.verify(jwt);            // validated claims object, or null
const claims2 = await verifier.verify(jwt, { expectedNonce }); // + OIDC nonce check
```

`verify(jwt)` does exactly the 0.8 bearer work — signature + `alg`/`kid`/RSA-bits + `iss`/`aud`/`exp`/`nbf` — and returns the **validated claims object** (not an identity) or `null` on any failure (fully fail-closed). `nonce` is **not** part of the bearer surface: it is checked only when `expectedNonce` is passed, and is a no-op when omitted. This is the single verification path reused by the `haechi-auth-oidc` broker (0.9).

## Scope (0.8)

Single-origin issuers only (issuer host == JWKS host). Multi-origin/CDN-fronted JWKS and full interactive OIDC (`haechi-auth-oidc`) are 0.9.
