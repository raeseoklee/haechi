# `haechi-auth-jwt`

A **headless** JWKS bearer (JWT) `authProvider` for Haechi. It verifies an `Authorization: Bearer <jwt>` against an issuer's JWKS and resolves a **PII-safe identity** — using `node:` builtins only (no `jose`). Published independently as `haechi-auth-jwt`; it adds **no runtime dependency** to core.

## Install

```sh
npm install haechi haechi-auth-jwt   # peer: haechi >=0.8.0 <2.0.0
```

**`haechi` (the core) must be installed** — it is a peer dependency, not bundled. This satellite imports `haechi/runtime` and reuses your installed `haechi` instance (single crypto/identity surface), so install the core alongside it.

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
- **JWKS fetching is SSRF-hardened:** `issuer` and `jwksUri` must be **HTTPS**, and the JWKS host must equal the issuer host **or** be listed in `trustedEndpointHosts` (multi-origin / CDN-fronted IdPs — see below; empty by default ⇒ strict single-origin); requests to private/loopback/link-local/metadata addresses are refused (literal host + resolved IPs) regardless of the allowlist; fetch has a timeout and a 1 MiB response cap; JSON parsing is depth-bounded; JWT segments are strict base64url.
- **JWKS cache is bounded:** TTL-cached; an unknown `kid` triggers at most one refetch per cooldown (no fetch-storm against the IdP).
- **Identity is PII-safe (fail-closed):** a `cryptoProvider` with `hmac()` is required; `subjectHash`/`issuerHash` are keyed HMAC-SHA-256 (`haechi:identity:hash:v1`, built by core's `buildExternalIdentity`) — raw `sub`/`iss` are never stored or logged. `scopes` from the configured scope claim; `labels` from an allowlisted claim mapping.
- **Fail-closed everywhere:** any verification error → `authenticate` returns `null` (deny), never throws into the request path, and echoes no token detail.

## `createJwtVerifier` (the reusable primitive)

`createJwtVerifier(options)` is the standalone, audited JWS/JWKS verification path that `createJwtAuthProvider` is built on. It takes the verification-only options (`issuer`, `audience`, `jwksUri`, `trustedEndpointHosts`, `algorithms`, `clockSkewSeconds`, JWKS cache/fetch knobs, `now`) — **no `cryptoProvider`, `claimMappings`, or `allowedLabelKeys`** (those stay in the provider) — and returns `{ verify }`:

```js
const verifier = createJwtVerifier({ issuer, audience, jwksUri /* ... */ });
const claims = await verifier.verify(jwt);            // validated claims object, or null
const claims2 = await verifier.verify(jwt, { expectedNonce }); // + OIDC nonce check
```

`verify(jwt)` does exactly the 0.8 bearer work — signature + `alg`/`kid`/RSA-bits + `iss`/`aud`/`exp`/`nbf` — and returns the **validated claims object** (not an identity) or `null` on any failure (fully fail-closed). `nonce` is **not** part of the bearer surface: it is checked only when `expectedNonce` is passed, and is a no-op when omitted. This is the single verification path reused by the `haechi-auth-oidc` broker (0.9).

### `trustedEndpointHosts` (multi-origin / CDN-fronted IdPs)

`trustedEndpointHosts` (an array of **bare hostnames**, default `[]`) lets an operator pin additional hosts that are allowed to serve this IdP's JWKS when the JWKS host differs from the issuer host — the common shape for a CDN-fronted or custom-domain IdP (Azure AD B2C, Auth0). A JWKS host is accepted **iff** it equals the issuer host **OR** it is listed in `trustedEndpointHosts`:

```js
const verifier = createJwtVerifier({
  issuer: "https://login.contoso.com",                       // issuer host: login.contoso.com
  audience: "haechi-gateway",
  jwksUri: "https://contoso.b2clogin.com/contoso.onmicrosoft.com/b2c_1_signin/discovery/v2.0/keys",
  trustedEndpointHosts: ["contoso.b2clogin.com"]             // pin the differing JWKS host
});
```

This option **relaxes ONLY the same-host string check**. Every other guard still runs **unconditionally**:

- `jwksUri` must still be **`https`**.
- The `isBlockedAddress` **SSRF guard** still refuses a private/loopback/link-local/metadata host (literal host at construction + every DNS-resolved address before each fetch) — you cannot allowlist `169.254.169.254` or a loopback host.
- The set is **config-only**: it is built exclusively from the operator-supplied array, **never** from discovery- or JWKS-document content, so an attacker who controls the JWKS payload cannot introduce a new host.

Each entry must be a bare hostname (no scheme, path, port, or whitespace) or construction throws. **Empty/absent ⇒ strict single-origin** (the JWKS host must equal the issuer host — the default, zero behavior change).

## 한국어 (요약)

이 위성에는 별도 `README.ko.md` 형제 파일이 없습니다(저장소의 다른 위성 README도 모두 영문 단독입니다). 영문-주 + 한국어-형제 관례에 따라 핵심 내용을 아래에 요약합니다.

`createJwtVerifier`의 `trustedEndpointHosts`(bare 호스트명 배열, 기본 `[]`)는 운영자가 issuer 호스트와 다른 JWKS 호스트를 허용하도록 핀하는 옵션입니다(CDN-fronted / 커스텀 도메인 IdP — Azure AD B2C, Auth0). JWKS 호스트는 issuer 호스트와 같거나 `trustedEndpointHosts`에 포함될 때**만** 허용됩니다. 예: issuer `https://login.contoso.com`, jwksUri `https://contoso.b2clogin.com/.../keys`, `trustedEndpointHosts: ["contoso.b2clogin.com"]`.

이 옵션은 **same-host 문자열 검사만 완화**합니다. `https` 요구, `isBlockedAddress` SSRF 가드(private/loopback/link-local/metadata 호스트 거부 — `169.254.169.254`나 loopback은 allowlist에 추가해도 거부됨)는 **무조건** 실행됩니다. 이 집합은 **설정 전용**으로 discovery/JWKS 문서 내용에서는 절대 만들어지지 않으므로, JWKS 페이로드를 장악한 공격자가 새 호스트를 주입할 수 없습니다. 비어 있거나 없으면 **엄격한 single-origin**(JWKS 호스트 == issuer 호스트)이 기본값입니다.

## Scope

Multi-origin / CDN-fronted JWKS is supported via `trustedEndpointHosts` (auth-jwt 0.3.0; see above). Full interactive OIDC (`haechi-auth-oidc`) is a separate satellite.
