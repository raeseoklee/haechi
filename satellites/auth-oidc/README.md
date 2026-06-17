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
  scopes: ["openid", "profile"],                   // "openid" forced in; "offline_access" stripped unless enableRefresh
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

- **SSRF-hardened discovery.** `GET <issuer>/.well-known/openid-configuration` over HTTPS only, bounded body, `metadata.issuer` must string-equal the configured issuer, and every endpoint host must equal the issuer host **or** be listed in `trustedEndpointHosts` (multi-origin / CDN-fronted IdPs — see below; empty by default ⇒ strict single-origin). Every egress (discovery, JWKS via the verifier, the token POST) runs a `lookup`→`isBlockedAddress` re-check immediately before the request (post-DNS rebinding guard) with `redirect:"error"`, a bounded body, and a timeout, regardless of the allowlist.
- **State-first short-circuit.** `/auth/callback` atomically `take()`s the pending record and asserts `state` **before any outbound request**; a missing/used/mismatched state denies with no IdP round-trip.
- **PKCE S256**, CSPRNG `state`/`nonce`/`code_verifier`, nonce binding on the ID token, RFC 9207 `iss` check, and an OIDC `aud`/`azp` profile (`aud` must contain `clientId`; multi-valued `aud` requires `azp === clientId`).
- **Server-side sessions; tokens never reach the browser.** The session cookie carries only an opaque ≥256-bit id. The access token is **discarded** (never stored or used). Under opt-in refresh (see below) the `refresh_token` is held server-side **only as an AEAD envelope**, never in plaintext and never sent to the browser. Two hardened cookies (`__Host-haechi_preauth`, `__Host-haechi_session`): `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` + `__Host-` whenever the externally-visible scheme is https.
- **PII-safe audit.** `oidc.login.{start,success,failure}` / `oidc.logout` / `oidc.session.evict` carry only `subjectHash`/`issuerHash`/`sessionIdHash` (keyed-HMAC), `provider:"oidc"`, a coarse `reasonCode`, and a timestamp — never a raw token, secret, `state`, `nonce`, or `sub`.
- **Fail-closed everywhere.** Every callback failure returns the same generic deny, no IdP detail echoed. Open-redirect prevention via `returnToAllowlist`; logout is non-GET + custom-header CSRF protected; a hard pending-auth cap rejects new logins with a generic 429 rather than evicting an in-flight auth.

## `trustedEndpointHosts` (multi-origin / CDN-fronted IdPs)

`trustedEndpointHosts` (an array of **bare hostnames**, default `[]`) pins additional hosts that may serve this IdP's **discovered** endpoints (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, `end_session_endpoint`) when they differ from the issuer host — the common shape for a CDN-fronted or custom-domain IdP (Azure AD B2C, Auth0). A discovered endpoint host is accepted **iff** it equals the issuer host **OR** it is listed in `trustedEndpointHosts`:

```js
const broker = createOidcSessionBroker({
  cryptoProvider,
  issuer: "https://login.contoso.com",                       // issuer host: login.contoso.com
  clientId: "haechi-dashboard",
  redirectUri: "https://dash.example.com/auth/callback",
  trustedEndpointHosts: ["contoso.b2clogin.com"],            // endpoints live on a different host
  // ...
});
```

It **relaxes ONLY the same-host string check** on discovered endpoints. Every other guard still runs **unconditionally**:

- Each endpoint must still be **`https`**.
- The per-egress `isBlockedAddress` **SSRF re-check** (literal host + post-DNS, immediately before every request) still refuses a private/loopback/link-local/metadata host — you cannot allowlist `169.254.169.254` or a loopback host.
- The **issuer-confusion guard** (`metadata.issuer` must string-equal the configured issuer) and the **RFC 9207 `iss`** checks still run.
- The set is **config-only** — built exclusively from the operator-supplied array, **never** from discovery-document content — so an attacker who controls the discovery document cannot introduce a new host (the mix-up defence stands). The same allowlist is threaded into the shared `createJwtVerifier`, which applies its own `https` + SSRF guards independently.

Each entry must be a bare hostname (no scheme, path, port, or whitespace) or construction throws. **Empty/absent ⇒ strict single-origin** (every endpoint host must equal the issuer host — the default, zero behavior change).

## Silent refresh (`enableRefresh`, `refreshMaxLifetimeSeconds`)

Refresh-token rotation / silent renewal is **opt-in** and **off by default**. When `enableRefresh` is `false` (the default) the broker is byte-behavior-identical to a refresh-less broker: `offline_access` is stripped from the requested scopes, no refresh token is ever stored, and there is no silent renewal.

- **`enableRefresh`** (boolean, default `false`). When `true`, the broker requests/keeps `offline_access` so the IdP returns a `refresh_token`, and `authenticate()` silently renews a session that is within the last quarter of its absolute TTL. **Requires a `cryptoProvider` with `encrypt()` and `decrypt()`** (in addition to `hmac()`) — construction **fails closed** if `enableRefresh: true` is set without them, because the refresh token is never held in plaintext.
- **`refreshMaxLifetimeSeconds`** (positive integer, default `604800` = 7 days, bounded ≤ the 30-day `MAX_TTL`). A **hard ceiling on the total session age across all refreshes**: no silent renewal may extend a session beyond `originalCreatedAt + refreshMaxLifetimeSeconds`. It is always validated (an invalid value fails closed regardless of `enableRefresh`) but only consulted when refresh is enabled.

How a silent renewal stays safe:

- **The refresh token is stored ONLY as an AEAD envelope** (`cryptoProvider.encrypt` under a domain-separated AAD, `haechi:oidc:refresh-token:v1`). The plaintext exists only transiently inside one refresh attempt; it is never persisted, logged, audited, or returned to a client.
- **Full re-verification + subject pin (anti-swap).** The renewed `id_token` is verified through the same shared `createJwtVerifier`, and the new `sub` must equal the `sub` pinned at login — a mismatch denies (`refresh_subject_mismatch`).
- **Fail-closed.** A network / non-2xx / parse failure (`refresh_failed`), a failed re-verification (`refresh_token_invalid`), a subject mismatch (`refresh_subject_mismatch`), or hitting the hard ceiling (`refresh_ceiling`) all deny — the session is not extended. Audit events carry only the coarse `reasonCode`, never IdP detail or a token.
- **`at_hash`/`c_hash` stays out of scope (still valid under refresh).** A silent renewal consumes the `refresh_token` only — the broker still never reads or uses the access token — so the verifier's `at_hash`/`c_hash` exclusion remains correct.

See `docs/current/release-0.9-implementation-scope.md` §2.2 for the full specification.

## Session store (`sessionStore`) — synchronous contract

The session store is pluggable via `sessionStore` (default: the in-memory `createInMemorySessionStore()`), but it **MUST be synchronous**. `get()` returns the session object (or `null`) in the same event-loop turn — it must **never** return a `Promise`. The broker reads `get()` and acts on it synchronously in `authenticate()`, `logout()`, and the refresh resurrection guard, whose get-then-set atomicity (a logged-out / superseded session must never be silently resurrected by a concurrent refresh) depends on a synchronous read.

An async (Redis/DB) store whose `get()` returns a `Promise` is **rejected fail-closed at construction** (`normalizeOidcConfig` probes a non-existent id and throws if the result is thenable), and `authenticate()` carries a defense-in-depth thenable guard so a store that slips past construction still fails closed rather than treating a truthy `Promise` as a valid session (which would authenticate an arbitrary cookie). To use a shared backend, wrap it in a synchronous in-process cache.

A natively-async shared session store is intentionally **out of scope** for now: it needs a CAS / version / tombstone contract for the resurrection guard, not just `await` — that is a future item.

## 한국어 (요약)

이 위성에는 별도 `README.ko.md` 형제 파일이 없습니다(저장소의 다른 위성 README도 모두 영문 단독입니다). 영문-주 + 한국어-형제 관례에 따라 새 옵션을 아래에 요약합니다.

- **`trustedEndpointHosts`** (bare 호스트명 배열, 기본 `[]`): issuer 호스트와 다른 호스트가 IdP의 **discovery된** 엔드포인트(`authorization_endpoint`/`token_endpoint`/`jwks_uri`/`end_session_endpoint`)를 제공하도록 핀합니다(CDN-fronted / 커스텀 도메인 IdP — Azure AD B2C, Auth0). 엔드포인트 호스트는 issuer 호스트와 같거나 이 allowlist에 포함될 때**만** 허용됩니다. 예: issuer `https://login.contoso.com`, `trustedEndpointHosts: ["contoso.b2clogin.com"]`. 이 옵션은 **same-host 문자열 검사만 완화**하며, `https` 요구, per-egress `isBlockedAddress` SSRF 재검사(`169.254.169.254`/loopback 거부), issuer-confusion 가드(`metadata.issuer` string-equal), RFC 9207 `iss` 검사는 **무조건** 실행됩니다. 이 집합은 **설정 전용**으로 discovery 문서 내용에서는 절대 만들어지지 않으므로 공격자가 새 호스트를 주입할 수 없습니다(mix-up 방어 유지). 비어 있거나 없으면 **엄격한 single-origin**이 기본값입니다.

- **`enableRefresh`** (boolean, 기본 `false`): opt-in silent refresh. `true`이면 `offline_access`를 요청·유지해 IdP가 `refresh_token`을 반환하게 하고, 절대 TTL의 마지막 1/4 구간에 든 세션을 무인 갱신합니다. **`encrypt()`/`decrypt()`를 갖춘 `cryptoProvider`가 필수**이며(없이 `true`로 설정하면 구성 시 fail-closed), refresh token은 절대 평문으로 보관되지 않습니다. refresh token은 **AEAD 봉투(envelope)로만** 저장되고(도메인 분리 AAD), 갱신된 `id_token`은 공유 verifier로 **완전 재검증**되며 로그인 시 핀된 `sub`와 일치해야 합니다(anti-swap). 갱신은 항상 **fail-closed**입니다. `at_hash`/`c_hash`는 갱신이 access token이 아닌 `refresh_token`만 소비하므로 **여전히 범위 외**입니다.

- **`refreshMaxLifetimeSeconds`** (양의 정수, 기본 `604800` = 7일, `MAX_TTL` 30일 이하로 제한): 모든 갱신을 통틀어 **세션 총 수명의 하드 상한**입니다. 어떤 무인 갱신도 `originalCreatedAt + refreshMaxLifetimeSeconds`를 넘기지 못합니다.

- **`sessionStore`** (기본 `createInMemorySessionStore()`): 교체 가능하지만 **반드시 동기(synchronous)** 여야 합니다. `get()`은 같은 이벤트 루프 턴에서 세션 객체(또는 `null`)를 반환해야 하며 **절대 `Promise`를 반환하면 안 됩니다**. 브로커는 `authenticate()`·`logout()`·refresh resurrection 가드에서 `get()`을 동기로 읽고 처리하는데, 이 get-then-set 원자성(로그아웃·교체된 세션이 동시 refresh로 조용히 되살아나지 않도록)이 동기 읽기에 의존합니다. `get()`이 `Promise`를 반환하는 async(Redis/DB) 스토어는 **구성 시 fail-closed로 거부**되며(`normalizeOidcConfig`가 존재하지 않는 id로 probe해 thenable이면 throw), `authenticate()`에도 방어선이 하나 더 있어 구성 검사를 통과해도 truthy `Promise`를 유효 세션으로 취급하지 않고 fail-closed 합니다(임의 쿠키 인증 방지). 공유 백엔드는 동기 in-process 캐시로 감싸 쓰세요. 네이티브 async 공유 세션 스토어는 resurrection 가드용 CAS/버전/tombstone 계약이 필요하므로 **현재 범위 밖**(향후 과제)입니다.
