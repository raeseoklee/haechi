// haechi-auth-jwt — headless JWKS bearer verification for Haechi.
//
// createJwtVerifier(...) is the standalone, audited JWS/JWKS verification
// primitive: verify(jwt) -> validated claims | null (fail-closed). It is the
// ONE verification path reused by createJwtAuthProvider here and by the future
// haechi-auth-oidc broker (see release-0.9-implementation-scope.md §2.2).
//
// createJwtAuthProvider(...) implements the authProvider contract
// (authenticate(request) -> identity | null, fail-closed) on top of the
// verifier, using node: builtins only (no `jose`): JWKS fetched via global
// fetch, JWK->key via crypto.createPublicKey({ format: "jwk" }), signatures
// verified via crypto.verify.
//
// Every security decision below is a DECISION, not implementation discretion;
// see docs/current/release-0.8-implementation-scope.md §2.4. The verifier never
// trusts the token to pick the algorithm, rejects alg:"none" and HMAC/JWE,
// requires kid, enforces RSA>=2048 and EC P-256, validates iss/aud/sub/exp/nbf
// with a bounded clock skew, SSRF-guards JWKS fetching, bounds the JWKS cache,
// and builds a PII-safe identity via the injected cryptoProvider.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { buildExternalIdentity } from "haechi/auth";

// --- constants (decisions) -------------------------------------------------

const SUPPORTED = {
  // alg -> how to verify it. NEVER includes HS* (alg-confusion) or "none".
  RS256: { kty: "RSA", digest: "sha256" },
  RS384: { kty: "RSA", digest: "sha384" },
  RS512: { kty: "RSA", digest: "sha512" },
  ES256: { kty: "EC", crv: "P-256", digest: "sha256", dsaEncoding: "ieee-p1363" },
  ES384: { kty: "EC", crv: "P-384", digest: "sha384", dsaEncoding: "ieee-p1363" },
  ES512: { kty: "EC", crv: "P-521", digest: "sha512", dsaEncoding: "ieee-p1363" }
};
const DEFAULT_ALGORITHMS = ["RS256", "ES256"];
const MAX_CLOCK_SKEW_SECONDS = 300;
const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_JWKS_TTL_MS = 300_000;        // cache JWKS for 5 min
const DEFAULT_JWKS_COOLDOWN_MS = 60_000;    // >=60s between unknown-kid refetches
const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const MAX_JWKS_BYTES = 1024 * 1024;         // 1 MiB
const MAX_JSON_DEPTH = 32;
const MIN_RSA_MODULUS_BITS = 2048;

// --- small utilities -------------------------------------------------------

function parseHttpsUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`${label} must be https`);
  }
  return url;
}

// Parse an IPv6 literal into its 16 octets (or null when it is not a valid IPv6
// text form). This is the SOUND way to recognise an IPv4-mapped IPv6 address in
// EVERY textual form: dotted (::ffff:127.0.0.1), HEX (::ffff:7f00:1), bracketed
// ([::ffff:7f00:1], stripped by the caller), leading-zero (::ffff:7f00:0001),
// mixed `::` compression, and case-insensitive ffff. We classify the last 32
// bits as the embedded IPv4 ONLY when bytes 0..9 are zero and bytes 10..11 are
// 0xffff (the ::ffff:0:0/96 IPv4-mapped prefix), so a genuinely public mapped
// address (::ffff:8.8.8.8 == ::ffff:808:808) stays allowed and a non-mapped v6
// (::ffff:0:7f00:1, NAT64 64:ff9b::…) is NOT mistaken for an embedded IPv4.
//
// Kept byte-for-behavior identical to packages/ssrf/index.mjs and
// satellites/crypto-kms/vault.mjs (parity-tested) — see this module's header and
// crypto-kms/ssrf-parity.test.mjs. The DELIBERATE 1.1 decoupling means each copy
// carries this logic rather than importing haechi/ssrf.
function ipv6ToBytes(str) {
  let s = str;
  // A trailing dotted IPv4 quad (::ffff:127.0.0.1) — peel it off into the final
  // two hextets so the remaining text is pure hex groups.
  let tailV4 = null;
  if (s.includes(".")) {
    const idx = s.lastIndexOf(":");
    if (idx === -1) return null;
    const quad = s.slice(idx + 1).split(".");
    if (quad.length !== 4) return null;
    const oct = quad.map(Number);
    if (oct.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    tailV4 = oct;
    s = `${s.slice(0, idx + 1)}0:0`; // placeholder hextets; overwritten below
  }
  const halves = s.split("::");
  if (halves.length > 2) return null; // at most one "::"
  const toGroups = (g) => (g === "" ? [] : g.split(":").map((h) => (/^[0-9a-fA-F]{1,4}$/.test(h) ? parseInt(h, 16) : NaN)));
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : null;
  if (head.some(Number.isNaN) || (tail && tail.some(Number.isNaN))) return null;
  let groups;
  if (tail === null) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill(0), ...tail];
  }
  if (groups.length !== 8) return null;
  const bytes = [];
  for (const g of groups) bytes.push((g >> 8) & 0xff, g & 0xff);
  if (tailV4) { bytes[12] = tailV4[0]; bytes[13] = tailV4[1]; bytes[14] = tailV4[2]; bytes[15] = tailV4[3]; }
  return bytes;
}

// Return the embedded IPv4 dotted quad of an IPv4-mapped IPv6 address, or null.
function mappedIpv4(bare) {
  const b = ipv6ToBytes(bare);
  if (!b) return null;
  for (let i = 0; i < 10; i += 1) if (b[i] !== 0) return null; // bytes 0..9 must be zero
  if (b[10] !== 0xff || b[11] !== 0xff) return null;           // bytes 10..11 must be 0xffff
  return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
}

// Block literal addresses in private/loopback/link-local ranges + cloud metadata.
// Applied to both a literal host in the URL and every DNS-resolved address.
// Exported (additive, behavior-preserving — auth-jwt stays 0.2.0) so the
// haechi-auth-oidc broker reuses the SAME guard rather than copying the range
// logic (release-0.9-implementation-scope.md §2.2).
export function isBlockedAddress(host) {
  // A URL's .hostname keeps the brackets on an IPv6 literal ("[::1]"), and isIP
  // rejects a bracketed string — strip them first so literals are classified.
  const bare = String(host).replace(/^\[|\]$/g, "");
  const v = isIP(bare);
  if (v === 4) {
    const o = bare.split(".").map(Number);
    if (o[0] === 127) return true;                          // 127.0.0.0/8 loopback
    if (o[0] === 10) return true;                           // 10.0.0.0/8
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16/12
    if (o[0] === 192 && o[1] === 168) return true;          // 192.168/16
    if (o[0] === 169 && o[1] === 254) return true;          // 169.254/16 link-local incl. metadata
    if (o[0] === 0) return true;                            // 0.0.0.0/8
    return false;
  }
  if (v === 6) {
    const h = bare.toLowerCase();
    if (h === "::1" || h === "::") return true;             // loopback / unspecified
    // IPv4-mapped IPv6 — normalise to the embedded IPv4 (handles dotted AND hex
    // forms, e.g. ::ffff:127.0.0.1 and ::ffff:7f00:1) and run the v4 check, so a
    // private/loopback/metadata target can't slip past as hex (P1-CR-002).
    const mapped = mappedIpv4(bare);
    if (mapped !== null) return isBlockedAddress(mapped);
    // Range-check the first hextet (startsWith("fe80") wrongly let fe81–febf
    // through): fe80::/10 link-local, fc00::/7 ULA, ff00::/8 multicast.
    const firstHextet = parseInt(h.split(":")[0] || "", 16);
    if (Number.isFinite(firstHextet)) {
      if (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) return true; // link-local
      if (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) return true; // unique local
      if (firstHextet >= 0xff00 && firstHextet <= 0xffff) return true; // multicast
    }
    return false;
  }
  return false; // not a literal IP; resolved addresses are checked separately
}

// Strict base64url: only [A-Za-z0-9_-], no padding, no whitespace.
function decodeBase64UrlStrict(segment) {
  if (typeof segment !== "string" || segment.length === 0 || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new Error("invalid base64url segment");
  }
  return Buffer.from(segment, "base64url");
}

// JSON.parse with a recursion-depth bound (guards against stack-exhaustion via
// deeply nested JWKS/claims). Operates on already-size-bounded input.
function parseJsonBounded(text) {
  const value = JSON.parse(text);
  const check = (node, depth) => {
    if (depth > MAX_JSON_DEPTH) throw new Error("JSON nesting too deep");
    if (Array.isArray(node)) {
      for (const item of node) check(item, depth + 1);
    } else if (node && typeof node === "object") {
      for (const key of Object.keys(node)) check(node[key], depth + 1);
    }
  };
  check(value, 0);
  return value;
}

function rsaModulusBits(jwk) {
  let n = decodeBase64UrlStrict(jwk.n);
  let i = 0;
  while (i < n.length && n[i] === 0) i += 1; // strip leading zero bytes
  if (i >= n.length) return 0;
  const topByte = n[i];
  let topBits = 8;
  for (let mask = 0x80; mask > 0 && (topByte & mask) === 0; mask >>= 1) topBits -= 1;
  return (n.length - i - 1) * 8 + topBits;
}

// --- the verifier primitive ------------------------------------------------
//
// createJwtVerifier(options) is the standalone, audited JWS/JWKS verification
// path carved out of createJwtAuthProvider so the future haechi-auth-oidc broker
// reuses ONE verification path (release-0.9-implementation-scope.md §2.2).
//
// It owns ALL construction-time validation EXCEPT the cryptoProvider check and
// claimMappings/allowedLabelKeys handling (those stay in the provider), plus the
// JWKS cache machinery, publicKeyFor, verifySignature, and audienceMatches.
//
// verify(jwt, { expectedNonce } = {}) returns the validated claims OBJECT on
// success or null on ANY failure (fully fail-closed). nonce is NOT part of the
// 0.8 bearer surface: it is checked ONLY when expectedNonce !== undefined.
export function createJwtVerifier(options = {}) {
  const {
    issuer,
    audience,
    jwksUri,
    algorithms = DEFAULT_ALGORITHMS,
    clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
    jwksTtlMs = DEFAULT_JWKS_TTL_MS,
    jwksCooldownMs = DEFAULT_JWKS_COOLDOWN_MS,
    fetchTimeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
    fetchImpl,
    lookupImpl = lookup,
    now = () => Date.now()
  } = options;

  // ---- construction-time validation (fail closed) ----
  if (typeof issuer !== "string" || !issuer) {
    throw new Error("createJwtVerifier requires an issuer");
  }
  const issuerUrl = parseHttpsUrl(issuer, "issuer");
  if (typeof audience !== "string" || !audience) {
    throw new Error("createJwtVerifier requires a non-empty audience");
  }
  const jwksUrl = parseHttpsUrl(jwksUri, "jwksUri");
  if (jwksUrl.hostname.toLowerCase() !== issuerUrl.hostname.toLowerCase()) {
    throw new Error("jwksUri host must equal the issuer host (single-origin issuers only in 0.8)");
  }
  if (isBlockedAddress(jwksUrl.hostname)) {
    throw new Error("jwksUri host resolves to a blocked (private/loopback/link-local/metadata) address");
  }
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new Error("algorithms must be a non-empty array");
  }
  for (const alg of algorithms) {
    if (!Object.prototype.hasOwnProperty.call(SUPPORTED, alg)) {
      throw new Error(`Unsupported or unsafe algorithm: ${alg} (allowed: ${Object.keys(SUPPORTED).join(", ")})`);
    }
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > MAX_CLOCK_SKEW_SECONDS) {
    throw new Error(`clockSkewSeconds must be between 0 and ${MAX_CLOCK_SKEW_SECONDS}`);
  }
  const algorithmSet = new Set(algorithms);
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new Error("global fetch is unavailable; pass fetchImpl");
  }

  // ---- JWKS cache (bounded + cooldown) ----
  let cache = { keysByKid: new Map(), fetchedAt: 0 };
  let lastRefetchAt = 0;
  let inflight = null;

  async function fetchJwks() {
    // SSRF: resolve the host and refuse if any address is blocked (catches a
    // hostname that maps to a private/metadata IP). Residual DNS-rebinding
    // between this check and the fetch is acceptable for a single-origin,
    // operator-configured jwksUri.
    const records = await lookupImpl(jwksUrl.hostname, { all: true });
    for (const { address } of records) {
      if (isBlockedAddress(address)) {
        throw new Error("jwksUri resolved to a blocked address");
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), fetchTimeoutMs);
    let res;
    try {
      res = await doFetch(jwksUrl.href, { signal: controller.signal, redirect: "error" });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);

    // Bound the body to MAX_JWKS_BYTES while reading.
    const reader = res.body?.getReader?.();
    let text;
    if (reader) {
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_JWKS_BYTES) {
          await reader.cancel();
          throw new Error("JWKS response exceeds the size limit");
        }
        chunks.push(Buffer.from(value));
      }
      text = Buffer.concat(chunks).toString("utf8");
    } else {
      // Fallback for a non-streaming fetchImpl (global fetch always provides a
      // reader, so the streaming branch above is the real path). Reject early on
      // a declared oversize before buffering, then re-check the actual bytes.
      const declared = Number(res.headers?.get?.("content-length"));
      if (Number.isFinite(declared) && declared > MAX_JWKS_BYTES) {
        throw new Error("JWKS response exceeds the size limit");
      }
      text = await res.text();
      if (Buffer.byteLength(text, "utf8") > MAX_JWKS_BYTES) {
        throw new Error("JWKS response exceeds the size limit");
      }
    }

    const jwks = parseJsonBounded(text);
    const keysByKid = new Map();
    for (const jwk of Array.isArray(jwks.keys) ? jwks.keys : []) {
      if (jwk && typeof jwk.kid === "string") keysByKid.set(jwk.kid, jwk);
    }
    cache = { keysByKid, fetchedAt: now() };
    return cache;
  }

  function refreshOnce() {
    if (!inflight) {
      inflight = fetchJwks().finally(() => { inflight = null; });
    }
    return inflight;
  }

  // Resolve a kid to a JWK with a SINGLE cooldown-gated refetch per call. ONE
  // rule governs every refetch trigger — stale cache, empty cache, and unknown
  // kid (rotation) — so neither a rotation nor an attacker flood can exceed one
  // JWKS fetch per cooldown, even when the cache is stale or the IdP is failing
  // (lastRefetchAt is set BEFORE the await, so a throwing fetch still burns the
  // cooldown — no fetch storm). A known kid is served from cache even if stale.
  async function resolveJwk(kid) {
    const fresh = now() - cache.fetchedAt < jwksTtlMs;
    if (cache.keysByKid.has(kid) && fresh) {
      return cache.keysByKid.get(kid);
    }
    const cooldownElapsed = cache.fetchedAt === 0 || now() - lastRefetchAt >= jwksCooldownMs;
    if (cooldownElapsed) {
      lastRefetchAt = now();
      await refreshOnce();
      if (cache.keysByKid.has(kid)) return cache.keysByKid.get(kid);
    }
    return cache.keysByKid.has(kid) ? cache.keysByKid.get(kid) : null;
  }

  function publicKeyFor(jwk, spec) {
    if (jwk.kty !== spec.kty) throw new Error("JWK kty does not match the algorithm");
    if (spec.crv && jwk.crv !== spec.crv) throw new Error("JWK crv does not match the algorithm");
    if (jwk.use && jwk.use !== "sig") throw new Error("JWK use is not 'sig'");
    if (Array.isArray(jwk.key_ops)) {
      if (jwk.key_ops.some((op) => op === "encrypt" || op === "decrypt")) {
        throw new Error("JWK key_ops include encrypt/decrypt");
      }
      if (!jwk.key_ops.some((op) => op === "verify" || op === "sign")) {
        throw new Error("JWK key_ops do not include verify/sign");
      }
    }
    if (spec.kty === "RSA") {
      const bits = rsaModulusBits(jwk);
      if (bits < MIN_RSA_MODULUS_BITS) {
        throw new Error(`RSA modulus ${bits} bits is below the ${MIN_RSA_MODULUS_BITS}-bit floor`);
      }
    }
    return createPublicKey({ key: jwk, format: "jwk" });
  }

  function verifySignature(alg, spec, signingInput, signature, key) {
    const data = Buffer.from(signingInput, "utf8");
    const keyArg = spec.dsaEncoding ? { key, dsaEncoding: spec.dsaEncoding } : key;
    return cryptoVerify(spec.digest, data, keyArg, signature);
  }

  function audienceMatches(aud) {
    if (typeof aud === "string") return aud === audience;
    // RFC 7519: aud is a string or an array OF STRINGS — reject a heterogeneous
    // array (defence-in-depth; a spec-violating token never authenticates).
    if (Array.isArray(aud)) return aud.every((a) => typeof a === "string") && aud.includes(audience);
    return false;
  }

  return {
    // verify(jwt, { expectedNonce } = {}) — the same work authenticate() does
    // between parsing the JWT string and building the identity. Returns the
    // validated claims OBJECT on success, or null on ANY failure (fail-closed:
    // the whole body is wrapped so malformed base64url / fetch failures deny).
    async verify(jwt, { expectedNonce } = {}) {
      try {
        const parts = String(jwt).split(".");
        if (parts.length !== 3) return null;
        const [h, p, s] = parts;

        const head = parseJsonBounded(decodeBase64UrlStrict(h).toString("utf8"));
        if (head.typ && String(head.typ).toUpperCase() !== "JWT") return null; // reject JWE/other
        if (typeof head.alg !== "string" || !algorithmSet.has(head.alg)) return null; // none/HS*/unlisted
        if (typeof head.kid !== "string" || !head.kid) return null; // kid required
        const spec = SUPPORTED[head.alg];

        const signature = decodeBase64UrlStrict(s);
        const claims = parseJsonBounded(decodeBase64UrlStrict(p).toString("utf8"));

        const jwk = await resolveJwk(head.kid);
        if (!jwk) return null;
        const key = publicKeyFor(jwk, spec);
        if (!verifySignature(head.alg, spec, `${h}.${p}`, signature, key)) return null;

        // ---- claim validation (all mandatory) ----
        if (claims.iss !== issuer) return null;
        if (!audienceMatches(claims.aud)) return null;
        if (typeof claims.sub !== "string" || !claims.sub.trim()) return null;
        const t = now() / 1000;
        if (typeof claims.exp !== "number" || t > claims.exp + clockSkewSeconds) return null;
        if (typeof claims.nbf !== "number" || t < claims.nbf - clockSkewSeconds) return null;
        if (claims.iat !== undefined && (typeof claims.iat !== "number" || claims.iat - clockSkewSeconds > t)) return null;

        // ---- optional nonce (NOT part of the 0.8 bearer surface) ----
        // Only checked when the caller passes expectedNonce; the provider's
        // bearer path omits it, preserving 0.8 behavior exactly.
        if (expectedNonce !== undefined) {
          if (typeof claims.nonce !== "string" || claims.nonce !== expectedNonce) return null;
        }

        return claims;
      } catch {
        // Fail closed: any parse/verify error denies, with no detail.
        return null;
      }
    }
  };
}

// --- the provider ----------------------------------------------------------
//
// createJwtAuthProvider(options) is the authProvider contract reimplemented on
// top of createJwtVerifier. It keeps the cryptoProvider check FIRST (so its
// error still fires before any verifier-construction error), owns Bearer-header
// parsing + claim->identity mapping + the PII-safe identity build, and passes
// every other option through to the verifier. Observable behavior is UNCHANGED.
export function createJwtAuthProvider(options = {}) {
  const {
    cryptoProvider,
    claimMappings = {},
    allowedLabelKeys,
    ...verifierOptions
  } = options;

  // ---- construction-time validation (fail closed) ----
  // cryptoProvider FIRST so this error still fires before any verifier error.
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("createJwtAuthProvider requires a cryptoProvider with hmac() (for a PII-safe identity)");
  }

  const verifier = createJwtVerifier(verifierOptions);

  const scopeClaim = claimMappings.scope || "scope";
  const typeClaim = claimMappings.type || null;
  const labelMap = claimMappings.labels && typeof claimMappings.labels === "object" ? claimMappings.labels : {};

  function claimType(claims) {
    if (!typeClaim) return "user";
    const raw = claims[typeClaim];
    return typeof raw === "string" ? raw : "user";
  }

  function claimScopes(claims) {
    const raw = claims[scopeClaim];
    if (Array.isArray(raw)) return raw.filter((s) => typeof s === "string" && s.trim());
    if (typeof raw === "string") return raw.split(/\s+/).filter(Boolean);
    return [];
  }

  function claimLabels(claims) {
    const labels = {};
    for (const [labelKey, claimKey] of Object.entries(labelMap)) {
      const v = claims[claimKey];
      if (typeof v === "string" && v) labels[labelKey] = v;
    }
    return labels;
  }

  return {
    id: "haechi.auth.jwt",
    async authenticate(request) {
      try {
        const header = request?.headers?.authorization ?? request?.headers?.Authorization;
        if (typeof header !== "string") return null;
        const m = /^Bearer\s+(.+)$/i.exec(header.trim());
        if (!m) return null;
        const jwt = m[1].trim();

        // No expectedNonce — a bearer JWT has none; preserves 0.8 behavior.
        const claims = await verifier.verify(jwt);
        if (!claims) return null;

        return await buildExternalIdentity(
          {
            provider: "jwt",
            subject: claims.sub,
            issuer: claims.iss,
            type: claimType(claims),
            scopes: claimScopes(claims),
            labels: claimLabels(claims),
            ...(allowedLabelKeys ? { allowedLabelKeys } : {})
          },
          cryptoProvider
        );
      } catch {
        // Fail closed: any parse/verify/identity error denies, with no detail.
        return null;
      }
    }
  };
}
