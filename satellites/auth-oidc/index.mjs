// haechi-auth-oidc — interactive OIDC session broker (authorization-code + PKCE).
//
// This is the dashboard's human-login mechanism: it implements the OIDC
// authorization-code flow with PKCE, produces an opaque server-side session,
// and satisfies the dashboard's sessionGuard contract
//   { authenticate(req) -> session|null,
//     handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }.
// It is NOT a per-request bearer validator — that role stays with
// haechi-auth-jwt. See docs/current/release-0.9-implementation-scope.md §2.2.
//
// Zero runtime dependency: node: builtins + the "haechi/*" and "haechi-auth-jwt"
// peer imports only. Every security decision below is a DECISION, not
// implementation discretion (§7.3 maps each to an acceptance criterion):
//   - SSRF-hardened discovery + per-egress post-DNS isBlockedAddress re-check.
//   - state-first short-circuit at /auth/callback (no IdP round-trip on a state
//     failure), atomic take() pending store, PKCE S256, nonce binding.
//   - OIDC ID-token aud/azp profile layered on the shared JWS verifier.
//   - fresh CSPRNG session id at callback (no fixation), two hardened cookies.
//   - PII-safe identity via core's buildExternalIdentity; the broker emits only
//     *Hash/reasonCode/provider/timestamp audit events (allowlist projection).
//   - the access token is DISCARDED (never stored/used).

import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";

import { buildExternalIdentity } from "haechi/auth";
import { createJwtVerifier, isBlockedAddress } from "haechi-auth-jwt";

// --- constants (decisions) -------------------------------------------------

const IDENTITY_PROVIDER = "oidc";
const PREAUTH_COOKIE = "__Host-haechi_preauth";
const SESSION_COOKIE = "__Host-haechi_session";
// Off-loopback-plaintext (an explicit, documented opt-in) drops the __Host-
// prefix because __Host- requires Secure, which a plaintext listener can't set.
const PREAUTH_COOKIE_INSECURE = "haechi_preauth";
const SESSION_COOKIE_INSECURE = "haechi_session";

const SESSION_ID_BYTES = 32;          // >= 256-bit opaque session id
const STATE_BYTES = 32;
const NONCE_BYTES = 32;
const CODE_VERIFIER_BYTES = 32;       // 32 bytes -> 43-char base64url verifier
const PREAUTH_ID_BYTES = 32;

const SESSION_ID_HASH_DOMAIN = "haechi:oidc:session-id:hash:v1";

const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;   // 8h absolute
const DEFAULT_IDLE_TTL_SECONDS = 30 * 60;          // 30m idle
const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;         // 30d ceiling
const DEFAULT_PENDING_TTL_SECONDS = 600;           // 10m to complete a login
const DEFAULT_PENDING_CAP = 1024;                  // hard pending-auth cap
const DEFAULT_RATE_MAX = 60;                       // /auth/login+/auth/callback per source per window
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_KEYS = 4096;

const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const MAX_DISCOVERY_BYTES = 1024 * 1024;           // 1 MiB
const MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024;      // 1 MiB

const DEFAULT_ALGORITHMS = ["RS256", "ES256"];
const VALID_AUTH_METHODS = new Set(["client_secret_basic", "client_secret_post"]);

// Coarse reasonCode enum — NEVER a free-form string (no IdP detail echoed).
const REASON = {
  state_mismatch: "state_mismatch",
  nonce_mismatch: "nonce_mismatch",
  token_invalid: "token_invalid",
  exchange_failed: "exchange_failed",
  host_blocked: "host_blocked",
  expired: "expired"
};

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

function isLoopbackHostname(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost") return true;
  if (h === "::1") return true;
  if (h === "::ffff:127.0.0.1") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

function base64UrlSha256(input) {
  return createHash("sha256").update(input).digest("base64url");
}

function randomToken(bytes) {
  return randomBytes(bytes).toString("base64url");
}

// Constant-time string comparison that never short-circuits on length.
function constantTimeEqual(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  if (ba.length !== bb.length) {
    // Still do a compare against self to avoid a trivial timing oracle on length;
    // the result is forced false.
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

// Parse a Cookie header into a Map name->value (last value wins, RFC 6265-ish).
function parseCookies(header) {
  const out = new Map();
  if (typeof header !== "string" || header.length === 0) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) out.set(name, value);
  }
  return out;
}

// --- default in-memory stores (atomic take() contract) ---------------------

// pendingStore: keyed by the pre-auth cookie id. take() is consume-and-delete
// (single-use under concurrency). A HARD cap rejects NEW logins when full and
// NEVER evicts an in-flight auth (fail-closed against pending exhaustion).
export function createInMemoryPendingStore({ cap = DEFAULT_PENDING_CAP } = {}) {
  const map = new Map();
  return {
    // set returns false when the store is at the hard cap (after pruning
    // expired records). The caller must then reject the /auth/login.
    set(key, record, { now }) {
      // prune expired before measuring capacity.
      for (const [k, v] of map) {
        if (v.expiresAt <= now) map.delete(k);
      }
      if (!map.has(key) && map.size >= cap) {
        return false;
      }
      map.set(key, record);
      return true;
    },
    // ATOMIC take: returns the record and deletes it in the same call. A
    // concurrent replay finds nothing. Returns null on miss/expiry.
    take(key, { now }) {
      const record = map.get(key);
      if (!record) return null;
      map.delete(key);
      if (record.expiresAt <= now) return null;
      return record;
    },
    size() {
      return map.size;
    }
  };
}

// sessionStore: opaque-id -> session. Absolute + idle TTL enforced by the broker.
export function createInMemorySessionStore() {
  const map = new Map();
  return {
    set(id, session) {
      map.set(id, session);
    },
    get(id) {
      return map.get(id) ?? null;
    },
    delete(id) {
      return map.delete(id);
    },
    size() {
      return map.size;
    }
  };
}

// Satellite-local fixed-window rate limiter (proxy's createRateLimiter is
// private — same DEVIATION the dashboard documents). Per-source 60s window.
function createRateLimiter({ max = DEFAULT_RATE_MAX, windowMs = RATE_WINDOW_MS, maxKeys = RATE_MAX_KEYS } = {}) {
  const buckets = new Map();
  function prune(now) {
    for (const [key, bucket] of buckets) {
      if (now >= bucket.resetAt) buckets.delete(key);
    }
    if (buckets.size >= maxKeys) {
      for (const key of buckets.keys()) {
        if (buckets.size < maxKeys) break;
        buckets.delete(key);
      }
    }
  }
  return {
    allow(key) {
      const now = Date.now();
      const bucket = buckets.get(key);
      if (!bucket || now >= bucket.resetAt) {
        if (!buckets.has(key)) prune(now);
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }
      if (bucket.count >= max) return false;
      bucket.count += 1;
      return true;
    }
  };
}

// ---------------------------------------------------------------------------
// normalizeOidcConfig — strict, fail-closed, enumerated throws.
// Unknown keys rejected; stable messages.
// ---------------------------------------------------------------------------

const KNOWN_KEYS = new Set([
  "cryptoProvider",
  "issuer",
  "clientId",
  "clientSecret",
  "redirectUri",
  "scopes",
  "returnToAllowlist",
  "trustedEndpointHosts",
  "sessionTtlSeconds",
  "idleTtlSeconds",
  "maxAgeSeconds",
  "tokenEndpointAuthMethod",
  "secureCookies",
  "trustProxy",
  "algorithms",
  "clockSkewSeconds",
  "prompt",
  "pendingTtlSeconds",
  "pendingCap",
  "rateLimitMax",
  "fetchTimeoutMs",
  "fetchImpl",
  "lookupImpl",
  "now",
  "sessionStore",
  "pendingStore",
  "auditSink"
]);

function boundedIntField(value, label, { min, max, def }) {
  if (value === undefined) return def;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`normalizeOidcConfig '${label}' must be an integer in [${min},${max}]`);
  }
  return value;
}

export function normalizeOidcConfig(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new Error("oidc config must be an object");
  }
  for (const key of Object.keys(options)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new Error(`Unknown oidc config option: ${key}`);
    }
  }

  // cryptoProvider.hmac required (no PII-safe identity / sessionIdHash without it).
  const cryptoProvider = options.cryptoProvider;
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("normalizeOidcConfig requires a cryptoProvider with hmac() (for a PII-safe identity)");
  }

  // issuer: valid HTTPS URL.
  if (typeof options.issuer !== "string" || !options.issuer) {
    throw new Error("normalizeOidcConfig requires an issuer");
  }
  const issuerUrl = parseHttpsUrl(options.issuer, "issuer");
  // Normalize the issuer string for the string-equality discovery check: drop a
  // trailing slash difference is NOT applied (OIDC requires exact string-equal),
  // so keep the configured string verbatim.
  const issuer = options.issuer;

  // clientId: non-empty string.
  if (typeof options.clientId !== "string" || !options.clientId.trim()) {
    throw new Error("normalizeOidcConfig requires a non-empty clientId");
  }
  const clientId = options.clientId;

  // clientSecret: optional string. Present => confidential client.
  let clientSecret = null;
  if (options.clientSecret !== undefined && options.clientSecret !== null) {
    if (typeof options.clientSecret !== "string" || options.clientSecret.length === 0) {
      throw new Error("normalizeOidcConfig 'clientSecret' must be a non-empty string or omitted");
    }
    clientSecret = options.clientSecret;
  }
  const isConfidential = clientSecret !== null;

  // tokenEndpointAuthMethod: never "none" for a confidential client.
  let tokenEndpointAuthMethod = "client_secret_basic";
  if (options.tokenEndpointAuthMethod !== undefined) {
    if (!VALID_AUTH_METHODS.has(options.tokenEndpointAuthMethod)) {
      throw new Error(
        `normalizeOidcConfig 'tokenEndpointAuthMethod' must be one of ${[...VALID_AUTH_METHODS].join(", ")}`
      );
    }
    tokenEndpointAuthMethod = options.tokenEndpointAuthMethod;
  }
  if (!isConfidential && options.tokenEndpointAuthMethod !== undefined) {
    // A public (PKCE-only) client does not authenticate at the token endpoint.
    throw new Error(
      "normalizeOidcConfig 'tokenEndpointAuthMethod' is only valid for a confidential client (provide clientSecret)"
    );
  }

  // cookie hardening keyed off the EXTERNALLY-VISIBLE scheme.
  // secureCookies: true | 'auto' (default 'auto'). trustProxy optional string.
  let secureCookies = "auto";
  if (options.secureCookies !== undefined) {
    if (options.secureCookies !== true && options.secureCookies !== false && options.secureCookies !== "auto") {
      throw new Error("normalizeOidcConfig 'secureCookies' must be true, false, or 'auto'");
    }
    secureCookies = options.secureCookies;
  }
  let trustProxy = null;
  if (options.trustProxy !== undefined && options.trustProxy !== null) {
    if (typeof options.trustProxy !== "string" || options.trustProxy.trim().length === 0) {
      throw new Error("normalizeOidcConfig 'trustProxy' must be a non-empty string (a trusted-proxy address) or null");
    }
    trustProxy = options.trustProxy.trim();
  }

  // redirectUri: absolute URL, https (or loopback http under the carve-out),
  // same-origin with the broker, path === "/auth/callback".
  if (typeof options.redirectUri !== "string" || !options.redirectUri) {
    throw new Error("normalizeOidcConfig requires a redirectUri");
  }
  let redirectUrl;
  try {
    redirectUrl = new URL(options.redirectUri);
  } catch {
    throw new Error("normalizeOidcConfig 'redirectUri' must be a valid absolute URL");
  }
  const redirectIsHttps = redirectUrl.protocol === "https:";
  const redirectIsLoopbackHttp = redirectUrl.protocol === "http:" && isLoopbackHostname(redirectUrl.hostname);
  if (!redirectIsHttps && !redirectIsLoopbackHttp) {
    throw new Error("normalizeOidcConfig 'redirectUri' must be https (or loopback http under the carve-out)");
  }
  if (redirectUrl.pathname !== "/auth/callback") {
    throw new Error("normalizeOidcConfig 'redirectUri' path must be '/auth/callback' (the mounted callback)");
  }
  const brokerOrigin = redirectUrl.origin;

  // off-loopback without declared https => fail closed (a Secure/__Host- cookie
  // can't be sent over plaintext, so login silently breaks).
  const redirectLoopback = isLoopbackHostname(redirectUrl.hostname);
  // trustProxy !== null means a TLS-terminating reverse proxy fronts this broker,
  // so the externally-visible (browser-facing) scheme is https even when the
  // redirectUri is http-loopback. Fold it into the cookie-hardening decision.
  const secureScheme = redirectIsHttps || secureCookies === true || trustProxy !== null;
  if (!secureScheme && !redirectLoopback) {
    throw new Error(
      "normalizeOidcConfig: an off-loopback broker requires confirmed HTTPS (https redirectUri or secureCookies:true); " +
        "a Secure/__Host- session cookie is never sent over plaintext http"
    );
  }

  // scopes: array; force-include "openid" (dedup); strip "offline_access".
  let scopesInput = ["openid"];
  if (options.scopes !== undefined) {
    if (!Array.isArray(options.scopes) || !options.scopes.every((s) => typeof s === "string" && s.trim())) {
      throw new Error("normalizeOidcConfig 'scopes' must be an array of non-empty strings");
    }
    scopesInput = options.scopes;
  }
  const scopeSet = [];
  const seen = new Set();
  for (const s of ["openid", ...scopesInput]) {
    if (s === "offline_access") continue; // refresh out of scope
    if (seen.has(s)) continue;
    seen.add(s);
    scopeSet.push(s);
  }
  const scopes = scopeSet;

  // returnToAllowlist: relative same-origin paths (start "/", no scheme/host).
  let returnToAllowlist = ["/"];
  if (options.returnToAllowlist !== undefined) {
    if (!Array.isArray(options.returnToAllowlist)) {
      throw new Error("normalizeOidcConfig 'returnToAllowlist' must be an array of relative paths");
    }
    for (const p of options.returnToAllowlist) {
      if (typeof p !== "string" || !p.startsWith("/") || p.startsWith("//")) {
        throw new Error("normalizeOidcConfig 'returnToAllowlist' entries must be relative same-origin paths starting '/' (not '//')");
      }
      // Reject an embedded scheme/host.
      if (/^\/\\|:\/\//.test(p) || p.includes("\\")) {
        throw new Error("normalizeOidcConfig 'returnToAllowlist' entries must not contain a scheme/host");
      }
    }
    returnToAllowlist = options.returnToAllowlist.length > 0 ? options.returnToAllowlist : ["/"];
  }

  // trustedEndpointHosts: operator-PINNED allowlist of additional bare hostnames
  // permitted to serve this IdP's discovered endpoints (authorization/token/jwks/
  // end_session) when they differ from the issuer host — e.g. an Azure AD B2C /
  // Auth0 custom-domain whose issuer is https://login.contoso.com but whose
  // endpoints live on https://contoso.b2clogin.com. It RELAXES the same-host
  // discovery check ONLY (never https, never the per-egress SSRF re-check, never
  // the issuer-confusion guard) and is built EXCLUSIVELY from operator config —
  // never from discovery-document content — so an attacker controlling the
  // discovery doc cannot introduce a new host (mix-up defence stands). Symmetric
  // with PR-1's createJwtVerifier option. Empty/absent => today's strict
  // single-origin behavior (zero behavior change by default).
  let trustedEndpointHosts = [];
  if (options.trustedEndpointHosts !== undefined && options.trustedEndpointHosts !== null) {
    if (!Array.isArray(options.trustedEndpointHosts)) {
      throw new Error("normalizeOidcConfig 'trustedEndpointHosts' must be an array of bare hostnames");
    }
    const normalized = [];
    for (const entry of options.trustedEndpointHosts) {
      if (typeof entry !== "string" || !entry.trim()) {
        throw new Error("normalizeOidcConfig 'trustedEndpointHosts' entries must be a non-empty hostname string");
      }
      if (/[\s/:]/.test(entry) || entry.includes("://")) {
        throw new Error(
          "normalizeOidcConfig 'trustedEndpointHosts' entries must be a bare hostname (no scheme, path, port, or whitespace)"
        );
      }
      normalized.push(entry.toLowerCase());
    }
    trustedEndpointHosts = normalized;
  }

  // TTLs.
  const sessionTtlSeconds = boundedIntField(options.sessionTtlSeconds, "sessionTtlSeconds", {
    min: 1,
    max: MAX_TTL_SECONDS,
    def: DEFAULT_SESSION_TTL_SECONDS
  });
  const idleTtlSeconds = boundedIntField(options.idleTtlSeconds, "idleTtlSeconds", {
    min: 1,
    max: MAX_TTL_SECONDS,
    def: DEFAULT_IDLE_TTL_SECONDS
  });
  let maxAgeSeconds = null;
  if (options.maxAgeSeconds !== undefined && options.maxAgeSeconds !== null) {
    maxAgeSeconds = boundedIntField(options.maxAgeSeconds, "maxAgeSeconds", { min: 1, max: MAX_TTL_SECONDS, def: null });
  }

  // algorithms / clockSkew pass through to the verifier (validated there too).
  let algorithms = DEFAULT_ALGORITHMS;
  if (options.algorithms !== undefined) {
    if (!Array.isArray(options.algorithms) || options.algorithms.length === 0) {
      throw new Error("normalizeOidcConfig 'algorithms' must be a non-empty array");
    }
    algorithms = options.algorithms;
  }
  let clockSkewSeconds;
  if (options.clockSkewSeconds !== undefined) {
    if (!Number.isFinite(options.clockSkewSeconds) || options.clockSkewSeconds < 0 || options.clockSkewSeconds > 300) {
      throw new Error("normalizeOidcConfig 'clockSkewSeconds' must be between 0 and 300");
    }
    clockSkewSeconds = options.clockSkewSeconds;
  }

  let prompt = null;
  if (options.prompt !== undefined && options.prompt !== null) {
    if (typeof options.prompt !== "string" || !options.prompt.trim()) {
      throw new Error("normalizeOidcConfig 'prompt' must be a non-empty string or null");
    }
    prompt = options.prompt.trim();
  }

  const pendingTtlSeconds = boundedIntField(options.pendingTtlSeconds, "pendingTtlSeconds", {
    min: 1,
    max: 3600,
    def: DEFAULT_PENDING_TTL_SECONDS
  });
  const pendingCap = boundedIntField(options.pendingCap, "pendingCap", {
    min: 1,
    max: 1_000_000,
    def: DEFAULT_PENDING_CAP
  });
  const rateLimitMax = boundedIntField(options.rateLimitMax, "rateLimitMax", {
    min: 1,
    max: 1_000_000,
    def: DEFAULT_RATE_MAX
  });
  const fetchTimeoutMs = boundedIntField(options.fetchTimeoutMs, "fetchTimeoutMs", {
    min: 1,
    max: 120_000,
    def: DEFAULT_FETCH_TIMEOUT_MS
  });

  // Injectables: validated only for type when present.
  if (options.fetchImpl !== undefined && typeof options.fetchImpl !== "function") {
    throw new Error("normalizeOidcConfig 'fetchImpl' must be a function");
  }
  if (options.lookupImpl !== undefined && typeof options.lookupImpl !== "function") {
    throw new Error("normalizeOidcConfig 'lookupImpl' must be a function");
  }
  if (options.now !== undefined && typeof options.now !== "function") {
    throw new Error("normalizeOidcConfig 'now' must be a function");
  }
  if (options.sessionStore !== undefined && options.sessionStore !== null) {
    const s = options.sessionStore;
    if (typeof s.get !== "function" || typeof s.set !== "function" || typeof s.delete !== "function") {
      throw new Error("normalizeOidcConfig 'sessionStore' must implement get/set/delete");
    }
  }
  if (options.pendingStore !== undefined && options.pendingStore !== null) {
    const s = options.pendingStore;
    if (typeof s.set !== "function" || typeof s.take !== "function") {
      throw new Error("normalizeOidcConfig 'pendingStore' must implement set/take (atomic take)");
    }
  }
  if (options.auditSink !== undefined && options.auditSink !== null) {
    const a = options.auditSink;
    if (typeof a !== "function" && typeof a.record !== "function") {
      throw new Error("normalizeOidcConfig 'auditSink' must be a function or an object with record()");
    }
  }

  return {
    cryptoProvider,
    issuer,
    issuerUrl,
    clientId,
    clientSecret,
    isConfidential,
    redirectUri: options.redirectUri,
    redirectOrigin: brokerOrigin,
    scopes,
    returnToAllowlist,
    trustedEndpointHosts,
    sessionTtlSeconds,
    idleTtlSeconds,
    maxAgeSeconds,
    tokenEndpointAuthMethod,
    secureScheme,
    secureCookies,
    trustProxy,
    algorithms,
    clockSkewSeconds,
    prompt,
    pendingTtlSeconds,
    pendingCap,
    rateLimitMax,
    fetchTimeoutMs,
    fetchImpl: options.fetchImpl,
    lookupImpl: options.lookupImpl,
    now: options.now,
    sessionStore: options.sessionStore,
    pendingStore: options.pendingStore,
    auditSink: options.auditSink
  };
}

// ---------------------------------------------------------------------------
// The broker.
// ---------------------------------------------------------------------------

export function createOidcSessionBroker(options = {}) {
  const config = normalizeOidcConfig(options);
  const {
    cryptoProvider,
    issuer,
    issuerUrl,
    clientId,
    clientSecret,
    isConfidential,
    redirectUri,
    scopes,
    returnToAllowlist,
    trustedEndpointHosts,
    sessionTtlSeconds,
    idleTtlSeconds,
    maxAgeSeconds,
    tokenEndpointAuthMethod,
    secureScheme,
    algorithms,
    clockSkewSeconds,
    prompt,
    pendingTtlSeconds,
    fetchTimeoutMs
  } = config;

  const now = config.now || (() => Date.now());
  const lookupImpl = config.lookupImpl || dnsLookup;
  const doFetch = config.fetchImpl || globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new Error("global fetch is unavailable; pass fetchImpl");
  }
  const sessionStore = config.sessionStore || createInMemorySessionStore();
  const pendingStore = config.pendingStore || createInMemoryPendingStore({ cap: config.pendingCap });
  const rateLimiter = createRateLimiter({ max: config.rateLimitMax });

  const auditSinkRaw = config.auditSink;
  function emit(event) {
    if (!auditSinkRaw) return;
    try {
      if (typeof auditSinkRaw === "function") auditSinkRaw(event);
      else if (typeof auditSinkRaw.record === "function") auditSinkRaw.record(event);
    } catch {
      // never let audit emission break the flow.
    }
  }

  const cookieNames = secureScheme
    ? { preauth: PREAUTH_COOKIE, session: SESSION_COOKIE }
    : { preauth: PREAUTH_COOKIE_INSECURE, session: SESSION_COOKIE_INSECURE };

  // --- discovery (SSRF-hardened, cached) + verifier construction (lazy) ---

  let discovery = null;       // resolved metadata + endpoints
  let verifier = null;        // createJwtVerifier instance
  let discoveryInflight = null;

  // Operator-PINNED set of additional endpoint hosts (custom-domain IdPs). Built
  // ONLY from normalized config — never from discovery-document content — so a
  // compromised discovery doc cannot introduce a new host. Entries are already
  // validated + lowercased by normalizeOidcConfig. Empty => strict single-origin.
  const trustedHostSet = new Set(trustedEndpointHosts);

  async function guardedFetch(rawUrl, init, maxBytes) {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") {
      const e = new Error("egress must be https");
      e.reasonCode = REASON.host_blocked;
      throw e;
    }
    // Literal-host check first.
    if (isBlockedAddress(url.hostname)) {
      const e = new Error("egress host is a blocked address");
      e.reasonCode = REASON.host_blocked;
      throw e;
    }
    // Post-DNS re-check IMMEDIATELY before the request (rebinding guard).
    const records = await lookupImpl(url.hostname, { all: true });
    for (const { address } of records) {
      if (isBlockedAddress(address)) {
        const e = new Error("egress resolved to a blocked address");
        e.reasonCode = REASON.host_blocked;
        throw e;
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), fetchTimeoutMs);
    let res;
    try {
      res = await doFetch(url.href, { ...init, signal: controller.signal, redirect: "error" });
    } finally {
      clearTimeout(timer);
    }
    const text = await readBounded(res, maxBytes);
    return { res, text };
  }

  async function readBounded(res, maxBytes) {
    const reader = res.body?.getReader?.();
    if (reader) {
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new Error("response exceeds the size limit");
        }
        chunks.push(Buffer.from(value));
      }
      return Buffer.concat(chunks).toString("utf8");
    }
    const declared = Number(res.headers?.get?.("content-length"));
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new Error("response exceeds the size limit");
    }
    const t = await res.text();
    if (Buffer.byteLength(t, "utf8") > maxBytes) {
      throw new Error("response exceeds the size limit");
    }
    return t;
  }

  function sameIssuerHost(endpoint, label) {
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error(`discovery ${label} is not a valid URL`);
    }
    if (url.protocol !== "https:") {
      throw new Error(`discovery ${label} must be https`);
    }
    // The host must equal the issuer host OR be an operator-pinned
    // trustedEndpointHosts entry (custom-domain IdPs). The https requirement
    // above and the per-egress SSRF re-check in guardedFetch ALWAYS run — the
    // allowlist relaxes ONLY this string-equality check, never those guards.
    const host = url.hostname.toLowerCase();
    if (host !== issuerUrl.hostname.toLowerCase() && !trustedHostSet.has(host)) {
      throw new Error(`discovery ${label} host must equal the issuer host or be listed in trustedEndpointHosts`);
    }
    return url.href;
  }

  async function discover() {
    if (discovery) return discovery;
    if (discoveryInflight) return discoveryInflight;
    discoveryInflight = (async () => {
      const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
      const url = `${base}/.well-known/openid-configuration`;
      const { res, text } = await guardedFetch(url, { method: "GET" }, MAX_DISCOVERY_BYTES);
      if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
      let metadata;
      try {
        metadata = JSON.parse(text);
      } catch {
        throw new Error("discovery document is not valid JSON");
      }
      // issuer-confusion guard: metadata.issuer MUST string-equal the config issuer.
      if (metadata.issuer !== issuer) {
        throw new Error("discovery metadata.issuer does not equal the configured issuer");
      }
      const authorizationEndpoint = sameIssuerHost(metadata.authorization_endpoint, "authorization_endpoint");
      const tokenEndpoint = sameIssuerHost(metadata.token_endpoint, "token_endpoint");
      const jwksUri = sameIssuerHost(metadata.jwks_uri, "jwks_uri");
      let endSessionEndpoint = null;
      if (metadata.end_session_endpoint !== undefined && metadata.end_session_endpoint !== null) {
        endSessionEndpoint = sameIssuerHost(metadata.end_session_endpoint, "end_session_endpoint");
      }

      // Assert the configured auth method is supported and never downgrade a
      // confidential client to "none".
      if (isConfidential && Array.isArray(metadata.token_endpoint_auth_methods_supported)) {
        const supported = metadata.token_endpoint_auth_methods_supported;
        if (!supported.includes(tokenEndpointAuthMethod)) {
          throw new Error(`discovery token_endpoint does not support ${tokenEndpointAuthMethod}`);
        }
      }

      verifier = createJwtVerifier({
        issuer,
        audience: clientId,
        jwksUri,
        // Thread the SAME operator-pinned allowlist (PR-1 added this option) so a
        // custom-domain JWKS host is accepted by the shared verifier too. The
        // verifier still applies its own https + SSRF guards independently.
        trustedEndpointHosts,
        algorithms,
        ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
        fetchImpl: doFetch,
        lookupImpl,
        now
      });

      discovery = { authorizationEndpoint, tokenEndpoint, jwksUri, endSessionEndpoint };
      return discovery;
    })().finally(() => {
      discoveryInflight = null;
    });
    return discoveryInflight;
  }

  // --- cookie + response helpers ---

  function cookieAttrs(extra = {}) {
    // __Host- requires Secure + Path=/ + no Domain. SameSite=Lax so the IdP
    // top-level GET to /auth/callback carries the cookie. HttpOnly always.
    const parts = ["Path=/", "HttpOnly", "SameSite=Lax"];
    if (secureScheme) parts.push("Secure");
    if (extra.maxAge !== undefined) parts.push(`Max-Age=${extra.maxAge}`);
    return parts.join("; ");
  }

  function setCookie(res, name, value, extra) {
    appendSetCookie(res, `${name}=${value}; ${cookieAttrs(extra)}`);
  }

  function clearCookie(res, name) {
    appendSetCookie(res, `${name}=; ${cookieAttrs({ maxAge: 0 })}`);
  }

  function appendSetCookie(res, cookie) {
    const existing = res.getHeader ? res.getHeader("Set-Cookie") : undefined;
    if (existing === undefined) {
      res.setHeader("Set-Cookie", [cookie]);
    } else if (Array.isArray(existing)) {
      res.setHeader("Set-Cookie", [...existing, cookie]);
    } else {
      res.setHeader("Set-Cookie", [existing, cookie]);
    }
  }

  function redirect(res, location) {
    res.statusCode = 302;
    res.setHeader("Location", location);
    res.setHeader("Cache-Control", "no-store");
    res.end();
  }

  // Identical generic deny for EVERY callback failure (no IdP detail echoed).
  function denyCallback(res) {
    res.statusCode = 401;
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ error: "unauthorized" }));
  }

  function sourceKey(req) {
    return (req.socket && req.socket.remoteAddress) || (req.headers && req.headers["x-forwarded-for"]) || "unknown";
  }

  async function sessionIdHash(sessionId) {
    return cryptoProvider.hmac({ data: sessionId, domain: SESSION_ID_HASH_DOMAIN });
  }

  // --- /auth/login ---

  async function handleLogin(req, res) {
    if (!rateLimiter.allow(sourceKey(req))) {
      res.statusCode = 429;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }
    let meta;
    try {
      meta = await discover();
    } catch (error) {
      emit(buildEvent("oidc.login.failure", { reasonCode: error?.reasonCode || REASON.exchange_failed }));
      // generic deny
      res.statusCode = 503;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "unavailable" }));
      return;
    }

    const state = randomToken(STATE_BYTES);
    const nonce = randomToken(NONCE_BYTES);
    const codeVerifier = randomToken(CODE_VERIFIER_BYTES);
    const codeChallenge = base64UrlSha256(codeVerifier);
    const preauthId = randomToken(PREAUTH_ID_BYTES);
    const createdAt = now();

    const record = {
      state,
      nonce,
      codeVerifier,
      issuer,
      tokenEndpoint: meta.tokenEndpoint,
      jwksUri: meta.jwksUri,
      createdAt,
      expiresAt: createdAt + pendingTtlSeconds * 1000
    };

    const stored = pendingStore.set(preauthId, record, { now: createdAt });
    if (!stored) {
      // Hard pending cap reached — reject the NEW login, NEVER evict in-flight.
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.exchange_failed }));
      res.statusCode = 429;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }

    setCookie(res, cookieNames.preauth, preauthId, { maxAge: pendingTtlSeconds });

    const authUrl = new URL(meta.authorizationEndpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("scope", scopes.join(" "));
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    if (maxAgeSeconds !== null) authUrl.searchParams.set("max_age", String(maxAgeSeconds));
    if (prompt !== null) authUrl.searchParams.set("prompt", prompt);

    emit(buildEvent("oidc.login.start", {}));
    redirect(res, authUrl.href);
  }

  // --- /auth/callback ---

  async function handleCallback(req, res) {
    if (!rateLimiter.allow(sourceKey(req))) {
      res.statusCode = 429;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "rate_limited" }));
      return;
    }

    let url;
    try {
      url = new URL(req.url || "/", "http://placeholder");
    } catch {
      denyCallback(res);
      return;
    }
    const query = url.searchParams;
    const cookies = parseCookies(req.headers?.cookie);
    const preauthId = cookies.get(cookieNames.preauth);

    // STATE-FIRST SHORT-CIRCUIT: atomic take(), assert state BEFORE any egress.
    // A missing/used/mismatched state or missing pre-auth cookie -> generic deny,
    // NO IdP round-trip.
    if (!preauthId) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.state_mismatch }));
      clearCookie(res, cookieNames.preauth);
      denyCallback(res);
      return;
    }
    const record = pendingStore.take(preauthId, { now: now() });
    // Always clear the (single-use) pre-auth cookie on any callback outcome.
    clearCookie(res, cookieNames.preauth);
    if (!record) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.state_mismatch }));
      denyCallback(res);
      return;
    }
    const stateParam = query.get("state");
    if (typeof stateParam !== "string" || !constantTimeEqual(stateParam, record.state)) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.state_mismatch }));
      denyCallback(res);
      return;
    }

    // RFC 9207: an iss param on the callback (if present) must equal the pinned issuer.
    const callbackIss = query.get("iss");
    if (callbackIss !== null && callbackIss !== issuer) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    const code = query.get("code");
    if (typeof code !== "string" || !code) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.exchange_failed }));
      denyCallback(res);
      return;
    }

    // --- token exchange at the PINNED token endpoint ---
    let tokenResponse;
    try {
      tokenResponse = await exchangeCode(record, code);
    } catch (error) {
      emit(buildEvent("oidc.login.failure", { reasonCode: error?.reasonCode || REASON.exchange_failed }));
      denyCallback(res);
      return;
    }

    // RFC 9207: an iss in the token response must equal the pinned issuer.
    if (typeof tokenResponse.iss === "string" && tokenResponse.iss !== issuer) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    const idToken = tokenResponse.id_token;
    if (typeof idToken !== "string" || !idToken) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    // --- verify the ID token (shared verifier + nonce) ---
    let claims;
    try {
      claims = await verifier.verify(idToken, { expectedNonce: record.nonce });
    } catch {
      claims = null;
    }
    if (!claims) {
      // Distinguish a nonce miss only for the audit reasonCode (NOT the response).
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    // --- OIDC ID-token aud/azp profile (layered on the verified claims) ---
    if (!oidcAudienceProfileOk(claims)) {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    // max_age -> require auth_time and (now - auth_time) <= maxAge + skew.
    if (maxAgeSeconds !== null) {
      const skew = clockSkewSeconds ?? 60;
      const nowS = now() / 1000;
      if (typeof claims.auth_time !== "number" || nowS - claims.auth_time > maxAgeSeconds + skew) {
        emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
        denyCallback(res);
        return;
      }
    }

    // --- success: DISCARD the access token; mint a fresh session id ---
    let identity;
    try {
      identity = await buildExternalIdentity(
        {
          provider: IDENTITY_PROVIDER,
          subject: claims.sub,
          issuer: claims.iss,
          type: "user",
          scopes: [],
          labels: {}
        },
        cryptoProvider
      );
    } catch {
      emit(buildEvent("oidc.login.failure", { reasonCode: REASON.token_invalid }));
      denyCallback(res);
      return;
    }

    const sessionId = randomToken(SESSION_ID_BYTES);
    const createdAt = now();
    sessionStore.set(sessionId, { identity, createdAt, lastSeen: createdAt });

    setCookie(res, cookieNames.session, sessionId, {});

    const sidHash = await sessionIdHash(sessionId);
    emit(buildEvent("oidc.login.success", { identity, sessionIdHash: sidHash }));

    // return_to validated against the allowlist (relative same-origin only).
    const returnTo = resolveReturnTo(query.get("return_to"));
    redirect(res, returnTo);
  }

  function oidcAudienceProfileOk(claims) {
    const aud = claims.aud;
    if (typeof aud === "string") {
      return aud === clientId;
    }
    if (Array.isArray(aud)) {
      if (!aud.every((a) => typeof a === "string")) return false;
      if (!aud.includes(clientId)) return false;
      // multi-valued aud => azp MUST be present and === clientId.
      if (aud.length > 1) {
        if (typeof claims.azp !== "string" || claims.azp !== clientId) return false;
      }
      return true;
    }
    return false;
  }

  async function exchangeCode(record, code) {
    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", redirectUri); // IDENTICAL redirect_uri as on authorize
    body.set("code_verifier", record.codeVerifier);
    body.set("client_id", clientId);

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    };

    if (isConfidential) {
      if (tokenEndpointAuthMethod === "client_secret_basic") {
        const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`, "utf8").toString(
          "base64"
        );
        headers.Authorization = `Basic ${basic}`;
      } else {
        // client_secret_post — secret in the body, NEVER the URL/query.
        body.set("client_secret", clientSecret);
      }
    }

    const { res, text } = await guardedFetch(
      record.tokenEndpoint,
      { method: "POST", headers, body: body.toString() },
      MAX_TOKEN_RESPONSE_BYTES
    );
    if (!res.ok) {
      const e = new Error("token exchange failed");
      e.reasonCode = REASON.exchange_failed;
      throw e;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      const e = new Error("token response is not valid JSON");
      e.reasonCode = REASON.exchange_failed;
      throw e;
    }
    return parsed;
  }

  function resolveReturnTo(raw) {
    if (typeof raw !== "string" || raw.length === 0) return "/";
    // Must be relative same-origin: start with a single "/", no scheme/host,
    // no protocol-relative "//", no backslash.
    if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/";
    if (/:\/\//.test(raw)) return "/";
    // Compare the PATH against the allowlist (ignore query/fragment for matching).
    let pathOnly = raw;
    const q = raw.search(/[?#]/);
    if (q !== -1) pathOnly = raw.slice(0, q);
    if (returnToAllowlist.includes(pathOnly) || returnToAllowlist.includes(raw)) {
      return raw;
    }
    return "/";
  }

  // --- /auth/logout ---

  async function handleLogout(req, res) {
    // NON-GET; require a non-simple custom header (proves a same-origin fetch).
    const method = (req.method || "GET").toUpperCase();
    const csrfHeader = req.headers?.["x-haechi-csrf"];
    if (method === "GET" || method === "HEAD" || csrfHeader === undefined) {
      res.statusCode = 403;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "forbidden" }));
      return;
    }

    const cookies = parseCookies(req.headers?.cookie);
    const sessionId = cookies.get(cookieNames.session);
    let idTokenHint = null;
    let sidHash = null;
    if (sessionId) {
      const session = sessionStore.get(sessionId);
      if (session) {
        sidHash = await sessionIdHash(sessionId);
        idTokenHint = session.idTokenHint || null;
      }
      // Destroy the server-side session (replaying the cookie yields nothing).
      sessionStore.delete(sessionId);
    }
    clearCookie(res, cookieNames.session);

    emit(buildEvent("oidc.logout", sidHash ? { sessionIdHash: sidHash } : {}));

    // Optional RP-initiated logout to an allowlisted post_logout_redirect_uri.
    let postLogout = null;
    try {
      const url = new URL(req.url || "/", "http://placeholder");
      postLogout = url.searchParams.get("post_logout_redirect_uri");
    } catch {
      postLogout = null;
    }
    if (postLogout !== null) {
      const safe = resolveReturnTo(postLogout);
      // An off-allowlist post_logout_redirect_uri is REFUSED (no open-redirect):
      // resolveReturnTo collapses anything off-allowlist to "/" — treat that as
      // a refusal of the supplied value (do not honor it) unless it was "/".
      if (safe === postLogout) {
        // honor an allowlisted relative path (optionally via end_session_endpoint).
        if (discovery && discovery.endSessionEndpoint && idTokenHint) {
          const endUrl = new URL(discovery.endSessionEndpoint);
          endUrl.searchParams.set("id_token_hint", idTokenHint);
          endUrl.searchParams.set("state", randomToken(STATE_BYTES));
          endUrl.searchParams.set("post_logout_redirect_uri", postLogout);
          redirect(res, endUrl.href);
          return;
        }
        redirect(res, safe);
        return;
      }
      // Off-allowlist -> refuse: respond 400 rather than redirecting anywhere
      // attacker-chosen.
      res.statusCode = 400;
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "bad_request" }));
      return;
    }

    res.statusCode = 200;
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ status: "logged_out" }));
  }

  // --- authenticate(req) -> session|null (read-only; never throws) ---

  async function authenticate(req) {
    try {
      const cookies = parseCookies(req?.headers?.cookie);
      const sessionId = cookies.get(cookieNames.session);
      if (!sessionId) return null;
      const session = sessionStore.get(sessionId);
      if (!session) return null;
      const t = now();
      const absoluteExpiry = session.createdAt + sessionTtlSeconds * 1000;
      const idleExpiry = session.lastSeen + idleTtlSeconds * 1000;
      if (t >= absoluteExpiry || t >= idleExpiry) {
        sessionStore.delete(sessionId);
        const sidHash = await sessionIdHash(sessionId).catch(() => null);
        emit(buildEvent("oidc.session.evict", sidHash ? { sessionIdHash: sidHash, reasonCode: REASON.expired } : { reasonCode: REASON.expired }));
        return null;
      }
      session.lastSeen = t;
      sessionStore.set(sessionId, session);
      // Return a fresh shallow copy so callers cannot mutate the live store entry.
      return { identity: session.identity, createdAt: session.createdAt, lastSeen: session.lastSeen };
    } catch {
      return null;
    }
  }

  // --- PII-safe audit event builder (allowlist projection) ---
  //
  // Build the event with ONLY safe fields. NEVER spread raw claims/tokens. The
  // only identity-derived fields are the keyed-HMAC hashes from buildExternalIdentity.
  function buildEvent(type, { identity, sessionIdHash: sidHash, reasonCode } = {}) {
    const event = {
      type,
      provider: IDENTITY_PROVIDER,
      timestamp: new Date(now()).toISOString()
    };
    if (identity) {
      event.subjectHash = identity.subjectHash;
      event.issuerHash = identity.issuerHash;
    }
    if (sidHash) event.sessionIdHash = sidHash;
    if (reasonCode) event.reasonCode = reasonCode;
    return event;
  }

  return {
    // The dashboard sessionGuard contract.
    authenticate,
    handlers: {
      "/auth/login": handleLogin,
      "/auth/callback": handleCallback,
      "/auth/logout": handleLogout
    },
    // Exposed for testing/introspection (not part of the guard contract).
    config
  };
}
