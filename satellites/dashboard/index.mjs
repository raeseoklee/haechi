// haechi-dashboard — a zero-dependency, read-only audit viewer.
//
// node: builtins + the "haechi/audit" and "haechi/proxy" peer imports ONLY.
// It takes PATHS (auditPath/anchorPath), not a full runtime, and serves the
// audit JSONL + its hash-chain status read-only over node:http.
//
// Security posture (acceptance criteria, see docs/current/release-0.9-implementation-scope.md §2.1):
//   - normalizeDashboardConfig: strict fail-closed enumerated throws.
//   - construction bind/guard/TLS precedence.
//   - anti-DNS-rebinding Host-header allowlist on every request.
//   - GET/HEAD only; read-only API; fixed in-code asset map (no fs traversal).
//   - recursive key-by-key projection of audit events (no blind spread).
//   - strict CSP + Trusted Types + security headers on every response.
//   - generic {error:"internal"} 5xx (never a stack/path).
//   - satellite-local fixed-window rate limiter on /api/*.
//   - sessionGuard seam: gate /api/* behind authenticate(), mount handlers.

import http from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { open, stat } from "node:fs/promises";

import { verifyAuditChain } from "haechi/audit";
import { assertSafeProxyBind } from "haechi/proxy";

import { ASSETS, HTML_SHELL } from "./assets.mjs";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PORT = 1018;
const DEFAULT_WINDOW = 1 << 20; // 1 MiB tail window for event reads.
const MIN_WINDOW = 4096;
const MAX_WINDOW = 64 << 20; // 64 MiB hard ceiling for the tail window option.
const MAX_LIMIT = 200;
const CHAIN_MAX_BYTES = 32 << 20; // above this, /api/chain returns 413 / {valid:null}.
const RATE_LIMIT_MAX = 120; // requests per window per source key.
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_KEYS = 4096; // hard cap on distinct source keys (DoS bound).

// The ONLY handler paths a sessionGuard may declare and the ONLY paths exempt
// from the auth gate. A FIXED allowlist — never raw Object.keys(handlers) — so a
// guard cannot exempt "/api/chain" (or "/", "/healthz") and serve audit data
// unauthenticated. The request gate computes its exempt set as the INTERSECTION
// of this list and the declared handlers via EXACT match.
const BROKER_PATHS = ["/auth/login", "/auth/callback", "/auth/logout"];

// The exact CSP string is an acceptance criterion (asserted verbatim in tests).
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; " +
  "form-action 'none'; require-trusted-types-for 'script'";

// ---------------------------------------------------------------------------
// Loopback predicate (bind/guard/TLS precedence decision).
//
// isLoopbackHost is PRIVATE in packages/proxy (not exported), so the dashboard
// ships its own small predicate for the precedence decision. This is distinct
// from the request Host-header allowlist normalizer below.
// ---------------------------------------------------------------------------

function isLoopbackHost(host) {
  const normalized = String(host).trim().toLowerCase();
  return (
    normalized === "localhost" ||
    normalized === "::1" ||
    normalized === "[::1]" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    normalized === "::ffff:127.0.0.1" ||
    normalized === "[::ffff:127.0.0.1]" ||
    normalized === "127.0.0.1" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized)
  );
}

// ---------------------------------------------------------------------------
// Config normalization — strict, fail-closed, enumerated throws.
// ---------------------------------------------------------------------------

const KNOWN_KEYS = new Set([
  "auditPath",
  "anchorPath",
  "host",
  "port",
  "allowRemoteBind",
  "sessionGuard",
  "window",
  "tlsContext",
  "trustProxy"
]);

// A tlsContext is usable iff it can actually terminate TLS: (key && cert) or pfx.
// This is the single source of truth for both config validation and buildServer.
function hasUsableTlsMaterial(ctx) {
  if (!ctx || typeof ctx !== "object" || Array.isArray(ctx)) {
    return false;
  }
  const hasKeyCert = Boolean(ctx.key) && Boolean(ctx.cert);
  const hasPfx = Boolean(ctx.pfx);
  return hasKeyCert || hasPfx;
}

export function normalizeDashboardConfig(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new Error("dashboard config must be an object");
  }

  for (const key of Object.keys(options)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new Error(`Unknown dashboard config option: ${key}`);
    }
  }

  const { auditPath } = options;
  if (typeof auditPath !== "string" || auditPath.trim().length === 0) {
    throw new Error("dashboard config 'auditPath' must be a non-empty string");
  }

  let anchorPath = null;
  if (options.anchorPath !== undefined && options.anchorPath !== null) {
    if (typeof options.anchorPath !== "string" || options.anchorPath.length === 0) {
      throw new Error("dashboard config 'anchorPath' must be a non-empty string or null");
    }
    anchorPath = options.anchorPath;
  }

  let host = "127.0.0.1";
  if (options.host !== undefined) {
    if (typeof options.host !== "string" || options.host.length === 0) {
      throw new Error("dashboard config 'host' must be a non-empty string");
    }
    host = options.host;
  }

  let port = DEFAULT_PORT;
  if (options.port !== undefined) {
    if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535) {
      throw new Error("dashboard config 'port' must be an integer in [0,65535]");
    }
    // port 0 = OS-assigned ephemeral port. This is an INTENTIONAL affordance (the
    // test harness binds port 0 to get a free port); the [0,65535] range and the
    // README both document it. Do not narrow the lower bound to 1.
    port = options.port;
  }

  let allowRemoteBind = false;
  if (options.allowRemoteBind !== undefined) {
    if (typeof options.allowRemoteBind !== "boolean") {
      throw new Error("dashboard config 'allowRemoteBind' must be a boolean");
    }
    allowRemoteBind = options.allowRemoteBind;
  }

  let sessionGuard = null;
  if (options.sessionGuard !== undefined && options.sessionGuard !== null) {
    const guard = options.sessionGuard;
    if (typeof guard !== "object" || typeof guard.authenticate !== "function") {
      throw new Error("dashboard config 'sessionGuard' must be an object with an authenticate() function");
    }
    if (guard.handlers !== undefined && guard.handlers !== null) {
      if (typeof guard.handlers !== "object" || Array.isArray(guard.handlers)) {
        throw new Error("dashboard config 'sessionGuard.handlers' must be an object mapping paths to handlers");
      }
      // A handler key may ONLY be one of the fixed BROKER_PATHS. Rejecting any
      // other key (notably "/api/*", "/healthz", "/") at construction closes the
      // auth bypass where a guard exempts an audit-data route from the gate.
      for (const key of Object.keys(guard.handlers)) {
        if (!BROKER_PATHS.includes(key)) {
          throw new Error(
            `dashboard config 'sessionGuard.handlers' key '${key}' is not an allowed broker path ` +
              `(only ${BROKER_PATHS.join(", ")} may be exempt from the auth gate)`
          );
        }
      }
    }
    sessionGuard = guard;
  }

  let window = DEFAULT_WINDOW;
  if (options.window !== undefined) {
    if (!Number.isInteger(options.window) || options.window < MIN_WINDOW || options.window > MAX_WINDOW) {
      throw new Error(`dashboard config 'window' must be an integer in [${MIN_WINDOW},${MAX_WINDOW}]`);
    }
    window = options.window;
  }

  let tlsContext = null;
  if (options.tlsContext !== undefined && options.tlsContext !== null) {
    if (typeof options.tlsContext !== "object" || Array.isArray(options.tlsContext)) {
      throw new Error("dashboard config 'tlsContext' must be an object or null");
    }
    // A non-null tlsContext MUST carry usable TLS material: either (key && cert)
    // or pfx. An empty {} would otherwise green-light the non-loopback path yet
    // build a plaintext http server — fail closed.
    if (!hasUsableTlsMaterial(options.tlsContext)) {
      throw new Error(
        "dashboard config 'tlsContext' must contain usable TLS material ((key && cert) or pfx)"
      );
    }
    tlsContext = options.tlsContext;
  }

  let trustProxy = null;
  if (options.trustProxy !== undefined && options.trustProxy !== null) {
    // trustProxy names a trusted fronting-proxy address/CIDR — it MUST be a
    // non-empty string. A boolean (or a falsy-looking string like "false"/"0"/"")
    // never authorizes anything; reject it so it can't be mistaken for "TLS is
    // handled". trustProxy alone never satisfies a non-loopback bind (see
    // precedence in createDashboardServer).
    if (typeof options.trustProxy !== "string") {
      throw new Error("dashboard config 'trustProxy' must be a non-empty string (a trusted-proxy address/CIDR) or null");
    }
    const normalizedTrustProxy = options.trustProxy.trim().toLowerCase();
    if (
      normalizedTrustProxy.length === 0 ||
      normalizedTrustProxy === "false" ||
      normalizedTrustProxy === "0"
    ) {
      throw new Error("dashboard config 'trustProxy' must be a non-empty string (a trusted-proxy address/CIDR) or null");
    }
    trustProxy = options.trustProxy;
  }

  return {
    auditPath,
    anchorPath,
    host,
    port,
    allowRemoteBind,
    sessionGuard,
    window,
    tlsContext,
    trustProxy
  };
}

// ---------------------------------------------------------------------------
// Request Host-header allowlist normalizer (anti-DNS-rebinding).
//
// Separate from assertSafeProxyBind (which validates a bind STRING). This
// normalizes an UNTRUSTED Host header: parse host+port, reject malformed or
// duplicate Host, strip one trailing dot ("localhost."), handle bracketed IPv6
// and "::ffff:127.0.0.1". Returns the lowercased host portion, or null when
// the header is malformed/duplicated.
// ---------------------------------------------------------------------------

function parseHostHeader(rawHost) {
  // node sets req.headers.host to a single string; a duplicated Host header is
  // joined with ", " by node's parser — reject any comma as duplicate/malformed.
  if (typeof rawHost !== "string" || rawHost.length === 0) {
    return null;
  }
  if (rawHost.includes(",")) {
    return null; // duplicate Host header
  }
  const value = rawHost.trim();
  if (value.length === 0) {
    return null;
  }

  let host;
  if (value.startsWith("[")) {
    // Bracketed IPv6: [::1] or [::1]:port
    const close = value.indexOf("]");
    if (close === -1) {
      return null;
    }
    host = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (rest.length > 0 && !/^:\d{1,5}$/.test(rest)) {
      return null;
    }
  } else {
    const colon = value.indexOf(":");
    if (colon === -1) {
      host = value;
    } else {
      // A bare IPv6 (multiple colons) without brackets is malformed in a Host
      // header — reject it.
      if (value.indexOf(":", colon + 1) !== -1) {
        return null;
      }
      host = value.slice(0, colon);
      const portPart = value.slice(colon + 1);
      if (!/^\d{1,5}$/.test(portPart)) {
        return null;
      }
    }
  }

  host = host.toLowerCase();
  // Strip a single trailing dot ("localhost." -> "localhost").
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }
  if (host.length === 0) {
    return null;
  }
  return host;
}

function buildHostAllowlist(configuredHost) {
  const set = new Set(["localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1"]);
  const normalized = String(configuredHost).trim().toLowerCase();
  // The configured bind host (and a bracketed form, normalized to bare) is allowed.
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    set.add(normalized.slice(1, -1));
  } else {
    set.add(normalized);
  }
  return set;
}

// ---------------------------------------------------------------------------
// Satellite-local fixed-window in-memory rate limiter.
//
// DEVIATION (design §2.1 says "reuse createRateLimiter"): proxy's
// createRateLimiter is PRIVATE (not exported), so the dashboard ships its own
// tiny per-key 60s fixed-window counter to keep 0.9 with NO core change.
// ---------------------------------------------------------------------------

function createRateLimiter({
  max = RATE_LIMIT_MAX,
  windowMs = RATE_LIMIT_WINDOW_MS,
  maxKeys = RATE_LIMIT_MAX_KEYS
} = {}) {
  const buckets = new Map(); // key -> { count, resetAt }

  // Expiry eviction so the Map cannot grow unbounded across many distinct peer
  // keys: drop every window whose resetAt has passed, and if we are still at the
  // hard key cap, evict the oldest-resetting entries (Map preserves insertion
  // order, so the first surviving entries are the oldest). Tiny + zero-dep.
  function prune(now) {
    for (const [key, bucket] of buckets) {
      if (now >= bucket.resetAt) {
        buckets.delete(key);
      }
    }
    if (buckets.size >= maxKeys) {
      for (const key of buckets.keys()) {
        if (buckets.size < maxKeys) {
          break;
        }
        buckets.delete(key);
      }
    }
  }

  return {
    allow(key) {
      const now = Date.now();
      const bucket = buckets.get(key);
      if (!bucket || now >= bucket.resetAt) {
        if (!buckets.has(key)) {
          // Only prune when about to insert a NEW key (the unbounded-growth path).
          prune(now);
        }
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }
      if (bucket.count >= max) {
        return false;
      }
      bucket.count += 1;
      return true;
    }
  };
}

// ---------------------------------------------------------------------------
// Recursive key-by-key projection of an audit event (defense in depth).
//
// Never spread a nested sub-object through blind. Build NEW objects so a
// synthetic/future field at any level is dropped.
// ---------------------------------------------------------------------------

function pick(source, keys) {
  const out = {};
  if (!source || typeof source !== "object") {
    return out;
  }
  for (const key of keys) {
    if (source[key] !== undefined) {
      out[key] = source[key];
    }
  }
  return out;
}

function projectDetection(detection) {
  return pick(detection, ["type", "ruleId", "path", "kind", "confidence", "action", "enforced"]);
}

function projectIdentity(identity) {
  if (!identity || typeof identity !== "object") {
    return null;
  }
  // NEVER scopes/labels/raw subject.
  return pick(identity, ["id", "type", "subjectHash", "issuerHash", "provider"]);
}

function projectSummary(summary) {
  if (!summary || typeof summary !== "object") {
    return { byType: {}, byAction: {}, detectionCount: 0 };
  }
  const out = {};
  out.byType = sanitizeCounts(summary.byType);
  out.byAction = sanitizeCounts(summary.byAction);
  out.detectionCount = Number.isFinite(summary.detectionCount) ? summary.detectionCount : 0;
  return out;
}

function sanitizeCounts(counts) {
  const out = {};
  if (counts && typeof counts === "object" && !Array.isArray(counts)) {
    for (const [key, value] of Object.entries(counts)) {
      if (typeof value === "number" && Number.isFinite(value)) {
        out[key] = value;
      }
    }
  }
  return out;
}

function projectIntegrity(integrity) {
  return pick(integrity, ["sequence", "previousHash", "eventHash"]);
}

function projectEvent(event) {
  const out = pick(event, [
    "id",
    "timestamp",
    "protocol",
    "operation",
    "mode",
    "enforced",
    "blocked",
    "direction",
    "payloadShapeHash"
  ]);
  out.identity = projectIdentity(event.identity);
  out.detections = Array.isArray(event.detections)
    ? event.detections.map(projectDetection)
    : [];
  out.summary = projectSummary(event.summary);
  out.auditIntegrity = projectIntegrity(event.auditIntegrity);
  return out;
}

// ---------------------------------------------------------------------------
// Bounded tail read of the JSONL audit file.
//
// Mirrors packages/audit/index.mjs readLastIntegrity: open()+stat()+read from
// (size - window). Tolerates a torn trailing/leading line. Returns parsed,
// projected events plus whether the requested cursor page predates the window.
// ---------------------------------------------------------------------------

async function readTailEvents(auditPath, windowBytes) {
  let handle;
  try {
    handle = await open(auditPath, "r");
  } catch (error) {
    if (error.code === "ENOENT") {
      return { events: [], coveredFromStart: true };
    }
    throw error;
  }
  try {
    const { size } = await handle.stat();
    if (size === 0) {
      return { events: [], coveredFromStart: true };
    }
    const start = Math.max(0, size - windowBytes);
    const length = size - start;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    const text = buffer.toString("utf8");
    const coveredFromStart = start === 0;

    let lines = text.split("\n");
    // If we did not start at byte 0, the first line is very likely a torn
    // partial record from a window boundary — drop it.
    if (!coveredFromStart && lines.length > 0) {
      lines = lines.slice(1);
    }

    const events = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      let record;
      try {
        record = JSON.parse(trimmed);
      } catch {
        // A torn trailing line from a concurrent append (or the dropped torn
        // leader) is skipped, never a 500.
        continue;
      }
      if (record && typeof record === "object" && record.auditIntegrity) {
        events.push(record);
      }
    }
    return { events, coveredFromStart };
  } finally {
    await handle.close();
  }
}

// ---------------------------------------------------------------------------
// Chain-status cache (single serialized in-process job; mtime+size keyed).
// ---------------------------------------------------------------------------

function createChainCache(auditPath, anchorPath) {
  let cacheKey = null;
  let cachedResult = null;
  let inFlight = null;

  async function compute() {
    let fileStat;
    try {
      fileStat = await stat(auditPath);
    } catch (error) {
      if (error.code === "ENOENT") {
        // No audit file yet: an empty, valid chain.
        return { status: 200, body: { valid: true, records: 0, headHash: null } };
      }
      throw error;
    }

    if (fileStat.size > CHAIN_MAX_BYTES) {
      // Above the hard cap, do not walk: 413 / {valid:null}.
      return { status: 413, body: { valid: null } };
    }

    const raw = await verifyAuditChain(auditPath, { anchorPath });
    return { status: 200, body: shapeChainResult(raw) };
  }

  return {
    async get() {
      let fileStat;
      try {
        fileStat = await stat(auditPath);
        const key = `${fileStat.mtimeMs}:${fileStat.size}`;
        if (cacheKey === key && cachedResult) {
          return cachedResult;
        }
        if (inFlight) {
          // A walk is already in progress — await it (no concurrent re-walk).
          return await inFlight;
        }
        inFlight = (async () => {
          const result = await compute();
          cacheKey = key;
          cachedResult = result;
          return result;
        })();
        try {
          return await inFlight;
        } finally {
          inFlight = null;
        }
      } catch (error) {
        if (error.code === "ENOENT") {
          const result = { status: 200, body: { valid: true, records: 0, headHash: null } };
          return result;
        }
        throw error;
      }
    },
    // HEAD: return the last known status without forcing a fresh walk.
    peekStatus() {
      return cachedResult ? cachedResult.status : 200;
    }
  };
}

function shapeChainResult(raw) {
  if (raw && raw.valid === true) {
    const body = { valid: true, records: raw.records, headHash: raw.headHash ?? null };
    if (raw.anchored) {
      body.anchored = {
        count: raw.anchored.count,
        lastSequence: raw.anchored.lastSequence
      };
    }
    return body;
  }
  // Failure: derive truncationDetected from the reason; NEVER surface reason.
  const reason = typeof raw?.reason === "string" ? raw.reason : "";
  return {
    valid: false,
    records: raw?.records ?? 0,
    truncationDetected: reason.startsWith("tail truncation")
  };
}

// ---------------------------------------------------------------------------
// HTTP response helpers
// ---------------------------------------------------------------------------

function setSecurityHeaders(res, { hsts, noStore }) {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (noStore) {
    res.setHeader("Cache-Control", "no-store");
  }
  if (hsts) {
    // HSTS is emitted ONLY when this server actually serves https — NEVER over
    // plaintext http (a Strict-Transport-Security header over http is meaningless
    // at best and a footgun at worst).
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  // CORS is intentionally absent: never set/reflect Access-Control-Allow-Origin.
}

function sendJson(res, status, body, { hsts }) {
  setSecurityHeaders(res, { hsts, noStore: true });
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const payload = JSON.stringify(body);
  res.statusCode = status;
  if (res.req && res.req.method === "HEAD") {
    res.setHeader("Content-Length", Buffer.byteLength(payload));
    res.end();
    return;
  }
  res.end(payload);
}

function sendText(res, status, contentType, body, { hsts, noStore }) {
  setSecurityHeaders(res, { hsts, noStore });
  res.setHeader("Content-Type", contentType);
  res.statusCode = status;
  if (res.req && res.req.method === "HEAD") {
    res.setHeader("Content-Length", Buffer.byteLength(body));
    res.end();
    return;
  }
  res.end(body);
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

export function createDashboardServer(options = {}) {
  const config = normalizeDashboardConfig(options);
  const {
    auditPath,
    anchorPath,
    host,
    port,
    allowRemoteBind,
    sessionGuard,
    window: windowBytes,
    tlsContext,
    trustProxy
  } = config;

  const loopback = isLoopbackHost(host);

  // --- Construction bind/guard/TLS precedence (exact order) ---

  // (1) loopback bind guard — reuse assertSafeProxyBind, rethrow dashboard-worded.
  try {
    assertSafeProxyBind({ host, allowRemoteBind });
  } catch {
    throw new Error(
      `Refusing to bind Haechi dashboard to non-loopback host ${host}. ` +
        `Set the allowRemoteBind option only for an explicitly secured, TLS-terminated, session-guarded environment.`
    );
  }

  // (2) remote bind requires a sessionGuard.
  if (!loopback && allowRemoteBind && !sessionGuard) {
    throw new Error("remote bind requires a sessionGuard");
  }

  // (3) remote bind requires the dashboard itself to terminate TLS — a VALID
  // tlsContext (normalizeDashboardConfig already guaranteed any non-null
  // tlsContext carries usable material). trustProxy does NOT satisfy a
  // non-loopback bind: it merely names a fronting TLS terminator that reaches
  // this dashboard over loopback. A non-loopback plaintext listener would serve
  // audit data in cleartext while emitting HSTS — fail closed.
  const validTlsContext = hasUsableTlsMaterial(tlsContext);
  if (!loopback && !validTlsContext) {
    throw new Error(
      "remote bind requires the dashboard to terminate TLS (a valid tlsContext with (key && cert) or pfx); " +
        "trustProxy alone does not authorize a non-loopback plaintext listener, and " +
        "a Secure/__Host- session cookie is never sent over plaintext http"
    );
  }

  // HSTS is emitted ONLY when this server actually serves https (a valid
  // tlsContext is present) — NEVER over plaintext http.
  const servesHttps = validTlsContext;
  const hostAllowlist = buildHostAllowlist(host);
  const rateLimiter = createRateLimiter();
  const chainCache = createChainCache(auditPath, anchorPath);

  // The auth-exempt handler set is the INTERSECTION of the FIXED BROKER_PATHS and
  // the declared handlers, matched EXACTLY — never raw Object.keys(handlers). Even
  // though normalizeDashboardConfig already rejects a non-broker handler key, this
  // intersection is the load-bearing gate: a guard can NEVER exempt "/api/chain",
  // "/healthz", or "/" from authenticate() by declaring it as a handler.
  const exemptHandlerPaths = new Set();
  if (sessionGuard && sessionGuard.handlers) {
    for (const brokerPath of BROKER_PATHS) {
      if (Object.prototype.hasOwnProperty.call(sessionGuard.handlers, brokerPath)) {
        exemptHandlerPaths.add(brokerPath);
      }
    }
  }

  function rateKey(req) {
    return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
  }

  function requestHandler(req, res) {
    handleRequest(req, res).catch((error) => {
      // Generic error: never a stack/message/OS code/absolute path.
      logServerSide("request handler error", error);
      if (!res.headersSent) {
        try {
          sendJson(res, 500, { error: "internal" }, { hsts: servesHttps });
        } catch {
          res.statusCode = 500;
          res.end();
        }
      } else {
        res.end();
      }
    });
  }

  async function handleRequest(req, res) {
    // Anti-DNS-rebinding Host allowlist is the UNCONDITIONAL FIRST gate on EVERY
    // request (incl. /api/*, /healthz, and any method). A bad Host is 403 even on
    // a POST — the Host gate precedes the method allowlist so a rebinding page
    // never learns anything from a method-specific status.
    const hostPortion = parseHostHeader(req.headers.host);
    if (hostPortion === null || !hostAllowlist.has(hostPortion)) {
      sendJson(res, 403, { error: "forbidden" }, { hsts: servesHttps });
      return;
    }

    const method = req.method || "GET";

    // Method allowlist: only GET/HEAD.
    if (method !== "GET" && method !== "HEAD") {
      sendJson(res, 405, { error: "method_not_allowed" }, { hsts: servesHttps });
      return;
    }

    // Parse the URL path (same-origin only; query is parsed per-route).
    let url;
    try {
      url = new URL(req.url || "/", "http://placeholder");
    } catch {
      sendJson(res, 400, { error: "bad_request" }, { hsts: servesHttps });
      return;
    }
    const path = url.pathname;

    // /healthz — liveness only, no session needed even off-loopback.
    if (path === "/healthz") {
      sendJson(res, 200, { status: "ok" }, { hsts: servesHttps });
      return;
    }

    const isApi = path === "/api/events" || path === "/api/chain" || path === "/api/summary";

    // Rate limit /api/* (satellite-local fixed-window).
    if (isApi && !rateLimiter.allow(rateKey(req))) {
      sendJson(res, 429, { error: "rate_limited" }, { hsts: servesHttps });
      return;
    }

    // sessionGuard seam.
    if (sessionGuard) {
      // Mount handlers ONLY at the intersection of BROKER_PATHS and the declared
      // handlers (exact match). A path outside that fixed set is never exempt.
      if (exemptHandlerPaths.has(path)) {
        const handler = sessionGuard.handlers[path];
        await handler(req, res);
        return;
      }
      // Gate every /api/* behind authenticate(); unauthenticated -> 401 (never 302).
      if (isApi) {
        let session = null;
        try {
          session = await sessionGuard.authenticate(req);
        } catch {
          session = null;
        }
        if (!session) {
          sendJson(res, 401, { error: "unauthorized" }, { hsts: servesHttps });
          return;
        }
      }
    }

    // Routes.
    if (path === "/" || path === "/index.html") {
      sendText(res, 200, "text/html; charset=utf-8", HTML_SHELL, { hsts: servesHttps, noStore: true });
      return;
    }

    if (ASSETS.has(path)) {
      const asset = ASSETS.get(path);
      // JS/CSS: no-store is fine (a localhost tool gains nothing from caching).
      sendText(res, 200, asset.contentType, asset.body, { hsts: servesHttps, noStore: true });
      return;
    }

    if (path === "/api/events") {
      await handleEvents(req, res, url);
      return;
    }
    if (path === "/api/chain") {
      await handleChain(req, res);
      return;
    }
    if (path === "/api/summary") {
      await handleSummary(req, res);
      return;
    }

    // Unknown path (incl. an attempted asset traversal that missed the Map) -> 404.
    sendJson(res, 404, { error: "not_found" }, { hsts: servesHttps });
  }

  async function handleEvents(req, res, url) {
    const params = url.searchParams;

    // Strict limit parsing: integer in [1,200]; reject NaN/negative/non-integer.
    let limit = 50;
    if (params.has("limit")) {
      const rawLimit = params.get("limit");
      // Reject anything that is not a plain decimal integer string.
      if (!/^\d+$/.test(rawLimit)) {
        sendJson(res, 400, { error: "bad_request" }, { hsts: servesHttps });
        return;
      }
      const parsed = Number(rawLimit);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_LIMIT) {
        sendJson(res, 400, { error: "bad_request" }, { hsts: servesHttps });
        return;
      }
      limit = parsed;
    }

    // cursor: opaque = auditIntegrity.sequence; never an fs offset.
    let cursor = null;
    if (params.has("cursor")) {
      const rawCursor = params.get("cursor");
      if (!/^\d+$/.test(rawCursor)) {
        sendJson(res, 400, { error: "bad_request" }, { hsts: servesHttps });
        return;
      }
      const parsedCursor = Number(rawCursor);
      if (!Number.isInteger(parsedCursor) || parsedCursor < 0) {
        sendJson(res, 400, { error: "bad_request" }, { hsts: servesHttps });
        return;
      }
      cursor = parsedCursor;
    }

    const { events: rawEvents, coveredFromStart } = await readTailEvents(auditPath, windowBytes);

    // Newest-first.
    const ordered = rawEvents.slice().sort((a, b) => {
      const sa = a.auditIntegrity?.sequence ?? 0;
      const sb = b.auditIntegrity?.sequence ?? 0;
      return sb - sa;
    });

    // Lowest sequence present in the window (for window-exceeded detection).
    let minSeqInWindow = Infinity;
    for (const ev of ordered) {
      const seq = ev.auditIntegrity?.sequence;
      if (typeof seq === "number" && seq < minSeqInWindow) {
        minSeqInWindow = seq;
      }
    }

    let windowExceeded = false;
    let page = ordered;
    if (cursor !== null) {
      // Page strictly older than the cursor sequence.
      page = ordered.filter((ev) => (ev.auditIntegrity?.sequence ?? 0) < cursor);
      // If the requested cursor predates the retained window, there may be older
      // events that fell off the tail — signal window exceeded.
      if (!coveredFromStart && cursor <= minSeqInWindow) {
        windowExceeded = true;
      }
    }

    const limited = page.slice(0, limit);
    const projected = limited.map(projectEvent);

    // Next cursor = the lowest sequence in this page (client pages older).
    let nextCursor = null;
    if (projected.length > 0) {
      const last = projected[projected.length - 1];
      nextCursor = last.auditIntegrity?.sequence ?? null;
    }

    sendJson(
      res,
      200,
      {
        events: projected,
        nextCursor: nextCursor !== null ? String(nextCursor) : null,
        windowExceeded
      },
      { hsts: servesHttps }
    );
  }

  async function handleChain(req, res) {
    if (req.method === "HEAD") {
      // HEAD: headers only, NO fresh walk.
      setSecurityHeaders(res, { hsts: servesHttps, noStore: true });
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.statusCode = chainCache.peekStatus();
      res.end();
      return;
    }
    const result = await chainCache.get();
    sendJson(res, result.status, result.body, { hsts: servesHttps });
  }

  async function handleSummary(req, res) {
    const { events } = await readTailEvents(auditPath, windowBytes);
    const byType = {};
    const byAction = {};
    let detectionCount = 0;
    for (const ev of events) {
      const summary = projectSummary(ev.summary);
      for (const [k, v] of Object.entries(summary.byType)) {
        byType[k] = (byType[k] ?? 0) + v;
      }
      for (const [k, v] of Object.entries(summary.byAction)) {
        byAction[k] = (byAction[k] ?? 0) + v;
      }
      detectionCount += summary.detectionCount;
    }
    sendJson(res, 200, { byType, byAction, detectionCount }, { hsts: servesHttps });
  }

  // --- The server object ---

  let server = null;

  function buildServer() {
    // HTTPS ONLY with a valid tlsContext (key&&cert or pfx). Otherwise plain http.
    // This is the same predicate that gates HSTS (servesHttps), so HSTS is emitted
    // iff we actually serve https — never over plaintext.
    if (validTlsContext) {
      return createHttpsServer(tlsContext, requestHandler);
    }
    return http.createServer(requestHandler);
  }

  return {
    config,
    // requestHandler is exposed for testing and embedding (drive the handler
    // directly without binding a socket).
    requestHandler,
    async listen() {
      if (!server) {
        server = buildServer();
      }
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server.removeListener("error", onError);
          reject(error);
        };
        server.once("error", onError);
        server.listen(port, host, () => {
          server.removeListener("error", onError);
          resolve();
        });
      });
      const address = server.address();
      const boundHost = address && typeof address === "object" ? address.address : host;
      const boundPort = address && typeof address === "object" ? address.port : port;
      return { host: boundHost, port: boundPort };
    },
    async close() {
      if (!server) {
        return;
      }
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      server = null;
    }
  };
}

function logServerSide(label, error) {
  // The real reason is logged server-side ONLY (never sent to the client).
  // Kept minimal; an operator can wire a real logger by patching this later.
  try {
    const detail = error && error.message ? error.message : String(error);
    process.emitWarning(`[haechi-dashboard] ${label}: ${detail}`);
  } catch {
    // never let logging throw into the request path
  }
}
