import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createHash, randomUUID } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { inspectResponseStream } from "../stream-filter/index.mjs";

export const DEFAULT_PROXY_PORT = 11016;

// The published package version, read once from the package's own manifest.
// package.json IS in the published tarball, and packages/proxy/index.mjs sits
// two levels below the repo root, so this URL resolves in both the dev tree and
// the packed tarball. Falls back to "unknown" rather than throwing — a version
// read must never break proxy startup.
export const HAECHI_VERSION = readPackageVersion();

function readPackageVersion() {
  try {
    const pkgUrl = new URL("../../package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(fileURLToPath(pkgUrl), "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

// A tlsContext is usable iff it can actually terminate TLS: (key && cert) or pfx.
// This is the SINGLE source of truth for both the bind guard and server
// selection — the SAME shape the haechi-dashboard satellite uses, so the proxy
// and the dashboard share one TLS-material predicate. A non-null tlsContext that
// fails this check must fail closed (never green-light a remote bind that then
// builds a plaintext http server).
export function hasUsableTlsMaterial(ctx) {
  if (!ctx || typeof ctx !== "object" || Array.isArray(ctx)) {
    return false;
  }
  const hasKeyCert = Boolean(ctx.key) && Boolean(ctx.cert);
  const hasPfx = Boolean(ctx.pfx);
  return hasKeyCert || hasPfx;
}

// Structured logger honoring config.logging.format. In "json" mode it emits a
// single JSON line carrying a correlationId and an error NAME/class — NEVER a
// request/response payload, headers, token, or any PII. In "text" mode it
// preserves the prior human-readable console output.
function createLogger(format = "text") {
  const json = format === "json";
  return {
    error(event, fields = {}) {
      if (json) {
        process.stderr.write(`${JSON.stringify({ level: "error", event, ...fields })}\n`);
      } else {
        const parts = Object.entries(fields)
          .filter(([, value]) => value !== undefined && value !== null)
          .map(([key, value]) => `${key}=${value}`);
        process.stderr.write(`haechi ${event}${parts.length ? `: ${parts.join(" ")}` : ""}\n`);
      }
    }
  };
}

export function createHaechiProxy({ runtime, port = DEFAULT_PROXY_PORT, host = "127.0.0.1", allowRemoteBind = false, tlsContext, trustForwardedProto }) {
  const { haechi, config, protocolAdapter } = runtime;

  // WS6 TLS hardening. The tlsContext / trustForwardedProto source of truth is
  // the normalized config (proxy.tls is loaded into a tlsContext at startup;
  // proxy.trustForwardedProto is a boolean), but an explicit argument overrides
  // it (so a hand-built runtime / a test can drive these directly). hasUsableTls
  // is the same predicate the dashboard satellite uses.
  const resolvedTlsContext = tlsContext !== undefined ? tlsContext : (config.proxy?.tls ?? null);
  const resolvedTrustForwardedProto = trustForwardedProto !== undefined
    ? trustForwardedProto
    : Boolean(config.proxy?.trustForwardedProto);
  const usableTls = hasUsableTlsMaterial(resolvedTlsContext);

  // Bind guard, two layers. (1) the loopback/remote-bind gate (shared with the
  // dashboard). (2) WS6: a remote bind ADDITIONALLY requires a usable tlsContext
  // OR an explicit trustForwardedProto acknowledgement (a trusted reverse proxy
  // terminates TLS in front of Haechi). Otherwise it THROWS at startup — the
  // proxy must NEVER serve bearer tokens + payloads in plaintext on a remote
  // bind. Loopback dev is unaffected (plain http, no TLS).
  assertSafeProxyBind({ host, allowRemoteBind });
  assertSafeProxyTransport({
    host,
    allowRemoteBind,
    hasUsableTls: usableTls,
    trustForwardedProto: resolvedTrustForwardedProto
  });

  // When the remote bind rests on trustForwardedProto (plain http behind a
  // trusted TLS hop) we REJECT any protected-route request whose
  // X-Forwarded-Proto is not https — a plaintext request that bypassed the hop.
  // This is only meaningful for a non-loopback, plain-http, trust-forwarded
  // listener; a loopback dev server or an https-terminating server never gates.
  const enforceForwardedProto = !isLoopbackHost(host)
    && allowRemoteBind
    && !usableTls
    && resolvedTrustForwardedProto;
  // The runtime owns the rate limiter (an injectable collaborator). Fall back to
  // a local per-process default so a hand-built runtime object without a
  // rateLimiter still works (backward-compatible). The default and the runtime's
  // default share the same allow(key, limit) -> boolean fixed-window contract.
  const rateLimiter = runtime.rateLimiter ?? createRateLimiter();
  // The metrics collector is owned by the runtime (injectable). Fall back to a
  // no-op so a hand-built runtime object without metrics still works.
  const metrics = runtime.metrics ?? noopMetrics();
  const logger = createLogger(config.logging?.format ?? "text");

  // P0-CR-001 — the upstream header forward policy, derived ONCE from config.
  // gatewayConsumedAuthorization is true whenever the gateway authenticates the
  // CLIENT (auth.provider !== "none"): the request's Authorization is then the
  // gateway credential Haechi consumed and must NOT be forwarded to the model
  // upstream. With auth.provider "none" the client's Authorization is the
  // upstream provider key and IS forwarded. extraHeaders is the operator's
  // additive target.forwardHeaders allowlist (validated lowercase in
  // normalizeConfig); it can only widen, never override the always-drop set.
  const forwardPolicy = {
    gatewayConsumedAuthorization: (config.auth?.provider ?? "none") !== "none",
    extraHeaders: new Set(config.target?.forwardHeaders ?? [])
  };

  // WS4-B backpressure: a configurable global max-in-flight ceiling. 0 (default)
  // disables it, preserving 1.1 behavior. When > 0 and the live count is at the
  // ceiling, a NEW non-exempt request is rejected 503 + Retry-After BEFORE auth
  // and body-read. The /__haechi/* observability routes are EXEMPT so metrics +
  // liveness can be scraped under saturation.
  const maxInFlight = config.limits.maxInFlight ?? 0;
  const retryAfterSeconds = Math.max(1, Math.ceil((config.limits.shutdownGraceMs ?? 10000) / 1000));
  // Live in-flight request count for the drain-tracking AND the ceiling. A
  // bounded integer — never identity/value bearing.
  let inFlight = 0;
  // Resolves once in-flight drains to zero during a graceful close().
  let drained = null;
  let resolveDrained = null;

  const requestHandler = async (request, response) => {
    // Per-REQUEST correlation id: generated here, threaded into every protect
    // context (so the audit events of one request share it) AND into the error
    // log. A UUID — never a payload/identity/PII value.
    const correlationId = randomUUID();
    const startedAt = process.hrtime.bigint();
    let routeId = "unknown";

    // Observability routes are exempt from the in-flight ceiling and are NOT
    // counted toward it: liveness/readiness/metrics must answer under saturation.
    const exemptRoute = isObservabilityRoute(request);

    // Backpressure: reject at the ceiling BEFORE doing any work. Counted in
    // metrics by a bounded enum decision; the body is never read.
    if (!exemptRoute && maxInFlight > 0 && inFlight >= maxInFlight) {
      metrics.increment("haechi_overloaded_total");
      response.writeHead(503, {
        "content-type": "application/json",
        "retry-after": String(retryAfterSeconds)
      });
      response.end(`${JSON.stringify({ error: "haechi_overloaded", message: "Server at max in-flight capacity; retry later" }, null, 2)}\n`);
      return;
    }

    // Track in-flight for graceful drain + the ceiling. Decrement in finally so a
    // throw/early-return can never leak the count (which would wedge close()).
    let counted = false;
    if (!exemptRoute) {
      inFlight += 1;
      counted = true;
    }
    try {
      // WS6 forwarded-proto enforcement. When this is a non-loopback plain-http
      // listener resting on trustForwardedProto (a trusted reverse proxy
      // terminates TLS in front of Haechi), a request whose X-Forwarded-Proto is
      // not "https" arrived over plaintext that BYPASSED the TLS hop — reject it
      // fail-closed BEFORE auth and body-read, so a protected route never serves
      // tokens/payloads over an unverified-plaintext hop. The /__haechi/* liveness
      // routes are EXEMPT (they leak nothing) so a health check / metrics scrape
      // from the loopback sidecar still answers.
      if (enforceForwardedProto && !exemptRoute && !isForwardedHttps(request)) {
        writeJson(response, 403, {
          error: "haechi_forwarded_proto_required",
          message: "This proxy runs behind a trusted TLS-terminating hop (proxy.trustForwardedProto). A request without X-Forwarded-Proto: https bypassed the hop and is refused."
        });
        return;
      }
      // Health + telemetry endpoints are unauthenticated and checked BEFORE auth
      // and body-read. They live under the reserved /__haechi/* prefix.
      if (request.method === "GET" && request.url === "/__haechi/live") {
        // Cheap process liveness. Always 200 while the event loop is serving.
        writeJson(response, 200, { ok: true, version: HAECHI_VERSION });
        return;
      }
      if (request.method === "GET" && request.url === "/__haechi/ready") {
        await handleReady({ runtime, response });
        return;
      }
      if (request.method === "GET" && request.url === "/__haechi/health") {
        // Back-compat: keep the original shape (ok + mode) and add version.
        writeJson(response, 200, { ok: true, mode: config.mode, version: HAECHI_VERSION });
        return;
      }
      if (request.method === "GET" && request.url === "/__haechi/metrics") {
        if (!config.metrics?.enabled) {
          writeJson(response, 404, { error: "haechi_metrics_disabled", message: "Metrics endpoint is disabled (metrics.enabled: false)" });
          return;
        }
        response.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
        response.end(metrics.render());
        return;
      }

      assertRelativeProxyTarget(request.url);
      const routeContext = protocolAdapter.classifyRequest(request);
      routeId = routeContext?.routeId ?? "unknown";
      const mode = config.policy.mode ?? config.mode;

      // Authenticate, resolve the policy profile, and rate-limit BEFORE reading
      // the body, so a denied/throttled request cannot stream a large body.
      const gate = await authorizeRequest({ runtime, request, routeContext, rateLimiter, metrics, correlationId });
      if (gate.denied) {
        writeJson(response, gate.denied.status, {
          error: gate.denied.error,
          message: gate.denied.message
        });
        return;
      }
      const { identity, profile, policyEngine, modelAllowlist } = gate;
      const authContext = { identity, profile, policyEngine, correlationId };

      const body = await readBody(request, {
        maxBytes: config.limits.maxRequestBytes,
        response
      });
      const json = parseJsonBody(body);

      // Model allowlist runs after body read (the model field is in the body).
      if (modelAllowlist && typeof json?.model === "string" && !modelAllowlist.includes(json.model)) {
        await recordProxyDecision({
          runtime, routeContext, identity, profile, correlationId,
          decision: "model_not_allowed",
          reason: `model:${json.model}`,
          enforced: true,
          blocked: true
        });
        countDecision(metrics, { routeContext, mode, decision: "model_not_allowed" });
        metrics.increment("haechi_blocks_total");
        writeJson(response, 403, {
          error: "haechi_model_not_allowed",
          message: `Model not allowed: ${json.model}`
        });
        return;
      }

      if (isStreamingRequest(json, routeContext)) {
        if (config.streaming.requestMode === "inspect") {
          await handleInspectedStream({ runtime, request, response, routeContext, json, authContext, metrics, forwardPolicy });
          return;
        }

        if (config.streaming.requestMode === "pass-through") {
          await recordProxyDecision({
            runtime,
            routeContext,
            identity,
            profile,
            correlationId,
            decision: "streaming_request_pass_through",
            reason: "streaming_request_pass_through",
            enforced: false,
            blocked: false
          });
          countDecision(metrics, { routeContext, mode, decision: "forwarded" });
          // CR2-001 — a per-request AbortController whose signal is threaded into
          // the upstream fetch; aborting it (on a downstream client disconnect)
          // tears down the upstream request + body so neither leaks.
          const streamAbort = new AbortController();
          const upstreamResponse = await forward({
            upstream: config.target.upstream,
            request,
            body,
            timeoutMs: config.limits.upstreamTimeoutMs,
            metrics,
            forwardPolicy,
            abortController: streamAbort
          });
          // P1-CR-003 — sanitize response headers (strip the upstream's
          // content-encoding/content-length/transfer/hop-by-hop) on this path
          // too: Node fetch() auto-decompressed the body, so the original
          // compressed headers would now be wrong. P1-CR-004 — TRUE bounded
          // streaming pass-through: pipe the upstream body to the client with a
          // running byte cap instead of buffering the whole response.
          response.writeHead(upstreamResponse.status, sanitizeResponseHeaders(upstreamResponse));
          await pipeUpstreamBodyBounded({
            upstreamResponse,
            response,
            request,
            maxBytes: streamingPassThroughMaxBytes(config),
            abortController: streamAbort,
            logger,
            metrics,
            correlationId
          });
          return;
        }

        countDecision(metrics, { routeContext, mode, decision: "streaming_blocked" });
        writeJson(response, 501, {
          error: "haechi_streaming_unsupported",
          message: "Streaming requests are blocked unless streaming.requestMode is set to pass-through or inspect"
        });
        return;
      }

      const result = routeContext.protectRequest
        ? await haechi.protectJson(json, {
          ...routeContext,
          ...authContext,
          operation: `request:${routeContext.operation}`,
          direction: "request",
          mode
        })
        : { payload: json, blocked: false };

      if (result.blocked) {
        countDecision(metrics, { routeContext, mode, decision: "blocked" });
        metrics.increment("haechi_blocks_total");
        writeJson(response, 403, {
          error: "haechi_policy_block",
          summary: result.summary,
          auditId: result.auditEvent.id
        });
        return;
      }

      const upstreamResponse = await forward({
        upstream: config.target.upstream,
        request,
        body: JSON.stringify(result.payload),
        timeoutMs: config.limits.upstreamTimeoutMs,
        metrics,
        forwardPolicy
      });

      const forwarded = await maybeProtectResponse({
        upstreamResponse,
        routeContext,
        runtime,
        authContext,
        issuedTokens: result.issuedTokens ?? [],
        metrics
      });

      countDecision(metrics, {
        routeContext,
        mode,
        decision: forwarded.decision ?? "forwarded"
      });
      response.writeHead(forwarded.status, forwarded.headers);
      response.end(forwarded.body);
    } catch (error) {
      const expected = typeof error?.statusCode === "number";
      if (!expected) {
        // Carry the error NAME/class + correlationId only — NEVER the payload,
        // headers, token, or any PII.
        logger.error("proxy_internal_error", {
          correlationId,
          errorName: error?.name ?? "Error",
          statusCode: error?.statusCode ?? 500
        });
        metrics.increment("haechi_internal_error_total");
      }
      // CR2-005 — an over-limit request body teardown carries `Connection: close`
      // so the socket releases once the 413 is delivered (readBody destroys the
      // request on response finish/close).
      const extraHeaders = error?.errorCode === "haechi_request_body_too_large"
        ? { connection: "close" }
        : null;
      writeJson(response, error.statusCode ?? 500, {
        error: error.errorCode ?? "haechi_proxy_error",
        message: expected ? error.message : "Internal proxy error"
      }, extraHeaders);
    } finally {
      const elapsedSeconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
      // route label is a bounded route id (or "unknown") — never an identity/value.
      metrics.observe("haechi_request_duration_seconds", elapsedSeconds, { route: routeId });
      if (counted) {
        inFlight -= 1;
        // If a graceful close() is awaiting drain and we just hit zero, resolve it.
        if (resolveDrained && inFlight <= 0) {
          resolveDrained();
        }
      }
    }
  };

  // Server selection: a usable tlsContext → an https listener terminating TLS in
  // this process; otherwise plain http (unchanged for loopback/dev). The bind
  // guard above already guarantees a non-loopback bind without usable TLS carries
  // an explicit trustForwardedProto acknowledgement, so a plain-http server is
  // only ever exposed remotely behind a trusted TLS hop (and gated below).
  const server = usableTls
    ? createHttpsServer(resolvedTlsContext, requestHandler)
    : createServer(requestHandler);
  const servesHttps = usableTls;

  // WS4-B tuned timeouts. Only override Node's server defaults when a value is
  // configured (null = leave Node's default untouched, so behavior is unchanged
  // unless an operator opts in). requestTimeout caps the whole request; a value
  // of 0 disables the timeout (Node semantics) — validated upstream.
  if (config.limits.requestTimeoutMs !== null && config.limits.requestTimeoutMs !== undefined) {
    server.requestTimeout = config.limits.requestTimeoutMs;
  }
  if (config.limits.headersTimeoutMs !== null && config.limits.headersTimeoutMs !== undefined) {
    server.headersTimeout = config.limits.headersTimeoutMs;
  }

  return {
    server,
    // Whether THIS listener terminates TLS (https) — the CLI/log line reflects
    // the right scheme, and a caller can assert the selected transport.
    servesHttps,
    listen() {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const address = server.address();
          resolve({ host: address.address, port: address.port, tls: servesHttps });
        });
      });
    },
    // WS4-B graceful drain. Stop accepting new connections, immediately close
    // idle keep-alive sockets, and wait for in-flight requests to drain. After a
    // configurable grace period (limits.shutdownGraceMs) force-close any lingering
    // socket so a stuck keep-alive cannot hold shutdown open forever. The grace
    // timer is .unref()-ed and cleared on a clean drain so `node --test` never
    // hangs on a leaked timer.
    close() {
      const graceMs = config.limits.shutdownGraceMs ?? 10000;
      return new Promise((resolve, reject) => {
        let settled = false;
        let graceTimer = null;

        const finish = (error) => {
          if (settled) {
            return;
          }
          settled = true;
          if (graceTimer) {
            clearTimeout(graceTimer);
            graceTimer = null;
          }
          resolveDrained = null;
          drained = null;
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        };

        // Stop accepting new connections; the callback fires once all
        // connections are closed (idle ones we close now, in-flight ones once
        // they drain or the grace timer force-closes them).
        server.close((error) => finish(error));

        // Close idle keep-alive sockets immediately so they don't keep the
        // server open waiting for a request that will never come.
        if (typeof server.closeIdleConnections === "function") {
          server.closeIdleConnections();
        }

        // If nothing is in flight, the close callback will fire promptly; still
        // arm a drain resolver in case requests are mid-flight.
        if (inFlight <= 0) {
          // No in-flight work; closeIdleConnections handled keep-alive, so
          // server.close() resolves on its own. Nothing more to wait for.
          return;
        }

        // Wait for in-flight requests to drain, then force-close stragglers
        // (the force close covers a request whose socket lingers after we stop).
        drained = new Promise((res) => { resolveDrained = res; });
        drained.then(() => {
          if (typeof server.closeAllConnections === "function") {
            server.closeAllConnections();
          }
        });

        // Grace cap: after graceMs force every remaining connection closed so a
        // lingering keep-alive socket cannot hold shutdown open forever. unref()
        // so this timer alone never keeps the event loop (and `node --test`) alive.
        graceTimer = setTimeout(() => {
          if (typeof server.closeAllConnections === "function") {
            server.closeAllConnections();
          }
        }, graceMs);
        if (typeof graceTimer.unref === "function") {
          graceTimer.unref();
        }
      });
    }
  };
}

// True for the reserved /__haechi/* observability routes (live/ready/health/
// metrics). These are EXEMPT from the in-flight ceiling so liveness + metrics
// stay scrapable under saturation, and they do not count toward drain tracking.
function isObservabilityRoute(request) {
  return request.method === "GET" && typeof request.url === "string" && request.url.startsWith("/__haechi/");
}

// Readiness probe (WS4-A). FAIL-CLOSED: a gateway that cannot write its audit
// log is NOT ready (503). Runs the audit sink's optional ready()/healthCheck()
// — if the sink lacks one, audit is treated as ready. The checks object carries
// only booleans/enums; never a path, payload, or PII value.
async function handleReady({ runtime, response }) {
  const checks = {};
  let ready = true;

  const probe = runtime.auditSink?.ready ?? runtime.auditSink?.healthCheck;
  if (typeof probe === "function") {
    try {
      const result = await probe.call(runtime.auditSink);
      checks.auditWritable = result === true || result?.ok === true;
    } catch {
      checks.auditWritable = false;
    }
  } else {
    // No probe method on the sink → cannot disprove writability; treat as ready.
    checks.auditWritable = true;
  }
  if (checks.auditWritable !== true) {
    ready = false;
  }

  writeJson(response, ready ? 200 : 503, { ready, version: HAECHI_VERSION, checks });
}

// Increment the request counter with a bounded enum label set. route is a route
// id, mode is the policy mode, decision is a fixed decision class — NEVER an
// identity/token/detected value (no-PII-in-telemetry invariant).
function countDecision(metrics, { routeContext, mode, decision }) {
  metrics?.increment("haechi_requests_total", {
    route: routeContext?.routeId ?? "unknown",
    mode: mode ?? "unknown",
    decision
  });
}

// Backward-compat fallback for a hand-built runtime object without metrics: a
// no-op collector with the same increment/observe/render contract.
function noopMetrics() {
  return {
    increment() {},
    observe() {},
    render() {
      return "";
    }
  };
}

// Authenticate → resolve policy profile → rate-limit. Returns the request's
// identity/profile/policyEngine/modelAllowlist, or a denial. Auth is required
// exactly when an authProvider is configured (auth.provider !== "none").
async function authorizeRequest({ runtime, request, routeContext, rateLimiter, metrics, correlationId }) {
  const { authProvider, policyProfiles, config } = runtime;
  const mode = config.policy.mode ?? config.mode;
  let identity = null;

  if (authProvider) {
    try {
      identity = await authProvider.authenticate(request);
    } catch {
      await recordAuthDenied({ runtime, routeContext, reason: "provider_error", correlationId });
      countDecision(metrics, { routeContext, mode, decision: "auth_denied" });
      metrics.increment("haechi_auth_denied_total");
      return { denied: { status: 401, error: "haechi_auth_denied", message: "Authentication failed" } };
    }
    if (!identity) {
      const reason = hasBearerHeader(request) ? "invalid_token" : "no_token";
      await recordAuthDenied({ runtime, routeContext, reason, correlationId });
      countDecision(metrics, { routeContext, mode, decision: "auth_denied" });
      metrics.increment("haechi_auth_denied_total");
      return { denied: { status: 401, error: "haechi_auth_denied", message: "Authentication required" } };
    }
  }

  const resolved = policyProfiles.resolve(identity);

  if (resolved.rate && resolved.rate.requestsPerMinute) {
    const key = identity?.id ?? "anonymous";
    // allow() may return a boolean OR a Promise<boolean>: the built-in default is
    // synchronous, but a shared-store (e.g. Redis-backed) limiter is inherently
    // async. We await unconditionally — `await <boolean>` returns the boolean
    // unchanged, so the sync default keeps working, while `!somePromise` (always
    // false, because a Promise is truthy) can no longer let an async limiter
    // silently fail open. See haechi-ratelimit-redis (shared-store satellite).
    if (!(await rateLimiter.allow(key, resolved.rate.requestsPerMinute))) {
      await recordProxyDecision({
        runtime, routeContext, identity, profile: resolved.profile, correlationId,
        decision: "rate_limited",
        reason: `rate:${resolved.rate.requestsPerMinute}`,
        enforced: true,
        blocked: true
      });
      countDecision(metrics, { routeContext, mode, decision: "rate_limited" });
      metrics.increment("haechi_rate_limited_total");
      return { denied: { status: 429, error: "haechi_rate_limited", message: "Rate limit exceeded" } };
    }
  }

  return {
    identity,
    profile: resolved.profile,
    policyEngine: resolved.policyEngine,
    modelAllowlist: resolved.modelAllowlist
  };
}

function hasBearerHeader(request) {
  const header = request?.headers?.authorization ?? request?.headers?.Authorization;
  return typeof header === "string" && /^Bearer\s+/i.test(header.trim());
}

function createRateLimiter() {
  // Backward-compat fallback ONLY: the canonical default lives in the runtime
  // (createRuntime owns providers.rateLimiter). This path runs when a hand-built
  // runtime object lacks rateLimiter. In-memory fixed-window counter, per-process
  // (resets on restart, not shared across replicas). The window Map is bounded by
  // a lazy, amortized sweep — NO timer — so aged-out one-shot identities do not
  // accumulate unboundedly (mirrors runtime's createRateLimiter).
  const windows = new Map();
  const windowMs = 60000;
  const sweepThreshold = 1024;
  const sweepBudget = 256;

  function sweepExpired(now) {
    let scanned = 0;
    for (const [key, slot] of windows) {
      if (scanned >= sweepBudget) {
        break;
      }
      scanned += 1;
      if (now - slot.windowStart >= windowMs) {
        windows.delete(key);
      }
    }
  }

  return {
    allow(key, limit) {
      const now = Date.now();
      if (windows.size >= sweepThreshold) {
        sweepExpired(now);
      }
      const slot = windows.get(key);
      if (!slot || now - slot.windowStart >= windowMs) {
        windows.set(key, { windowStart: now, count: 1 });
        return true;
      }
      if (slot.count >= limit) {
        return false;
      }
      slot.count += 1;
      return true;
    }
  };
}

async function recordAuthDenied({ runtime, routeContext, reason, correlationId = null }) {
  await recordProxyDecision({
    runtime, routeContext, identity: null, profile: null, correlationId,
    decision: "auth_denied",
    reason,
    enforced: true,
    blocked: true
  });
}

async function handleInspectedStream({ runtime, request, response, routeContext, json, authContext = {}, metrics = null, forwardPolicy = {} }) {
  const { haechi, config } = runtime;
  const requestMode = config.policy.mode ?? config.mode;

  // Inspection needs to know the wire format and delta channel for this route.
  if (!routeContext.streaming) {
    writeJson(response, 501, {
      error: "haechi_streaming_uninspectable_route",
      message: `streaming.requestMode is "inspect" but route ${routeContext.routeId} has no known streaming format`
    });
    return;
  }

  // The request body is ordinary JSON even when the response streams, so it is
  // protected like any other request.
  const requestResult = routeContext.protectRequest
    ? await haechi.protectJson(json, {
      ...routeContext,
      ...authContext,
      operation: `request:${routeContext.operation}`,
      direction: "request",
      mode: config.policy.mode ?? config.mode
    })
    : { payload: json, blocked: false };

  if (requestResult.blocked) {
    countDecision(metrics, { routeContext, mode: requestMode, decision: "blocked" });
    metrics?.increment("haechi_blocks_total");
    writeJson(response, 403, {
      error: "haechi_policy_block",
      summary: requestResult.summary,
      auditId: requestResult.auditEvent.id
    });
    return;
  }

  const upstreamResponse = await forward({
    upstream: config.target.upstream,
    request,
    body: JSON.stringify(requestResult.payload),
    timeoutMs: config.limits.upstreamTimeoutMs,
    metrics,
    forwardPolicy
  });

  const streamMode = config.streaming.responseMode ?? config.responseProtection.mode ?? config.policy.mode ?? config.mode;
  const protector = haechi.createStreamProtector({
    ...routeContext,
    ...authContext,
    operation: `response-stream:${routeContext.operation}`,
    direction: "response",
    mode: streamMode,
    maxMatchBytes: config.streaming.maxMatchBytes
  });

  response.writeHead(upstreamResponse.status, sanitizeResponseHeaders(upstreamResponse));

  const { blocked, summary } = await inspectResponseStream({
    source: upstreamResponse.body ?? emptyAsyncIterable(),
    sink: nodeResponseSink(response),
    streaming: routeContext.streaming,
    protector
  });

  await recordStreamDecision({
    runtime, routeContext, blocked, summary, mode: streamMode,
    identity: authContext.identity ?? null, profile: authContext.profile ?? null,
    correlationId: authContext.correlationId ?? null
  });
  countDecision(metrics, { routeContext, mode: streamMode, decision: blocked ? "stream_blocked" : "stream_inspected" });
  if (blocked) {
    metrics?.increment("haechi_blocks_total");
  }
  response.end();
}

// P1-CR-003 — the SINGLE centralized response-header sanitizer used on EVERY
// response path (pass-through, forwarded/unprotected, protected, streaming).
// Node fetch() auto-decompresses gzip/br/deflate, so the upstream's original
// content-encoding/content-length now describe the WIRE bytes Haechi no longer
// emits — forwarding them makes a downstream client see "content-encoding: gzip"
// on plain bytes and fail with "incorrect header check". transfer-encoding and
// the hop-by-hop control headers (RFC 7230 §6.1) likewise describe the upstream
// hop, not Haechi's connection to the client, so they are stripped too. A
// correct content-length is re-set ONLY by a caller that emits a fully-buffered
// body (transformedJsonHeaders / the buffered-body helper below); a streamed or
// raw-piped body intentionally carries no content-length.
const RESPONSE_HOP_BY_HOP_HEADERS = [
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "upgrade",
  "proxy-authenticate"
];

function sanitizeResponseHeaders(upstreamResponse) {
  const headers = Object.fromEntries(upstreamResponse.headers.entries());
  for (const name of RESPONSE_HOP_BY_HOP_HEADERS) {
    delete headers[name];
  }
  return headers;
}

// P1-CR-004 — the byte cap for the streaming pass-through path. Reuse
// responseProtection.maxBytes (the existing hard response-size cap) so a single
// dial governs all raw upstream-body reads; falls back to a 1 MiB default for a
// hand-built config without responseProtection.
function streamingPassThroughMaxBytes(config) {
  const cap = config.responseProtection?.maxBytes;
  return typeof cap === "number" && cap > 0 ? cap : 1048576;
}

// P1-CR-004 — TRUE bounded streaming pass-through. Pipe the upstream body to the
// client response as it arrives (real streaming) while counting bytes; if the
// running total exceeds maxBytes, abort: cancel the upstream reader and destroy
// the client response so a long-lived or malicious stream cannot hold memory or
// the connection open unbounded. Bytes already written cannot be retracted, so
// this caps total memory/throughput, not the already-flushed prefix.
async function pipeUpstreamBodyBounded({ upstreamResponse, response, request = null, maxBytes, abortController = null, logger = null, metrics = null, correlationId = null }) {
  if (!upstreamResponse.body) {
    response.end();
    return;
  }

  const reader = upstreamResponse.body.getReader();
  let received = 0;

  // CR2-001 — a ONE-SHOT teardown on a downstream client disconnect. Without it,
  // a parked `await once(response, "drain")` (backpressure) or a parked
  // `await reader.read()` (no backpressure, upstream idle) never unparks after the
  // client socket dies — neither `drain` nor `error` fires — so the async task and
  // the upstream connection leak. On `close`/`aborted` we cancel the upstream
  // reader (interrupts a parked read) AND abort the upstream fetch (tears down the
  // connection); the listeners are removed on normal completion so the happy path
  // does not leak a handle.
  let disconnected = false;
  // A SINGLE promise resolved by the one-shot tearDown below, so the backpressure
  // wait can race against the disconnect WITHOUT registering a fresh `close`
  // listener every drain cycle (which would accumulate on a sustained
  // backpressured stream and trip MaxListenersExceededWarning).
  let signalDisconnected;
  const disconnectedPromise = new Promise((resolve) => {
    signalDisconnected = resolve;
  });
  const tearDown = () => {
    if (disconnected) {
      return;
    }
    disconnected = true;
    signalDisconnected();
    void cancelReader(reader);
    abortController?.abort();
  };
  const disconnectSources = [response, request].filter(Boolean);
  for (const source of disconnectSources) {
    source.once("close", tearDown);
    source.once("aborted", tearDown);
  }
  const cleanupListeners = () => {
    for (const source of disconnectSources) {
      source.removeListener("close", tearDown);
      source.removeListener("aborted", tearDown);
    }
  };

  try {
    while (true) {
      if (disconnected) {
        return;
      }
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      received += value.byteLength;
      if (maxBytes && received > maxBytes) {
        // Over the cap: stop reading upstream and tear down the client write so
        // the oversize stream is bounded (fail-closed on size).
        void cancelReader(reader);
        abortController?.abort();
        metrics?.increment("haechi_response_stream_truncated_total");
        logger?.error("proxy_stream_pass_through_too_large", {
          correlationId,
          maxBytes
        });
        if (!response.writableEnded) {
          response.destroy();
        }
        return;
      }
      // Respect downstream backpressure: stop pulling upstream until the client
      // socket has drained. CR2-001 — race the drain wait against `close` so a
      // client disconnect mid-backpressure unparks the wait instead of hanging
      // until the request timeout.
      const ok = response.write(Buffer.from(value));
      if (!ok && !disconnected) {
        await Promise.race([
          once(response, "drain"),
          disconnectedPromise
        ]);
        if (disconnected || response.writableEnded || response.destroyed) {
          return;
        }
      }
    }
    response.end();
  } catch (error) {
    void cancelReader(reader);
    abortController?.abort();
    if (!response.writableEnded) {
      response.destroy();
    }
  } finally {
    cleanupListeners();
  }
}

function nodeResponseSink(response) {
  return {
    write(text) {
      response.write(text);
    }
  };
}

async function* emptyAsyncIterable() {
  // No upstream body to inspect.
}

async function recordStreamDecision({ runtime, routeContext, blocked, summary, mode, identity = null, profile = null, correlationId = null }) {
  if (typeof runtime.auditSink?.record !== "function") {
    return;
  }
  await runtime.auditSink.record({
    id: randomUUID(),
    correlationId,
    timestamp: new Date().toISOString(),
    protocol: routeContext?.protocol ?? "proxy",
    operation: `response-stream:${routeContext?.operation ?? "unknown"}`,
    mode,
    identity,
    profile,
    enforced: !["dry-run", "report-only"].includes(mode),
    blocked,
    decision: blocked ? "stream_blocked" : "stream_inspected",
    reason: blocked ? "stream_policy_block" : "stream_inspected",
    routeId: routeContext?.routeId ?? "unknown",
    pathHash: routeContext?.path ? shortHash(routeContext.path) : null,
    summary
  });
}

async function maybeProtectResponse({ upstreamResponse, routeContext, runtime, authContext = {}, issuedTokens = [], metrics = null }) {
  // P1-CR-003 — content-encoding is read off the RAW upstream headers (before
  // sanitation) for the compressed-response gate; the headers RETURNED to the
  // client are always the sanitized set (no stale compression/length metadata).
  const rawHeaders = Object.fromEntries(upstreamResponse.headers.entries());
  const headers = sanitizeResponseHeaders(upstreamResponse);

  if (!runtime.config.responseProtection.enabled || !routeContext.protectResponse) {
    // P1-CR-004 — apply the same byte cap to this raw upstream-body read so an
    // unprotected/forwarded response cannot be buffered unbounded. Fail closed
    // (502) when the upstream body exceeds the cap.
    const passThroughMax = streamingPassThroughMaxBytes(runtime.config);
    const { body: rawBody, tooLarge } = await readUpstreamBody(upstreamResponse, { maxBytes: passThroughMax });
    if (tooLarge) {
      metrics?.increment("haechi_response_stream_truncated_total");
      return {
        decision: "response_unprotected_blocked",
        status: 502,
        headers: { "content-type": "application/json" },
        body: Buffer.from(`${JSON.stringify({
          error: "haechi_response_too_large",
          reason: "response_body_too_large",
          message: `Response body exceeds responseProtection.maxBytes (${passThroughMax})`
        }, null, 2)}\n`)
      };
    }
    return {
      status: upstreamResponse.status,
      // Re-set a correct content-length: this is a fully-buffered body.
      headers: { ...headers, "content-length": String(rawBody.byteLength) },
      body: rawBody,
      decision: "forwarded"
    };
  }

  const responsePolicy = runtime.config.responseProtection;
  const contentEncoding = rawHeaders["content-encoding"] ?? "";
  const bodyRead = await readUpstreamBody(upstreamResponse, { maxBytes: responsePolicy.maxBytes });

  if (bodyRead.tooLarge) {
    return unprotectedResponseDecision({
      reason: "response_body_too_large",
      detail: `Response body exceeds responseProtection.maxBytes (${responsePolicy.maxBytes})`,
      upstreamResponse,
      headers,
      rawBody: bodyRead.body,
      responsePolicy,
      routeContext,
      runtime,
      correlationId: authContext.correlationId ?? null,
      metrics,
      hardDeny: true
    });
  }

  const rawBody = bodyRead.body;

  if (rawBody.byteLength > responsePolicy.maxBytes) {
    return unprotectedResponseDecision({
      reason: "response_body_too_large",
      detail: `Response body exceeds responseProtection.maxBytes (${responsePolicy.maxBytes})`,
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy,
      routeContext,
      runtime,
      correlationId: authContext.correlationId ?? null,
      metrics,
      hardDeny: true
    });
  }

  if (contentEncoding && contentEncoding.toLowerCase() !== "identity" && !responsePolicy.allowCompressed) {
    return unprotectedResponseDecision({
      reason: "compressed_response",
      detail: "Compressed responses cannot be inspected by responseProtection",
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy,
      routeContext,
      runtime,
      correlationId: authContext.correlationId ?? null,
      metrics
    });
  }

  if (!isJson(headers["content-type"])) {
    return unprotectedResponseDecision({
      reason: "non_json_response",
      detail: "Non-JSON responses cannot be inspected by responseProtection",
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy,
      routeContext,
      runtime,
      correlationId: authContext.correlationId ?? null,
      metrics
    });
  }

  let json;
  try {
    json = JSON.parse(rawBody.toString("utf8"));
  } catch (error) {
    return unprotectedResponseDecision({
      reason: "invalid_json_response",
      detail: error.message,
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy,
      routeContext,
      runtime,
      correlationId: authContext.correlationId ?? null,
      metrics
    });
  }

  const result = await runtime.haechi.protectJson(json, {
    ...routeContext,
    ...authContext,
    operation: `response:${routeContext.operation}`,
    direction: "response",
    // Opt-in: scan bare number leaves on the response (off by default — they are
    // inference-server metadata; see the filter engine's number-leaf skip).
    scanNumbers: runtime.config.responseProtection.scanNumbers,
    mode: runtime.config.responseProtection.mode ?? runtime.config.policy.mode ?? runtime.config.mode
  });

  if (result.blocked) {
    metrics?.increment("haechi_blocks_total");
    return {
      decision: "response_blocked",
      status: 502,
      headers: { "content-type": "application/json" },
      body: Buffer.from(`${JSON.stringify({
        error: "haechi_response_policy_block",
        summary: result.summary,
        auditId: result.auditEvent.id
      }, null, 2)}\n`)
    };
  }

  let responsePayload = result.payload;

  // Request-scoped token round-trip: restore ONLY tokens issued/reused while
  // protecting this request, so the model sees tokens but the caller sees
  // plaintext. Explicit opt-in; runs after response protection, so an opt-in
  // here intentionally overrides response-direction transforms for values the
  // caller already sent.
  if (runtime.config.tokenVault.detokenizeResponses
    && issuedTokens.length > 0
    && typeof runtime.tokenVault?.detokenize === "function") {
    const values = await runtime.tokenVault.detokenize({ tokens: issuedTokens });
    if (values.size > 0) {
      responsePayload = restoreTokens(responsePayload, values);
    }
  }

  return {
    decision: "forwarded",
    status: upstreamResponse.status,
    headers: transformedJsonHeaders(headers),
    body: Buffer.from(`${JSON.stringify(responsePayload)}\n`)
  };
}

function restoreTokens(value, tokenValues) {
  if (typeof value === "string") {
    let output = value;
    for (const [token, plaintext] of tokenValues) {
      output = output.split(`[TOKEN:${token}]`).join(plaintext);
    }
    return output;
  }
  if (Array.isArray(value)) {
    return value.map((item) => restoreTokens(item, tokenValues));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .map(([key, item]) => [restoreTokens(key, tokenValues), restoreTokens(item, tokenValues)]));
  }
  return value;
}

async function forward({ upstream, request, body, timeoutMs = null, metrics = null, forwardPolicy = {}, abortController = null }) {
  const target = buildUpstreamUrl({ upstream, requestUrl: request.url });
  // CR2-001 — combine the upstream timeout with a per-request AbortController so a
  // downstream client disconnect (which aborts `abortController`) tears down the
  // in-flight upstream fetch + its body, instead of leaking the connection.
  const timeoutSignal = timeoutMs ? AbortSignal.timeout(timeoutMs) : null;
  let signal;
  if (abortController && timeoutSignal) {
    signal = AbortSignal.any([abortController.signal, timeoutSignal]);
  } else {
    signal = abortController ? abortController.signal : timeoutSignal ?? undefined;
  }
  try {
    return await fetch(target, {
      method: request.method,
      headers: filteredHeaders(request.headers, forwardPolicy),
      body: request.method === "GET" || request.method === "HEAD" ? undefined : body,
      signal
    });
  } catch (error) {
    if (error?.name === "TimeoutError" || error?.name === "AbortError") {
      metrics?.increment("haechi_upstream_timeout_total");
      throw proxyError({
        statusCode: 504,
        errorCode: "haechi_upstream_timeout",
        message: `Upstream did not respond within limits.upstreamTimeoutMs (${timeoutMs})`
      });
    }
    metrics?.increment("haechi_upstream_error_total");
    throw proxyError({
      statusCode: 502,
      errorCode: "haechi_upstream_unreachable",
      message: "Upstream request failed"
    });
  }
}

function buildUpstreamUrl({ upstream, requestUrl }) {
  assertRelativeProxyTarget(requestUrl);
  const parsed = new URL(requestUrl, "http://haechi.local");
  return new URL(`${parsed.pathname}${parsed.search}`, upstream.endsWith("/") ? upstream : `${upstream}/`);
}

// P0-CR-001 — DEFAULT-DROP upstream header allowlist. The client's request
// headers cross from the local gateway trust boundary into the MODEL PROVIDER
// boundary, so the policy is: forward ONLY a known-safe set; everything else
// (including ambient client credentials — Cookie, Proxy-Authorization, and the
// client's gateway Authorization) is dropped. The conditional `authorization`
// rule is handled in filteredHeaders against the forward policy. An operator can
// additively widen the set with `target.forwardHeaders` for an unusual upstream.
//
// The forwarded set is exactly the headers the OpenAI-compatible / Anthropic /
// Gemini adapters need: the provider key headers (x-api-key, x-goog-api-key,
// openai-organization, openai-beta), provider version/feature pins
// (anthropic-version, anthropic-beta), and benign request metadata (accept,
// content-type — always rewritten to application/json, user-agent,
// accept-language). content-type is set unconditionally below so it is NOT in
// this set.
const FORWARD_HEADER_ALLOWLIST = new Set([
  "x-api-key",
  "anthropic-version",
  "anthropic-beta",
  "x-goog-api-key",
  "openai-organization",
  "openai-beta",
  "accept",
  "user-agent",
  "accept-language"
]);

// ALWAYS-DROP: ambient client credentials + hop-by-hop control headers. These
// must NEVER reach the upstream regardless of the allowlist or the operator's
// target.forwardHeaders extension (a fail-closed denylist that wins over both).
//   - host / content-length: rewritten/recomputed by fetch for the new request.
//   - cookie / set-cookie / proxy-authorization: ambient client credentials.
//   - connection / keep-alive / te / trailer / transfer-encoding / upgrade:
//     hop-by-hop headers (RFC 7230 §6.1) that must not be tunneled end-to-end.
const FORWARD_HEADER_DENYLIST = new Set([
  "host",
  "content-length",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

// `forwardPolicy` is built by createHaechiProxy from the runtime: it carries
//   - gatewayConsumedAuthorization: true when auth.provider !== "none", i.e. the
//     gateway authenticated the CLIENT with the request's Authorization. That
//     header is the GATEWAY credential Haechi already consumed; forwarding it
//     would leak a gateway secret into the model provider, so it is DROPPED.
//     When false (auth.provider "none"), the client's Authorization is the
//     UPSTREAM provider key (the OpenAI-compatible pass-through pattern), so it
//     is FORWARDED.
//   - extraHeaders: the operator's additive target.forwardHeaders allowlist
//     (lowercase names) — never able to override the always-drop denylist.
function filteredHeaders(headers, forwardPolicy = {}) {
  const gatewayConsumedAuthorization = Boolean(forwardPolicy.gatewayConsumedAuthorization);
  const extraHeaders = forwardPolicy.extraHeaders instanceof Set
    ? forwardPolicy.extraHeaders
    : new Set(Array.isArray(forwardPolicy.extraHeaders) ? forwardPolicy.extraHeaders : []);

  const next = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (!value) {
      continue;
    }
    const name = key.toLowerCase();

    // Always-drop wins over everything (credentials + hop-by-hop).
    if (FORWARD_HEADER_DENYLIST.has(name)) {
      continue;
    }

    // Conditional gateway-vs-upstream Authorization separation.
    if (name === "authorization") {
      if (gatewayConsumedAuthorization) {
        // Gateway token Haechi already consumed — must not leak upstream.
        continue;
      }
      // auth.provider "none": the client put the UPSTREAM provider key here.
      appendHeader(next, key, value);
      continue;
    }

    // content-type is rewritten unconditionally below; skip the client's value.
    if (name === "content-type") {
      continue;
    }

    if (FORWARD_HEADER_ALLOWLIST.has(name) || extraHeaders.has(name)) {
      appendHeader(next, key, value);
    }
    // Everything else is default-dropped (fail-closed).
  }
  next.set("content-type", "application/json");
  return next;
}

function appendHeader(target, key, value) {
  if (Array.isArray(value)) {
    for (const item of value) {
      target.append(key, item);
    }
  } else {
    target.set(key, value);
  }
}

function readBody(request, { maxBytes, response = null }) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let rejected = false;

    request.on("data", (chunk) => {
      if (rejected) {
        return;
      }
      received += chunk.byteLength;
      if (received > maxBytes) {
        rejected = true;
        // CR2-005 — stop reading and release the socket PROMPTLY instead of
        // reading-and-discarding the rest of the upload until Node's finite
        // requestTimeout. pause() halts the flowing read immediately (no further
        // data is consumed); the connection is then torn down — but only AFTER the
        // 413 has been written, so the client still receives it. The 413 carries
        // `Connection: close` and the socket is destroyed once the response
        // finishes/closes (destroying before the response is sent would reset the
        // socket and the client would get a transport error instead of the 413).
        request.pause();
        if (response) {
          const destroyRequest = () => {
            if (!request.destroyed) {
              request.destroy();
            }
          };
          response.once("finish", destroyRequest);
          response.once("close", destroyRequest);
        } else {
          request.destroy();
        }
        reject(proxyError({
          statusCode: 413,
          errorCode: "haechi_request_body_too_large",
          message: `Request body exceeds limits.maxRequestBytes (${maxBytes})`
        }));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (rejected) {
        return;
      }
      const raw = Buffer.concat(chunks);
      // Fail closed on a non-UTF-8 body: Buffer.toString("utf8") would otherwise
      // replace invalid bytes with U+FFFD BEFORE detection runs, so a secret/PII
      // could be smuggled past the regex rules via invalid encoding. Reject with
      // a clear 4xx instead of lossily decoding.
      if (raw.byteLength > 0 && !isUtf8(raw)) {
        reject(proxyError({
          statusCode: 400,
          errorCode: "haechi_request_body_not_utf8",
          message: "Request body is not valid UTF-8"
        }));
        return;
      }
      resolve(raw.toString("utf8"));
    });
    request.on("error", (error) => {
      if (!rejected) {
        reject(error);
      }
    });
  });
}

function parseJsonBody(body) {
  if (!body) {
    return {};
  }

  try {
    return JSON.parse(body);
  } catch (error) {
    throw proxyError({
      statusCode: 400,
      errorCode: "haechi_invalid_json_request",
      message: error.message
    });
  }
}

function writeJson(response, status, body, extraHeaders = null) {
  response.writeHead(status, { "content-type": "application/json", ...(extraHeaders ?? {}) });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function isJson(contentType = "") {
  return contentType.toLowerCase().includes("application/json");
}

// CR2-004 — body-coupled validator headers that describe the UPSTREAM body. On a
// transformed (protected/redacted/re-serialized) response the body changed, so
// these become stale and must be dropped (a client/proxy honoring the upstream's
// etag/last-modified could otherwise serve or revalidate against the wrong body).
const BODY_COUPLED_VALIDATOR_HEADERS = [
  "etag",
  "content-md5",
  "digest",
  "last-modified"
];

function transformedJsonHeaders(headers) {
  // P1-CR-003 — defensively strip the full hop-by-hop/compression set (the
  // caller already passes the sanitized headers, but the transformed JSON body
  // is freshly serialized, so any stale length/encoding metadata must not leak).
  const next = { ...headers, "content-type": "application/json" };
  for (const name of RESPONSE_HOP_BY_HOP_HEADERS) {
    delete next[name];
  }
  // CR2-004 — the body was MUTATED, so drop validators coupled to the upstream
  // body and forbid caching the rewritten response. This path only (the raw
  // pass-through path keeps its etag — its body is byte-unchanged so still valid).
  for (const name of BODY_COUPLED_VALIDATOR_HEADERS) {
    delete next[name];
  }
  next["cache-control"] = "no-store";
  return next;
}

async function unprotectedResponseDecision({
  reason,
  detail,
  upstreamResponse,
  headers,
  rawBody,
  responsePolicy,
  routeContext,
  runtime,
  metrics = null,
  correlationId = null,
  hardDeny = false
}) {
  const allowed = responsePolicy.failureMode === "allow" && !hardDeny;
  const decision = allowed ? "response_unprotected_allowed" : "response_unprotected_blocked";
  await recordProxyDecision({
    runtime,
    routeContext,
    correlationId,
    decision,
    reason,
    enforced: !allowed,
    blocked: !allowed
  });
  // A forwarded-without-protection (or blocked-because-unprotectable) response is
  // an operability signal. The label is the bounded reason enum, never a value.
  metrics?.increment("haechi_response_unprotected_total");

  if (allowed) {
    // P1-CR-003 — `headers` is already the sanitized set (no stale
    // compression/length metadata). Re-set a correct content-length for this
    // fully-buffered body.
    return {
      decision,
      status: upstreamResponse.status,
      headers: { ...headers, "content-length": String(rawBody.byteLength) },
      body: rawBody
    };
  }

  if (!hardDeny) {
    metrics?.increment("haechi_blocks_total");
  }
  return {
    decision,
    status: 502,
    headers: { "content-type": "application/json" },
    body: Buffer.from(`${JSON.stringify({
      error: "haechi_response_unprotected",
      reason,
      message: detail
    }, null, 2)}\n`)
  };
}

async function readUpstreamBody(upstreamResponse, { maxBytes = null } = {}) {
  const contentLength = parseContentLength(upstreamResponse.headers.get("content-length"));
  if (maxBytes && contentLength !== null && contentLength > maxBytes) {
    void cancelUpstreamBody(upstreamResponse);
    return {
      body: Buffer.alloc(0),
      tooLarge: true,
      receivedBytes: contentLength
    };
  }

  if (!upstreamResponse.body) {
    return {
      body: Buffer.alloc(0),
      tooLarge: false,
      receivedBytes: 0
    };
  }

  const reader = upstreamResponse.body.getReader();
  const chunks = [];
  let receivedBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      return {
        body: Buffer.concat(chunks),
        tooLarge: false,
        receivedBytes
      };
    }

    receivedBytes += value.byteLength;
    if (maxBytes && receivedBytes > maxBytes) {
      void cancelReader(reader);
      return {
        body: Buffer.concat(chunks),
        tooLarge: true,
        receivedBytes
      };
    }
    chunks.push(Buffer.from(value));
  }
}

function parseContentLength(value) {
  if (!value) {
    return null;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

async function cancelUpstreamBody(upstreamResponse) {
  try {
    await upstreamResponse.body?.cancel();
  } catch {
    // Best-effort cancellation after a hard size cap decision.
  }
}

async function cancelReader(reader) {
  try {
    await reader.cancel();
  } catch {
    // Best-effort cancellation after a hard size cap decision.
  }
}

async function recordProxyDecision({ runtime, routeContext, decision, reason, enforced, blocked, identity = null, profile = null, correlationId = null }) {
  if (typeof runtime.auditSink?.record !== "function") {
    return;
  }

  await runtime.auditSink.record({
    id: randomUUID(),
    // Per-request correlation id so a proxy-decision event shares the id of the
    // protect events of the same request. A UUID — never a payload/PII value.
    correlationId,
    timestamp: new Date().toISOString(),
    protocol: routeContext?.protocol ?? "proxy",
    operation: routeContext ? `proxy:${routeContext.protocol}:${routeContext.routeId ?? "unknown"}` : "proxy",
    mode: runtime.config.policy.mode ?? runtime.config.mode,
    identity,
    profile,
    enforced,
    blocked,
    decision,
    reason,
    routeId: routeContext?.routeId ?? "unknown",
    pathHash: routeContext?.path ? shortHash(routeContext.path) : null,
    summary: {
      detectionCount: 0,
      byType: {},
      byAction: {
        [decision]: 1
      }
    }
  });
}

function isStreamingRequest(value, routeContext = {}) {
  if (!value || typeof value !== "object") {
    return false;
  }
  if (value.stream === true) {
    return true;
  }
  // Routes that stream unless explicitly disabled (e.g. Ollama /api/chat,
  // /api/generate) are treated as streaming whenever stream !== false.
  if (routeContext.streamingByDefault && value.stream !== false) {
    return true;
  }
  return false;
}

function proxyError({ statusCode, errorCode, message }) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.errorCode = errorCode;
  return error;
}

function assertRelativeProxyTarget(url) {
  const target = String(url ?? "").trim();
  if (/^[A-Za-z][A-Za-z\d+.-]*:/.test(target) || target.startsWith("//")) {
    throw proxyError({
      statusCode: 400,
      errorCode: "haechi_invalid_proxy_target",
      message: "Proxy request target must be origin-form path, not an absolute URL"
    });
  }
}

function shortHash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

// X-Forwarded-Proto enforcement helper. Node lowercases header names; a comma-
// joined multi-value header (e.g. "https, http" from a chain of proxies) is
// trusted only when the FIRST hop — the one closest to the client, set by the
// trusted terminator — is https. Any other value (http, missing, malformed)
// fails closed.
function isForwardedHttps(request) {
  const raw = request?.headers?.["x-forwarded-proto"];
  if (typeof raw !== "string" || raw.length === 0) {
    return false;
  }
  const first = raw.split(",")[0].trim().toLowerCase();
  return first === "https";
}

// Loopback / remote-bind gate. Loopback always binds (plain http for dev). A
// non-loopback bind is refused UNLESS allowRemoteBind is set. This is the SHARED
// primitive the haechi-dashboard satellite reuses, so its contract is preserved
// unchanged: { host, allowRemoteBind } and nothing more. The WS6 TLS fail-closed
// rule is layered ON TOP of this in assertSafeProxyTransport (the proxy's own
// requirement that a remote bind carry TLS), mirroring how the dashboard layers
// its own tlsContext precedence after calling assertSafeProxyBind.
export function assertSafeProxyBind({ host = "127.0.0.1", allowRemoteBind = false } = {}) {
  if (allowRemoteBind || isLoopbackHost(host)) {
    return;
  }

  throw new Error(`Refusing to bind Haechi proxy to non-loopback host ${host}. Use --allow-remote-bind only for explicitly secured environments.`);
}

// WS6 fail-closed TLS requirement for a REMOTE bind. After the loopback/remote
// gate above, a non-loopback (allowRemoteBind) listener must ALSO carry usable
// TLS material (Haechi terminates TLS) OR an explicit trustForwardedProto
// acknowledgement (a trusted reverse proxy terminates TLS in front of Haechi).
// Neither → THROW: never serve bearer tokens + payloads in plaintext on a remote
// bind. Loopback dev is exempt (plain http, no TLS needed). Separate from
// assertSafeProxyBind so the dashboard satellite's reuse of that primitive is
// unaffected.
export function assertSafeProxyTransport({
  host = "127.0.0.1",
  allowRemoteBind = false,
  hasUsableTls = false,
  trustForwardedProto = false
} = {}) {
  if (isLoopbackHost(host) || !allowRemoteBind) {
    // Loopback (or an already-refused remote bind) needs no TLS check here.
    return;
  }
  if (!hasUsableTls && !trustForwardedProto) {
    throw new Error(
      `Refusing to bind Haechi proxy to non-loopback host ${host} without TLS. ` +
        `A remote bind would expose bearer tokens and payloads in plaintext. ` +
        `Set proxy.tls (a keyFile+certFile or pfxFile so Haechi terminates TLS), ` +
        `or set proxy.trustForwardedProto: true only when a trusted reverse proxy ` +
        `terminates TLS in front of Haechi (Haechi will then require X-Forwarded-Proto: https).`
    );
  }
}

function isLoopbackHost(host) {
  const normalized = String(host).trim().toLowerCase();
  return normalized === "localhost"
    || normalized === "::1"
    || normalized === "[::1]"
    || normalized === "0:0:0:0:0:0:0:1"
    || normalized === "127.0.0.1"
    || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized);
}
