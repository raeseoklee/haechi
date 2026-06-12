import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { inspectResponseStream } from "../stream-filter/index.mjs";

export const DEFAULT_PROXY_PORT = 11016;

export function createHaechiProxy({ runtime, port = DEFAULT_PROXY_PORT, host = "127.0.0.1", allowRemoteBind = false }) {
  assertSafeProxyBind({ host, allowRemoteBind });
  const { haechi, config, protocolAdapter } = runtime;
  const rateLimiter = createRateLimiter();

  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/__haechi/health") {
        // Intentionally unauthenticated; exposes only the mode.
        writeJson(response, 200, { ok: true, mode: config.mode });
        return;
      }

      assertRelativeProxyTarget(request.url);
      const routeContext = protocolAdapter.classifyRequest(request);

      // Authenticate, resolve the policy profile, and rate-limit BEFORE reading
      // the body, so a denied/throttled request cannot stream a large body.
      const gate = await authorizeRequest({ runtime, request, routeContext, rateLimiter });
      if (gate.denied) {
        writeJson(response, gate.denied.status, {
          error: gate.denied.error,
          message: gate.denied.message
        });
        return;
      }
      const { identity, profile, policyEngine, modelAllowlist } = gate;
      const authContext = { identity, profile, policyEngine };

      const body = await readBody(request, {
        maxBytes: config.limits.maxRequestBytes
      });
      const json = parseJsonBody(body);

      // Model allowlist runs after body read (the model field is in the body).
      if (modelAllowlist && typeof json?.model === "string" && !modelAllowlist.includes(json.model)) {
        await recordProxyDecision({
          runtime, routeContext, identity, profile,
          decision: "model_not_allowed",
          reason: `model:${json.model}`,
          enforced: true,
          blocked: true
        });
        writeJson(response, 403, {
          error: "haechi_model_not_allowed",
          message: `Model not allowed: ${json.model}`
        });
        return;
      }

      if (isStreamingRequest(json, routeContext)) {
        if (config.streaming.requestMode === "inspect") {
          await handleInspectedStream({ runtime, request, response, routeContext, json, authContext });
          return;
        }

        if (config.streaming.requestMode === "pass-through") {
          await recordProxyDecision({
            runtime,
            routeContext,
            identity,
            profile,
            decision: "streaming_request_pass_through",
            reason: "streaming_request_pass_through",
            enforced: false,
            blocked: false
          });
          const upstreamResponse = await forward({
            upstream: config.target.upstream,
            request,
            body,
            timeoutMs: config.limits.upstreamTimeoutMs
          });
          const { body: rawBody } = await readUpstreamBody(upstreamResponse);
          response.writeHead(upstreamResponse.status, Object.fromEntries(upstreamResponse.headers.entries()));
          response.end(rawBody);
          return;
        }

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
          mode: config.policy.mode ?? config.mode
        })
        : { payload: json, blocked: false };

      if (result.blocked) {
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
        timeoutMs: config.limits.upstreamTimeoutMs
      });

      const forwarded = await maybeProtectResponse({
        upstreamResponse,
        routeContext,
        runtime,
        authContext,
        issuedTokens: result.issuedTokens ?? []
      });

      response.writeHead(forwarded.status, forwarded.headers);
      response.end(forwarded.body);
    } catch (error) {
      const expected = typeof error?.statusCode === "number";
      if (!expected) {
        console.error(`haechi proxy internal error: ${error?.stack ?? error?.message ?? error}`);
      }
      writeJson(response, error.statusCode ?? 500, {
        error: error.errorCode ?? "haechi_proxy_error",
        message: expected ? error.message : "Internal proxy error"
      });
    }
  });

  return {
    server,
    listen() {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const address = server.address();
          resolve({ host: address.address, port: address.port });
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

// Authenticate → resolve policy profile → rate-limit. Returns the request's
// identity/profile/policyEngine/modelAllowlist, or a denial. Auth is required
// exactly when an authProvider is configured (auth.provider !== "none").
async function authorizeRequest({ runtime, request, routeContext, rateLimiter }) {
  const { authProvider, policyProfiles } = runtime;
  let identity = null;

  if (authProvider) {
    try {
      identity = await authProvider.authenticate(request);
    } catch {
      await recordAuthDenied({ runtime, routeContext, reason: "provider_error" });
      return { denied: { status: 401, error: "haechi_auth_denied", message: "Authentication failed" } };
    }
    if (!identity) {
      const reason = hasBearerHeader(request) ? "invalid_token" : "no_token";
      await recordAuthDenied({ runtime, routeContext, reason });
      return { denied: { status: 401, error: "haechi_auth_denied", message: "Authentication required" } };
    }
  }

  const resolved = policyProfiles.resolve(identity);

  if (resolved.rate && resolved.rate.requestsPerMinute) {
    const key = identity?.id ?? "anonymous";
    if (!rateLimiter.allow(key, resolved.rate.requestsPerMinute)) {
      await recordProxyDecision({
        runtime, routeContext, identity, profile: resolved.profile,
        decision: "rate_limited",
        reason: `rate:${resolved.rate.requestsPerMinute}`,
        enforced: true,
        blocked: true
      });
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
  // In-memory fixed-window counter. Per-process: resets on restart, not shared
  // across replicas — acceptable for a single-process self-hosted preview.
  const windows = new Map();
  const windowMs = 60000;
  return {
    allow(key, limit) {
      const now = Date.now();
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

async function recordAuthDenied({ runtime, routeContext, reason }) {
  await recordProxyDecision({
    runtime, routeContext, identity: null, profile: null,
    decision: "auth_denied",
    reason,
    enforced: true,
    blocked: true
  });
}

async function handleInspectedStream({ runtime, request, response, routeContext, json, authContext = {} }) {
  const { haechi, config } = runtime;

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
    timeoutMs: config.limits.upstreamTimeoutMs
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

  response.writeHead(upstreamResponse.status, streamingResponseHeaders(upstreamResponse));

  const { blocked, summary } = await inspectResponseStream({
    source: upstreamResponse.body ?? emptyAsyncIterable(),
    sink: nodeResponseSink(response),
    streaming: routeContext.streaming,
    protector
  });

  await recordStreamDecision({
    runtime, routeContext, blocked, summary, mode: streamMode,
    identity: authContext.identity ?? null, profile: authContext.profile ?? null
  });
  response.end();
}

function streamingResponseHeaders(upstreamResponse) {
  const headers = Object.fromEntries(upstreamResponse.headers.entries());
  delete headers["content-length"];
  delete headers["content-encoding"];
  return headers;
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

async function recordStreamDecision({ runtime, routeContext, blocked, summary, mode, identity = null, profile = null }) {
  if (typeof runtime.auditSink?.record !== "function") {
    return;
  }
  await runtime.auditSink.record({
    id: randomUUID(),
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

async function maybeProtectResponse({ upstreamResponse, routeContext, runtime, authContext = {}, issuedTokens = [] }) {
  const headers = Object.fromEntries(upstreamResponse.headers.entries());

  if (!runtime.config.responseProtection.enabled || !routeContext.protectResponse) {
    const { body: rawBody } = await readUpstreamBody(upstreamResponse);
    return {
      status: upstreamResponse.status,
      headers,
      body: rawBody
    };
  }

  const responsePolicy = runtime.config.responseProtection;
  const contentEncoding = headers["content-encoding"] ?? "";
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
      runtime
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
      runtime
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
      runtime
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
    return {
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

async function forward({ upstream, request, body, timeoutMs = null }) {
  const target = buildUpstreamUrl({ upstream, requestUrl: request.url });
  try {
    return await fetch(target, {
      method: request.method,
      headers: filteredHeaders(request.headers),
      body: request.method === "GET" || request.method === "HEAD" ? undefined : body,
      signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined
    });
  } catch (error) {
    if (error?.name === "TimeoutError" || error?.name === "AbortError") {
      throw proxyError({
        statusCode: 504,
        errorCode: "haechi_upstream_timeout",
        message: `Upstream did not respond within limits.upstreamTimeoutMs (${timeoutMs})`
      });
    }
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

function filteredHeaders(headers) {
  const next = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (!value || ["host", "content-length"].includes(key.toLowerCase())) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        next.append(key, item);
      }
    } else {
      next.set(key, value);
    }
  }
  next.set("content-type", "application/json");
  return next;
}

function readBody(request, { maxBytes }) {
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

function writeJson(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function isJson(contentType = "") {
  return contentType.toLowerCase().includes("application/json");
}

function transformedJsonHeaders(headers) {
  const next = { ...headers, "content-type": "application/json" };
  delete next["content-length"];
  delete next["content-encoding"];
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
  hardDeny = false
}) {
  const allowed = responsePolicy.failureMode === "allow" && !hardDeny;
  await recordProxyDecision({
    runtime,
    routeContext,
    decision: allowed ? "response_unprotected_allowed" : "response_unprotected_blocked",
    reason,
    enforced: !allowed,
    blocked: !allowed
  });

  if (allowed) {
    return {
      status: upstreamResponse.status,
      headers,
      body: rawBody
    };
  }

  return {
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

async function recordProxyDecision({ runtime, routeContext, decision, reason, enforced, blocked, identity = null, profile = null }) {
  if (typeof runtime.auditSink?.record !== "function") {
    return;
  }

  await runtime.auditSink.record({
    id: randomUUID(),
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

export function assertSafeProxyBind({ host = "127.0.0.1", allowRemoteBind = false } = {}) {
  if (allowRemoteBind || isLoopbackHost(host)) {
    return;
  }

  throw new Error(`Refusing to bind Haechi proxy to non-loopback host ${host}. Use --allow-remote-bind only for explicitly secured environments.`);
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
