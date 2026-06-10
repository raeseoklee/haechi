import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";

export const DEFAULT_PROXY_PORT = 1016;

export function createHaechiProxy({ runtime, port = DEFAULT_PROXY_PORT, host = "127.0.0.1", allowRemoteBind = false }) {
  assertSafeProxyBind({ host, allowRemoteBind });
  const { haechi, config, protocolAdapter } = runtime;

  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/__haechi/health") {
        writeJson(response, 200, { ok: true, mode: config.mode });
        return;
      }

      assertRelativeProxyTarget(request.url);
      const routeContext = protocolAdapter.classifyRequest(request);
      const body = await readBody(request, {
        maxBytes: config.limits.maxRequestBytes
      });
      const json = parseJsonBody(body);

      if (isStreamingRequest(json, routeContext)) {
        if (config.streaming.requestMode === "pass-through") {
          await recordProxyDecision({
            runtime,
            routeContext,
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
          message: "Streaming requests are blocked unless streaming.requestMode is explicitly set to pass-through"
        });
        return;
      }

      const result = routeContext.protectRequest
        ? await haechi.protectJson(json, {
          ...routeContext,
          operation: `request:${routeContext.operation}`,
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
        runtime
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

async function maybeProtectResponse({ upstreamResponse, routeContext, runtime }) {
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
    operation: `response:${routeContext.operation}`,
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

  return {
    status: upstreamResponse.status,
    headers: transformedJsonHeaders(headers),
    body: Buffer.from(`${JSON.stringify(result.payload)}\n`)
  };
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
      if (!rejected) {
        resolve(Buffer.concat(chunks).toString("utf8"));
      }
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

async function recordProxyDecision({ runtime, routeContext, decision, reason, enforced, blocked }) {
  if (typeof runtime.auditSink?.record !== "function") {
    return;
  }

  await runtime.auditSink.record({
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    protocol: routeContext?.protocol ?? "proxy",
    operation: routeContext ? `proxy:${routeContext.protocol}:${routeContext.routeId ?? "unknown"}` : "proxy",
    mode: runtime.config.policy.mode ?? runtime.config.mode,
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
