import { createServer } from "node:http";

export function createHaechiProxy({ runtime, port = 8787, host = "127.0.0.1", allowRemoteBind = false }) {
  assertSafeProxyBind({ host, allowRemoteBind });
  const { haechi, config, protocolAdapter } = runtime;

  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/__haechi/health") {
        writeJson(response, 200, { ok: true, mode: config.mode });
        return;
      }

      const routeContext = protocolAdapter.classifyRequest(request);
      const body = await readBody(request, {
        maxBytes: config.limits.maxRequestBytes
      });
      const json = parseJsonBody(body);

      if (isStreamingRequest(json)) {
        if (config.streaming.requestMode === "pass-through") {
          const upstreamResponse = await forward({
            upstream: config.target.upstream,
            request,
            body
          });
          const rawBody = Buffer.from(await upstreamResponse.arrayBuffer());
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
        body: JSON.stringify(result.payload)
      });

      const forwarded = await maybeProtectResponse({
        upstreamResponse,
        routeContext,
        runtime
      });

      response.writeHead(forwarded.status, forwarded.headers);
      response.end(forwarded.body);
    } catch (error) {
      writeJson(response, error.statusCode ?? 500, {
        error: error.errorCode ?? "haechi_proxy_error",
        message: error.message
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
  const rawBody = Buffer.from(await upstreamResponse.arrayBuffer());

  if (!runtime.config.responseProtection.enabled || !routeContext.protectResponse) {
    return {
      status: upstreamResponse.status,
      headers,
      body: rawBody
    };
  }

  const responsePolicy = runtime.config.responseProtection;
  const contentEncoding = headers["content-encoding"] ?? "";

  if (rawBody.byteLength > responsePolicy.maxBytes) {
    return unprotectedResponseDecision({
      reason: "response_body_too_large",
      detail: `Response body exceeds responseProtection.maxBytes (${responsePolicy.maxBytes})`,
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy
    });
  }

  if (contentEncoding && contentEncoding.toLowerCase() !== "identity" && !responsePolicy.allowCompressed) {
    return unprotectedResponseDecision({
      reason: "compressed_response",
      detail: "Compressed responses cannot be inspected by responseProtection",
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy
    });
  }

  if (!isJson(headers["content-type"])) {
    return unprotectedResponseDecision({
      reason: "non_json_response",
      detail: "Non-JSON responses cannot be inspected by responseProtection",
      upstreamResponse,
      headers,
      rawBody,
      responsePolicy
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
      responsePolicy
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

async function forward({ upstream, request, body }) {
  const target = new URL(request.url, upstream.endsWith("/") ? upstream : `${upstream}/`);
  return fetch(target, {
    method: request.method,
    headers: filteredHeaders(request.headers),
    body: request.method === "GET" || request.method === "HEAD" ? undefined : body
  });
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

function unprotectedResponseDecision({ reason, detail, upstreamResponse, headers, rawBody, responsePolicy }) {
  if (responsePolicy.failureMode === "allow") {
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

function isStreamingRequest(value) {
  return Boolean(value && typeof value === "object" && value.stream === true);
}

function proxyError({ statusCode, errorCode, message }) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.errorCode = errorCode;
  return error;
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
