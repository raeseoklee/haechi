import { createServer } from "node:http";

export function createHaechiProxy({ runtime, port = 8787, host = "127.0.0.1" }) {
  const { haechi, config, protocolAdapter } = runtime;

  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/__haechi/health") {
        writeJson(response, 200, { ok: true, mode: config.mode });
        return;
      }

      const routeContext = protocolAdapter.classifyRequest(request);
      const body = await readBody(request);
      const json = body ? JSON.parse(body) : {};
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
      writeJson(response, 500, {
        error: "haechi_proxy_error",
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

  if (!runtime.config.responseProtection.enabled || !routeContext.protectResponse || !isJson(headers["content-type"])) {
    return {
      status: upstreamResponse.status,
      headers,
      body: rawBody
    };
  }

  const json = JSON.parse(rawBody.toString("utf8"));
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

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
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
  return next;
}
