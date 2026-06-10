import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { assertSafeProxyBind, createHaechiProxy } from "../packages/proxy/index.mjs";

test("vLLM-compatible proxy protects request and JSON response", async () => {
  const upstream = createServer(async (request, response) => {
    const body = JSON.parse(await readBody(request));
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      id: "cmpl-test",
      requestContent: body.messages[0].content,
      choices: [
        {
          message: {
            role: "assistant",
            content: "I found minji.kim@example.com in the result"
          }
        }
      ]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-03-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact"
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        messages: [
          {
            role: "user",
            content: "contact minji.kim@example.com"
          }
        ]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 200);
    assert.match(json.requestContent, /\[REDACTED:email\]/);
    assert.match(json.choices[0].message.content, /\[REDACTED:email\]/);
    assert.doesNotMatch(JSON.stringify(json), /minji\.kim@example\.com/);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /request:POST chat-completions/);
    assert.match(audit, /response:POST chat-completions/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("proxy refuses non-loopback bind unless explicitly allowed", () => {
  assert.throws(
    () => assertSafeProxyBind({ host: "0.0.0.0" }),
    /Refusing to bind/
  );

  assert.doesNotThrow(() => assertSafeProxyBind({ host: "0.0.0.0", allowRemoteBind: true }));
});

test("proxy rejects absolute-form request targets before forwarding", async () => {
  let intendedUpstreamHit = false;
  let attackerUpstreamHit = false;
  const intendedUpstream = createServer(async (_request, response) => {
    intendedUpstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const attackerUpstream = createServer(async (_request, response) => {
    attackerUpstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ exfiltrated: true }));
  });
  const intendedAddress = await listen(intendedUpstream);
  const attackerAddress = await listen(attackerUpstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-absolute-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${intendedAddress.port}`
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await sendRawHttpRequest({
      host: proxyAddress.host,
      port: proxyAddress.port,
      path: `http://127.0.0.1:${attackerAddress.port}/v1/chat/completions`,
      body: JSON.stringify({
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = JSON.parse(response.body);

    assert.equal(response.statusCode, 400);
    assert.equal(json.error, "haechi_invalid_proxy_target");
    assert.equal(intendedUpstreamHit, false);
    assert.equal(attackerUpstreamHit, false);
  } finally {
    await proxy.close();
    await close(intendedUpstream);
    await close(attackerUpstream);
  }
});

test("proxy blocks streaming requests by default", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        stream: true,
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 501);
    assert.equal(json.error, "haechi_streaming_unsupported");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("streaming pass-through records a bypass audit event", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-audit-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    streaming: {
      requestMode: "pass-through"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        stream: true,
        messages: [{ role: "user", content: "hello" }]
      })
    });
    assert.equal(response.status, 200);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /streaming_request_pass_through/);
    assert.doesNotMatch(audit, /hello/);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("responseProtection fails closed for uninspectable responses", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("minji.kim@example.com");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-response-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 502);
    assert.equal(json.error, "haechi_response_unprotected");
    assert.equal(json.reason, "non_json_response");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("responseProtection stops reading upstream responses after maxBytes", { timeout: 2000 }, async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.write(`{"content":"${"x".repeat(128)}`);
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-response-limit-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce",
      maxBytes: 64
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(800),
      body: JSON.stringify({
        model: "local-model",
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 502);
    assert.equal(json.error, "haechi_response_unprotected");
    assert.equal(json.reason, "response_body_too_large");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("responseProtection allow mode records unprotected response decisions", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("minji.kim@example.com");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-response-allow-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce",
      failureMode: "allow"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        messages: [{ role: "user", content: "hello" }]
      })
    });

    assert.equal(response.status, 200);
    assert.equal(await response.text(), "minji.kim@example.com");

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /response_unprotected_allowed/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("proxy rejects request bodies over configured limit", async () => {
  let upstreamHit = false;
  const upstream = createServer(async (_request, response) => {
    upstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-limit-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    limits: {
      maxRequestBytes: 64
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        messages: [{ role: "user", content: "a".repeat(128) }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 413);
    assert.equal(json.error, "haechi_request_body_too_large");
    assert.equal(upstreamHit, false);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function sendRawHttpRequest({ host, port, path, body }) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      host,
      port,
      path,
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body)
      }
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    request.on("error", reject);
    request.end(body);
  });
}
