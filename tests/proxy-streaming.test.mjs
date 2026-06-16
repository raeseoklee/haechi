import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";
import { verifyAuditChain } from "../packages/audit/index.mjs";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

async function readAll(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

test("proxy inspect mode protects the request and stream-filters the SSE response", async () => {
  let upstreamRequestBody = null;
  const upstream = createServer(async (request, response) => {
    upstreamRequestBody = JSON.parse(await readAll(request));
    response.writeHead(200, { "content-type": "text/event-stream" });
    // The model leaks an email split across two SSE deltas.
    response.write(`data: ${JSON.stringify({ choices: [{ delta: { content: "reply to minji" } }] })}\n\n`);
    response.write(`data: ${JSON.stringify({ choices: [{ delta: { content: ".kim@example.com soon" } }] })}\n\n`);
    response.write("data: [DONE]\n\n");
    response.end();
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "contact seoul@example.com" }] })
    });
    const body = await response.text();

    // Request PII never reached the upstream.
    assert.doesNotMatch(JSON.stringify(upstreamRequestBody), /seoul@example\.com/);
    // Response PII (split across frames) never reached the client.
    assert.doesNotMatch(body, /minji\.kim@example\.com/);
    assert.match(body, /\[REDACTED:email\]/);
    assert.match(body, /\[DONE\]/);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /"decision":"stream_inspected"/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
    assert.doesNotMatch(audit, /seoul@example\.com/);
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("inspect mode blocks an Ollama NDJSON stream carrying a secret", async () => {
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/x-ndjson" });
    response.write(`${JSON.stringify({ message: { role: "assistant", content: "ok so far " }, done: false })}\n`);
    response.write(`${JSON.stringify({ message: { role: "assistant", content: "key sk_demo_0123456789abcdef0123456789ab" }, done: false })}\n`);
    response.write(`${JSON.stringify({ message: { role: "assistant", content: "tail" }, done: true })}\n`);
    response.end();
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-block-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "ollama", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { api_key: "block" } },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "llama3", messages: [{ role: "user", content: "hi" }] })
    });
    const body = await response.text();

    assert.doesNotMatch(body, /sk_demo_0123456789abcdef0123456789ab/);
    assert.doesNotMatch(body, /tail/);
    const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
    assert.match(audit, /"decision":"stream_blocked"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("P1-CR-005: inspect mode redacts a non-JSON plain-text SSE frame end-to-end", async () => {
  // The exact repro: an upstream emits `data: <email>` (plain text, NOT JSON).
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write("data: minji.kim@example.com\n\n");
    response.write("data: [DONE]\n\n");
    response.end();
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-plaintext-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "hi" }] })
    });
    const body = await response.text();

    // The plain-text email is no longer raw-passed: it is redacted, not leaked.
    assert.doesNotMatch(body, /minji\.kim@example\.com/);
    assert.match(body, /\[REDACTED:email\]/);
    assert.match(body, /\[DONE\]/);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /"decision":"stream_inspected"/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("inspect mode 501s a streaming route with no known format", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-noroute-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "ollama", upstream: "http://127.0.0.1:9" },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    // /api/embed has no streaming descriptor.
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/api/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, input: "x" })
    });
    assert.equal(response.status, 501);
    assert.equal((await response.json()).error, "haechi_streaming_uninspectable_route");
  } finally {
    await proxy.close();
  }
});

test("CR2-001: a downstream client disconnect mid-stream promptly tears down the upstream connection", async () => {
  // A never-ending streaming upstream: it sends one frame then holds the
  // connection open forever (no further writes, never ends). Without the
  // disconnect teardown, the proxy's pipe parks on `reader.read()`/`drain` until
  // the request timeout and the upstream connection leaks. We assert the upstream
  // request is torn down (its `close`/`aborted` fires) PROMPTLY after the client
  // disconnects — not parked until the (long) upstream timeout.
  let upstreamClosedResolve;
  const upstreamClosed = new Promise((resolve) => { upstreamClosedResolve = resolve; });
  const upstream = createServer((request, response) => {
    request.on("close", () => upstreamClosedResolve(true));
    request.on("aborted", () => upstreamClosedResolve(true));
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(`data: ${JSON.stringify({ choices: [{ delta: { content: "first chunk" } }] })}\n\n`);
    // Intentionally never write again and never end — hold the stream open.
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-disconnect-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "pass-through" },
    // A long upstream timeout so a pass (prompt teardown) is unambiguous: if the
    // teardown is missing, this test would only pass after this timeout fires.
    limits: { upstreamTimeoutMs: 120000 },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const controller = new AbortController();
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "hi" }] }),
      signal: controller.signal
    });
    // Read the first frame so the stream is actively flowing, then disconnect.
    const reader = response.body.getReader();
    await reader.read();
    // Disconnect the client: cancel the body reader (which closes the downstream
    // socket) and abort the request. Swallow the resulting AbortError on the
    // in-flight read so it does not surface as an unhandled rejection.
    const drained = reader.read().catch(() => {});
    controller.abort();
    await drained;

    // The upstream connection must be torn down promptly (well under the 120s
    // upstream timeout). Race against a short watchdog so a leak fails fast.
    const watchdog = new Promise((resolve) => setTimeout(() => resolve(false), 5000));
    const closedPromptly = await Promise.race([upstreamClosed, watchdog]);
    assert.equal(closedPromptly, true,
      "upstream connection must be torn down promptly after the client disconnects (not parked until the upstream timeout)");
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("config validation covers the new streaming keys", () => {
  assert.throws(() => normalizeConfig({ streaming: { requestMode: "weird" } }), /streaming.requestMode/);
  assert.throws(() => normalizeConfig({ streaming: { responseMode: "weird" } }), /streaming.responseMode/);
  assert.throws(() => normalizeConfig({ streaming: { maxMatchBytes: 0 } }), /streaming.maxMatchBytes/);
  const ok = normalizeConfig({ streaming: { requestMode: "inspect" } });
  assert.equal(ok.streaming.requestMode, "inspect");
  assert.equal(ok.streaming.responseMode, "enforce");
  assert.equal(ok.streaming.maxMatchBytes, 256);
});
