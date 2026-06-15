import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createProtocolAdapter, knownProtocolAdapters } from "../packages/protocol-adapters/index.mjs";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";
import { verifyAuditChain } from "../packages/audit/index.mjs";

function request(url) {
  return { method: "POST", url };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// ---------------------------------------------------------------------------
// 1. Classification: target.type "anthropic" selects the adapter and routes.
// ---------------------------------------------------------------------------

test("knownProtocolAdapters() includes anthropic", () => {
  assert.ok(knownProtocolAdapters().includes("anthropic"));
});

test("target.type:anthropic classifies /v1/messages with the SSE messages descriptor", () => {
  // target.type:"anthropic" selects the adapter directly via the ADAPTERS[type] path.
  const adapter = createProtocolAdapter({ type: "anthropic" });
  assert.equal(adapter.id, "anthropic");
  assert.equal(adapter.protocol, "anthropic");

  const messages = adapter.classifyRequest(request("/v1/messages"));
  assert.deepEqual(messages, {
    adapterId: "anthropic",
    protocol: "anthropic",
    routeId: "messages",
    path: "/v1/messages",
    operation: "POST messages",
    protectRequest: true,
    protectResponse: true,
    streamingByDefault: false,
    streaming: {
      format: "sse",
      deltaPath: ["delta", "text"],
      flushOnType: { path: ["type"], values: ["content_block_stop", "message_delta", "message_stop"] }
    }
  });

  const countTokens = adapter.classifyRequest(request("/v1/messages/count_tokens"));
  assert.equal(countTokens.routeId, "count-tokens");
  assert.equal(countTokens.protectRequest, true);
  assert.equal(countTokens.streaming, null);

  const complete = adapter.classifyRequest(request("/v1/complete"));
  assert.equal(complete.routeId, "complete");
  assert.deepEqual(complete.streaming, { format: "sse", deltaPath: ["completion"] });
});

test("a specific anthropic target.type wins over a default openai-compatible adapter", () => {
  // Mirrors the deep-merged default config (adapter: openai-compatible).
  const adapter = createProtocolAdapter({ type: "anthropic", adapter: "openai-compatible" });
  assert.equal(adapter.id, "anthropic");
  assert.equal(adapter.classifyRequest(request("/v1/messages")).routeId, "messages");
});

// ---------------------------------------------------------------------------
// 2. Request protection end-to-end — system string, content string, content
//    block text. The core tree walk covers every string leaf; no custom
//    extraction. PII (email/phone) and a card are detected+transformed.
// ---------------------------------------------------------------------------

test("request protection transforms PII in system, content string, and content-block text", async () => {
  let upstreamBody = null;
  const upstream = createServer(async (req, res) => {
    upstreamBody = JSON.parse(await readAll(req));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "msg_1", type: "message", role: "assistant", content: [{ type: "text", text: "ok" }] }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-anthropic-req-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "anthropic", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: ["korean-pii", "secrets-only", "llm-redact"], defaultAction: "redact", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "sk-ant-test",
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-opus-4-8",
        max_tokens: 1024,
        // Top-level system as a STRING with an email.
        system: "You help minji.kim@example.com. Always be concise.",
        messages: [
          // content as a STRING with a KR phone number.
          { role: "user", content: "call me at 010-1234-5678 tomorrow" },
          { role: "assistant", content: "Sure." },
          // content as an ARRAY of content BLOCKS; text block carries an email.
          { role: "user", content: [{ type: "text", text: "and email jisoo.park@example.com" }] }
        ]
      })
    });
    assert.equal(response.status, 200);

    // None of the PII reached the upstream — every string leaf was transformed.
    const upstreamSerialized = JSON.stringify(upstreamBody);
    assert.doesNotMatch(upstreamSerialized, /minji\.kim@example\.com/);
    assert.doesNotMatch(upstreamSerialized, /jisoo\.park@example\.com/);
    assert.doesNotMatch(upstreamSerialized, /010-1234-5678/);
    // The system field and content blocks survive structurally (redaction markers in place).
    assert.match(JSON.stringify(upstreamBody.system), /\[REDACTED:email\]/);
    assert.match(JSON.stringify(upstreamBody.messages[2].content[0].text), /\[REDACTED:email\]/);

    const audit = await readFile(auditPath, "utf8");
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
    assert.doesNotMatch(audit, /jisoo\.park@example\.com/);
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("a card in a content block blocks the request fail-closed", async () => {
  const upstream = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-anthropic-card-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "anthropic", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-opus-4-8",
        max_tokens: 1024,
        messages: [{ role: "user", content: [{ type: "text", text: "my card is 4242 4242 4242 4242" }] }]
      })
    });
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, "haechi_policy_block");
  } finally {
    await proxy.close();
    upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 3. Response protection — a non-streaming content[].text leaking a card is
//    caught (string leaves are walked on the response direction).
// ---------------------------------------------------------------------------

test("response protection catches a card leaked in content[].text", async () => {
  const upstream = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      id: "msg_2",
      type: "message",
      role: "assistant",
      content: [{ type: "text", text: "Here it is: 4242 4242 4242 4242" }]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-anthropic-resp-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "anthropic", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    responseProtection: { enabled: true, mode: "enforce" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-opus-4-8", max_tokens: 1024, messages: [{ role: "user", content: "hi" }] })
    });
    const body = await response.text();
    // The card never reaches the client; a card maps to block, so the response is denied.
    assert.doesNotMatch(body, /4242 4242 4242 4242/);
    assert.equal(response.status, 502);
    assert.equal(JSON.parse(body).error, "haechi_response_policy_block");
  } finally {
    await proxy.close();
    upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 4. Streaming — within-frame + cross-frame delta.text PII caught; ping passes.
// ---------------------------------------------------------------------------

test("inspect mode stream-filters Anthropic content_block_delta frames (within + cross frame), passes ping", async () => {
  let upstreamBody = null;
  const upstream = createServer(async (req, res) => {
    upstreamBody = JSON.parse(await readAll(req));
    res.writeHead(200, { "content-type": "text/event-stream" });
    // Anthropic SSE: event-typed frames. Non-delta frames pass untouched; the
    // model leaks an email split across two content_block_delta frames, and a
    // whole email within one frame.
    res.write("event: message_start\ndata: " + JSON.stringify({ type: "message_start", message: { id: "msg_3", role: "assistant" } }) + "\n\n");
    res.write("event: ping\ndata: " + JSON.stringify({ type: "ping" }) + "\n\n");
    res.write("event: content_block_start\ndata: " + JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }) + "\n\n");
    // Within-frame: a full email in one delta.
    res.write("event: content_block_delta\ndata: " + JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "write to whole@example.com now " } }) + "\n\n");
    // Cross-frame: an email split across two consecutive deltas.
    res.write("event: content_block_delta\ndata: " + JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "and also split" } }) + "\n\n");
    res.write("event: content_block_delta\ndata: " + JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: ".name@example.com tail" } }) + "\n\n");
    res.write("event: content_block_stop\ndata: " + JSON.stringify({ type: "content_block_stop", index: 0 }) + "\n\n");
    res.write("event: message_stop\ndata: " + JSON.stringify({ type: "message_stop" }) + "\n\n");
    res.end();
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-anthropic-stream-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "anthropic", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, model: "claude-opus-4-8", max_tokens: 1024, messages: [{ role: "user", content: "contact seoul@example.com" }] })
    });
    const body = await response.text();

    // Request PII never reached upstream.
    assert.doesNotMatch(JSON.stringify(upstreamBody), /seoul@example\.com/);
    // Within-frame email redacted.
    assert.doesNotMatch(body, /whole@example\.com/);
    // Cross-frame email (split across two deltas) redacted via the sliding buffer.
    assert.doesNotMatch(body, /split\.name@example\.com/);
    assert.match(body, /\[REDACTED:email\]/);
    // PROTOCOL FIDELITY: the SSE `event:` dispatch lines must survive re-serialize
    // (Anthropic clients dispatch on them). Each frame keeps its event: line.
    assert.match(body, /event: ping\ndata: /);
    assert.match(body, /event: message_start\ndata: /);
    assert.match(body, /event: content_block_delta\ndata: /);
    assert.match(body, /event: message_stop\ndata: /);
    // ORDERING: the held cross-frame buffer tail is flushed as a valid
    // content_block_delta BEFORE message_stop — never after it (a delta after
    // message_stop would be dropped by a real Anthropic client).
    assert.ok(
      body.lastIndexOf("content_block_delta") < body.indexOf("message_stop"),
      "no content_block_delta may appear after message_stop"
    );

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /"decision":"stream_inspected"/);
    assert.doesNotMatch(audit, /whole@example\.com/);
    assert.doesNotMatch(audit, /seoul@example\.com/);
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 5. Header pass-through — x-api-key / anthropic-version forwarded, not stripped.
// ---------------------------------------------------------------------------

test("proxy forwards Anthropic auth headers (x-api-key, anthropic-version) to upstream", async () => {
  let receivedHeaders = null;
  const upstream = createServer(async (req, res) => {
    receivedHeaders = req.headers;
    await readAll(req);
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-anthropic-headers-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "anthropic", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "sk-ant-secret",
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({ model: "claude-opus-4-8", max_tokens: 1024, messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(receivedHeaders["x-api-key"], "sk-ant-secret");
    assert.equal(receivedHeaders["anthropic-version"], "2023-06-01");
  } finally {
    await proxy.close();
    upstream.close();
  }
});
