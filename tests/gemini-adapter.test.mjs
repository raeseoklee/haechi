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
// 1. Classification: target.type "gemini" selects the adapter; model-in-path
//    `:method`-suffix routing matches across model names and version prefixes.
// ---------------------------------------------------------------------------

test("knownProtocolAdapters() includes gemini", () => {
  assert.ok(knownProtocolAdapters().includes("gemini"));
});

test("target.type:gemini classifies :generateContent with the SSE_GEMINI descriptor", () => {
  // target.type:"gemini" selects the adapter directly via the ADAPTERS[type] path.
  const adapter = createProtocolAdapter({ type: "gemini" });
  assert.equal(adapter.id, "gemini");
  assert.equal(adapter.protocol, "gemini");

  const generate = adapter.classifyRequest(request("/v1beta/models/gemini-2.0-flash:generateContent"));
  assert.deepEqual(generate, {
    adapterId: "gemini",
    protocol: "gemini",
    routeId: "generate-content",
    path: "/v1beta/models/gemini-2.0-flash:generateContent",
    operation: "POST generate-content",
    protectRequest: true,
    protectResponse: true,
    streamingByDefault: false,
    streaming: null
  });

  const stream = adapter.classifyRequest(request("/v1beta/models/gemini-2.0-flash:streamGenerateContent"));
  assert.equal(stream.routeId, "stream-generate-content");
  // The :stream* endpoint always streams (intent is in the path, no body flag).
  assert.equal(stream.streamingByDefault, true);
  assert.deepEqual(stream.streaming, {
    format: "sse",
    deltaPath: ["candidates", 0, "content", "parts", 0, "text"]
  });
  // Data-only SSE: no flushOnType.
  assert.ok(!("flushOnType" in stream.streaming));

  const count = adapter.classifyRequest(request("/v1beta/models/gemini-1.5-pro:countTokens"));
  assert.equal(count.routeId, "count-tokens");
  assert.equal(count.protectRequest, true);
  assert.equal(count.streaming, null);

  const embed = adapter.classifyRequest(request("/v1beta/models/text-embedding-004:embedContent"));
  assert.equal(embed.routeId, "embed");
  const batchEmbed = adapter.classifyRequest(request("/v1beta/models/text-embedding-004:batchEmbedContents"));
  assert.equal(batchEmbed.routeId, "batch-embed");
});

test("gemini :method-suffix routing is model-name agnostic and works on /v1 and /v1beta prefixes", () => {
  const adapter = createProtocolAdapter({ type: "gemini" });

  // Different model names, both version prefixes — all match the same route.
  assert.equal(
    adapter.classifyRequest(request("/v1beta/models/gemini-2.0-flash:generateContent")).routeId,
    "generate-content"
  );
  assert.equal(
    adapter.classifyRequest(request("/v1/models/gemini-1.5-pro:generateContent")).routeId,
    "generate-content"
  );
  assert.equal(
    adapter.classifyRequest(request("/v1beta/models/gemini-1.5-flash-8b:streamGenerateContent")).routeId,
    "stream-generate-content"
  );
  assert.equal(
    adapter.classifyRequest(request("/v1/models/gemini-2.0-pro-exp:countTokens")).routeId,
    "count-tokens"
  );

  // A query string (Gemini's ?alt=sse / ?key=...) does not affect the suffix match.
  const withQuery = adapter.classifyRequest(
    request("/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse")
  );
  assert.equal(withQuery.routeId, "stream-generate-content");
  assert.equal(withQuery.path, "/v1beta/models/gemini-2.0-flash:streamGenerateContent");

  // An unknown method suffix falls through to unknown (fail-open classification
  // still protects request+response by default).
  const unknown = adapter.classifyRequest(request("/v1beta/models/gemini-2.0-flash:nonsenseMethod"));
  assert.equal(unknown.routeId, "unknown");
  assert.equal(unknown.protectRequest, true);
  assert.equal(unknown.protectResponse, true);
});

test("a specific gemini target.type wins over a default openai-compatible adapter", () => {
  // Mirrors the deep-merged default config (adapter: openai-compatible).
  const adapter = createProtocolAdapter({ type: "gemini", adapter: "openai-compatible" });
  assert.equal(adapter.id, "gemini");
  assert.equal(
    adapter.classifyRequest(request("/v1beta/models/gemini-2.0-flash:generateContent")).routeId,
    "generate-content"
  );
});

// ---------------------------------------------------------------------------
// NO MATCHER REGRESSION: adding the suffix matcher must not change the EXACT
// classification of any existing adapter route. The exact-path matcher runs
// first and wins for openai/anthropic.
// ---------------------------------------------------------------------------

test("existing exact-match routes classify identically (no suffix-matcher regression)", () => {
  const openai = createProtocolAdapter({ type: "openai-compatible" });
  assert.deepEqual(openai.classifyRequest(request("/v1/chat/completions")), {
    adapterId: "openai-compatible",
    protocol: "llm-http",
    routeId: "chat-completions",
    path: "/v1/chat/completions",
    operation: "POST chat-completions",
    protectRequest: true,
    protectResponse: true,
    streamingByDefault: false,
    streaming: { format: "sse", deltaPath: ["choices", 0, "delta", "content"] }
  });

  const anthropic = createProtocolAdapter({ type: "anthropic" });
  assert.deepEqual(anthropic.classifyRequest(request("/v1/messages")), {
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
});

// ---------------------------------------------------------------------------
// 2. Request protection end-to-end — systemInstruction.parts[].text and any
//    contents[].parts[].text. The core tree walk covers every string leaf; no
//    custom extraction. PII (email/phone) is transformed.
// ---------------------------------------------------------------------------

test("request protection transforms PII in systemInstruction + contents parts", async () => {
  let upstreamBody = null;
  const upstream = createServer(async (req, res) => {
    upstreamBody = JSON.parse(await readAll(req));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      candidates: [{ content: { parts: [{ text: "ok" }], role: "model" }, finishReason: "STOP" }]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-gemini-req-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "gemini", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: ["korean-pii", "secrets-only", "llm-redact"], defaultAction: "redact", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(
      `http://${proxyAddress.host}:${proxyAddress.port}/v1beta/models/gemini-2.0-flash:generateContent`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": "test-key" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: "You help minji.kim@example.com. Be concise." }] },
          contents: [
            { role: "user", parts: [{ text: "call me at 010-1234-5678 tomorrow" }] },
            { role: "model", parts: [{ text: "Sure." }] },
            { role: "user", parts: [{ text: "and email jisoo.park@example.com" }] }
          ]
        })
      }
    );
    assert.equal(response.status, 200);

    // None of the PII reached the upstream — every string leaf was transformed.
    const upstreamSerialized = JSON.stringify(upstreamBody);
    assert.doesNotMatch(upstreamSerialized, /minji\.kim@example\.com/);
    assert.doesNotMatch(upstreamSerialized, /jisoo\.park@example\.com/);
    assert.doesNotMatch(upstreamSerialized, /010-1234-5678/);
    // The structure survives; redaction markers in place.
    assert.match(JSON.stringify(upstreamBody.systemInstruction.parts[0].text), /\[REDACTED:email\]/);
    assert.match(JSON.stringify(upstreamBody.contents[2].parts[0].text), /\[REDACTED:email\]/);

    const audit = await readFile(auditPath, "utf8");
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
    assert.doesNotMatch(audit, /jisoo\.park@example\.com/);
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("a card in a contents part blocks the request fail-closed", async () => {
  const upstream = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-gemini-card-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "gemini", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(
      `http://${proxyAddress.host}:${proxyAddress.port}/v1beta/models/gemini-2.0-flash:generateContent`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: "my card is 4242 4242 4242 4242" }] }]
        })
      }
    );
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, "haechi_policy_block");
  } finally {
    await proxy.close();
    upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 3. Response protection — a non-streaming candidates[].content.parts[].text
//    leaking a card is caught (string leaves are walked on the response side).
// ---------------------------------------------------------------------------

test("response protection catches a card leaked in candidates[].content.parts[].text", async () => {
  const upstream = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      candidates: [{
        content: { parts: [{ text: "Here it is: 4242 4242 4242 4242" }], role: "model" },
        finishReason: "STOP"
      }]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-gemini-resp-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "gemini", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    responseProtection: { enabled: true, mode: "enforce" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { card: "block" } },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(
      `http://${proxyAddress.host}:${proxyAddress.port}/v1beta/models/gemini-2.0-flash:generateContent`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] })
      }
    );
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
// 4. Streaming — within-frame + cross-frame delta-text PII caught in the deeper
//    candidates[0].content.parts[0].text channel; data-only SSE frames.
// ---------------------------------------------------------------------------

test("inspect mode stream-filters Gemini data-only SSE frames (within + cross frame)", async () => {
  let upstreamBody = null;
  const upstream = createServer(async (req, res) => {
    upstreamBody = JSON.parse(await readAll(req));
    res.writeHead(200, { "content-type": "text/event-stream" });
    // Gemini SSE: data-only frames, each a FULL GenerateContentResponse. The
    // model leaks a whole email within one frame, then an email split across two.
    const frame = (text) => "data: " + JSON.stringify({
      candidates: [{ content: { parts: [{ text }], role: "model" }, index: 0 }]
    }) + "\n\n";
    res.write(frame("write to whole@example.com now "));
    res.write(frame("and also split"));
    res.write(frame(".name@example.com tail"));
    res.end();
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-gemini-stream-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "gemini", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    streaming: { requestMode: "inspect" },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(
      `http://${proxyAddress.host}:${proxyAddress.port}/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "contact seoul@example.com" }] }] })
      }
    );
    const body = await response.text();

    // Request PII never reached upstream.
    assert.doesNotMatch(JSON.stringify(upstreamBody), /seoul@example\.com/);
    // Within-frame email redacted.
    assert.doesNotMatch(body, /whole@example\.com/);
    // Cross-frame email (split across two deltas) redacted via the sliding buffer.
    assert.doesNotMatch(body, /split\.name@example\.com/);
    assert.match(body, /\[REDACTED:email\]/);
    // Data-only SSE: each frame is still a `data:` line (no event: lines for Gemini).
    assert.match(body, /data: /);
    assert.doesNotMatch(body, /event:/);

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
// 5. Header pass-through — the client supplies Gemini's x-goog-api-key, which
//    the proxy forwards to the upstream unchanged.
// ---------------------------------------------------------------------------

test("proxy forwards Gemini auth header (x-goog-api-key) to upstream", async () => {
  let receivedHeaders = null;
  const upstream = createServer(async (req, res) => {
    receivedHeaders = req.headers;
    await readAll(req);
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-gemini-headers-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "gemini", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    await fetch(
      `http://${proxyAddress.host}:${proxyAddress.port}/v1beta/models/gemini-2.0-flash:generateContent`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": "goog-secret" },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] })
      }
    );
    assert.equal(receivedHeaders["x-goog-api-key"], "goog-secret");
  } finally {
    await proxy.close();
    upstream.close();
  }
});
