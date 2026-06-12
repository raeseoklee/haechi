// WS5 — core robustness (1.1.2 patch).
//
// Guards for two fail-closed paths added in this patch:
//   1. collectStringEntries / protectJson reject an over-deep JSON payload
//      (would otherwise overflow the call stack → uncaught process crash) with a
//      clear 4xx-shaped error, mirroring the byte-limit path. A normal nested
//      payload still protects.
//   2. The proxy rejects a non-UTF-8 request body with a clear 4xx instead of
//      lossily decoding invalid bytes to U+FFFD before detection runs.

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  collectStringEntries,
  DEFAULT_MAX_NESTING_DEPTH
} from "../packages/core/index.mjs";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";

function deeplyNested(depth, leaf = { content: "deep" }) {
  let node = leaf;
  for (let level = 0; level < depth; level += 1) {
    node = { nested: node };
  }
  return node;
}

async function buildEnforceRuntime(dir, overrides = {}) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath },
    ...overrides
  });
}

// ---------------------------------------------------------------------------
// 1. Depth guard — exported collectStringEntries throws fail-closed.
// ---------------------------------------------------------------------------

test("collectStringEntries rejects a payload deeper than DEFAULT_MAX_NESTING_DEPTH (no crash)", () => {
  const payload = deeplyNested(5000);
  let thrown;
  try {
    collectStringEntries(payload);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, "a 5000-deep payload must be rejected, not silently walked");
  assert.equal(thrown.statusCode, 413, "depth error carries a 4xx statusCode for the proxy");
  assert.equal(thrown.errorCode, "haechi_request_too_deeply_nested");
  assert.match(thrown.message, /maxNestingDepth/);
});

test("collectStringEntries honors a custom maxDepth and still walks shallow payloads", () => {
  // Within the limit: a 4-deep payload (chain length 4) is fully walked.
  const within = collectStringEntries(deeplyNested(4, { content: "ok" }), [], { maxDepth: 8 });
  assert.ok(within.some((entry) => entry.value === "ok"), "leaf within depth must be collected");

  // Beyond the limit fails closed.
  assert.throws(
    () => collectStringEntries(deeplyNested(20), [], { maxDepth: 8 }),
    /maxNestingDepth/
  );
});

test("DEFAULT_MAX_NESTING_DEPTH is a safe positive default", () => {
  assert.ok(Number.isInteger(DEFAULT_MAX_NESTING_DEPTH) && DEFAULT_MAX_NESTING_DEPTH > 0);
  assert.equal(DEFAULT_MAX_NESTING_DEPTH, 256);
});

// ---------------------------------------------------------------------------
// 2. Depth guard — protectJson surfaces it; a normal nested payload still works.
// ---------------------------------------------------------------------------

test("protectJson rejects an over-deep payload fail-closed and protects a normal nested one", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-depth-"));
  const runtime = await buildEnforceRuntime(dir, { limits: { maxNestingDepth: 64 } });

  // Over-deep: 5000 levels — would overflow the stack without the guard.
  await assert.rejects(
    () => runtime.haechi.protectJson(deeplyNested(5000), { protocol: "test", operation: "deep" }),
    (error) => {
      assert.equal(error.statusCode, 413);
      assert.equal(error.errorCode, "haechi_request_too_deeply_nested");
      return true;
    }
  );

  // Normal nested payload (well within the limit) still protects the PII leaf.
  const normal = {
    messages: [{ role: "user", content: "email minji.kim@example.com" }]
  };
  const result = await runtime.haechi.protectJson(normal, { protocol: "test", operation: "normal" });
  assert.match(result.payload.messages[0].content, /\[REDACTED:email\]/);
  assert.doesNotMatch(JSON.stringify(result.payload), /minji\.kim@example\.com/);
});

// ---------------------------------------------------------------------------
// 3. Depth guard — config key validation (additive, fail-closed).
// ---------------------------------------------------------------------------

test("limits.maxNestingDepth defaults to 256 and validates as a positive integer", () => {
  assert.equal(normalizeConfig({}).limits.maxNestingDepth, 256);
  assert.equal(normalizeConfig({ limits: { maxNestingDepth: 32 } }).limits.maxNestingDepth, 32);
  for (const bad of [0, -1, 1.5, "256", null]) {
    assert.throws(
      () => normalizeConfig({ limits: { maxNestingDepth: bad } }),
      /limits\.maxNestingDepth must be a positive integer/
    );
  }
});

// ---------------------------------------------------------------------------
// 4. Depth guard surfaces through the proxy as a clean 4xx (not a 500).
// ---------------------------------------------------------------------------

test("proxy returns a 4xx (not a 500) for an over-deep request body", async () => {
  let upstreamHit = false;
  const upstream = createServer((_request, response) => {
    upstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-depth-proxy-"));
  const runtime = await buildEnforceRuntime(dir, {
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    limits: { maxNestingDepth: 32 }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(deeplyNested(2000))
    });
    const json = await response.json();

    assert.equal(response.status, 413, "over-deep payload must be a clean 4xx, not a 500");
    assert.equal(json.error, "haechi_request_too_deeply_nested");
    assert.equal(upstreamHit, false, "an over-deep request must never reach upstream");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

// ---------------------------------------------------------------------------
// 5. Non-UTF-8 request body — proxy rejects fail-closed with a clear 4xx.
// ---------------------------------------------------------------------------

test("proxy rejects a non-UTF-8 request body with a clear 4xx (no lossy decode)", async () => {
  let upstreamHit = false;
  const upstream = createServer((_request, response) => {
    upstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-utf8-"));
  const runtime = await buildEnforceRuntime(dir, {
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    // A lone continuation byte (0x80) and 0xFF are never valid UTF-8.
    const invalid = Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0x80, 0xff, 0x22, 0x7d]);
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: invalid
    });
    const json = await response.json();

    assert.equal(response.status, 400, "non-UTF-8 body must be a clean 4xx");
    assert.equal(json.error, "haechi_request_body_not_utf8");
    assert.equal(upstreamHit, false, "a non-UTF-8 request must never reach upstream");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("proxy still accepts a valid UTF-8 (multibyte) request body", async () => {
  const upstream = createServer(async (request, response) => {
    const body = JSON.parse(await readBody(request));
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ echoed: body.messages[0].content }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-utf8-ok-"));
  const runtime = await buildEnforceRuntime(dir, {
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // Korean + emoji: valid multibyte UTF-8 must NOT be rejected.
      body: JSON.stringify({ messages: [{ role: "user", content: "안녕하세요 🌿" }] })
    });
    const json = await response.json();

    assert.equal(response.status, 200);
    assert.equal(json.echoed, "안녕하세요 🌿");
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
