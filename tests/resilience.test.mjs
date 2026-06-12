// WS4-B operability / Day-2 resilience tests (reliability-hardening-track §WS4).
//
// Covers the four resilience + deploy seams added in WS4-B:
//   1. Graceful drain — an in-flight request completes, close() resolves once it
//      drains, an idle keep-alive socket is force-closed within the grace period,
//      and the suite TERMINATES (no leaked grace timer keeps node --test alive).
//   2. Max-in-flight backpressure — at the ceiling a request returns 503 +
//      Retry-After; the /__haechi/live + /__haechi/metrics observability routes
//      still return 200 UNDER saturation (they are exempt from the ceiling).
//   3. Env-var config overlay — a valid HAECHI_PROXY_PORT / HAECHI_MODE overlays
//      the file; an invalid one THROWS; a secret-shaped env var is NOT applied.
//   4. Tuned timeouts — server.requestTimeout / headersTimeout come from config.
//   5. Fail-closed validation of the new limits.* keys + configVersion.

import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createServer } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { applyEnvOverlay, createRuntime, normalizeConfig, CONFIG_VERSION } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

async function makeRuntime(overrides = {}, providers = {}) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-resilience-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath },
    ...overrides
  }, providers);
  return { runtime, dir };
}

// ---------------------------------------------------------------------------
// 1. graceful drain
// ---------------------------------------------------------------------------

test("graceful drain: an in-flight request completes and close() resolves after it drains", async () => {
  // Upstream that holds the response until released, so the proxy request is
  // genuinely in flight when we call close().
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain body */ }
    await held;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }));
  });
  const upstreamAddr = await listen(upstream);

  const { runtime } = await makeRuntime({
    target: { type: "openai-compatible", upstream: `http://127.0.0.1:${upstreamAddr.port}` }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();

  // Fire a request; do NOT await it yet — it is now in flight (blocked upstream).
  const inflight = fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] })
  });

  // Give the request a moment to reach the upstream-hold point.
  await new Promise((r) => setTimeout(r, 50));

  // Begin graceful shutdown; it must NOT resolve until the in-flight drains.
  let closed = false;
  const closing = proxy.close().then(() => { closed = true; });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(closed, false, "close() must wait for the in-flight request to drain");

  // Release upstream → the in-flight request completes → close() resolves.
  release();
  const res = await inflight;
  assert.equal(res.status, 200);
  await closing;
  assert.equal(closed, true, "close() resolves once in-flight drains");

  await close(upstream);
});

test("graceful drain: an idle keep-alive socket does not hold shutdown open (force-closed within grace)", async () => {
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddr = await listen(upstream);

  // A small grace so the test is fast even if the force-close path runs.
  const { runtime } = await makeRuntime({
    target: { type: "openai-compatible", upstream: `http://127.0.0.1:${upstreamAddr.port}` },
    limits: { shutdownGraceMs: 200 }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();

  // Open a raw keep-alive socket and send one request so the connection is
  // established, then leave it idle (no further requests).
  const socket = net.connect(address.port, address.host);
  await new Promise((resolve, reject) => {
    socket.on("connect", resolve);
    socket.on("error", reject);
  });
  socket.write(
    "GET /__haechi/live HTTP/1.1\r\n" +
    `Host: ${address.host}\r\n` +
    "Connection: keep-alive\r\n\r\n"
  );
  // Wait for the response so the socket is now idle keep-alive.
  await new Promise((resolve) => socket.once("data", resolve));

  // close() must resolve promptly (idle connection closed immediately; even if it
  // lingered, the grace timer force-closes within 200ms). This asserts no hang.
  const start = Date.now();
  await proxy.close();
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 2000, `close() must not hang on an idle keep-alive socket (took ${elapsed}ms)`);

  socket.destroy();
  await close(upstream);
});

test("graceful drain: close() resolves immediately with no in-flight work", async () => {
  const { runtime } = await makeRuntime();
  const proxy = createHaechiProxy({ runtime, port: 0 });
  await proxy.listen();
  const start = Date.now();
  await proxy.close();
  assert.ok(Date.now() - start < 1000, "close() resolves promptly with nothing in flight");
});

// ---------------------------------------------------------------------------
// 2. max-in-flight backpressure
// ---------------------------------------------------------------------------

test("backpressure: at the ceiling a request returns 503 + Retry-After; observability routes stay 200", async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    await held;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddr = await listen(upstream);

  // Ceiling of 1: the first request occupies the only slot.
  const { runtime } = await makeRuntime({
    target: { type: "openai-compatible", upstream: `http://127.0.0.1:${upstreamAddr.port}` },
    limits: { maxInFlight: 1, shutdownGraceMs: 200 }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  const base = `http://${address.host}:${address.port}`;

  // Occupy the single slot with a held request.
  const occupying = fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] })
  });
  await new Promise((r) => setTimeout(r, 50));

  try {
    // A second non-exempt request is rejected at the ceiling.
    const rejected = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "second" }] })
    });
    assert.equal(rejected.status, 503);
    assert.ok(rejected.headers.get("retry-after"), "503 must carry a Retry-After header");
    const retryAfter = Number(rejected.headers.get("retry-after"));
    assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1, "Retry-After is a positive integer seconds value");
    const body = await rejected.json();
    assert.equal(body.error, "haechi_overloaded");

    // Observability routes are EXEMPT from the ceiling: still 200 under saturation.
    const live = await fetch(`${base}/__haechi/live`);
    assert.equal(live.status, 200, "/__haechi/live must answer under saturation");
    const metricsRes = await fetch(`${base}/__haechi/metrics`);
    assert.equal(metricsRes.status, 200, "/__haechi/metrics must answer under saturation");
    const metricsText = await metricsRes.text();
    assert.match(metricsText, /haechi_overloaded_total 1/);
  } finally {
    release();
    await occupying;
    await proxy.close();
    await close(upstream);
  }
});

test("backpressure: maxInFlight 0 (default) imposes no ceiling", async () => {
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddr = await listen(upstream);
  const { runtime } = await makeRuntime({
    target: { type: "openai-compatible", upstream: `http://127.0.0.1:${upstreamAddr.port}` }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const results = await Promise.all([0, 1, 2, 3, 4].map(() =>
      fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] })
      })
    ));
    for (const res of results) {
      assert.equal(res.status, 200, "with maxInFlight 0 no request is rejected");
    }
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

// ---------------------------------------------------------------------------
// 3. env-var config overlay
// ---------------------------------------------------------------------------

test("env overlay: a valid HAECHI_PROXY_PORT and HAECHI_MODE overlay the file", () => {
  const file = { proxy: { port: 11016 }, mode: "dry-run" };
  const overlaid = applyEnvOverlay(file, {
    HAECHI_PROXY_PORT: "8080",
    HAECHI_MODE: "enforce",
    HAECHI_PROXY_HOST: "127.0.0.1",
    HAECHI_UPSTREAM: "http://upstream.local:9000",
    HAECHI_LOG_FORMAT: "json"
  });
  const config = normalizeConfig(overlaid);
  assert.equal(config.proxy.port, 8080, "env port wins over the file");
  assert.equal(config.mode, "enforce", "env mode wins over the file");
  assert.equal(config.proxy.host, "127.0.0.1");
  assert.equal(config.target.upstream, "http://upstream.local:9000");
  assert.equal(config.logging.format, "json");
  // The original file object is not mutated.
  assert.equal(file.proxy.port, 11016);
  assert.equal(file.mode, "dry-run");
});

test("env overlay: no relevant env vars leaves the file unchanged", () => {
  const file = { proxy: { port: 11016 }, mode: "dry-run" };
  const overlaid = applyEnvOverlay(file, { PATH: "/usr/bin", HOME: "/root" });
  assert.equal(overlaid.proxy.port, 11016);
  assert.equal(overlaid.mode, "dry-run");
});

test("env overlay: an invalid HAECHI_PROXY_PORT THROWS naming the variable", () => {
  assert.throws(
    () => applyEnvOverlay({}, { HAECHI_PROXY_PORT: "not-a-port" }),
    /HAECHI_PROXY_PORT/
  );
  assert.throws(
    () => applyEnvOverlay({}, { HAECHI_PROXY_PORT: "70000" }),
    /HAECHI_PROXY_PORT/
  );
});

test("env overlay: an invalid HAECHI_MODE THROWS naming the variable", () => {
  assert.throws(
    () => applyEnvOverlay({}, { HAECHI_MODE: "yolo" }),
    /HAECHI_MODE/
  );
});

test("env overlay: an invalid HAECHI_UPSTREAM (not a URL) THROWS", () => {
  assert.throws(
    () => applyEnvOverlay({}, { HAECHI_UPSTREAM: "%%%not-a-url" }),
    /HAECHI_UPSTREAM/
  );
});

test("env overlay: a secret-shaped env var is NOT applied (no keys.* / auth overlay)", () => {
  const file = { keys: { provider: "local", keyFile: ".haechi/dev.keys.json" }, auth: { provider: "none", store: ".haechi/auth.json" } };
  // None of these is an allowlisted overlay key, so they are ignored entirely.
  const overlaid = applyEnvOverlay(file, {
    HAECHI_KEYS_KEYFILE: "/etc/secret.key",
    HAECHI_KEY_FILE: "/etc/secret.key",
    HAECHI_AUTH_TOKEN: "sk-live-SUPERSECRET",
    HAECHI_AUTH_STORE: "/etc/auth.json",
    HAECHI_KEYS_PROVIDER: "external"
  });
  // The keys/auth blocks are byte-for-byte the same as the file — nothing leaked in.
  assert.deepEqual(overlaid.keys, file.keys);
  assert.deepEqual(overlaid.auth, file.auth);
  // And no stray key was introduced from the secret-shaped env vars.
  assert.ok(!("HAECHI_AUTH_TOKEN" in overlaid));
  assert.equal(overlaid.keys.keyFile, ".haechi/dev.keys.json");
});

// ---------------------------------------------------------------------------
// 4. tuned timeouts from config
// ---------------------------------------------------------------------------

test("timeouts: server.requestTimeout / headersTimeout are set from config", async () => {
  const { runtime } = await makeRuntime({
    limits: { requestTimeoutMs: 45000, headersTimeoutMs: 30000 }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  await proxy.listen();
  try {
    assert.equal(proxy.server.requestTimeout, 45000);
    assert.equal(proxy.server.headersTimeout, 30000);
  } finally {
    await proxy.close();
  }
});

test("timeouts: null config leaves Node's server defaults untouched", async () => {
  const { runtime } = await makeRuntime();
  const probe = createServer(() => {});
  const nodeDefaultRequestTimeout = probe.requestTimeout;
  probe.close();

  const proxy = createHaechiProxy({ runtime, port: 0 });
  await proxy.listen();
  try {
    // The default config carries null timeouts → the server keeps Node's default.
    assert.equal(proxy.server.requestTimeout, nodeDefaultRequestTimeout);
  } finally {
    await proxy.close();
  }
});

// ---------------------------------------------------------------------------
// 5. fail-closed config validation
// ---------------------------------------------------------------------------

test("normalizeConfig: bad maxInFlight / shutdownGraceMs / timeouts fail closed", () => {
  assert.throws(() => normalizeConfig({ limits: { maxInFlight: -1 } }), /limits\.maxInFlight/);
  assert.throws(() => normalizeConfig({ limits: { maxInFlight: 1.5 } }), /limits\.maxInFlight/);
  assert.throws(() => normalizeConfig({ limits: { shutdownGraceMs: -5 } }), /limits\.shutdownGraceMs/);
  assert.throws(() => normalizeConfig({ limits: { requestTimeoutMs: -1 } }), /limits\.requestTimeoutMs/);
  assert.throws(() => normalizeConfig({ limits: { headersTimeoutMs: "soon" } }), /limits\.headersTimeoutMs/);
  // Defaults preserve 1.1 behavior.
  const cfg = normalizeConfig({});
  assert.equal(cfg.limits.maxInFlight, 0);
  assert.equal(cfg.limits.shutdownGraceMs, 10000);
  assert.equal(cfg.limits.requestTimeoutMs, null);
  assert.equal(cfg.limits.headersTimeoutMs, null);
});

test("normalizeConfig: configVersion stamp defaults and fails closed on unknown/newer", () => {
  // Default stamp present.
  assert.equal(normalizeConfig({}).configVersion, CONFIG_VERSION);
  // A file omitting it is treated as the current version (not undefined).
  assert.equal(normalizeConfig({ mode: "dry-run" }).configVersion, CONFIG_VERSION);
  // An explicit current version is accepted.
  assert.equal(normalizeConfig({ configVersion: CONFIG_VERSION }).configVersion, CONFIG_VERSION);
  // A newer version fails closed.
  assert.throws(() => normalizeConfig({ configVersion: CONFIG_VERSION + 1 }), /Unsupported configVersion/);
  // A non-positive / non-integer value fails closed.
  assert.throws(() => normalizeConfig({ configVersion: 0 }), /configVersion must be a positive integer/);
  assert.throws(() => normalizeConfig({ configVersion: 1.5 }), /configVersion must be a positive integer/);
});
