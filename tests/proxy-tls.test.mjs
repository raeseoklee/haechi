// WS6 — proxy TLS / remote-bind hardening.
//
// TODAY a remote bind (--allow-remote-bind, non-loopback host) served PLAIN HTTP,
// exposing bearer tokens + payloads in cleartext. This suite pins the hardening:
//   - a remote bind WITHOUT TLS and WITHOUT trustForwardedProto THROWS at startup;
//   - a usable tlsContext makes createHaechiProxy select node:https and serve a
//     request over real TLS (a committed self-signed cert fixture);
//   - trustForwardedProto allows a plain-http remote bind but REJECTS any request
//     lacking X-Forwarded-Proto: https (a plaintext request that bypassed the hop);
//   - loopback stays plain http with no TLS required;
//   - normalizeConfig is fail-closed on a malformed proxy.tls.
//
// A 0.0.0.0 bind is non-loopback per the proxy's predicate (so it exercises the
// real remote path) yet is reachable via 127.0.0.1, so these tests need no real
// remote interface.

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdtemp, readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import {
  createHaechiProxy,
  assertSafeProxyTransport,
  hasUsableTlsMaterial
} from "../packages/proxy/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CERT_FILE = join(HERE, "fixtures", "tls", "test-cert.pem");
const KEY_FILE = join(HERE, "fixtures", "tls", "test-key.pem");

async function buildRuntime({ tls, trustForwardedProto } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-tls-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "llm-http",
      adapter: "openai-compatible",
      upstream: "http://127.0.0.1:9" // never reached in these tests
    },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath },
    proxy: { tls: tls ?? null, trustForwardedProto: trustForwardedProto ?? false }
  });
  return { runtime, dir, auditPath };
}

// -----------------------------------------------------------------------------
// hasUsableTlsMaterial — the single source of truth, shared with the dashboard.
// -----------------------------------------------------------------------------

test("hasUsableTlsMaterial gates correctly ((key && cert) or pfx)", () => {
  assert.equal(hasUsableTlsMaterial(null), false);
  assert.equal(hasUsableTlsMaterial({}), false);
  assert.equal(hasUsableTlsMaterial({ key: "k" }), false);
  assert.equal(hasUsableTlsMaterial({ cert: "c" }), false);
  assert.equal(hasUsableTlsMaterial({ key: "k", cert: "c" }), true);
  assert.equal(hasUsableTlsMaterial({ pfx: "p" }), true);
  assert.equal(hasUsableTlsMaterial([1, 2]), false);
});

// -----------------------------------------------------------------------------
// Remote bind without TLS and without trustForwardedProto THROWS.
// -----------------------------------------------------------------------------

test("remote bind without TLS and without trustForwardedProto throws at startup", async () => {
  const { runtime } = await buildRuntime();
  assert.throws(
    () => createHaechiProxy({ runtime, port: 0, host: "0.0.0.0", allowRemoteBind: true }),
    /without TLS/,
    "a remote bind that would serve tokens/payloads in plaintext must fail closed"
  );
});

test("assertSafeProxyTransport: remote needs TLS or trustForwardedProto; loopback never does", () => {
  assert.throws(
    () => assertSafeProxyTransport({ host: "0.0.0.0", allowRemoteBind: true }),
    /without TLS/
  );
  assert.doesNotThrow(() => assertSafeProxyTransport({ host: "0.0.0.0", allowRemoteBind: true, hasUsableTls: true }));
  assert.doesNotThrow(() => assertSafeProxyTransport({ host: "0.0.0.0", allowRemoteBind: true, trustForwardedProto: true }));
  // Loopback is exempt — plain http dev needs no TLS.
  assert.doesNotThrow(() => assertSafeProxyTransport({ host: "127.0.0.1", allowRemoteBind: true }));
  // A non-loopback bind WITHOUT allowRemoteBind is gated earlier (by
  // assertSafeProxyBind) — this transport check is a no-op there.
  assert.doesNotThrow(() => assertSafeProxyTransport({ host: "0.0.0.0", allowRemoteBind: false }));
});

// -----------------------------------------------------------------------------
// A usable tlsContext → node:https server serving a request over real TLS.
// -----------------------------------------------------------------------------

test("a usable tlsContext selects node:https and serves a request over TLS", async () => {
  const tls = { key: readFileSync(KEY_FILE), cert: readFileSync(CERT_FILE) };
  const { runtime } = await buildRuntime({ tls });

  // Bind 0.0.0.0 (non-loopback per predicate, reachable via 127.0.0.1) WITH a
  // real cert → the remote bind is allowed and an https server is selected.
  const proxy = createHaechiProxy({ runtime, port: 0, host: "0.0.0.0", allowRemoteBind: true });
  assert.equal(proxy.servesHttps, true, "a usable tlsContext must select an https server");

  const address = await proxy.listen();
  assert.equal(address.tls, true, "listen() must report tls:true for an https listener");
  try {
    // A liveness probe over TLS proves the server is genuinely https (a plain
    // http.request to an https socket would fail to parse). rejectUnauthorized
    // false: the fixture is self-signed.
    const body = await tlsGet({ host: "127.0.0.1", port: address.port, path: "/__haechi/live" });
    const parsed = JSON.parse(body);
    assert.equal(parsed.ok, true, "the https liveness route answers over TLS");
  } finally {
    await proxy.close();
  }
});

test("a loopback bind with a usable tlsContext also serves https (TLS is by material, not host)", async () => {
  const tls = { key: readFileSync(KEY_FILE), cert: readFileSync(CERT_FILE) };
  const { runtime } = await buildRuntime({ tls });
  const proxy = createHaechiProxy({ runtime, port: 0, host: "127.0.0.1" });
  assert.equal(proxy.servesHttps, true);
  const address = await proxy.listen();
  try {
    const body = await tlsGet({ host: "127.0.0.1", port: address.port, path: "/__haechi/live" });
    assert.equal(JSON.parse(body).ok, true);
  } finally {
    await proxy.close();
  }
});

// -----------------------------------------------------------------------------
// trustForwardedProto: a plain-http remote bind is allowed, but a request
// lacking X-Forwarded-Proto: https is rejected fail-closed.
// -----------------------------------------------------------------------------

test("trustForwardedProto allows a plain-http remote bind but enforces X-Forwarded-Proto: https", async () => {
  const { runtime } = await buildRuntime({ trustForwardedProto: true });
  const proxy = createHaechiProxy({ runtime, port: 0, host: "0.0.0.0", allowRemoteBind: true });
  assert.equal(proxy.servesHttps, false, "trustForwardedProto stays plain http (the hop terminates TLS)");
  const address = await proxy.listen();
  const base = `http://127.0.0.1:${address.port}`;
  try {
    // (1) A protected route WITHOUT X-Forwarded-Proto: https → 403 fail-closed
    // (the request bypassed the trusted TLS hop). Checked before auth/body.
    const denied = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error, "haechi_forwarded_proto_required");

    // (2) X-Forwarded-Proto: http is also rejected (only https passes).
    const httpProto = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-proto": "http" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(httpProto.status, 403);

    // (3) The /__haechi/live route is EXEMPT (it leaks nothing) — a loopback
    // sidecar health check answers without the forwarded-proto header.
    const live = await fetch(`${base}/__haechi/live`);
    assert.equal(live.status, 200);
    assert.equal((await live.json()).ok, true);

    // (4) WITH X-Forwarded-Proto: https the request passes the gate (it then
    // proceeds; the unreachable upstream yields a 5xx, NOT the 403 gate code —
    // proving the forwarded-proto gate let it through).
    const allowed = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-proto": "https" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });
    assert.notEqual(allowed.status, 403, "an https-forwarded request must clear the gate");
  } finally {
    await proxy.close();
  }
});

// -----------------------------------------------------------------------------
// Loopback stays plain http, no TLS required.
// -----------------------------------------------------------------------------

test("loopback stays plain http with no TLS required", async () => {
  const upstream = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(Buffer.concat(chunks));
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const upstreamPort = upstream.address().port;

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-tls-loop-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "llm-http", adapter: "openai-compatible", upstream: `http://127.0.0.1:${upstreamPort}` },
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });

  const proxy = createHaechiProxy({ runtime, port: 0, host: "127.0.0.1" });
  assert.equal(proxy.servesHttps, false, "a loopback bind with no tls is plain http");
  const address = await proxy.listen();
  assert.equal(address.tls, false);
  try {
    // Plain http reaches the proxy and round-trips through the upstream.
    const res = await fetch(`http://127.0.0.1:${address.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "ok" }] })
    });
    assert.equal(res.status, 200);
  } finally {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

// -----------------------------------------------------------------------------
// normalizeConfig fail-closed on a malformed proxy.tls.
// -----------------------------------------------------------------------------

test("normalizeConfig is fail-closed on a malformed proxy.tls", () => {
  // Not an object.
  assert.throws(() => normalizeConfig({ proxy: { tls: 5 } }), /proxy\.tls must be null or an object/);
  assert.throws(() => normalizeConfig({ proxy: { tls: [1, 2] } }), /proxy\.tls must be null or an object/);
  // keyFile without certFile (and vice-versa).
  assert.throws(() => normalizeConfig({ proxy: { tls: { keyFile: KEY_FILE } } }), /certFile/);
  assert.throws(() => normalizeConfig({ proxy: { tls: { certFile: CERT_FILE } } }), /keyFile/);
  // pfx AND key/cert together.
  assert.throws(
    () => normalizeConfig({ proxy: { tls: { pfxFile: "x.pfx", keyFile: KEY_FILE, certFile: CERT_FILE } } }),
    /not both/
  );
  // An unreadable file path.
  assert.throws(
    () => normalizeConfig({ proxy: { tls: { keyFile: "/no/such/key.pem", certFile: "/no/such/cert.pem" } } }),
    /could not be read/
  );
  // trustForwardedProto must be boolean.
  assert.throws(() => normalizeConfig({ proxy: { trustForwardedProto: "yes" } }), /trustForwardedProto must be boolean/);
});

test("normalizeConfig resolves proxy.tls file paths into a usable tlsContext", () => {
  const config = normalizeConfig({ proxy: { tls: { keyFile: KEY_FILE, certFile: CERT_FILE } } });
  assert.ok(config.proxy.tls, "proxy.tls resolves to a context");
  assert.ok(hasUsableTlsMaterial(config.proxy.tls), "the resolved context carries usable material");
  assert.ok(Buffer.isBuffer(config.proxy.tls.key));
  assert.ok(Buffer.isBuffer(config.proxy.tls.cert));
});

// -----------------------------------------------------------------------------
// Helper: a minimal https GET that accepts the self-signed fixture cert.
// -----------------------------------------------------------------------------

function tlsGet({ host, port, path }) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      { host, port, path, method: "GET", rejectUnauthorized: false },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      }
    );
    req.on("error", reject);
    req.end();
  });
}
