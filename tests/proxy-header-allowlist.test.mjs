// ============================================================================
// P0-CR-001 / P1-CR-003 / P1-CR-004 regression suite.
//
// P0-CR-001 — the upstream header forward policy is a DEFAULT-DROP allowlist:
//   - a GATEWAY bearer token (auth.provider: bearer) the gateway consumed to
//     authenticate the client is NOT visible to a local stub upstream,
//   - provider headers the adapters need (x-api-key / anthropic-version /
//     x-goog-api-key) ARE forwarded,
//   - cookie / proxy-authorization / hop-by-hop are dropped,
//   - auth.provider: none forwards the client's Authorization (the upstream key),
//   - target.forwardHeaders additively widens the allowlist.
//
// P1-CR-003 — a gzip upstream response (Node fetch auto-decompresses) returns
//   without a stale content-encoding/content-length, and a downstream fetch can
//   read it (pass-through + unprotected paths).
//
// P1-CR-004 — the streaming pass-through path enforces the byte cap: an oversize
//   upstream stream is bounded/aborted rather than buffered unbounded.
// ============================================================================

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { gzipSync } from "node:zlib";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile, createLocalCryptoProvider } from "../packages/crypto/index.mjs";
import { addToken } from "../packages/auth/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

// An upstream that records the headers of the LAST request it received, so a
// test can assert exactly what crossed the gateway->upstream boundary.
function headerCapturingUpstream() {
  const state = { lastHeaders: null };
  const server = createServer((request, response) => {
    state.lastHeaders = { ...request.headers };
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  return { server, state };
}

async function project(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return {
    keyFile,
    auditPath: join(dir, ".haechi", "audit.jsonl"),
    storePath: join(dir, ".haechi", "auth.json"),
    cryptoProvider: createLocalCryptoProvider({ keyFile })
  };
}

async function startProxy(runtimeConfig, upstream) {
  const upstreamAddress = await listen(upstream);
  runtimeConfig.target = {
    ...(runtimeConfig.target ?? {}),
    type: runtimeConfig.target?.type ?? "vllm-openai",
    upstream: `http://127.0.0.1:${upstreamAddress.port}`
  };
  const runtime = createRuntime(runtimeConfig);
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();
  return { proxy, base: `http://${proxyAddress.host}:${proxyAddress.port}` };
}

// --- P0-CR-001 ---------------------------------------------------------------

test("P0-CR-001: gateway bearer token is NOT forwarded to the upstream; provider headers ARE", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-hdr-bearer-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const { token } = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["team:eng"] });

  const { server, state } = headerCapturingUpstream();
  const { proxy, base } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, server);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
        "x-api-key": "sk-provider-key",
        "anthropic-version": "2023-06-01",
        "x-goog-api-key": "goog-provider-key"
      },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(res.status, 200);

    // The GATEWAY credential must NOT have reached the upstream.
    assert.equal(state.lastHeaders.authorization, undefined,
      "gateway bearer Authorization must not be forwarded upstream");
    assert.equal(state.lastHeaders.authorization?.includes?.(token) ?? false, false);

    // Provider headers the adapters need MUST still cross.
    assert.equal(state.lastHeaders["x-api-key"], "sk-provider-key");
    assert.equal(state.lastHeaders["anthropic-version"], "2023-06-01");
    assert.equal(state.lastHeaders["x-goog-api-key"], "goog-provider-key");
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("P0-CR-001: cookie, proxy-authorization, and hop-by-hop headers are dropped", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-hdr-drop-"));
  const { keyFile, auditPath } = await project(dir);

  const { server, state } = headerCapturingUpstream();
  const { proxy, base } = await startProxy({
    mode: "enforce",
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, server);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: "session=secret-cookie",
        "proxy-authorization": "Basic proxy-secret",
        // hop-by-hop control header (fetch may strip some itself, but the proxy
        // allowlist guarantees neither survives).
        te: "trailers",
        "x-custom-unlisted": "should-be-dropped"
      },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 200);

    assert.equal(state.lastHeaders.cookie, undefined, "cookie must be dropped");
    assert.equal(state.lastHeaders["proxy-authorization"], undefined, "proxy-authorization must be dropped");
    assert.equal(state.lastHeaders.te, undefined, "hop-by-hop te must be dropped");
    assert.equal(state.lastHeaders["x-custom-unlisted"], undefined, "an unlisted header must be default-dropped");
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("P0-CR-001: auth.provider none forwards the client Authorization (upstream provider key)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-hdr-none-"));
  const { keyFile, auditPath } = await project(dir);

  const { server, state } = headerCapturingUpstream();
  const { proxy, base } = await startProxy({
    mode: "enforce",
    // auth.provider defaults to none.
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, server);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer sk-upstream-provider-key"
      },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 200);

    // With no gateway auth, Authorization is the upstream provider key and IS forwarded.
    assert.equal(state.lastHeaders.authorization, "Bearer sk-upstream-provider-key");
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("P0-CR-001: target.forwardHeaders additively widens the allowlist", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-hdr-extra-"));
  const { keyFile, auditPath } = await project(dir);

  const { server, state } = headerCapturingUpstream();
  const { proxy, base } = await startProxy({
    mode: "enforce",
    target: { type: "vllm-openai", forwardHeaders: ["x-tenant-id"] },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, server);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-tenant-id": "tenant-42",
        "x-other-unlisted": "dropped"
      },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 200);

    assert.equal(state.lastHeaders["x-tenant-id"], "tenant-42", "an extra forwardHeaders entry must cross");
    assert.equal(state.lastHeaders["x-other-unlisted"], undefined, "an unlisted header stays dropped");
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("P0-CR-001: target.forwardHeaders is fail-closed in normalizeConfig", () => {
  assert.throws(() => normalizeConfig({ target: { forwardHeaders: "x-api-key" } }), /target\.forwardHeaders must be an array/);
  assert.throws(() => normalizeConfig({ target: { forwardHeaders: [123] } }), /non-empty strings/);
  assert.throws(() => normalizeConfig({ target: { forwardHeaders: ["X-Mixed-Case"] } }), /lowercase/);
  // It may NOT re-enable an always-dropped credential / hop-by-hop header.
  assert.throws(() => normalizeConfig({ target: { forwardHeaders: ["cookie"] } }), /always-dropped/);
  assert.throws(() => normalizeConfig({ target: { forwardHeaders: ["authorization"] } }), /always-dropped/);
  // A valid extension passes and is normalized/de-duplicated.
  const ok = normalizeConfig({ target: { forwardHeaders: ["x-tenant-id", "x-tenant-id"] } });
  assert.deepEqual(ok.target.forwardHeaders, ["x-tenant-id"]);
});

// --- P1-CR-003 ---------------------------------------------------------------

test("P1-CR-003: gzip upstream returns without a stale content-encoding (pass-through path)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-gzip-pt-"));
  const { keyFile, auditPath } = await project(dir);

  const payload = JSON.stringify({ choices: [{ message: { content: "hello world" } }] });
  const gz = gzipSync(Buffer.from(payload));
  const upstream = createServer((request, response) => {
    response.writeHead(200, {
      "content-type": "application/json",
      "content-encoding": "gzip",
      "content-length": String(gz.byteLength)
    });
    response.end(gz);
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    streaming: { requestMode: "pass-through" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, messages: [] })
    });
    assert.equal(res.status, 200);
    // No stale compression metadata on the downstream response.
    assert.equal(res.headers.get("content-encoding"), null);
    // A downstream fetch can read the body (it does not fail "incorrect header check").
    const body = await res.text();
    assert.match(body, /hello world/);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("P1-CR-003: gzip upstream returns readable bytes on the unprotected/forwarded path", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-gzip-unprot-"));
  const { keyFile, auditPath } = await project(dir);

  const payload = JSON.stringify({ result: "no response protection here" });
  const gz = gzipSync(Buffer.from(payload));
  const upstream = createServer((request, response) => {
    response.writeHead(200, {
      "content-type": "application/json",
      "content-encoding": "gzip",
      "content-length": String(gz.byteLength)
    });
    response.end(gz);
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    // responseProtection disabled => the unprotected/forwarded path.
    responseProtection: { enabled: false },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-encoding"), null);
    const json = await res.json();
    assert.equal(json.result, "no response protection here");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

// --- P1-CR-004 ---------------------------------------------------------------

test("P1-CR-004: streaming pass-through enforces the byte cap (oversize stream is bounded)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pt-cap-"));
  const { keyFile, auditPath } = await project(dir);

  const cap = 1024;
  // The upstream streams far more than the cap and never sets content-length, so
  // the cap must be enforced by the running byte count, not by a length header.
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    let sent = 0;
    const chunk = "x".repeat(256);
    const timer = setInterval(() => {
      if (sent > cap * 8) {
        clearInterval(timer);
        response.end();
        return;
      }
      sent += chunk.length;
      response.write(chunk);
    }, 1);
    request.on("close", () => clearInterval(timer));
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    streaming: { requestMode: "pass-through" },
    responseProtection: { enabled: false, maxBytes: cap },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ stream: true, messages: [] })
    });
    assert.equal(res.status, 200);

    // The body is bounded: either the read aborts (network error) or the bytes
    // delivered are capped near maxBytes — never the full multi-cap stream.
    let received = 0;
    let aborted = false;
    try {
      const reader = res.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
      }
    } catch {
      aborted = true;
    }
    assert.ok(aborted || received <= cap + 512,
      `pass-through must bound the stream (aborted=${aborted}, received=${received}, cap=${cap})`);
    assert.ok(received < cap * 8,
      `pass-through must not deliver the full oversize stream (received=${received})`);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("P1-CR-004: unprotected/forwarded path fails closed on an oversize buffered body", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-unprot-cap-"));
  const { keyFile, auditPath } = await project(dir);

  const cap = 256;
  const big = "y".repeat(cap * 4);
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json", "content-length": String(big.length) });
    response.end(big);
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    responseProtection: { enabled: false, maxBytes: cap },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 502);
    assert.equal((await res.json()).reason, "response_body_too_large");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});
