// WS4-A operability / observability tests (reliability-hardening-track §WS4).
//
// Covers: the /__haechi/live + /__haechi/ready + back-compat /__haechi/health
// split (incl. fail-closed 503 when audit is not writable, and the version
// field); the /__haechi/metrics surface (renders the expected counters after
// driving traffic; 404 when metrics.enabled:false); the no-PII-in-telemetry
// invariant (a driven secret value AND identity id appear in NEITHER the metrics
// output NOR a captured JSON log line); the per-request correlationId shared
// across a request's audit events; and structured json error logging on a forced
// error. The api-contract freeze stays green (verified by its own suite).

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy, HAECHI_VERSION } from "../packages/proxy/index.mjs";
import { createMetrics, METRIC_NAMES } from "../packages/metrics/index.mjs";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

async function makeUpstream(handler) {
  const server = createServer(handler);
  const address = await listen(server);
  return { server, url: `http://127.0.0.1:${address.port}` };
}

async function makeRuntime(overrides = {}, providers = {}) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-obs-"));
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
  return { runtime, dir, auditPath };
}

async function readAuditEvents(path) {
  const raw = await readFile(path, "utf8");
  return raw.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// ---------------------------------------------------------------------------
// 1. metrics module unit shape
// ---------------------------------------------------------------------------

test("createMetrics renders Prometheus text with HELP/TYPE and bounded names", () => {
  const metrics = createMetrics();
  metrics.increment("haechi_requests_total", { route: "chat-completions", mode: "enforce", decision: "forwarded" });
  metrics.increment("haechi_blocks_total");
  metrics.observe("haechi_request_duration_seconds", 0.012, { route: "chat-completions" });
  const out = metrics.render();

  assert.match(out, /# HELP haechi_requests_total/);
  assert.match(out, /# TYPE haechi_requests_total counter/);
  assert.match(out, /haechi_requests_total\{[^}]*decision="forwarded"[^}]*\} 1/);
  assert.match(out, /haechi_blocks_total 1/);
  assert.match(out, /# TYPE haechi_request_duration_seconds histogram/);
  assert.match(out, /haechi_request_duration_seconds_bucket\{[^}]*le="\+Inf"[^}]*\} 1/);
  assert.match(out, /haechi_request_duration_seconds_count\{route="chat-completions"\} 1/);

  // Bounded surface: every emitted metric name is in the declared catalogue.
  const known = new Set([
    ...METRIC_NAMES.counters,
    ...METRIC_NAMES.histograms.flatMap((n) => [`${n}_bucket`, `${n}_sum`, `${n}_count`])
  ]);
  for (const line of out.split("\n")) {
    if (!line || line.startsWith("#")) {
      continue;
    }
    const name = line.split("{")[0].split(" ")[0];
    assert.ok(known.has(name), `unexpected metric name in exposition: ${name}`);
  }
});

test("createMetrics ignores unknown metric names (fail-soft telemetry)", () => {
  const metrics = createMetrics();
  metrics.increment("not_a_metric", { x: "y" });
  metrics.observe("not_a_histogram", 1);
  const out = metrics.render();
  assert.doesNotMatch(out, /not_a_metric/);
  assert.doesNotMatch(out, /not_a_histogram/);
});

// ---------------------------------------------------------------------------
// 2. health split: live / ready / health
// ---------------------------------------------------------------------------

test("/__haechi/live returns 200 with version", async () => {
  const { runtime } = await makeRuntime();
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/live`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.version, HAECHI_VERSION);
    assert.notEqual(body.version, "unknown");
  } finally {
    await proxy.close();
  }
});

test("/__haechi/health stays back-compat (ok + mode) and adds version", async () => {
  const { runtime } = await makeRuntime();
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.mode, "enforce");
    assert.equal(body.version, HAECHI_VERSION);
  } finally {
    await proxy.close();
  }
});

test("/__haechi/ready returns 200 ready:true with auditWritable when audit is writable", async () => {
  const { runtime } = await makeRuntime();
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/ready`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ready, true);
    assert.equal(body.version, HAECHI_VERSION);
    assert.equal(body.checks.auditWritable, true);
  } finally {
    await proxy.close();
  }
});

test("/__haechi/ready FAILS CLOSED (503) when the audit sink reports not-ready", async () => {
  // Inject an audit sink whose ready() reports failure — a security gateway that
  // cannot audit is NOT ready.
  const failingSink = {
    record: async () => {},
    ready: async () => ({ ok: false, reason: "audit_dir_not_writable" })
  };
  const { runtime } = await makeRuntime({}, { auditSink: failingSink });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/ready`);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.ready, false);
    assert.equal(body.checks.auditWritable, false);
    assert.equal(body.version, HAECHI_VERSION);
  } finally {
    await proxy.close();
  }
});

test("/__haechi/ready treats a sink without a probe method as ready", async () => {
  const bareSink = { record: async () => {} };
  const { runtime } = await makeRuntime({}, { auditSink: bareSink });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/ready`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ready, true);
    assert.equal(body.checks.auditWritable, true);
  } finally {
    await proxy.close();
  }
});

// ---------------------------------------------------------------------------
// 3. /metrics endpoint
// ---------------------------------------------------------------------------

test("/__haechi/metrics renders expected counters after driving a request", async () => {
  const { server, url } = await makeUpstream(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] }));
  });
  const { runtime } = await makeRuntime({ target: { type: "openai-compatible", upstream: url } });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    await fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hello" }] })
    });

    const res = await fetch(`http://${address.host}:${address.port}/__haechi/metrics`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/plain/);
    const text = await res.text();
    assert.match(text, /# TYPE haechi_requests_total counter/);
    assert.match(text, /haechi_requests_total\{[^}]*decision="forwarded"[^}]*\} 1/);
    assert.match(text, /haechi_request_duration_seconds_count\{route="chat-completions"\}/);
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("/__haechi/metrics returns 404 when metrics.enabled:false", async () => {
  const { runtime } = await makeRuntime({ metrics: { enabled: false } });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/__haechi/metrics`);
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error, "haechi_metrics_disabled");
  } finally {
    await proxy.close();
  }
});

test("a blocked request increments blocks_total and the blocked decision counter", async () => {
  const { server, url } = await makeUpstream(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  // card → block (default action). Drive a Luhn-valid test card number.
  const { runtime } = await makeRuntime({
    target: { type: "openai-compatible", upstream: url },
    policy: { mode: "enforce", presets: ["korean-pii", "secrets-only", "llm-redact"], defaultAction: "redact", actions: { card: "block" } }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    const res = await fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "card 4111 1111 1111 1111" }] })
    });
    assert.equal(res.status, 403);
    const metricsRes = await fetch(`http://${address.host}:${address.port}/__haechi/metrics`);
    const text = await metricsRes.text();
    assert.match(text, /haechi_blocks_total 1/);
    assert.match(text, /haechi_requests_total\{[^}]*decision="blocked"[^}]*\} 1/);
  } finally {
    await proxy.close();
    await close(server);
  }
});

// ---------------------------------------------------------------------------
// 4. NO-PII-in-telemetry invariant
// ---------------------------------------------------------------------------

test("NO-PII: a driven secret value and identity id appear in NEITHER metrics NOR a json log line", async () => {
  const SECRET = "sk-live-ABCDEF0123456789TOPSECRETVALUE";
  const IDENTITY_ID = "user-PII-IDENTITY-12345";

  // Upstream that fails so a request reaches the error/log path too. We use a
  // closed socket: forward() will fail → internal/upstream path. To force the
  // INTERNAL-error json log (correlationId + errorName), inject an auditSink whose
  // record() throws AFTER detection, so protectJson rejects and the proxy logs.
  const throwingSink = {
    record: async () => { throw new Error("audit write blew up"); },
    ready: async () => ({ ok: true })
  };
  const { server, url } = await makeUpstream(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const { runtime } = await makeRuntime(
    {
      target: { type: "openai-compatible", upstream: url },
      logging: { format: "json" }
    },
    { auditSink: throwingSink }
  );

  // Capture stderr (where the json error log is written).
  const captured = [];
  const originalWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    captured.push(String(chunk));
    return originalWrite(chunk, ...rest);
  };

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    await fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${IDENTITY_ID}` },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: `my key is ${SECRET}` }] })
    }).catch(() => {});

    const metricsRes = await fetch(`http://${address.host}:${address.port}/__haechi/metrics`);
    const metricsText = await metricsRes.text();
    const logText = captured.join("");

    // The secret value and identity id must appear NOWHERE in telemetry.
    assert.doesNotMatch(metricsText, new RegExp(SECRET.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(metricsText, new RegExp(IDENTITY_ID));
    assert.doesNotMatch(logText, new RegExp(SECRET.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(logText, new RegExp(IDENTITY_ID));

    // At least one structured json error line was emitted, and it carries a
    // correlationId + errorName but no payload.
    const jsonLines = logText.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l));
    const errorLine = jsonLines.find((l) => l.event === "proxy_internal_error");
    assert.ok(errorLine, "expected a json proxy_internal_error log line");
    assert.equal(typeof errorLine.correlationId, "string");
    assert.equal(typeof errorLine.errorName, "string");
    assert.ok(!("payload" in errorLine) && !("body" in errorLine) && !("message" in errorLine && /sk-live/.test(errorLine.message ?? "")));
  } finally {
    process.stderr.write = originalWrite;
    await proxy.close();
    await close(server);
  }
});

// ---------------------------------------------------------------------------
// 5. correlationId on audit events, shared across a request's events
// ---------------------------------------------------------------------------

test("correlationId is present on audit events and shared across one request's events", async () => {
  const { server, url } = await makeUpstream(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "found minji.kim@example.com" } }] }));
  });
  const { runtime, auditPath } = await makeRuntime({
    target: { type: "openai-compatible", upstream: url },
    responseProtection: { enabled: true, mode: "enforce" }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    await fetch(`http://${address.host}:${address.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "contact minji.kim@example.com" }] })
    });

    const events = await readAuditEvents(auditPath);
    assert.ok(events.length >= 2, "expected request + response audit events");
    const requestEvent = events.find((e) => String(e.operation).startsWith("request:"));
    const responseEvent = events.find((e) => String(e.operation).startsWith("response:"));
    assert.ok(requestEvent && responseEvent);
    assert.equal(typeof requestEvent.correlationId, "string");
    assert.equal(requestEvent.correlationId, responseEvent.correlationId,
      "request and response events of one request must share the correlationId");
  } finally {
    await proxy.close();
    await close(server);
  }
});

test("non-proxy protectJson keeps correlationId null (preserves existing behavior)", async () => {
  const { runtime, auditPath } = await makeRuntime();
  await runtime.haechi.protectJson(
    { msg: "contact minji.kim@example.com" },
    { protocol: "test", operation: "protect" }
  );
  const events = await readAuditEvents(auditPath);
  assert.equal(events.at(-1).correlationId, null);
});

// ---------------------------------------------------------------------------
// 6. config validation (fail-closed)
// ---------------------------------------------------------------------------

test("logging.format and metrics.enabled validate fail-closed", async () => {
  const { normalizeConfig } = await import("../packages/cli/runtime.mjs");
  assert.throws(() => normalizeConfig({ logging: { format: "yaml" } }), /Invalid logging\.format/);
  assert.throws(() => normalizeConfig({ metrics: { enabled: "yes" } }), /metrics\.enabled must be boolean/);
  // Defaults preserve 1.1 behavior.
  const cfg = normalizeConfig({});
  assert.equal(cfg.logging.format, "text");
  assert.equal(cfg.metrics.enabled, true);
});
