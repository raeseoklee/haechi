import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile, createLocalCryptoProvider } from "../packages/crypto/index.mjs";
import { addToken } from "../packages/auth/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";
import { verifyAuditChain } from "../packages/audit/index.mjs";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

function echoUpstream() {
  return createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
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
  runtimeConfig.target = { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` };
  const runtime = createRuntime(runtimeConfig);
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();
  return { proxy, base: `http://${proxyAddress.host}:${proxyAddress.port}`, upstream };
}

test("bearer auth: valid token passes, missing/invalid is 401 and never reaches upstream", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pauth-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const { token } = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["team:eng"] });

  let upstreamHits = 0;
  const upstream = createServer((request, response) => {
    upstreamHits += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const ok = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(ok.status, 200);

    const noToken = await fetch(`${base}/v1/chat/completions`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(noToken.status, 401);
    assert.equal((await noToken.json()).error, "haechi_auth_denied");

    const badToken = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer hae_wrong" },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(badToken.status, 401);

    assert.equal(upstreamHits, 1); // only the authenticated request reached upstream

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /"decision":"auth_denied"/);
    assert.match(audit, /"reason":"no_token"/);
    assert.match(audit, /"reason":"invalid_token"/);
    assert.doesNotMatch(audit, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("health stays unauthenticated", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-phealth-"));
  const { keyFile, auditPath, storePath } = await project(dir);
  const { proxy, base, upstream } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: { mode: "enforce", presets: [] },
    keys: { keyFile }, audit: { path: auditPath }
  }, echoUpstream());

  try {
    const health = await fetch(`${base}/__haechi/health`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).ok, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("the resolved profile applies its policy and audit records identity + profile", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pprofile-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const eng = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["team:eng"] });

  // Upstream echoes the request body back so we can see what was forwarded.
  const upstream = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(Buffer.concat(chunks));
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow", actions: { email: "redact" },
      profiles: {
        strict: { actions: { email: "block" } },
        internal: { actions: { email: "allow" } }
      },
      profileBinding: { byScope: { "team:eng": "internal" }, default: "strict" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    // team:eng → internal profile → email allowed through.
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${eng.token}` },
      body: JSON.stringify({ messages: [{ role: "user", content: "mail minji.kim@example.com" }] })
    });
    const echoed = await res.json();
    assert.match(JSON.stringify(echoed), /minji\.kim@example\.com/);

    const audit = await readFile(auditPath, "utf8");
    const lines = audit.trim().split("\n").map((l) => JSON.parse(l));
    const protectEvent = lines.find((l) => l.operation?.startsWith("request:"));
    assert.equal(protectEvent.profile, "internal");
    assert.equal(protectEvent.identity.id, eng.record.id);
    assert.equal(protectEvent.identity.provider, "bearer");
    // No raw token/subject in the audit.
    assert.doesNotMatch(audit, new RegExp(eng.token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("model allowlist blocks a disallowed model with 403", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pmodel-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const tok = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["team:eng"] });

  let upstreamHits = 0;
  const upstream = createServer((request, response) => {
    upstreamHits += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });

  const { proxy, base } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      profiles: { eng: { modelAllowlist: ["llama3"] } },
      profileBinding: { byScope: { "team:eng": "eng" }, default: "eng" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  }, upstream);

  try {
    const allowed = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
      body: JSON.stringify({ model: "llama3", messages: [] })
    });
    assert.equal(allowed.status, 200);

    const denied = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
      body: JSON.stringify({ model: "gpt-4o", messages: [] })
    });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error, "haechi_model_not_allowed");
    assert.equal(upstreamHits, 1);

    assert.match(await readFile(auditPath, "utf8"), /"decision":"model_not_allowed"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("rate limit returns 429 after the per-minute budget and isolates identities", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-prate-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const a = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:a"] });
  const b = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:b"] });

  const { proxy, base, upstream } = await startProxy({
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      profiles: { limited: { rate: { requestsPerMinute: 2 } }, other: {} },
      profileBinding: { byScope: { "tier:a": "limited", "tier:b": "other" }, default: "other" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  }, echoUpstream());

  async function hit(token) {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ messages: [] })
    });
    return res.status;
  }

  try {
    assert.equal(await hit(a.token), 200);
    assert.equal(await hit(a.token), 200);
    assert.equal(await hit(a.token), 429); // over the budget of 2/min
    // A different identity is not affected by A's window.
    assert.equal(await hit(b.token), 200);
    assert.match(await readFile(auditPath, "utf8"), /"decision":"rate_limited"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("auth provider that throws fails closed: 401, no upstream, no exception/stack leak, audit records provider_error", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pthrow-"));
  const { keyFile, auditPath, cryptoProvider } = await project(dir);

  // The throw carries a secret-shaped message + stack we can grep for to prove
  // neither the client body nor the audit event echoes the raw exception.
  const secretInError = "boom-aws-AKIAIOSFODNN7EXAMPLE-subject=alice@corp.example";
  const failingAuthProvider = {
    async authenticate() {
      throw new Error(secretInError);
    }
  };

  let upstreamHits = 0;
  const upstream = createServer((request, response) => {
    upstreamHits += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });

  // Inline the startup (mirrors startProxy) so the throwing authProvider can be
  // injected via createRuntime's providers argument; auth.provider "external"
  // requires an injected authProvider.
  const upstreamAddress = await listen(upstream);
  const runtime = createRuntime({
    mode: "enforce",
    auth: { provider: "external" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath },
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` }
  }, { authProvider: failingAuthProvider, cryptoProvider });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();
  const base = `http://${proxyAddress.host}:${proxyAddress.port}`;

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer hae_anything" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] })
    });

    // (a) fail closed: rejected, generic client error, never forwarded upstream.
    assert.equal(res.status, 401);
    const bodyText = await res.text();
    const body = JSON.parse(bodyText);
    assert.equal(body.error, "haechi_auth_denied");
    assert.equal(body.message, "Authentication failed");
    assert.equal(upstreamHits, 0);
    // No raw exception text/stack in the client body.
    assert.doesNotMatch(bodyText, /boom-aws/);
    assert.doesNotMatch(bodyText, /AKIA/);
    assert.doesNotMatch(bodyText, /alice@corp\.example/);
    assert.doesNotMatch(bodyText, /\bat \w/); // stack-frame shape ("at fn (file:line)")

    // (b) audit records the fail-closed status (decision auth_denied / reason provider_error).
    const audit = await readFile(auditPath, "utf8");
    const lines = audit.trim().split("\n").map((l) => JSON.parse(l));
    const denied = lines.find((l) => l.decision === "auth_denied");
    assert.ok(denied, "expected an auth_denied audit event");
    assert.equal(denied.reason, "provider_error");
    assert.equal(denied.enforced, true);
    assert.equal(denied.blocked, true);

    // (c) no raw error message/stack and no raw subject/issuer leak into the audit;
    // identity is null on the provider-error path (no keyed-hash subject/issuer either).
    assert.equal(denied.identity, null);
    assert.equal(denied.profile, null);
    assert.doesNotMatch(audit, /boom-aws/);
    assert.doesNotMatch(audit, /AKIA/);
    assert.doesNotMatch(audit, /alice@corp\.example/);
    assert.doesNotMatch(audit, /\bat \w/);

    assert.equal((await verifyAuditChain(auditPath)).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("provider none keeps identity null and audit unchanged", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pnone-"));
  const { keyFile, auditPath } = await project(dir);
  const { proxy, base, upstream } = await startProxy({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile }, audit: { path: auditPath }
  }, echoUpstream());

  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "mail minji.kim@example.com" }] })
    });
    assert.equal(res.status, 200);
    const lines = (await readFile(auditPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const protectEvent = lines.find((l) => l.operation?.startsWith("request:"));
    assert.equal(protectEvent.identity, null);
    assert.equal(protectEvent.profile, null);
  } finally {
    await proxy.close();
    upstream.close();
  }
});
