import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHmac } from "node:crypto";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { createLocalCryptoProvider, initLocalKeyFile, canonicalize } from "../packages/crypto/index.mjs";
import { createLocalTokenVault } from "../packages/token-vault/index.mjs";
import { createJsonlAuditSink, verifyAuditChain } from "../packages/audit/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";
import { applyPrivacyProfile } from "../packages/privacy-profiles/index.mjs";
import { signPolicyBundle, verifyPolicyBundle } from "../packages/policy-bundle/index.mjs";
import { protectMcpJsonRpcMessage } from "../packages/mcp-stdio/index.mjs";

async function makeRuntime(dir, overrides = {}) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact"
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    ...overrides
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

test("ollama chat requests without stream:false are treated as streaming and blocked", async () => {
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: { role: "assistant", content: "ok" } }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-ollama-stream-"));
  const runtime = await makeRuntime(dir, {
    target: {
      type: "ollama",
      adapter: "ollama",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    // Ollama defaults to streaming when stream is omitted: must be blocked.
    const implicit = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "llama3", messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(implicit.status, 501);
    assert.equal((await implicit.json()).error, "haechi_streaming_unsupported");

    // Explicit stream:false is a regular JSON request and passes through.
    const explicit = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "llama3", stream: false, messages: [{ role: "user", content: "hi" }] })
    });
    assert.equal(explicit.status, 200);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("proxy fails with 504 when upstream exceeds limits.upstreamTimeoutMs", async () => {
  const upstream = createServer(() => {
    // Never respond.
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-upstream-timeout-"));
  const runtime = await makeRuntime(dir, {
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    limits: {
      maxRequestBytes: 1048576,
      upstreamTimeoutMs: 200
    }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hello" }] })
    });
    assert.equal(response.status, 504);
    assert.equal((await response.json()).error, "haechi_upstream_timeout");
  } finally {
    await proxy.close();
    upstream.closeAllConnections();
    upstream.close();
  }
});

test("privacy profile cannot weaken a stricter user action", async () => {
  const applied = applyPrivacyProfile({
    actions: {
      email: "block"
    }
  }, "eu-gdpr");

  // eu-gdpr sets email: tokenize, but the user's block must win.
  assert.equal(applied.actions.email, "block");
  // Profile still strengthens unset types.
  assert.equal(applied.actions.card, "block");
});

test("decrypt selects key by envelope kid after rotation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-key-rotation-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });

  const before = createLocalCryptoProvider({ keyFile });
  const envelope = await before.encrypt({ plaintext: "secret@example.com", aad: { p: "x" } });

  const rotation = await initLocalKeyFile(keyFile, { force: true });
  assert.equal(rotation.rotated, true);

  const keyData = JSON.parse(await readFile(keyFile, "utf8"));
  assert.equal(keyData.keys.length, 2);
  assert.equal(keyData.keys.filter((key) => key.status === "active").length, 1);
  assert.equal(keyData.keys.filter((key) => key.status === "retired").length, 1);

  // A fresh provider over the rotated file still decrypts the old envelope.
  const after = createLocalCryptoProvider({ keyFile });
  assert.equal(await after.decrypt({ envelope, aad: { p: "x" } }), "secret@example.com");
});

test("policy bundle signatures use a domain-separated signing key", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-bundle-domain-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });

  const policy = { presets: ["secrets-only"], defaultAction: "redact" };
  const bundle = signPolicyBundle(policy, { keyFile });
  assert.equal(verifyPolicyBundle(bundle, { keyFile }).valid, true);

  // A signature computed directly with the raw stored key (no domain
  // separation) must NOT verify.
  const keyData = JSON.parse(await readFile(keyFile, "utf8"));
  const rawKey = Buffer.from(keyData.keys[0].k, "base64url");
  const payload = {
    version: bundle.version,
    alg: bundle.alg,
    kid: bundle.kid,
    signedAt: bundle.signedAt,
    policy: bundle.policy
  };
  const rawSignature = createHmac("sha256", rawKey).update(canonicalize(payload)).digest("base64url");
  assert.notEqual(rawSignature, bundle.signature);
  assert.throws(
    () => verifyPolicyBundle({ ...bundle, signature: rawSignature }, { keyFile }),
    /signature verification failed/
  );
});

test("token reveal decisions are recorded in the audit log", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-reveal-audit-"));
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const runtime = await makeRuntime(dir, {
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { email: "tokenize" }
    },
    audit: { path: auditPath },
    tokenVault: {
      path: join(dir, ".haechi", "token-vault.json"),
      revealPolicy: "local-dev"
    }
  });

  const result = await runtime.haechi.protectJson({ message: "contact minji.kim@example.com" });
  const token = result.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];

  await runtime.tokenVault.reveal({ token });
  await assert.rejects(() => runtime.tokenVault.reveal({ token: "tok_email_unknown" }), /Unknown token/);

  const audit = await readFile(auditPath, "utf8");
  assert.match(audit, /"decision":"reveal_allowed"/);
  assert.match(audit, /"decision":"reveal_failed"/);
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  assert.equal((await verifyAuditChain(auditPath)).valid, true);
});

test("denied reveal under disabled policy is audited", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-reveal-denied-"));
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const runtime = await makeRuntime(dir, {
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { email: "tokenize" }
    },
    audit: { path: auditPath },
    tokenVault: { path: join(dir, ".haechi", "token-vault.json") }
  });

  const result = await runtime.haechi.protectJson({ message: "contact minji.kim@example.com" });
  const token = result.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];

  await assert.rejects(() => runtime.tokenVault.reveal({ token }), /Token reveal is disabled/);
  const audit = await readFile(auditPath, "utf8");
  assert.match(audit, /"decision":"reveal_denied"/);
});

test("expired tokens are purged from disk", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-retention-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  await initLocalKeyFile(keyFile, { force: true });
  const vault = createLocalTokenVault({
    path: vaultPath,
    cryptoProvider: createLocalCryptoProvider({ keyFile }),
    revealPolicy: "local-dev",
    retentionDays: 1e-8
  });

  await vault.tokenize({ plaintext: "old@example.com", type: "email" });
  await new Promise((resolve) => setTimeout(resolve, 20));

  const result = await vault.purgeExpired();
  assert.equal(result.purged, 1);
  assert.doesNotMatch(await readFile(vaultPath, "utf8"), /tok_email_/);
});

test("audit sink recovers from a stale lock file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stale-lock-"));
  const auditPath = join(dir, "audit.jsonl");
  const lockPath = `${auditPath}.lock`;
  await writeFile(lockPath, "", "utf8");
  const past = new Date(Date.now() - 60000);
  await utimes(lockPath, past, past);

  const sink = createJsonlAuditSink({ path: auditPath });
  await sink.record({
    id: "stale-lock-test",
    timestamp: new Date(0).toISOString(),
    protocol: "test",
    operation: "stale-lock",
    mode: "enforce",
    enforced: true,
    blocked: false,
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  });

  assert.deepEqual(await verifyAuditChain(auditPath), { valid: true, records: 1 });
});

test("card numbers passed as JSON numbers are detected and enforced", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-number-scan-"));
  const runtime = await makeRuntime(dir, {
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { card: "block" }
    }
  });

  const result = await runtime.haechi.protectJson({ card: 4111111111111111 });
  assert.equal(result.blocked, true);
  assert.equal(result.payload, null);
});

test("short masked values are fully masked", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-mask-short-"));
  const runtime = await makeRuntime(dir, {
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { pin: "mask" }
    },
    filters: {
      customRules: [
        { id: "pin", type: "pin", pattern: "PIN[0-9]{4}", confidence: 0.9 }
      ]
    }
  });

  const result = await runtime.haechi.protectJson({ message: "code PIN1234 end" });
  assert.match(result.payload.message, /code \*{7} end/);
});

test("assignment secrets keep the key name and redact only the value", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-assignment-secret-"));
  const runtime = await makeRuntime(dir, {
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { secret: "redact" }
    }
  });

  const result = await runtime.haechi.protectJson({
    message: "config api_key: abcdef123456789012 done"
  });
  assert.equal(result.payload.message, "config api_key: [REDACTED:secret] done");
});

test("MCP notifications are dropped instead of answered when rejected", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-mcp-notification-"));
  const runtime = await makeRuntime(dir, {
    mcp: { allowedMethods: ["tools/call"] }
  });

  const dropped = await protectMcpJsonRpcMessage({
    jsonrpc: "2.0",
    method: "notifications/cancelled",
    params: {}
  }, runtime);
  assert.equal(dropped, null);

  // Requests (with id) still receive an explicit error response.
  const rejected = await protectMcpJsonRpcMessage({
    jsonrpc: "2.0",
    id: 9,
    method: "roots/list",
    params: {}
  }, runtime);
  assert.equal(rejected.error.message, "haechi_mcp_method_not_allowed");

  await assert.rejects(
    () => protectMcpJsonRpcMessage([{ jsonrpc: "2.0", id: 1, method: "tools/call" }], runtime),
    /batch messages are not supported/
  );
});
