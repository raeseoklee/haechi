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

async function makeRuntime(dir, tokenVaultOverrides = {}, extra = {}) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { email: "tokenize" }
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    tokenVault: {
      path: join(dir, ".haechi", "token-vault.json"),
      ...tokenVaultOverrides
    },
    ...extra
  });
}

function tokenOf(result) {
  return result.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

test("deterministic tokenization maps equal values to equal tokens", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-deterministic-"));
  const runtime = await makeRuntime(dir, { deterministic: true });

  const first = await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  const second = await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  const other = await runtime.haechi.protectJson({ message: "other@example.com" });

  assert.equal(tokenOf(first), tokenOf(second));
  assert.notEqual(tokenOf(first), tokenOf(other));
  assert.deepEqual(first.issuedTokens, [tokenOf(first)]);

  // A single vault record is reused, not duplicated.
  const metadata = await runtime.tokenVault.exportMetadata({ type: "email" });
  assert.equal(metadata.filter((entry) => entry.token === tokenOf(first)).length, 1);
});

test("random tokenization stays the default", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-random-token-"));
  const runtime = await makeRuntime(dir);

  const first = await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  const second = await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  assert.notEqual(tokenOf(first), tokenOf(second));
});

test("a different derived key produces different deterministic tokens", async () => {
  const dirA = await mkdtemp(join(tmpdir(), "haechi-det-key-a-"));
  const dirB = await mkdtemp(join(tmpdir(), "haechi-det-key-b-"));
  const runtimeA = await makeRuntime(dirA, { deterministic: true });
  const runtimeB = await makeRuntime(dirB, { deterministic: true });

  const tokenA = tokenOf(await runtimeA.haechi.protectJson({ message: "minji.kim@example.com" }));
  const tokenB = tokenOf(await runtimeB.haechi.protectJson({ message: "minji.kim@example.com" }));
  assert.notEqual(tokenA, tokenB);
});

test("deterministicTypes limits determinism to listed types", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-det-types-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: { email: "tokenize", phone: "tokenize" }
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    tokenVault: {
      path: join(dir, ".haechi", "token-vault.json"),
      deterministic: true,
      deterministicTypes: ["email"]
    }
  });

  const payload = { message: "minji.kim@example.com call 010-1234-5678" };
  const first = (await runtime.haechi.protectJson(payload)).payload.message;
  const second = (await runtime.haechi.protectJson(payload)).payload.message;

  const emailToken = (text) => text.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];
  const phoneToken = (text) => text.match(/\[TOKEN:(tok_phone_[a-f0-9]+)\]/)[1];
  assert.equal(emailToken(first), emailToken(second));
  assert.notEqual(phoneToken(first), phoneToken(second));
});

test("config validation rejects malformed round-trip settings", () => {
  assert.throws(() => normalizeConfig({ tokenVault: { deterministic: "yes" } }), /deterministic must be boolean/);
  assert.throws(() => normalizeConfig({ tokenVault: { deterministicTypes: [] } }), /deterministicTypes/);
  assert.throws(() => normalizeConfig({ tokenVault: { deterministicTypes: [7] } }), /deterministicTypes/);
  assert.throws(() => normalizeConfig({ tokenVault: { detokenizeResponses: 1 } }), /detokenizeResponses must be boolean/);
});

test("proxy restores request-issued tokens in the response (model sees token, caller sees plaintext)", async () => {
  let upstreamSawBody = null;
  const upstream = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
    }
    upstreamSawBody = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const token = upstreamSawBody.messages[0].content.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      choices: [{ message: { role: "assistant", content: `The address [TOKEN:${token}] is confirmed` } }]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-detokenize-"));
  const runtime = await makeRuntime(dir, {
    deterministic: true,
    detokenizeResponses: true
  }, {
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    responseProtection: { enabled: true, mode: "enforce" }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "email minji.kim@example.com please" }] })
    });
    const body = await response.json();

    // Upstream (the model) saw a token, never the plaintext.
    assert.doesNotMatch(JSON.stringify(upstreamSawBody), /minji\.kim@example\.com/);
    assert.match(upstreamSawBody.messages[0].content, /\[TOKEN:tok_email_/);
    // The caller got the plaintext back.
    assert.equal(body.choices[0].message.content, "The address minji.kim@example.com is confirmed");

    // Detokenization is audited by count, never by value.
    const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
    assert.match(audit, /"decision":"detokenize"/);
    assert.match(audit, /"count":1/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
    assert.equal((await verifyAuditChain(join(dir, ".haechi", "audit.jsonl"))).valid, true);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("tokens not issued by the request are NOT restored (scope isolation)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-detok-scope-"));

  let foreignToken = null;
  const upstream = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      choices: [{ message: { role: "assistant", content: `leak attempt [TOKEN:${foreignToken}]` } }]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const runtime = await makeRuntime(dir, {
    deterministic: true,
    detokenizeResponses: true
  }, {
    target: { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` },
    responseProtection: { enabled: true, mode: "enforce" }
  });

  // A token minted OUTSIDE this request (e.g. another client's secret).
  foreignToken = (await runtime.tokenVault.tokenize({ plaintext: "secret-victim@example.com", type: "email" })).token;

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "user", content: "no pii here" }] })
    });
    const body = await response.json();

    // The foreign token must pass through untouched — never its plaintext.
    assert.match(body.choices[0].message.content, /\[TOKEN:tok_email_/);
    assert.doesNotMatch(JSON.stringify(body), /secret-victim@example\.com/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("detokenize handles unknown tokens without throwing and audits the shortfall", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-detok-unknown-"));
  const runtime = await makeRuntime(dir, { deterministic: true });

  const issued = await runtime.tokenVault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  const values = await runtime.tokenVault.detokenize({ tokens: [issued.token, "tok_email_doesnotexist"] });

  assert.equal(values.size, 1);
  assert.equal(values.get(issued.token), "minji.kim@example.com");

  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.match(audit, /"reason":"1 tokens not restored"/);
});
