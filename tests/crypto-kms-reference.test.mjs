import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createLocalCryptoProvider,
  initLocalKeyFile,
  assertCryptoProviderConformance
} from "../packages/crypto/index.mjs";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { createKmsCryptoProvider, createInMemoryKms } from "../examples/crypto-kms-reference/index.mjs";

test("the local provider passes conformance", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-conf-local-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const result = await assertCryptoProviderConformance(createLocalCryptoProvider({ keyFile }));
  assert.equal(result.ok, true);
});

test("the reference KMS provider passes conformance", async () => {
  const provider = createKmsCryptoProvider({ kms: createInMemoryKms() });
  const result = await assertCryptoProviderConformance(provider);
  assert.equal(result.ok, true);
});

test("conformance flags a provider missing hmac (and passes with requireHmac:false)", async () => {
  // A real AEAD provider (the KMS reference) with hmac removed — a valid
  // encrypt-only provider.
  const { hmac, ...encryptOnly } = createKmsCryptoProvider({ kms: createInMemoryKms() });
  await assert.rejects(() => assertCryptoProviderConformance(encryptOnly), /provider does not implement hmac/);
  const ok = await assertCryptoProviderConformance(encryptOnly, { requireHmac: false });
  assert.equal(ok.ok, true);
});

test("conformance flags a provider with no AAD binding", async () => {
  // Real AEAD encryption, but decrypt ignores the AAD argument — isolates the
  // AAD-binding branch (a non-AEAD toy would fail the tampered-ct check first).
  const base = createKmsCryptoProvider({ kms: createInMemoryKms() });
  const noAad = {
    ...base,
    async decrypt({ envelope }) {
      return base.decrypt({ envelope, aad: { purpose: "conformance", path: "messages[0].content", type: "email" } });
    }
  };
  await assert.rejects(() => assertCryptoProviderConformance(noAad), /AAD binding|conformance failed/);
});

test("conformance flags non-deterministic hmac", async () => {
  const base = createKmsCryptoProvider({ kms: createInMemoryKms() });
  const flaky = { ...base, async hmac() { return Math.random().toString(); } };
  await assert.rejects(() => assertCryptoProviderConformance(flaky), /deterministic|conformance failed/);
});

test("conformance flags a provider whose decrypt returns the wrong plaintext", async () => {
  const wrongDecrypt = {
    async encrypt({ plaintext, aad }) {
      return { v: 1, kid: "x", aadHash: JSON.stringify(aad), ct: Buffer.from(plaintext).toString("base64url") };
    },
    async decrypt() {
      return "always-this";
    },
    async hmac({ data, domain }) {
      if (!domain) throw new Error("domain required");
      return `${domain}:${data}`;
    }
  };
  await assert.rejects(() => assertCryptoProviderConformance(wrongDecrypt), /original plaintext|conformance failed/);
});

test("conformance flags a provider whose encrypt throws", async () => {
  const broken = {
    async encrypt() { throw new Error("KMS timeout"); },
    async decrypt() { return "x"; },
    async hmac({ domain }) { if (!domain) throw new Error("domain required"); return "h"; }
  };
  await assert.rejects(() => assertCryptoProviderConformance(broken), /KMS timeout|conformance failed/);
});

test("conformance flags a provider that ignores the data argument of hmac", async () => {
  const constHmac = {
    async encrypt({ plaintext, aad }) {
      return { v: 1, kid: "x", aadHash: JSON.stringify(aad), ct: Buffer.from(plaintext).toString("base64url") };
    },
    async decrypt({ envelope, aad }) {
      if (envelope.aadHash !== JSON.stringify(aad)) throw new Error("AAD hash mismatch");
      return Buffer.from(envelope.ct, "base64url").toString("utf8");
    },
    async hmac({ domain }) {
      // ignores data — would collapse every token/identity to one value
      if (!domain) throw new Error("domain required");
      return `const:${domain}`;
    }
  };
  await assert.rejects(() => assertCryptoProviderConformance(constHmac), /ignores the data|conformance failed/);
});

test("the KMS reference provider's decrypt rejects an unwrappable data key", async () => {
  const kms = createInMemoryKms();
  const provider = createKmsCryptoProvider({ kms });
  const envelope = await provider.encrypt({ plaintext: "secret@example.com", aad: { p: "x" } });
  // A different KMS cannot unwrap a data key wrapped by the original master.
  const otherProvider = createKmsCryptoProvider({ kms: createInMemoryKms() });
  await assert.rejects(() => otherProvider.decrypt({ envelope, aad: { p: "x" } }));
});

test("the KMS reference provider's decrypt rejects tampered ciphertext", async () => {
  const provider = createKmsCryptoProvider({ kms: createInMemoryKms() });
  const envelope = await provider.encrypt({ plaintext: "secret@example.com", aad: { p: "x" } });
  const buf = Buffer.from(envelope.ct, "base64url");
  buf[0] ^= 0xff;
  await assert.rejects(() => provider.decrypt({ envelope: { ...envelope, ct: buf.toString("base64url") }, aad: { p: "x" } }));
});

test("a stable masterKey lets the KMS provider decrypt across instances", async () => {
  const masterKey = Buffer.alloc(32, 7);
  const a = createKmsCryptoProvider({ kms: createInMemoryKms({ masterKey }) });
  const envelope = await a.encrypt({ plaintext: "persist@example.com", aad: { p: "x" } });
  // A fresh provider with the SAME master key (simulating a restart) decrypts.
  const b = createKmsCryptoProvider({ kms: createInMemoryKms({ masterKey }) });
  assert.equal(await b.decrypt({ envelope, aad: { p: "x" } }), "persist@example.com");
});

test("runtime fails closed when bearer auth is configured but the provider lacks hmac", () => {
  const encryptOnly = { async encrypt() { return {}; }, async decrypt() { return ""; } };
  assert.throws(
    () => createRuntime({ keys: { provider: "external" }, auth: { provider: "bearer" }, audit: { path: "/tmp/x.jsonl" } }, { cryptoProvider: encryptOnly }),
    /must implement hmac/
  );
});

test("the KMS reference provider works end-to-end through createRuntime (external custody)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-kms-e2e-"));
  const cryptoProvider = createKmsCryptoProvider({ kms: createInMemoryKms() });
  const runtime = createRuntime({
    mode: "enforce",
    keys: { provider: "external" },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      actions: { email: "encrypt", api_key: "tokenize" }
    },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    tokenVault: { path: join(dir, ".haechi", "token-vault.json"), revealPolicy: "local-dev" }
  }, { cryptoProvider });

  // Encryption round-trips through the injected KMS provider.
  const result = await runtime.haechi.protectJson({ message: "mail minji.kim@example.com" });
  assert.match(result.payload.message, /\[HAECHI_ENC:/);
  assert.doesNotMatch(result.payload.message, /minji\.kim@example\.com/);

  // Tokenization (which needs hmac) also works via the KMS provider.
  const tok = await runtime.haechi.protectJson({ secret: "key sk_demo_0123456789abcdef0123456789ab" });
  const token = tok.payload.secret.match(/\[TOKEN:(tok_api_key_[a-f0-9]+)\]/)[1];
  const revealed = await runtime.tokenVault.reveal({ token });
  assert.match(revealed.plaintext, /sk_demo_/);

  // No plaintext leaked to the audit log.
  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
});

test("external key provider still fails closed without an injected cryptoProvider", () => {
  assert.throws(
    () => createRuntime({ keys: { provider: "external" }, audit: { path: "/tmp/x.jsonl" } }),
    /external requires/
  );
});
