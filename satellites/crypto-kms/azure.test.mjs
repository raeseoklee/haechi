import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { assertCryptoProviderConformance } from "haechi/crypto";
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "./index.mjs";
import { createAzureKmsClient } from "./azure.mjs";

// A faithful stand-in for an Azure Key Vault CryptographyClient: it isolates by
// keyId, deriving a distinct AES-256-GCM master key per keyId from an account
// seed. wrapKey envelopes a key under the keyId's master; unwrapKey recovers it
// and — because GCM authenticates — REJECTS a blob produced under a different
// keyId (cross-key isolation) or a corrupted blob. It also binds the wrap
// algorithm into the AAD so a mismatched algorithm is rejected. No SDK, no
// network. Implements the wrapKey/unwrapKey surface the client calls, keyed by
// keyId so the test can verify the client passes keyId through.
function createMockAzureAccount({ seed = randomBytes(32) } = {}) {
  const masterFor = (keyId) => Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), `mock-azure:${keyId ?? "default"}`, 32));
  return (keyId) => ({
    async wrapKey(algorithm, key) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", masterFor(keyId), iv);
      cipher.setAAD(Buffer.from(String(algorithm)));
      const ct = Buffer.concat([cipher.update(Buffer.from(key)), cipher.final()]);
      return { result: Buffer.concat([iv, cipher.getAuthTag(), ct]) };
    },
    async unwrapKey(algorithm, encryptedKey) {
      const buf = Buffer.from(encryptedKey);
      const decipher = createDecipheriv("aes-256-gcm", masterFor(keyId), buf.subarray(0, 12));
      decipher.setAAD(Buffer.from(String(algorithm)));
      decipher.setAuthTag(buf.subarray(12, 28));
      return { result: Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]) };
    }
  });
}

// A base64url Azure-"wrapped" 32-byte HMAC root, wrapped under the SAME keyId the
// client will unwrap with.
async function makeHmacRoot(mockClient, algorithm = "RSA-OAEP-256") {
  const { result } = await mockClient.wrapKey(algorithm, randomBytes(32));
  return Buffer.from(result).toString("base64url");
}

test("createAzureKmsClient requires a keyId", () => {
  const account = createMockAzureAccount();
  assert.throws(() => createAzureKmsClient({ client: account("x") }), /requires a keyId/);
});

test("Azure-backed provider passes full conformance with an injected mock (no SDK, no network)", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const mock = account(keyId);
  const kms = createAzureKmsClient({ keyId, client: mock, hmacRootCiphertext: await makeHmacRoot(mock) });
  const result = await assertCryptoProviderConformance(createKmsCryptoProvider({ kms }));
  assert.equal(result.ok, true);
});

test("an encrypt-only Azure provider (no hmacRootCiphertext) passes conformance with requireHmac:false", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const kms = createAzureKmsClient({ keyId, client: account(keyId) });
  const { hmac, ...encryptOnly } = createKmsCryptoProvider({ kms });
  const ok = await assertCryptoProviderConformance(encryptOnly, { requireHmac: false });
  assert.equal(ok.ok, true);
});

test("deriveHmacKey throws a clear error when no hmacRootCiphertext is configured", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const kms = createAzureKmsClient({ keyId, client: account(keyId) });
  await assert.rejects(() => kms.deriveHmacKey("haechi:token-vault:v1"), /requires hmacRootCiphertext/);
});

test("deriveHmacKey is deterministic and domain-separated", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const mock = account(keyId);
  const kms = createAzureKmsClient({ keyId, client: mock, hmacRootCiphertext: await makeHmacRoot(mock) });
  const a1 = await kms.deriveHmacKey("domain-a");
  const a2 = await kms.deriveHmacKey("domain-a");
  const b = await kms.deriveHmacKey("domain-b");
  assert.deepEqual(a1, a2);     // deterministic
  assert.notDeepEqual(a1, b);   // domain-separated
  assert.equal(a1.length, 32);
});

test("a data key wrapped under one key cannot be unwrapped under another (keyId isolation)", async () => {
  // One account (so isolation is NOT just two random masters); two clients whose
  // ONLY difference is keyId. The mock isolates by keyId.
  const account = createMockAzureAccount();
  const a = createAzureKmsClient({ keyId: "https://v.vault.azure.net/keys/a/1", client: account("https://v.vault.azure.net/keys/a/1") });
  const b = createAzureKmsClient({ keyId: "https://v.vault.azure.net/keys/b/1", client: account("https://v.vault.azure.net/keys/b/1") });
  const wrapped = await a.wrap(randomBytes(32));
  await assert.rejects(() => b.unwrap(wrapped));
  // positive control: the SAME keyId round-trips.
  const dataKey = randomBytes(32);
  assert.deepEqual(await a.unwrap(await a.wrap(dataKey)), dataKey);
});

test("a corrupted wrapped data key is rejected", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const kms = createAzureKmsClient({ keyId, client: account(keyId) });
  const wrapped = await kms.wrap(randomBytes(32));
  const buf = Buffer.from(wrapped, "base64url");
  buf[buf.length - 1] ^= 0xff;
  await assert.rejects(() => kms.unwrap(buf.toString("base64url")));
});

test("wrap is non-deterministic — the same data key produces different ciphertext (fresh IV)", async () => {
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const kms = createAzureKmsClient({ keyId, client: account(keyId) });
  const dataKey = randomBytes(32);
  assert.notEqual(await kms.wrap(dataKey), await kms.wrap(dataKey));
});

test("the in-memory and Azure clients derive identical HMAC keys from the same root (cross-backend parity)", async () => {
  // Migration safety: both derive via HKDF-SHA256 with the same domain-separated
  // info, so a shared root yields the same per-domain key. We wrap the SAME root
  // bytes through Azure and feed those same bytes to the in-memory client.
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const mock = account(keyId);
  const root = randomBytes(32);
  const { result } = await mock.wrapKey("RSA-OAEP-256", root);
  const azure = createAzureKmsClient({ keyId, client: mock, hmacRootCiphertext: Buffer.from(result).toString("base64url") });
  const mem = createInMemoryKms({ masterKey: root });
  assert.deepEqual(await azure.deriveHmacKey("haechi:token-vault:v1"), await mem.deriveHmacKey("haechi:token-vault:v1"));
});

test("without an injected client and without the SDKs installed, a clear error is thrown", async () => {
  // @azure/keyvault-keys + @azure/identity are OPTIONAL peers and are not
  // installed in the monorepo, so the lazy import fails with actionable guidance.
  const kms = createAzureKmsClient({ keyId: "https://vault.vault.azure.net/keys/k/v" });
  await assert.rejects(() => kms.wrap(randomBytes(32)), /@azure\/keyvault-keys and @azure\/identity are not installed/);
});

test("the Azure-backed provider works end-to-end through createRuntime (encrypt + tokenize round-trip)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-azure-e2e-"));
  const account = createMockAzureAccount();
  const keyId = "https://vault.vault.azure.net/keys/k/v";
  const mock = account(keyId);
  const kms = createAzureKmsClient({ keyId, client: mock, hmacRootCiphertext: await makeHmacRoot(mock) });
  const runtime = createRuntime({
    mode: "enforce",
    keys: { provider: "external" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { email: "encrypt", api_key: "tokenize" } },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    tokenVault: { path: join(dir, ".haechi", "token-vault.json"), revealPolicy: "local-dev" }
  }, { cryptoProvider: createKmsCryptoProvider({ kms }) });

  const result = await runtime.haechi.protectJson({ message: "mail minji.kim@example.com" });
  assert.match(result.payload.message, /\[HAECHI_ENC:/);
  assert.doesNotMatch(result.payload.message, /minji\.kim@example\.com/);

  const tok = await runtime.haechi.protectJson({ secret: "key sk_demo_0123456789abcdef0123456789ab" });
  const token = tok.payload.secret.match(/\[TOKEN:(tok_api_key_[a-f0-9]+)\]/)[1];
  const revealed = await runtime.tokenVault.reveal({ token });
  assert.equal(revealed.plaintext, "sk_demo_0123456789abcdef0123456789ab");

  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
});
