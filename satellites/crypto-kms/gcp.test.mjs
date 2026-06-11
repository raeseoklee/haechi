import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { assertCryptoProviderConformance } from "haechi/crypto";
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "./index.mjs";
import { createGcpKmsClient } from "./gcp.mjs";

// A faithful stand-in for a Cloud KMS *project*: it isolates by the crypto-key
// resource `name`, deriving a distinct AES-256-GCM master key per name from an
// account seed. encrypt wraps plaintext under the name's master; decrypt unwraps
// under the name's master and — because GCM authenticates — REJECTS a blob
// produced under a different name (cross-key isolation) or a corrupted blob. No
// SDK, no network. It implements the NORMALIZED surface the client adapts the SDK
// array-return into ({ ciphertext } / { plaintext }), so the test verifies the
// client passes `name` through correctly.
function createMockGcpAccount({ seed = randomBytes(32) } = {}) {
  const masterFor = (name) => Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), `mock-gcp:${name ?? "default"}`, 32));
  return {
    async encrypt({ name, plaintext }) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", masterFor(name), iv);
      const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
      return { ciphertext: Buffer.concat([iv, cipher.getAuthTag(), ct]) };
    },
    async decrypt({ name, ciphertext }) {
      const buf = Buffer.from(ciphertext);
      const decipher = createDecipheriv("aes-256-gcm", masterFor(name), buf.subarray(0, 12));
      decipher.setAuthTag(buf.subarray(12, 28));
      return { plaintext: Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]) };
    }
  };
}

// A base64url "KMS-encrypted" 32-byte HMAC root, wrapped under the SAME keyName
// the client will decrypt with.
async function makeHmacRoot(account, keyName) {
  const { ciphertext } = await account.encrypt({ name: keyName, plaintext: randomBytes(32) });
  return Buffer.from(ciphertext).toString("base64url");
}

test("createGcpKmsClient requires a keyName", () => {
  assert.throws(() => createGcpKmsClient({ client: createMockGcpAccount() }), /requires a keyName/);
});

test("GCP-backed provider passes full conformance with an injected mock (no SDK, no network)", async () => {
  const account = createMockGcpAccount();
  const keyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k";
  const kms = createGcpKmsClient({ keyName, client: account, hmacRootCiphertext: await makeHmacRoot(account, keyName) });
  const result = await assertCryptoProviderConformance(createKmsCryptoProvider({ kms }));
  assert.equal(result.ok, true);
});

test("an encrypt-only GCP provider (no hmacRootCiphertext) passes conformance with requireHmac:false", async () => {
  const kms = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/k", client: createMockGcpAccount() });
  const { hmac, ...encryptOnly } = createKmsCryptoProvider({ kms });
  const ok = await assertCryptoProviderConformance(encryptOnly, { requireHmac: false });
  assert.equal(ok.ok, true);
});

test("deriveHmacKey throws a clear error when no hmacRootCiphertext is configured", async () => {
  const kms = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/k", client: createMockGcpAccount() });
  await assert.rejects(() => kms.deriveHmacKey("haechi:token-vault:v1"), /requires hmacRootCiphertext/);
});

test("deriveHmacKey is deterministic and domain-separated", async () => {
  const account = createMockGcpAccount();
  const keyName = "projects/p/cryptoKeys/k";
  const kms = createGcpKmsClient({ keyName, client: account, hmacRootCiphertext: await makeHmacRoot(account, keyName) });
  const a1 = await kms.deriveHmacKey("domain-a");
  const a2 = await kms.deriveHmacKey("domain-a");
  const b = await kms.deriveHmacKey("domain-b");
  assert.deepEqual(a1, a2);     // deterministic
  assert.notDeepEqual(a1, b);   // domain-separated
  assert.equal(a1.length, 32);
});

test("a data key wrapped under one crypto-key cannot be unwrapped under another (name isolation)", async () => {
  const account = createMockGcpAccount();
  const a = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/a", client: account });
  const b = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/b", client: account });
  const wrapped = await a.wrap(randomBytes(32));
  await assert.rejects(() => b.unwrap(wrapped));
  // positive control: the SAME name round-trips.
  const dataKey = randomBytes(32);
  assert.deepEqual(await a.unwrap(await a.wrap(dataKey)), dataKey);
});

test("a corrupted wrapped data key is rejected", async () => {
  const kms = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/k", client: createMockGcpAccount() });
  const wrapped = await kms.wrap(randomBytes(32));
  const buf = Buffer.from(wrapped, "base64url");
  buf[buf.length - 1] ^= 0xff;
  await assert.rejects(() => kms.unwrap(buf.toString("base64url")));
});

test("wrap is non-deterministic — the same data key produces different ciphertext (fresh IV)", async () => {
  const kms = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/k", client: createMockGcpAccount() });
  const dataKey = randomBytes(32);
  assert.notEqual(await kms.wrap(dataKey), await kms.wrap(dataKey));
});

test("the in-memory and GCP clients derive identical HMAC keys from the same root (cross-backend parity)", async () => {
  const account = createMockGcpAccount();
  const keyName = "projects/p/cryptoKeys/k";
  const root = randomBytes(32);
  const { ciphertext } = await account.encrypt({ name: keyName, plaintext: root });
  const gcp = createGcpKmsClient({ keyName, client: account, hmacRootCiphertext: Buffer.from(ciphertext).toString("base64url") });
  const mem = createInMemoryKms({ masterKey: root });
  assert.deepEqual(await gcp.deriveHmacKey("haechi:token-vault:v1"), await mem.deriveHmacKey("haechi:token-vault:v1"));
});

test("without an injected client and without the SDK installed, a clear error is thrown", async () => {
  // @google-cloud/kms is an OPTIONAL peer dependency and is not installed in the
  // monorepo, so the lazy import fails with actionable guidance.
  const kms = createGcpKmsClient({ keyName: "projects/p/cryptoKeys/k" });
  await assert.rejects(() => kms.wrap(randomBytes(32)), /@google-cloud\/kms is not installed/);
});

test("the GCP-backed provider works end-to-end through createRuntime (encrypt + tokenize round-trip)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-gcp-e2e-"));
  const account = createMockGcpAccount();
  const keyName = "projects/p/cryptoKeys/k";
  const kms = createGcpKmsClient({ keyName, client: account, hmacRootCiphertext: await makeHmacRoot(account, keyName) });
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
