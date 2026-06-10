import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { assertCryptoProviderConformance } from "haechi/crypto";
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "./index.mjs";
import { createAwsKmsClient } from "./aws.mjs";

// A faithful stand-in for an AWS KMS *account*: it isolates by KeyId, deriving a
// distinct AES-256-GCM master key per KeyId from an account seed. Encrypt wraps
// Plaintext under the KeyId's master; Decrypt unwraps under the KeyId's master
// and — because GCM authenticates — REJECTS a blob produced under a different
// KeyId (the real cross-key isolation property) or a corrupted blob. No SDK, no
// network. Because it honours KeyId, tests can verify the client passes KeyId
// through correctly, not merely that two random keys differ.
function createMockKmsAccount({ seed = randomBytes(32) } = {}) {
  const masterFor = (KeyId) => Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), `mock-kms:${KeyId ?? "default"}`, 32));
  return {
    async encrypt({ KeyId, Plaintext }) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", masterFor(KeyId), iv);
      const ct = Buffer.concat([cipher.update(Buffer.from(Plaintext)), cipher.final()]);
      return { CiphertextBlob: Buffer.concat([iv, cipher.getAuthTag(), ct]) };
    },
    async decrypt({ KeyId, CiphertextBlob }) {
      const buf = Buffer.from(CiphertextBlob);
      const decipher = createDecipheriv("aes-256-gcm", masterFor(KeyId), buf.subarray(0, 12));
      decipher.setAuthTag(buf.subarray(12, 28));
      return { Plaintext: Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]) };
    }
  };
}

// A base64url "KMS-encrypted" 32-byte HMAC root, wrapped under the SAME keyId the
// client will decrypt with.
async function makeHmacRoot(account, keyId) {
  const { CiphertextBlob } = await account.encrypt({ KeyId: keyId, Plaintext: randomBytes(32) });
  return Buffer.from(CiphertextBlob).toString("base64url");
}

test("createAwsKmsClient requires a keyId", () => {
  assert.throws(() => createAwsKmsClient({ client: createMockKmsAccount() }), /requires a keyId/);
});

test("AWS-backed provider passes full conformance with an injected mock (no SDK, no network)", async () => {
  const account = createMockKmsAccount();
  const keyId = "arn:aws:kms:test:key";
  const kms = createAwsKmsClient({ keyId, client: account, hmacRootCiphertext: await makeHmacRoot(account, keyId) });
  const result = await assertCryptoProviderConformance(createKmsCryptoProvider({ kms }));
  assert.equal(result.ok, true);
});

test("an encrypt-only AWS provider (no hmacRootCiphertext) passes conformance with requireHmac:false", async () => {
  const kms = createAwsKmsClient({ keyId: "arn:test", client: createMockKmsAccount() });
  const { hmac, ...encryptOnly } = createKmsCryptoProvider({ kms });
  const ok = await assertCryptoProviderConformance(encryptOnly, { requireHmac: false });
  assert.equal(ok.ok, true);
});

test("deriveHmacKey throws a clear error when no hmacRootCiphertext is configured", async () => {
  const kms = createAwsKmsClient({ keyId: "arn:test", client: createMockKmsAccount() });
  await assert.rejects(() => kms.deriveHmacKey("haechi:token-vault:v1"), /requires hmacRootCiphertext/);
});

test("deriveHmacKey is deterministic and domain-separated", async () => {
  const account = createMockKmsAccount();
  const kms = createAwsKmsClient({ keyId: "arn:test", client: account, hmacRootCiphertext: await makeHmacRoot(account, "arn:test") });
  const a1 = await kms.deriveHmacKey("domain-a");
  const a2 = await kms.deriveHmacKey("domain-a");
  const b = await kms.deriveHmacKey("domain-b");
  assert.deepEqual(a1, a2);     // deterministic
  assert.notDeepEqual(a1, b);   // domain-separated
  assert.equal(a1.length, 32);
});

test("a data key wrapped under one KMS key cannot be unwrapped under another (KeyId isolation)", async () => {
  // One account (so isolation is NOT just two random masters); two clients whose
  // ONLY difference is keyId. The client must pass its keyId through to KMS, and
  // KMS isolates by keyId — so b cannot unwrap what a wrapped.
  const account = createMockKmsAccount();
  const a = createAwsKmsClient({ keyId: "arn:a", client: account });
  const b = createAwsKmsClient({ keyId: "arn:b", client: account });
  const wrapped = await a.wrap(randomBytes(32));
  await assert.rejects(() => b.unwrap(wrapped));
  // positive control: the SAME keyId round-trips (proves the failure above is
  // keyId isolation, not a broken mock).
  const dataKey = randomBytes(32);
  assert.deepEqual(await a.unwrap(await a.wrap(dataKey)), dataKey);
});

test("a corrupted wrapped data key is rejected", async () => {
  const kms = createAwsKmsClient({ keyId: "arn:test", client: createMockKmsAccount() });
  const wrapped = await kms.wrap(randomBytes(32));
  const buf = Buffer.from(wrapped, "base64url");
  buf[buf.length - 1] ^= 0xff;
  await assert.rejects(() => kms.unwrap(buf.toString("base64url")));
});

test("wrap is non-deterministic — the same data key produces different ciphertext (fresh IV)", async () => {
  const kms = createAwsKmsClient({ keyId: "arn:test", client: createMockKmsAccount() });
  const dataKey = randomBytes(32);
  assert.notEqual(await kms.wrap(dataKey), await kms.wrap(dataKey));
});

test("the in-memory and AWS clients derive identical HMAC keys from the same root (cross-backend parity)", async () => {
  // Migration safety: both clients in this package use HKDF-SHA256 with the same
  // domain-separated info, so a shared root yields the same per-domain key.
  const account = createMockKmsAccount();
  const root = randomBytes(32);
  const { CiphertextBlob } = await account.encrypt({ KeyId: "arn:test", Plaintext: root });
  const aws = createAwsKmsClient({ keyId: "arn:test", client: account, hmacRootCiphertext: Buffer.from(CiphertextBlob).toString("base64url") });
  const mem = createInMemoryKms({ masterKey: root });
  assert.deepEqual(await aws.deriveHmacKey("haechi:token-vault:v1"), await mem.deriveHmacKey("haechi:token-vault:v1"));
});

test("without an injected client and without the SDK installed, a clear error is thrown", async () => {
  // @aws-sdk/client-kms is an OPTIONAL peer dependency and is not installed in
  // the monorepo, so the lazy import fails with actionable guidance.
  const kms = createAwsKmsClient({ keyId: "arn:test" });
  await assert.rejects(() => kms.wrap(randomBytes(32)), /@aws-sdk\/client-kms is not installed/);
});

test("the AWS-backed provider works end-to-end through createRuntime (encrypt + tokenize round-trip)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-aws-e2e-"));
  const account = createMockKmsAccount();
  const keyId = "arn:test";
  const kms = createAwsKmsClient({ keyId, client: account, hmacRootCiphertext: await makeHmacRoot(account, keyId) });
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
  assert.equal(revealed.plaintext, "sk_demo_0123456789abcdef0123456789ab"); // exact, not partial

  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
});
