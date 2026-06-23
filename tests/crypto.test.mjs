import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import {
  CRYPTO_AAD_ENCODING_V2,
  canonicalize,
  canonicalizeCryptoAad,
  createLocalCryptoProvider,
  initLocalKeyFile
} from "../packages/crypto/index.mjs";
import { createRuntime } from "../packages/cli/runtime.mjs";

test("local crypto decrypts with the same AAD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const aad = { tenant: "demo", path: "messages[0].content" };
  const envelope = await crypto.encrypt({ plaintext: "secret@example.com", aad });
  const plaintext = await crypto.decrypt({ envelope, aad });

  assert.equal(plaintext, "secret@example.com");
});

test("local crypto rejects modified AAD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const envelope = await crypto.encrypt({
    plaintext: "secret@example.com",
    aad: { tenant: "demo-a" }
  });

  await assert.rejects(
    () => crypto.decrypt({ envelope, aad: { tenant: "demo-b" } }),
    /AAD hash mismatch/
  );
});

test("local crypto emits v2 envelopes with NFKC-normalized crypto AAD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-aad-v2-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const envelope = await crypto.encrypt({
    plaintext: "secret@example.com",
    aad: { "ｔｅｎａｎｔ": "ＡＣＭＥ", nested: { "ｐａｔｈ": "messages[0].content" } }
  });

  assert.equal(envelope.v, 2);
  assert.equal(envelope.aadEncoding, CRYPTO_AAD_ENCODING_V2);
  assert.equal(envelope.aadHash, sha256(canonicalizeCryptoAad({
    "ｔｅｎａｎｔ": "ＡＣＭＥ",
    nested: { "ｐａｔｈ": "messages[0].content" }
  })));
  assert.equal(await crypto.decrypt({
    envelope,
    aad: { tenant: "ACME", nested: { path: "messages[0].content" } }
  }), "secret@example.com");
  await assert.rejects(
    () => crypto.decrypt({
      envelope: { ...envelope, aadEncoding: "unknown-json-v99" },
      aad: { tenant: "ACME", nested: { path: "messages[0].content" } }
    }),
    /Unsupported crypto AAD encoding/
  );
});

test("crypto AAD NFKC key collision fails closed", async () => {
  assert.throws(
    () => canonicalizeCryptoAad({ "\u212B": "angstrom-sign", "\u00C5": "latin-a-ring" }),
    /NFKC key collision/
  );

  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-aad-collision-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });
  await assert.rejects(
    () => crypto.encrypt({
      plaintext: "secret@example.com",
      aad: { "\u212B": "angstrom-sign", "\u00C5": "latin-a-ring" }
    }),
    /NFKC key collision/
  );
});

test("local crypto decrypts legacy v1 envelopes with the old AAD canonicalization", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-v1-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });

  const aad = { "ｔｅｎａｎｔ": "ＡＣＭＥ" };
  const envelope = await encryptLegacyV1({ keyFile, plaintext: "legacy@example.com", aad });
  const crypto = createLocalCryptoProvider({ keyFile });

  assert.equal(envelope.v, 1);
  assert.equal(await crypto.decrypt({ envelope, aad }), "legacy@example.com");
  await assert.rejects(
    () => crypto.decrypt({ envelope, aad: { tenant: "ACME" } }),
    /AAD hash mismatch/
  );
});

test("local crypto rejects expired envelopes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-expired-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const aad = { purpose: "test" };
  const fresh = await crypto.encrypt({
    plaintext: "fresh@example.com",
    aad,
    expiresAt: new Date(Date.now() + 60_000)
  });
  assert.equal(await crypto.decrypt({ envelope: fresh, aad }), "fresh@example.com");

  const expired = await crypto.encrypt({
    plaintext: "expired@example.com",
    aad,
    expiresAt: "2000-01-01T00:00:00.000Z"
  });
  await assert.rejects(
    () => crypto.decrypt({ envelope: expired, aad }),
    /expired/
  );
});

test("external crypto provider can be injected for managed key custody", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-crypto-external-"));
  const calls = [];
  const runtime = createRuntime({
    mode: "enforce",
    keys: {
      provider: "external"
    },
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: {
        email: "encrypt"
      }
    },
    audit: {
      path: join(dir, ".haechi", "audit.jsonl")
    }
  }, {
    cryptoProvider: {
      async encrypt({ plaintext, aad }) {
        calls.push({ plaintext, aad });
        return {
          v: 1,
          alg: "EXTERNAL-TEST",
          kid: "kms-test",
          ct: Buffer.from(plaintext, "utf8").toString("base64url")
        };
      },
      async decrypt({ envelope }) {
        return Buffer.from(envelope.ct, "base64url").toString("utf8");
      }
    }
  });

  const result = await runtime.haechi.protectJson({
    message: "contact minji.kim@example.com"
  });

  assert.match(result.payload.message, /\[HAECHI_ENC:/);
  assert.equal(calls[0].plaintext, "minji.kim@example.com");
});

test("external key provider fails closed without injected crypto provider", () => {
  assert.throws(
    () => createRuntime({
      keys: {
        provider: "external"
      }
    }),
    /requires createRuntime/
  );
});

async function encryptLegacyV1({ keyFile, plaintext, aad }) {
  const raw = JSON.parse(await readFile(keyFile, "utf8"));
  const active = raw.keys.find((key) => key.status === "active") ?? raw.keys[0];
  const key = Buffer.from(active.k, "base64url");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const aadBytes = Buffer.from(canonicalize(aad), "utf8");
  cipher.setAAD(aadBytes);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    v: 1,
    alg: "AES-256-GCM",
    kid: active.kid,
    iv: iv.toString("base64url"),
    ct: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    aadHash: sha256(canonicalize(aad))
  };
}

function sha256(value) {
  return createHash("sha256").update(Buffer.from(value, "utf8")).digest("base64url");
}

async function writeKeyFile(contents) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-keyinit-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await mkdir(dirname(keyFile), { recursive: true });
  await writeFile(keyFile, contents);
  return keyFile;
}

test("init rejects a corrupted (non-JSON) existing key file", async () => {
  const keyFile = await writeKeyFile("{ not json ::::");
  await assert.rejects(() => initLocalKeyFile(keyFile, { force: false }));
});

test("init rejects an existing key file with no active key", async () => {
  const keyFile = await writeKeyFile(JSON.stringify({
    version: 1,
    keys: [
      {
        kid: "local-retired",
        kty: "oct",
        alg: "AES-256-GCM",
        status: "retired",
        k: randomBytes(32).toString("base64url")
      }
    ]
  }, null, 2));
  await assert.rejects(
    () => initLocalKeyFile(keyFile, { force: false }),
    /active key/
  );
});

test("init rejects an existing key file whose active key is the wrong length", async () => {
  const keyFile = await writeKeyFile(JSON.stringify({
    version: 1,
    keys: [
      {
        kid: "local-short",
        kty: "oct",
        alg: "AES-256-GCM",
        status: "active",
        k: randomBytes(16).toString("base64url")
      }
    ]
  }, null, 2));
  await assert.rejects(
    () => initLocalKeyFile(keyFile, { force: false }),
    /32 bytes/
  );
});

test("init succeeds non-destructively on a valid file with retired keys", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-keyinit-valid-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  // First init creates an active key; a forced rotation retires it and adds a
  // new active key, yielding a valid file that carries a retired key.
  await initLocalKeyFile(keyFile, { force: true });
  const rotated = await initLocalKeyFile(keyFile, { force: true });
  assert.equal(rotated.rotated, true);

  const before = await readFile(keyFile);
  const result = await initLocalKeyFile(keyFile, { force: false });
  assert.deepEqual(result, { created: false, keyFile });

  const after = await readFile(keyFile);
  assert.deepEqual(after, before, "init must not rewrite a valid existing key file");
});
