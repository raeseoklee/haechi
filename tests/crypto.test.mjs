import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "../packages/crypto/index.mjs";
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
