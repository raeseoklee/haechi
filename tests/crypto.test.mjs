import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "../packages/crypto/index.mjs";

test("local crypto decrypts with the same AAD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aicel-crypto-"));
  const keyFile = join(dir, ".aicel", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const aad = { tenant: "demo", path: "messages[0].content" };
  const envelope = await crypto.encrypt({ plaintext: "secret@example.com", aad });
  const plaintext = await crypto.decrypt({ envelope, aad });

  assert.equal(plaintext, "secret@example.com");
});

test("local crypto rejects modified AAD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aicel-crypto-"));
  const keyFile = join(dir, ".aicel", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const crypto = createLocalCryptoProvider({ keyFile });

  const envelope = await crypto.encrypt({
    plaintext: "secret@example.com",
    aad: { tenant: "demo-a" }
  });

  await assert.rejects(
    () => crypto.decrypt({ envelope, aad: { tenant: "demo-b" } }),
    /Unsupported state|authenticate|auth/i
  );
});
