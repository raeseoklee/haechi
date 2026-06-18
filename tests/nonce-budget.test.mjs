import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "../packages/crypto/index.mjs";

// The NIST SP 800-38D random-IV invocation ceiling the local provider enforces.
const NIST_LIMIT = 2 ** 32;
const AAD = { tenant: "demo", path: "messages[0].content", type: "email" };

async function freshKeyFile() {
  const dir = await mkdtemp(join(tmpdir(), "haechi-nonce-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return keyFile;
}

async function readActiveUsage(keyFile) {
  const raw = JSON.parse(await readFile(keyFile, "utf8"));
  const active = raw.keys.find((k) => k.status === "active") ?? raw.keys[0];
  return active.usage ?? 0;
}

async function setActiveUsage(keyFile, usage) {
  const raw = JSON.parse(await readFile(keyFile, "utf8"));
  const active = raw.keys.find((k) => k.status === "active") ?? raw.keys[0];
  active.usage = usage;
  await writeFile(keyFile, `${JSON.stringify(raw, null, 2)}\n`, { mode: 0o600 });
}

test("nonce budget is reserved a window at a time, not per-encrypt", async () => {
  const keyFile = await freshKeyFile();
  const crypto = createLocalCryptoProvider({ keyFile });

  await crypto.encrypt({ plaintext: "a@example.com", aad: AAD });
  const afterFirst = await readActiveUsage(keyFile);
  assert.ok(afterFirst > 0, "first encrypt must reserve (persist) a nonce window");

  await crypto.encrypt({ plaintext: "b@example.com", aad: AAD });
  const afterSecond = await readActiveUsage(keyFile);
  assert.equal(afterSecond, afterFirst, "a second encrypt within the window must NOT rewrite usage");
});

test("encrypt fails closed at the per-key invocation limit (no nonce past the budget)", async () => {
  const keyFile = await freshKeyFile();
  await setActiveUsage(keyFile, NIST_LIMIT);
  const crypto = createLocalCryptoProvider({ keyFile });

  await assert.rejects(
    () => crypto.encrypt({ plaintext: "secret@example.com", aad: AAD }),
    /safe encryption limit/
  );
});

test("the last invocation before the limit still works, then the next fails closed", async () => {
  const keyFile = await freshKeyFile();
  await setActiveUsage(keyFile, NIST_LIMIT - 1);
  const crypto = createLocalCryptoProvider({ keyFile });

  // Exactly one invocation remains: it must succeed and round-trip.
  const envelope = await crypto.encrypt({ plaintext: "last@example.com", aad: AAD });
  assert.equal(await crypto.decrypt({ envelope, aad: AAD }), "last@example.com");

  // The budget is now exhausted — the very next encrypt fails closed.
  await assert.rejects(
    () => crypto.encrypt({ plaintext: "over@example.com", aad: AAD }),
    /safe encryption limit/
  );
});

test("key rotation (init --force) resets the nonce budget for a fresh provider", async () => {
  const keyFile = await freshKeyFile();
  await setActiveUsage(keyFile, NIST_LIMIT);
  const exhausted = createLocalCryptoProvider({ keyFile });
  await assert.rejects(() => exhausted.encrypt({ plaintext: "x@example.com", aad: AAD }), /safe encryption limit/);

  await initLocalKeyFile(keyFile, { force: true }); // new active kid, usage 0
  assert.equal(await readActiveUsage(keyFile), 0, "a rotated active key starts with a fresh budget");

  const rotated = createLocalCryptoProvider({ keyFile });
  const envelope = await rotated.encrypt({ plaintext: "fresh@example.com", aad: AAD });
  assert.equal(await rotated.decrypt({ envelope, aad: AAD }), "fresh@example.com");
});

test("a read-only key file degrades to per-process counting instead of breaking encryption", async (t) => {
  const keyFile = await freshKeyFile();
  await chmod(keyFile, 0o444);
  // Detect an environment (e.g. CI running as root) where mode 0o444 does not
  // actually deny writes — there the read-only fallback cannot be exercised.
  let writable = false;
  try {
    const raw = await readFile(keyFile, "utf8");
    await writeFile(keyFile, raw, { mode: 0o444 });
    writable = true;
  } catch {
    writable = false;
  }
  if (writable) {
    t.skip("key file remained writable (likely running as root); cannot exercise the read-only fallback");
    return;
  }

  const warnings = [];
  const onWarn = (w) => warnings.push(w);
  process.on("warning", onWarn);
  try {
    const crypto = createLocalCryptoProvider({ keyFile });
    // Encryption must still work even though usage cannot be persisted.
    const envelope = await crypto.encrypt({ plaintext: "ro@example.com", aad: AAD });
    assert.equal(await crypto.decrypt({ envelope, aad: AAD }), "ro@example.com");
    // ...and the per-process limit must still be enforced in memory.
    assert.equal(await readActiveUsage(keyFile), 0, "a read-only key file must not be mutated");
    await new Promise((r) => setImmediate(r)); // let the 'warning' event drain
    assert.ok(
      warnings.some((w) => w?.code === "HAECHI_NONCE_BUDGET_NOPERSIST"),
      "a non-persistable nonce budget must warn that cross-restart protection is off"
    );
  } finally {
    process.removeListener("warning", onWarn);
    await chmod(keyFile, 0o600); // restore so the temp dir can be cleaned
  }
});
