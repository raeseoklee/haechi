import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "../packages/crypto/index.mjs";
import {
  createTokenVault,
  createFileTokenStore,
  createLocalTokenVault,
  readVault
} from "../packages/token-vault/index.mjs";

async function makeCrypto(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createLocalCryptoProvider({ keyFile });
}

// An in-memory token store implementing the same mutate(fn)/read(fn) contract
// with NO filesystem — the shared-store (e.g. Redis) precondition. mutate runs
// the mutation under an awaited promise chain (its own exclusive section);
// read snapshots the current map.
function createMemoryTokenStore() {
  const tokens = new Map();
  let lock = Promise.resolve();

  function mutableView() {
    return {
      get: (token) => tokens.get(token),
      set: (token, record) => tokens.set(token, record),
      delete: (token) => tokens.delete(token),
      entries: () => [...tokens.entries()]
    };
  }

  function readView() {
    // Snapshot so a concurrent mutate cannot mutate the view mid-read.
    const snapshot = new Map(tokens);
    return {
      get: (token) => snapshot.get(token),
      entries: () => [...snapshot.entries()]
    };
  }

  return {
    async mutate(fn) {
      const run = lock.then(() => fn(mutableView()));
      lock = run.then(() => {}, () => {});
      return run;
    },
    async read(fn) {
      return fn(readView());
    },
    _tokens: tokens
  };
}

test("createTokenVault over createFileTokenStore matches the file vault behavior", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-file-"));
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  const cryptoProvider = await makeCrypto(dir);
  const events = [];
  const vault = createTokenVault({
    store: createFileTokenStore({ path: vaultPath }),
    cryptoProvider,
    revealPolicy: "local-dev",
    auditSink: { record: async (event) => { events.push(event); } }
  });

  // Full tokenize -> reveal round-trip.
  const { token } = await vault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  assert.match(token, /^tok_email_[a-f0-9]{16,}$/);
  const revealed = await vault.reveal({ token });
  assert.equal(revealed.plaintext, "minji.kim@example.com");
  assert.equal(revealed.type, "email");

  // On-disk vault format stays the standard shape; plaintext never on disk.
  const onDisk = await readFile(vaultPath, "utf8");
  assert.doesNotMatch(onDisk, /minji\.kim@example\.com/);
  assert.ok(onDisk.endsWith("}\n"), "vault file ends with a trailing newline");
  const parsed = await readVault(vaultPath);
  assert.equal(parsed.version, 1);
  assert.ok(parsed.tokens[token], "token persisted in the file vault map");

  // purge removes the record.
  const purge = await vault.purge({ token });
  assert.equal(purge.purged, true);
  const afterPurge = await readVault(vaultPath);
  assert.equal(afterPurge.tokens[token], undefined);

  // The reveal_allowed + purge events were audited (token ids only).
  assert.ok(events.some((e) => e.decision === "reveal_allowed" && e.token === token));
  assert.ok(events.some((e) => e.decision === "purge" && e.token === token));
});

test("reveal-disabled denies before any store read (file store)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-disabled-"));
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  const cryptoProvider = await makeCrypto(dir);

  // A store whose read() throws — proving the disabled gate fires before it.
  let readCalled = false;
  const store = {
    ...createFileTokenStore({ path: vaultPath }),
    read: async () => {
      readCalled = true;
      throw new Error("read must not be reached when reveal is disabled");
    }
  };
  const events = [];
  const vault = createTokenVault({
    store,
    cryptoProvider,
    revealPolicy: "disabled",
    auditSink: { record: async (event) => { events.push(event); } }
  });

  await assert.rejects(
    () => vault.reveal({ token: "tok_email_deadbeefdeadbeef" }),
    /Token reveal is disabled/
  );
  assert.equal(readCalled, false, "store.read must not run when reveal is disabled");
  assert.ok(events.some((e) => e.decision === "reveal_denied" && e.reason === "reveal_policy_disabled"));
});

test("expired token records token_expired reasonCode (file store)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-expired-"));
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  const cryptoProvider = await makeCrypto(dir);
  const events = [];
  const vault = createTokenVault({
    store: createFileTokenStore({ path: vaultPath }),
    cryptoProvider,
    revealPolicy: "local-dev",
    retentionDays: -1,
    auditSink: { record: async (event) => { events.push(event); } }
  });

  const { token } = await vault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  await assert.rejects(() => vault.reveal({ token }), /Token expired/);
  const failure = events.find((e) => e.decision === "reveal_failed");
  assert.ok(failure);
  assert.equal(failure.reason, "token_expired");
  assert.equal(failure.token, token);
  assert.doesNotMatch(JSON.stringify(events), /minji\.kim@example\.com/);
});

test("a custom in-memory store yields a correct tokenize->reveal round-trip and governance", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-mem-"));
  const cryptoProvider = await makeCrypto(dir);
  const events = [];
  const store = createMemoryTokenStore();
  const vault = createTokenVault({
    store,
    cryptoProvider,
    revealPolicy: "local-dev",
    auditSink: { record: async (event) => { events.push(event); } }
  });

  const { token } = await vault.tokenize({ plaintext: "secret@example.com", type: "email" });
  // The record lives in the Map, never on disk; the stored value is encrypted.
  assert.ok(store._tokens.has(token));
  assert.doesNotMatch(JSON.stringify([...store._tokens.values()]), /secret@example\.com/);

  const revealed = await vault.reveal({ token });
  assert.equal(revealed.plaintext, "secret@example.com");

  // exportMetadata reads through the store view.
  const metadata = await vault.exportMetadata({ type: "email" });
  assert.equal(metadata.length, 1);
  assert.equal(metadata[0].token, token);
  assert.doesNotMatch(JSON.stringify(metadata), /secret@example\.com/);

  // purge through the in-memory store.
  const purge = await vault.purge({ token });
  assert.equal(purge.purged, true);
  assert.equal(store._tokens.has(token), false);

  // Governance: a disabled vault over the SAME store contract still denies.
  const disabledVault = createTokenVault({
    store: createMemoryTokenStore(),
    cryptoProvider,
    revealPolicy: "disabled"
  });
  await assert.rejects(
    () => disabledVault.reveal({ token: "tok_email_deadbeefdeadbeef" }),
    /Token reveal is disabled/
  );
});

test("concurrent tokenize() of distinct values all persist (no lost write, file store)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-concurrent-"));
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  const cryptoProvider = await makeCrypto(dir);
  const vault = createTokenVault({
    store: createFileTokenStore({ path: vaultPath }),
    cryptoProvider,
    revealPolicy: "local-dev"
  });

  const results = await Promise.all(Array.from({ length: 25 }, (_, index) => vault.tokenize({
    plaintext: `user-${index}@example.com`,
    type: "email"
  })));

  assert.equal(new Set(results.map((r) => r.token)).size, 25);
  const metadata = await vault.exportMetadata({ type: "email" });
  assert.equal(metadata.length, 25);
  const onDisk = await readVault(vaultPath);
  assert.equal(Object.keys(onDisk.tokens).length, 25);
});

test("concurrent tokenize() through the in-memory store also keeps every record", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-mem-concurrent-"));
  const cryptoProvider = await makeCrypto(dir);
  const store = createMemoryTokenStore();
  const vault = createTokenVault({ store, cryptoProvider, revealPolicy: "local-dev" });

  const results = await Promise.all(Array.from({ length: 25 }, (_, index) => vault.tokenize({
    plaintext: `user-${index}@example.com`,
    type: "email"
  })));

  assert.equal(new Set(results.map((r) => r.token)).size, 25);
  assert.equal(store._tokens.size, 25);
});

test("deterministic tokenization is stable across two calls over the in-memory store", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-det-"));
  const cryptoProvider = await makeCrypto(dir);
  const store = createMemoryTokenStore();
  const vault = createTokenVault({
    store,
    cryptoProvider,
    revealPolicy: "local-dev",
    deterministic: true
  });

  const first = await vault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  const second = await vault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  const other = await vault.tokenize({ plaintext: "other@example.com", type: "email" });

  assert.equal(first.token, second.token);
  assert.notEqual(first.token, other.token);
  assert.equal(second.reused, true, "second call reuses the existing record");
  // One record for the repeated value, plus one for the distinct value.
  assert.equal(store._tokens.size, 2);
});

test("createLocalTokenVault remains a thin back-compat wrapper", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-tv-seam-compat-"));
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  const cryptoProvider = await makeCrypto(dir);
  const vault = createLocalTokenVault({
    path: vaultPath,
    cryptoProvider,
    revealPolicy: "local-dev"
  });

  assert.equal(vault.id, "haechi.token-vault.local");
  assert.equal(vault.version, "0.2.0");
  assert.equal(vault.capabilities.revealPolicy, "local-dev");
  for (const method of ["tokenize", "reveal", "detokenize", "purge", "purgeExpired", "exportMetadata"]) {
    assert.equal(typeof vault[method], "function", `wrapper exposes ${method}`);
  }

  const { token } = await vault.tokenize({ plaintext: "minji.kim@example.com", type: "email" });
  assert.equal((await vault.reveal({ token })).plaintext, "minji.kim@example.com");
});
