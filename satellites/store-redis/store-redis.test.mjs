import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// haechi (the workspace-linked devDep) supplies the core seams under test.
import { createAuditSink, verifyAuditChain } from "haechi/audit";
import { createTokenVault } from "haechi/token-vault";
import { initLocalKeyFile, createLocalCryptoProvider } from "haechi/crypto";

import {
  createRedisAuditStore,
  createRedisTokenStore,
  createMemoryAuditStore,
  createMemoryTokenStore,
  withRedisLock,
  readChain
} from "./index.mjs";

// haechi-store-redis — the production shared-store audit + token-vault satellite
// for the 1.5.0 store seams. These tests use NO live Redis: the adapters run
// against a FAKE in-memory redis client, and are wired into the REAL core
// createAuditSink / createTokenVault so we prove the seam contracts end-to-end:
//   - the audit store transaction()/readLastIntegrity()/persist() build a chain
//     that verifyAuditChain accepts after materializing it back to JSONL
//   - the token store mutate()/read() round-trips tokenize -> reveal -> plaintext
//   - the distributed lock releases only its own token (compare-and-delete)
//   - the memory reference stores satisfy the same contracts.

// --- a faithful FAKE node-redis v4/v5 client (no live server) --------------
//
// Backs strings (set/get/del), the lock's NX/PX SET + the release Lua eval,
// lists (rPush/lRange), and hashes (hSet/hGet/hDel/hGetAll) over Maps. NX/PX is
// honored (with PX expiry) so the lock behaves; eval recognizes the lock's
// compare-and-delete script. A single fake instance can be shared by multiple
// store instances to emulate two replicas hitting one Redis.
function fakeRedisClient() {
  const strings = new Map();   // key -> { value, expireAt|null }
  const lists = new Map();     // key -> string[]
  const hashes = new Map();    // key -> Map<field, string>

  function live(key) {
    const slot = strings.get(key);
    if (!slot) return undefined;
    if (slot.expireAt != null && Date.now() >= slot.expireAt) {
      strings.delete(key);
      return undefined;
    }
    return slot;
  }

  return {
    _strings: strings,
    _lists: lists,
    _hashes: hashes,

    async ping() {
      return "PONG";
    },

    async set(key, value, opts = {}) {
      const exists = live(key) !== undefined;
      if (opts.NX && exists) {
        return null; // NX: do not set when present
      }
      const expireAt = opts.PX ? Date.now() + Number(opts.PX) : null;
      strings.set(key, { value: String(value), expireAt });
      return "OK";
    },

    async get(key) {
      const slot = live(key);
      return slot ? slot.value : null;
    },

    async del(key) {
      return strings.delete(key) ? 1 : 0;
    },

    // Only the lock's compare-and-delete script is used in these tests.
    async eval(script, { keys, arguments: args } = {}) {
      if (/redis\.call\('GET', KEYS\[1\]\)/.test(script) && /redis\.call\('DEL', KEYS\[1\]\)/.test(script)) {
        const slot = live(keys[0]);
        if (slot && slot.value === args[0]) {
          strings.delete(keys[0]);
          return 1;
        }
        return 0;
      }
      throw new Error(`fake eval: unsupported script: ${script}`);
    },

    async rPush(key, value) {
      const list = lists.get(key) ?? [];
      list.push(value);
      lists.set(key, list);
      return list.length;
    },

    async lRange(key, start, stop) {
      const list = lists.get(key) ?? [];
      // Emulate Redis LRANGE 0 -1 (and general negative-index) semantics.
      const len = list.length;
      const s = start < 0 ? Math.max(len + start, 0) : start;
      const e = stop < 0 ? len + stop : stop;
      return list.slice(s, e + 1);
    },

    async hSet(key, field, value) {
      const hash = hashes.get(key) ?? new Map();
      const existed = hash.has(field);
      hash.set(field, String(value));
      hashes.set(key, hash);
      return existed ? 0 : 1;
    },

    async hGet(key, field) {
      const hash = hashes.get(key);
      return hash && hash.has(field) ? hash.get(field) : null;
    },

    async hDel(key, field) {
      const hash = hashes.get(key);
      return hash && hash.delete(field) ? 1 : 0;
    },

    async hGetAll(key) {
      const hash = hashes.get(key);
      if (!hash) return {};
      return Object.fromEntries(hash.entries());
    }
  };
}

// --- audit store wired into the REAL core sink -----------------------------

test("redis audit store builds a verifiable chain through createAuditSink", async () => {
  const client = fakeRedisClient();
  const keyPrefix = "haechi:audit:test:";
  const store = createRedisAuditStore({ client, keyPrefix });
  const sink = createAuditSink({ store });

  // Build a 5-record chain through the core sink (chain math + sanitize are
  // core-owned; the store only does the exclusive read-previous + persist).
  for (let i = 0; i < 5; i += 1) {
    await sink.record({ operation: "demo", decision: "allow", count: i });
  }

  // Read the shared chain back via readChain and confirm sequencing.
  const records = await readChain(client, keyPrefix);
  assert.equal(records.length, 5);
  records.forEach((record, i) => {
    assert.equal(record.auditIntegrity.sequence, i + 1);
  });
  // The head pointer tracks the last record's integrity (the cheap tail-read).
  const head = JSON.parse(await client.get(`${keyPrefix}head`));
  assert.equal(head.sequence, 5);
  assert.equal(head.eventHash, records[4].auditIntegrity.eventHash);

  // Materialize to JSONL and verify the chain with the core verifier.
  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-"));
  const auditPath = join(dir, "audit.log");
  try {
    await writeFile(auditPath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    const result = await verifyAuditChain(auditPath);
    assert.equal(result.valid, true, `chain should verify: ${result.reason ?? ""}`);
    assert.equal(result.records, 5);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("redis audit store ready() probes the client", async () => {
  const client = fakeRedisClient();
  const store = createRedisAuditStore({ client });
  assert.deepEqual(await store.ready(), { ok: true });

  // A client whose ping rejects reports not-ready (fail closed) with an enum.
  const broken = { ...fakeRedisClient(), ping: async () => { throw new Error("down"); } };
  const brokenStore = createRedisAuditStore({ client: broken });
  assert.deepEqual(await brokenStore.ready(), { ok: false, reason: "redis_unreachable" });
});

// --- token store wired into the REAL core vault ----------------------------

async function makeCryptoProvider() {
  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-keys-"));
  const keyFile = join(dir, "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return { cryptoProvider: createLocalCryptoProvider({ keyFile }), dir };
}

test("redis token store round-trips tokenize -> reveal through createTokenVault", async () => {
  const client = fakeRedisClient();
  const { cryptoProvider, dir } = await makeCryptoProvider();
  try {
    const vault = createTokenVault({
      store: createRedisTokenStore({ client, keyPrefix: "haechi:tv:test:" }),
      cryptoProvider,
      revealPolicy: "local-dev",
      retentionDays: 30
    });

    const secret = "4242 4242 4242 4242";
    const { token } = await vault.tokenize({ plaintext: secret, type: "card" });
    assert.match(token, /^tok_card_/);

    const revealed = await vault.reveal({ token });
    assert.equal(revealed.plaintext, secret);
    assert.equal(revealed.type, "card");

    // The record actually lives in the shared hash.
    const stored = await client.hGet("haechi:tv:test:tokens", token);
    assert.ok(stored, "record persisted to the redis hash");
    assert.equal(JSON.parse(stored).type, "card");

    // exportMetadata (a read() path) sees the token; purge (a mutate() path)
    // removes it.
    const meta = await vault.exportMetadata();
    assert.equal(meta.length, 1);
    assert.equal(meta[0].token, token);

    const purge = await vault.purge({ token });
    assert.equal(purge.purged, true);
    assert.equal(await client.hGet("haechi:tv:test:tokens", token), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// --- the distributed lock --------------------------------------------------

test("withRedisLock releases only its own token (compare-and-delete)", async () => {
  const client = fakeRedisClient();
  const lockKey = "haechi:lock:test";

  let ranInside = false;
  await withRedisLock(client, lockKey, async () => {
    ranInside = true;
    // The lock key is held while fn runs.
    assert.ok(await client.get(lockKey), "lock held during fn");
  });
  assert.equal(ranInside, true);
  // Released after fn (our own token deleted).
  assert.equal(await client.get(lockKey), null, "lock released after fn");

  // If someone else's token sits on the key, our release must NOT delete it.
  await client.set(lockKey, "someone-elses-token", {});
  // Simulate our release attempt with a different token via the script path:
  const deleted = await client.eval(
    "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
    { keys: [lockKey], arguments: ["our-token"] }
  );
  assert.equal(deleted, 0, "must not delete a lock we do not own");
  assert.equal(await client.get(lockKey), "someone-elses-token", "the other holder's lock survives");
});

test("withRedisLock serializes overlapping critical sections", async () => {
  const client = fakeRedisClient();
  const lockKey = "haechi:lock:serial";
  const order = [];
  let active = 0;

  async function section(id) {
    await withRedisLock(client, lockKey, async () => {
      active += 1;
      assert.equal(active, 1, "only one section runs at a time");
      order.push(`start:${id}`);
      await new Promise((r) => setTimeout(r, 5));
      order.push(`end:${id}`);
      active -= 1;
    }, { retryMs: 1 });
  }

  await Promise.all([section("a"), section("b"), section("c")]);
  // Each section's start is immediately followed by its own end (never interleaved).
  for (let i = 0; i < order.length; i += 2) {
    const [, idStart] = order[i].split(":");
    const [, idEnd] = order[i + 1].split(":");
    assert.equal(idStart, idEnd, "sections did not interleave");
  }
});

test("withRedisLock fail-closed validation", async () => {
  await assert.rejects(() => withRedisLock(null, "k", async () => {}), /requires a node-redis/);
  await assert.rejects(() => withRedisLock({ set() {}, eval() {} }, "", async () => {}), /non-empty string lockKey/);
  await assert.rejects(() => withRedisLock({ set() {}, eval() {} }, "k", "nope"), /requires a function fn/);
});

// --- the memory reference stores satisfy the same contracts ----------------

test("memory audit store builds a verifiable chain through createAuditSink", async () => {
  const store = createMemoryAuditStore();
  const sink = createAuditSink({ store });
  for (let i = 0; i < 4; i += 1) {
    await sink.record({ operation: "demo", count: i });
  }
  const records = store._records();
  assert.equal(records.length, 4);

  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-mem-"));
  const auditPath = join(dir, "audit.log");
  try {
    await writeFile(auditPath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    const result = await verifyAuditChain(auditPath);
    assert.equal(result.valid, true, `mem chain should verify: ${result.reason ?? ""}`);
    assert.equal(result.records, 4);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  assert.deepEqual(await store.ready(), { ok: true });
});

test("memory token store round-trips tokenize -> reveal through createTokenVault", async () => {
  const { cryptoProvider, dir } = await makeCryptoProvider();
  try {
    const vault = createTokenVault({
      store: createMemoryTokenStore(),
      cryptoProvider,
      revealPolicy: "local-dev"
    });
    const secret = "hunter2-very-secret";
    const { token } = await vault.tokenize({ plaintext: secret, type: "secret" });
    const revealed = await vault.reveal({ token });
    assert.equal(revealed.plaintext, secret);

    assert.equal((await vault.exportMetadata()).length, 1);
    await vault.purge({ token });
    assert.equal((await vault.exportMetadata()).length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// --- adapter fail-closed validation ----------------------------------------

test("redis store adapters fail closed on a bad client", () => {
  assert.throws(() => createRedisAuditStore({}), /requires a node-redis/);
  assert.throws(() => createRedisAuditStore({ client: { get() {} } }), /method/);
  assert.throws(
    () => createRedisAuditStore({ client: fakeRedisClient(), keyPrefix: 5 }),
    /keyPrefix must be a string/
  );

  assert.throws(() => createRedisTokenStore({}), /requires a node-redis/);
  assert.throws(() => createRedisTokenStore({ client: { hGet() {} } }), /method/);
  assert.throws(
    () => createRedisTokenStore({ client: fakeRedisClient(), keyPrefix: 5 }),
    /keyPrefix must be a string/
  );
});
