import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// haechi (the workspace-linked devDep) supplies the core seams under test.
import { createAuditSink, verifyAuditChain, buildIntegrityRecord } from "haechi/audit";
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
//   - the memory reference stores satisfy the same contracts
//   - the SERVER-SIDE FENCES (audit compare-and-append on the head eventHash,
//     token compare-and-apply on a version counter) are atomic AND reject a
//     stale writer, so the chain can't fork and a token write can't be lost even
//     when the lock lapses and two writers run concurrently — and ready() catches
//     a write-denied Redis.

// --- a faithful FAKE node-redis v4/v5 client (no live server) --------------
//
// Backs strings (set/get/del), the lock's NX/PX SET + the release Lua eval,
// lists (rPush/lRange), and hashes (hSet/hGet/hDel/hGetAll) over Maps. NX/PX is
// honored (with PX expiry) so the lock behaves. eval() pattern-matches and
// emulates FOUR scripts over the same fake Maps:
//   1. the lock compare-and-delete (RELEASE),
//   2. the audit COMPARE-AND-APPEND fenced on the head eventHash,
//   3. the token COMPARE-AND-APPLY fenced on a version counter,
//   4. the ready() write-probe.
// A single fake instance can be shared by multiple store instances to emulate
// two replicas hitting one Redis.
//
// Fault injection: `failNextEval(predicate)` makes the NEXT eval whose script
// matches `predicate` throw ONCE, MID-script (after the fence check passes but
// before any mutation is observable) — this models a server-side crash partway
// through a multi-command op and lets us assert the Lua scripts are all-or-
// nothing (the fake applies a script's writes only after a successful pass, so a
// thrown eval leaves the Maps untouched, exactly like a real EVAL abort).
// `lockless: true` makes SET NX always succeed — modeling a lock whose TTL has
// FULLY lapsed, so two writers enter the critical section concurrently. With the
// lock providing zero mutual exclusion, ONLY the server-side fences (audit
// compare-and-append, token compare-and-apply) can keep the chain unforked and
// no token lost. The concurrency tests use this so the fence is genuinely
// exercised (a passing test proves the fence, not the lock, is doing the work).
function fakeRedisClient({ lockless = false } = {}) {
  const strings = new Map();   // key -> { value, expireAt|null }
  const lists = new Map();     // key -> string[]
  const hashes = new Map();    // key -> Map<field, string>

  // One-shot fault hooks: each is { match(script), used:false }. The first
  // unused hook whose match() returns true throws once, before applying writes.
  const evalFaults = [];

  function live(key) {
    const slot = strings.get(key);
    if (!slot) return undefined;
    if (slot.expireAt != null && Date.now() >= slot.expireAt) {
      strings.delete(key);
      return undefined;
    }
    return slot;
  }

  // Apply a script's effect only AFTER deciding to commit, so a fault thrown
  // before this point leaves the Maps untouched (atomic, like a real EVAL).
  function rpush(key, value) {
    const list = lists.get(key) ?? [];
    list.push(value);
    lists.set(key, list);
    return list.length;
  }
  function setString(key, value) {
    const prev = live(key);
    strings.set(key, { value: String(value), expireAt: prev ? prev.expireAt : null });
  }
  function hset(key, field, value) {
    const hash = hashes.get(key) ?? new Map();
    hash.set(field, String(value));
    hashes.set(key, hash);
  }
  function hdel(key, field) {
    const hash = hashes.get(key);
    if (hash) hash.delete(field);
  }

  function maybeFault(script) {
    const hook = evalFaults.find((f) => !f.used && f.match(script));
    if (hook) {
      hook.used = true;
      throw new Error("fake eval: injected mid-script failure");
    }
  }

  return {
    _strings: strings,
    _lists: lists,
    _hashes: hashes,

    // Register a one-shot fault: the next eval whose script matches throws once.
    failNextEval(match) {
      evalFaults.push({ match, used: false });
    },

    async ping() {
      return "PONG";
    },

    async set(key, value, opts = {}) {
      const exists = live(key) !== undefined;
      // In lockless mode NX always succeeds (the TTL fully lapsed), so the lock
      // grants no exclusion and the fence alone must hold correctness.
      if (opts.NX && exists && !lockless) {
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

    // Emulates the four Lua scripts the satellite uses over the fake Maps.
    async eval(script, { keys, arguments: args } = {}) {
      // 1. Lock compare-and-delete (RELEASE_SCRIPT).
      if (/redis\.call\('GET', KEYS\[1\]\)/.test(script) && /redis\.call\('DEL', KEYS\[1\]\)/.test(script)) {
        const slot = live(keys[0]);
        if (slot && slot.value === args[0]) {
          strings.delete(keys[0]);
          return 1;
        }
        return 0;
      }

      // 2. Audit COMPARE-AND-APPEND (APPEND_SCRIPT).
      //   KEYS = [headHashKey, chainKey, headKey]
      //   ARGV = [expectedPrevHash, recordJSON, integrityJSON, newEventHash]
      if (/redis\.call\('RPUSH', KEYS\[2\]/.test(script) && /redis\.call\('SET', KEYS\[1\]/.test(script)) {
        const [headHashKey, chainKey, headKey] = keys;
        const [expectedPrev, recordJSON, integrityJSON, newEventHash] = args;
        const curSlot = live(headHashKey);
        const cur = curSlot ? curSlot.value : false;
        const fenceOk = (cur === false && expectedPrev === "") || cur === expectedPrev;
        if (!fenceOk) {
          return 0; // head moved — reject the stale writer
        }
        maybeFault(script); // a crash here must leave NEITHER chain nor head advanced
        rpush(chainKey, recordJSON);
        setString(headKey, integrityJSON);
        setString(headHashKey, newEventHash);
        return 1;
      }

      // 3. Token COMPARE-AND-APPLY (APPLY_SCRIPT).
      //   KEYS = [versionKey, hashKey]
      //   ARGV = [expectedVersion, setPairsJSON, delFieldsJSON]
      if (/cjson\.decode\(ARGV\[2\]\)/.test(script) && /redis\.call\('HSET', KEYS\[2\]/.test(script)) {
        const [versionKey, hashKey] = keys;
        const [expectedVersion, setPairsJSON, delFieldsJSON] = args;
        const curSlot = live(versionKey);
        const cur = curSlot ? curSlot.value : false;
        const fenceOk = (cur === false && expectedVersion === "") || cur === expectedVersion;
        if (!fenceOk) {
          return 0; // version moved — reject the stale writer
        }
        maybeFault(script); // a crash here must leave the hash + version untouched
        const sets = JSON.parse(setPairsJSON);
        for (const [field, value] of sets) {
          hset(hashKey, field, value);
        }
        const dels = JSON.parse(delFieldsJSON);
        for (const field of dels) {
          hdel(hashKey, field);
        }
        const nv = cur === false ? 1 : Number(cur) + 1;
        setString(versionKey, String(nv));
        return 1;
      }

      // 4. ready() write-probe (READY_PROBE_SCRIPT).
      if (/redis\.call\('SET', KEYS\[1\], '1', 'PX'/.test(script)) {
        maybeFault(script); // lets a test deny the write probe
        const expireAt = Date.now() + 2000;
        strings.set(keys[0], { value: "1", expireAt });
        return 1;
      }

      throw new Error(`fake eval: unsupported script: ${script}`);
    },

    async rPush(key, value) {
      return rpush(key, value);
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
  // core-owned; the store only does the read-previous + fenced append).
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
  // The head:hash fence tracks the last record's eventHash.
  assert.equal(await client.get(`${keyPrefix}head:hash`), records[4].auditIntegrity.eventHash);

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

test("redis audit store ready() probes liveness AND writability", async () => {
  const client = fakeRedisClient();
  const store = createRedisAuditStore({ client });
  assert.deepEqual(await store.ready(), { ok: true });

  // A client whose ping rejects reports not-ready (fail closed) with an enum.
  const broken = { ...fakeRedisClient(), ping: async () => { throw new Error("down"); } };
  const brokenStore = createRedisAuditStore({ client: broken });
  assert.deepEqual(await brokenStore.ready(), { ok: false, reason: "redis_unreachable" });

  // A client that answers PING but DENIES writes (ACL/readonly/quota) is caught
  // by the write-probe: ready() reports redis_not_writable rather than green.
  const writeDenied = fakeRedisClient();
  const writeDeniedStore = createRedisAuditStore({ client: writeDenied });
  writeDenied.failNextEval((s) => /redis\.call\('SET', KEYS\[1\], '1', 'PX'/.test(s));
  assert.deepEqual(await writeDeniedStore.ready(), { ok: false, reason: "redis_not_writable" });
  // And it recovers once writes are allowed again (one-shot fault).
  assert.deepEqual(await writeDeniedStore.ready(), { ok: true });
});

// --- audit FENCE: atomicity + fork-proofing (the previously-missing tests) --

test("audit fenced append is all-or-nothing under a mid-script failure", async () => {
  const client = fakeRedisClient();
  const keyPrefix = "haechi:audit:atomic:";
  const store = createRedisAuditStore({ client, keyPrefix });
  const sink = createAuditSink({ store });

  // Seed two good records so there is a real tail to preserve.
  await sink.record({ operation: "demo", count: 0 });
  await sink.record({ operation: "demo", count: 1 });
  const headBefore = await client.get(`${keyPrefix}head`);
  const headHashBefore = await client.get(`${keyPrefix}head:hash`);
  const lenBefore = (await readChain(client, keyPrefix)).length;
  assert.equal(lenBefore, 2);

  // Force the NEXT append eval to crash mid-script. The OLD shape did RPUSH then
  // a separate SET(head); a crash between them advanced the list but not the head
  // (the next reader saw a stale head and FORKED). The new single Lua append is
  // all-or-nothing, so a crash leaves NEITHER the chain nor the head advanced.
  client.failNextEval((s) => /redis\.call\('RPUSH', KEYS\[2\]/.test(s));
  await assert.rejects(() => sink.record({ operation: "demo", count: 2 }), /injected mid-script failure/);

  assert.equal((await readChain(client, keyPrefix)).length, 2, "chain not advanced");
  assert.equal(await client.get(`${keyPrefix}head`), headBefore, "head not advanced");
  assert.equal(await client.get(`${keyPrefix}head:hash`), headHashBefore, "head:hash not advanced");

  // The sink recovers: the next append commits cleanly onto the preserved tail.
  await sink.record({ operation: "demo", count: 3 });
  const records = await readChain(client, keyPrefix);
  assert.equal(records.length, 3);
  records.forEach((r, i) => assert.equal(r.auditIntegrity.sequence, i + 1));

  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-atomic-"));
  const auditPath = join(dir, "audit.log");
  try {
    await writeFile(auditPath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    const result = await verifyAuditChain(auditPath);
    assert.equal(result.valid, true, `chain should verify: ${result.reason ?? ""}`);
    assert.equal(result.records, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("audit chain stays linear when two writers enter over a lapsed lock", async () => {
  // Drive the store's transaction() DIRECTLY (bypassing the per-sink writeQueue)
  // so two transactions can interleave as if two replicas entered concurrently
  // after the TTL lock lapsed. We reproduce the core sink's body: read the head,
  // build the record on it, persist. Both readers see the SAME head; the fenced
  // append lets exactly one commit and rejects the other, which retries onto the
  // new tail. The chain must end up linear with strictly increasing,
  // non-duplicate sequences and verify.
  // lockless: the lock's TTL has fully lapsed, so BOTH transactions enter the
  // critical section at once — only the fence keeps the chain unforked.
  const client = fakeRedisClient({ lockless: true });
  const keyPrefix = "haechi:audit:concurrent:";
  const store = createRedisAuditStore({ client, keyPrefix });

  // Seed one record so both writers contend over a non-empty tail.
  await store.transaction(async ({ readLastIntegrity, persist }) => {
    const record = buildIntegrityRecord(await readLastIntegrity(), { operation: "seed", count: 0 });
    await persist(record);
  });

  // Two transactions whose fn bodies BOTH read the same head before either
  // persists. The fenced append lets exactly one commit; the loser's append
  // eval returns 0 -> ConflictError -> the bounded-retry loop re-reads the new
  // tail and rebuilds. We gate the first read of each on a shared barrier so
  // they provably observe the SAME head on their first attempt.
  let releaseBarrier;
  const barrier = new Promise((r) => { releaseBarrier = r; });
  let firstReads = 0;
  async function writer(label, count) {
    let firstAttempt = true;
    return store.transaction(async ({ readLastIntegrity, persist }) => {
      const prev = await readLastIntegrity();
      if (firstAttempt) {
        firstAttempt = false;
        firstReads += 1;
        if (firstReads === 2) {
          releaseBarrier(); // both have read the same head; let them proceed
        } else {
          await barrier; // wait for the other writer's first read
        }
      }
      await persist(buildIntegrityRecord(prev, { operation: label, count }));
    });
  }
  await Promise.all([writer("writerA", 1), writer("writerB", 2)]);

  const records = await readChain(client, keyPrefix);
  assert.equal(records.length, 3, "all three records committed, none lost or duplicated");
  // Strictly increasing, non-duplicate sequences (no fork).
  records.forEach((r, i) => assert.equal(r.auditIntegrity.sequence, i + 1));
  // The two contending writers both landed (one after a fenced-conflict retry).
  const ops = records.map((r) => r.operation).sort();
  assert.deepEqual(ops, ["seed", "writerA", "writerB"]);

  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-concurrent-"));
  const auditPath = join(dir, "audit.log");
  try {
    await writeFile(auditPath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    const result = await verifyAuditChain(auditPath);
    assert.equal(result.valid, true, `concurrent chain should verify: ${result.reason ?? ""}`);
    assert.equal(result.records, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
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

    // The record actually lives in the shared hash, and the version fence bumped.
    const stored = await client.hGet("haechi:tv:test:tokens", token);
    assert.ok(stored, "record persisted to the redis hash");
    assert.equal(JSON.parse(stored).type, "card");
    assert.equal(await client.get("haechi:tv:test:version"), "1", "version bumped once");

    // exportMetadata (a read() path) sees the token; purge (a mutate() path)
    // removes it.
    const meta = await vault.exportMetadata();
    assert.equal(meta.length, 1);
    assert.equal(meta[0].token, token);

    const purge = await vault.purge({ token });
    assert.equal(purge.purged, true);
    assert.equal(await client.hGet("haechi:tv:test:tokens", token), null);
    assert.equal(await client.get("haechi:tv:test:version"), "2", "version bumped again on purge");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// --- token FENCE: atomicity + lost-update-proofing --------------------------

test("token diff-apply is all-or-nothing under a mid-script failure", async () => {
  const client = fakeRedisClient();
  const { cryptoProvider, dir } = await makeCryptoProvider();
  try {
    const store = createRedisTokenStore({ client, keyPrefix: "haechi:tv:atomic:" });
    const vault = createTokenVault({ store, cryptoProvider, revealPolicy: "local-dev" });

    // Seed one token so there is real state to preserve.
    const { token: first } = await vault.tokenize({ plaintext: "seed-secret", type: "secret" });
    const hashBefore = await client.hGetAll("haechi:tv:atomic:tokens");
    const versionBefore = await client.get("haechi:tv:atomic:version");
    assert.equal(versionBefore, "1");

    // Force the NEXT apply eval to crash mid-script. The OLD shape did sequential
    // hSet/hDel; a crash between them left a PARTIAL apply. The new single Lua
    // apply is all-or-nothing — the hash AND the version are untouched.
    client.failNextEval((s) => /cjson\.decode\(ARGV\[2\]\)/.test(s));
    await assert.rejects(
      () => vault.tokenize({ plaintext: "second-secret", type: "secret" }),
      /injected mid-script failure/
    );

    assert.deepEqual(await client.hGetAll("haechi:tv:atomic:tokens"), hashBefore, "hash unchanged");
    assert.equal(await client.get("haechi:tv:atomic:version"), versionBefore, "version unchanged");

    // The vault recovers: the seed token still reveals, and a new tokenize works.
    assert.equal((await vault.reveal({ token: first })).plaintext, "seed-secret");
    const { token: third } = await vault.tokenize({ plaintext: "third-secret", type: "secret" });
    assert.equal((await vault.reveal({ token: third })).plaintext, "third-secret");
    assert.equal(await client.get("haechi:tv:atomic:version"), "2", "version bumped once after recovery");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("token vault loses no write when two mutates run over a lapsed lock", async () => {
  // lockless: the lock's TTL has fully lapsed, so BOTH mutates enter at once —
  // only the version fence keeps a write from being lost.
  const client = fakeRedisClient({ lockless: true });
  const keyPrefix = "haechi:tv:concurrent:";
  const store = createRedisTokenStore({ client, keyPrefix });

  // Two mutates whose fn bodies BOTH snapshot the same version before either
  // applies. A shared barrier makes them provably observe the same version on
  // their first attempt; the version fence lets exactly one apply commit and
  // rejects the other, which re-snapshots and re-applies onto fresh state — so
  // NEITHER write is lost and the version increments once per applied mutate.
  let releaseBarrier;
  const barrier = new Promise((r) => { releaseBarrier = r; });
  let firstSnapshots = 0;
  async function addToken(field, record) {
    let firstAttempt = true;
    return store.mutate(async (view) => {
      if (firstAttempt) {
        firstAttempt = false;
        firstSnapshots += 1;
        if (firstSnapshots === 2) {
          releaseBarrier();
        } else {
          await barrier;
        }
      }
      view.set(field, record);
    });
  }

  await Promise.all([
    addToken("tok_a", { type: "secret", value: "a" }),
    addToken("tok_b", { type: "secret", value: "b" })
  ]);

  const stored = await client.hGetAll(`${keyPrefix}tokens`);
  assert.equal(Object.keys(stored).length, 2, "no lost update — both tokens present");
  assert.deepEqual(JSON.parse(stored.tok_a), { type: "secret", value: "a" });
  assert.deepEqual(JSON.parse(stored.tok_b), { type: "secret", value: "b" });
  // Version increments once per applied mutate (the loser retried but still
  // committed exactly one apply onto the fresh snapshot).
  assert.equal(await client.get(`${keyPrefix}version`), "2", "version bumped once per applied mutate");
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
