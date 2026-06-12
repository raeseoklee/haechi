import test from "node:test";
import assert from "node:assert/strict";

import { createSharedRateLimiter } from "./index.mjs";
import { createMemoryStore } from "./memory.mjs";
import { createRedisStore } from "./redis.mjs";

// haechi-ratelimit-redis — the production shared-store rateLimiter satellite.
// These tests use NO live Redis: the limiter is exercised against the in-memory
// reference store, and the Redis adapter against a MOCK client. They pin:
//   - the fixed-window budget (N allowed, then denied) + per-identity isolation
//   - the window resets after windowMs (via an injectable clock)
//   - the Redis adapter issues the atomic EVAL script and the returned count
//     drives allow/deny
//   - fail-closed input validation on both the limiter and the stores.

// --- limiter against the memory store -------------------------------------

test("fixed-window budget: N allowed then denied for one identity", async () => {
  const store = createMemoryStore();
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  // Budget of 3/window: three pass, the fourth in the same window is denied.
  assert.equal(await limiter.allow("alice", 3), true);
  assert.equal(await limiter.allow("alice", 3), true);
  assert.equal(await limiter.allow("alice", 3), true);
  assert.equal(await limiter.allow("alice", 3), false);
  assert.equal(await limiter.allow("alice", 3), false);
});

test("per-identity isolation: one identity's budget does not affect another", async () => {
  const store = createMemoryStore();
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  // Exhaust alice's 2/window budget.
  assert.equal(await limiter.allow("alice", 2), true);
  assert.equal(await limiter.allow("alice", 2), true);
  assert.equal(await limiter.allow("alice", 2), false);

  // bob has his own counter — unaffected.
  assert.equal(await limiter.allow("bob", 2), true);
  assert.equal(await limiter.allow("bob", 2), true);
  assert.equal(await limiter.allow("bob", 2), false);
});

test("the window resets after windowMs (injectable clock)", async () => {
  let clock = 1_000_000;
  const store = createMemoryStore({ now: () => clock });
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  assert.equal(await limiter.allow("alice", 1), true);
  assert.equal(await limiter.allow("alice", 1), false); // same window: denied

  // Advance past the window boundary so a new fixed-window bucket begins.
  clock += 60000;
  assert.equal(await limiter.allow("alice", 1), true); // fresh window: allowed
  assert.equal(await limiter.allow("alice", 1), false);
});

test("a tiny windowMs rolls the window over with real time advancing", async () => {
  // Exercise the real Date.now() path (no injected clock) with a 1ms window.
  const store = createMemoryStore();
  const limiter = createSharedRateLimiter({ store, windowMs: 1 });
  assert.equal(await limiter.allow("alice", 1), true);
  // Busy-wait a couple of ms so the millisecond bucket advances deterministically.
  const start = Date.now();
  while (Date.now() - start < 3) { /* spin */ }
  assert.equal(await limiter.allow("alice", 1), true);
});

test("limiter fail-closed validation", async () => {
  const store = createMemoryStore();
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  // Bad key → deny (never bypass the budget on a malformed identity).
  assert.equal(await limiter.allow("", 5), false);
  assert.equal(await limiter.allow(null, 5), false);
  assert.equal(await limiter.allow(42, 5), false);
  // Bad limit → deny.
  assert.equal(await limiter.allow("alice", 0), false);
  assert.equal(await limiter.allow("alice", -1), false);
  assert.equal(await limiter.allow("alice", 2.5), false);
  assert.equal(await limiter.allow("alice", undefined), false);

  // Constructor fail-closed.
  assert.throws(() => createSharedRateLimiter({}), /requires a store/);
  assert.throws(() => createSharedRateLimiter({ store: {} }), /requires a store/);
  assert.throws(() => createSharedRateLimiter({ store, windowMs: 0 }), /positive integer windowMs/);
  assert.throws(() => createSharedRateLimiter({ store, windowMs: -1 }), /positive integer windowMs/);
});

test("a store returning a nonsensical count fails closed (deny)", async () => {
  const badStore = { async hit() { return NaN; } };
  const limiter = createSharedRateLimiter({ store: badStore, windowMs: 60000 });
  assert.equal(await limiter.allow("alice", 10), false);
});

// --- the Redis adapter against a MOCK client -------------------------------

// A fake node-redis client recording EVAL calls and emulating INCR + PEXPIRE so
// the script's returned count is deterministic — NO live Redis.
function fakeRedisClient() {
  const counters = new Map();   // redisKey -> count
  const ttls = new Map();       // redisKey -> ttlMs
  const calls = [];
  return {
    calls,
    counters,
    ttls,
    async eval(script, { keys, arguments: args }) {
      calls.push({ script, keys, arguments: args });
      const redisKey = keys[0];
      // Emulate: local n = INCR(key)
      const n = (counters.get(redisKey) ?? 0) + 1;
      counters.set(redisKey, n);
      // Emulate: if n == 1 then PEXPIRE(key, ARGV[1])
      if (n === 1) {
        ttls.set(redisKey, Number(args[0]));
      }
      return n;
    }
  };
}

test("redis adapter issues the atomic EVAL script and the count drives allow/deny", async () => {
  const client = fakeRedisClient();
  const store = createRedisStore({ client, keyPrefix: "haechi:rl:" });
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  // Budget of 2: two pass, the third in the same window is denied.
  assert.equal(await limiter.allow("alice", 2), true);
  assert.equal(await limiter.allow("alice", 2), true);
  assert.equal(await limiter.allow("alice", 2), false);

  // Exactly the documented atomic script was issued.
  assert.equal(client.calls.length, 3);
  for (const call of client.calls) {
    assert.match(call.script, /redis\.call\('INCR',KEYS\[1\]\)/);
    assert.match(call.script, /redis\.call\('PEXPIRE',KEYS\[1\],ARGV\[1\]\)/);
    assert.match(call.script, /if n==1 then/);
    // The window TTL (ms) is passed as ARGV[1], stringified for Redis.
    assert.equal(call.arguments[0], "60000");
    // The key is prefixed and window-bucketed.
    assert.equal(call.keys.length, 1);
    assert.match(call.keys[0], /^haechi:rl:alice:\d+$/);
  }

  // PEXPIRE was applied exactly once (first hit only) — the fixed-window TTL.
  const aliceKeys = [...client.ttls.keys()].filter((k) => k.startsWith("haechi:rl:alice:"));
  assert.equal(aliceKeys.length, 1);
  assert.equal(client.ttls.get(aliceKeys[0]), 60000);
});

test("redis adapter buckets distinct identities into distinct keys", async () => {
  const client = fakeRedisClient();
  const store = createRedisStore({ client });
  const limiter = createSharedRateLimiter({ store, windowMs: 60000 });

  await limiter.allow("alice", 5);
  await limiter.allow("bob", 5);

  const keys = client.calls.map((c) => c.keys[0]);
  assert.match(keys[0], /:alice:\d+$/);
  assert.match(keys[1], /:bob:\d+$/);
  // Default prefix applied.
  assert.ok(keys.every((k) => k.startsWith("haechi:rl:")));
});

test("redis adapter rolls the window key over a window boundary", async () => {
  // Two EVALs straddling a window boundary must target DIFFERENT bucketed keys,
  // so the second window starts a fresh counter. Drive Date.now deterministically.
  const realNow = Date.now;
  let clock = 60000; // bucket 1 for windowMs=60000
  Date.now = () => clock;
  try {
    const client = fakeRedisClient();
    const store = createRedisStore({ client });
    await store.hit("alice", 60000);
    clock += 60000; // advance one full window → next bucket
    await store.hit("alice", 60000);
    const keys = client.calls.map((c) => c.keys[0]);
    assert.notEqual(keys[0], keys[1]);
  } finally {
    Date.now = realNow;
  }
});

test("redis adapter fail-closed validation", () => {
  assert.throws(() => createRedisStore({}), /requires a node-redis/);
  assert.throws(() => createRedisStore({ client: {} }), /requires a node-redis/);
  assert.throws(() => createRedisStore({ client: { eval() {} }, keyPrefix: 5 }), /keyPrefix must be a string/);
});

test("memory store fail-closed validation", () => {
  assert.throws(() => createMemoryStore({ now: "nope" }), /now must be a function/);
});
