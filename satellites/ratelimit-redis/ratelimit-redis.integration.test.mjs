// Optional REAL-Redis integration test for haechi-ratelimit-redis.
//
// Skipped unless HAECHI_REDIS_URL is set (mirrors tests/local-inference.integration.test.mjs).
// It needs the optional `redis` peer installed in this workspace. Run it with:
//
//   npm i -D redis            # once, in the repo root (redis is an optional peer)
//   HAECHI_REDIS_URL=redis://127.0.0.1:6379 \
//   node --test satellites/ratelimit-redis/ratelimit-redis.integration.test.mjs
//
// The point this proves — beyond the mock-client unit test — is SHARED-STORE
// enforcement ACROSS replicas: two independent limiter instances (each its own
// Redis connection, standing in for two proxy replicas behind a load balancer)
// share ONE budget. The built-in in-memory default cannot do this; that is the
// whole reason this satellite exists (WS3 seam → production shared store).

import test from "node:test";
import assert from "node:assert/strict";

import { createSharedRateLimiter } from "./index.mjs";
import { createRedisStore } from "./redis.mjs";

const REDIS_URL = process.env.HAECHI_REDIS_URL;

// A unique key prefix per run so repeated runs / parallel CI shards never share
// counters. Date.now()/random are fine in a test (not a workflow script).
const RUN_PREFIX = `haechi:rl:itest:${Date.now()}:${Math.floor(Math.random() * 1e6)}:`;

async function connect() {
  // `redis` is an OPTIONAL peer — import it lazily so this file loads (and skips)
  // even when it is not installed. If HAECHI_REDIS_URL is set but `redis` is
  // missing, fail with a clear, actionable message.
  let createClient;
  try {
    ({ createClient } = await import("redis"));
  } catch {
    throw new Error("HAECHI_REDIS_URL is set but the optional `redis` peer is not installed — run `npm i -D redis` in the repo root.");
  }
  const client = createClient({ url: REDIS_URL });
  await client.connect();
  return client;
}

test("shared-store: two limiter replicas over one Redis share a single budget", {
  skip: !REDIS_URL
}, async () => {
  const clientA = await connect();
  const clientB = await connect();
  try {
    const keyPrefix = `${RUN_PREFIX}shared:`;
    // Two independent limiters (two "replicas"), each its own connection, same Redis.
    const replicaA = createSharedRateLimiter({ store: createRedisStore({ client: clientA, keyPrefix }), windowMs: 60000 });
    const replicaB = createSharedRateLimiter({ store: createRedisStore({ client: clientB, keyPrefix }), windowMs: 60000 });
    const id = "user:shared";
    const limit = 4;

    // 3 on replica A + 1 on replica B = 4 allowed (the shared budget)...
    assert.equal(await replicaA.allow(id, limit), true, "A #1");
    assert.equal(await replicaA.allow(id, limit), true, "A #2");
    assert.equal(await replicaA.allow(id, limit), true, "A #3");
    assert.equal(await replicaB.allow(id, limit), true, "B #1 (4th overall)");
    // ...and the 5th is denied REGARDLESS of which replica serves it.
    assert.equal(await replicaB.allow(id, limit), false, "B #2 (5th overall) — over the shared budget");
    assert.equal(await replicaA.allow(id, limit), false, "A #4 (6th overall) — still over on the other replica");
  } finally {
    await clientA.quit();
    await clientB.quit();
  }
});

test("per-identity isolation against real Redis", { skip: !REDIS_URL }, async () => {
  const client = await connect();
  try {
    const limiter = createSharedRateLimiter({ store: createRedisStore({ client, keyPrefix: `${RUN_PREFIX}iso:` }), windowMs: 60000 });
    assert.equal(await limiter.allow("alice", 1), true);
    assert.equal(await limiter.allow("alice", 1), false, "alice is over her budget");
    assert.equal(await limiter.allow("bob", 1), true, "bob has his own budget");
  } finally {
    await client.quit();
  }
});

test("the fixed window resets after windowMs against real Redis", { skip: !REDIS_URL }, async () => {
  const client = await connect();
  try {
    const windowMs = 300;
    const limiter = createSharedRateLimiter({ store: createRedisStore({ client, keyPrefix: `${RUN_PREFIX}reset:` }), windowMs });
    const id = "user:reset";
    assert.equal(await limiter.allow(id, 1), true);
    assert.equal(await limiter.allow(id, 1), false, "exhausted within the window");
    await new Promise((r) => setTimeout(r, windowMs + 100));
    assert.equal(await limiter.allow(id, 1), true, "a fresh window allows again");
  } finally {
    await client.quit();
  }
});
