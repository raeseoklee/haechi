// Optional REAL-Redis integration test for haechi-store-redis.
//
// Skipped unless HAECHI_REDIS_URL is set (mirrors ratelimit-redis's integration
// test). It needs the optional `redis` peer installed in this workspace. Run it:
//
//   npm i -D redis            # once, in the repo root (redis is an optional peer)
//   HAECHI_REDIS_URL=redis://127.0.0.1:6379 \
//   node --test satellites/store-redis/store-redis.integration.test.mjs
//
// The point this proves — beyond the fake-client unit test — is SHARED-STORE
// integrity ACROSS replicas: two independent audit sinks (each its own Redis
// connection, standing in for two proxy replicas behind a load balancer) write
// to ONE chain, interleaved, and that chain still verifies (no fork); and a
// token tokenized on replica A reveals on replica B. The file-backed defaults
// cannot do this; that is the whole reason this satellite exists (1.5.0 store
// seams -> production shared store).

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createAuditSink, verifyAuditChain } from "haechi/audit";
import { createTokenVault } from "haechi/token-vault";
import { initLocalKeyFile, createLocalCryptoProvider } from "haechi/crypto";

import { createRedisAuditStore, readChain } from "./audit.mjs";
import { createRedisTokenStore } from "./token-vault.mjs";

const REDIS_URL = process.env.HAECHI_REDIS_URL;

// A unique key prefix per run so repeated runs / parallel CI shards never share
// state. randomBytes is fine in a test (not a workflow script).
const RUN = `${Date.now()}:${randomBytes(6).toString("hex")}`;

async function connect() {
  // `redis` is an OPTIONAL peer — import it lazily so this file loads (and
  // skips) even when it is not installed. If HAECHI_REDIS_URL is set but `redis`
  // is missing, fail with a clear, actionable message.
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

test("shared audit chain: two sinks over one Redis interleave into ONE verifiable chain", {
  skip: !REDIS_URL
}, async () => {
  const clientA = await connect();
  const clientB = await connect();
  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-itest-"));
  try {
    const keyPrefix = `haechi:audit:itest:${RUN}:`;
    // Two independent sinks (two "replicas"), each its own connection, one Redis.
    const sinkA = createAuditSink({ store: createRedisAuditStore({ client: clientA, keyPrefix }) });
    const sinkB = createAuditSink({ store: createRedisAuditStore({ client: clientB, keyPrefix }) });

    // Interleave 20 record() calls across both sinks concurrently. The Redis
    // lock must serialize the read-previous + persist so the chain never forks.
    const writes = [];
    for (let i = 0; i < 10; i += 1) {
      writes.push(sinkA.record({ operation: "demo", replica: "A", i }));
      writes.push(sinkB.record({ operation: "demo", replica: "B", i }));
    }
    await Promise.all(writes);

    // Read the shared chain and verify it with the core verifier.
    const records = await readChain(clientA, keyPrefix);
    assert.equal(records.length, 20, "all 20 records landed in one chain");
    // Sequences are strictly increasing 1..20 with no fork/gap.
    records.forEach((record, idx) => {
      assert.equal(record.auditIntegrity.sequence, idx + 1, `sequence ${idx + 1} in order`);
    });

    const auditPath = join(dir, "audit.log");
    await writeFile(auditPath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    const result = await verifyAuditChain(auditPath);
    assert.equal(result.valid, true, `shared chain must verify: ${result.reason ?? ""}`);
    assert.equal(result.records, 20);
  } finally {
    await rm(dir, { recursive: true, force: true });
    await clientA.quit();
    await clientB.quit();
  }
});

test("shared token vault: tokenize on replica A reveals on replica B", {
  skip: !REDIS_URL
}, async () => {
  const clientA = await connect();
  const clientB = await connect();
  const dir = await mkdtemp(join(tmpdir(), "haechi-store-redis-itest-keys-"));
  try {
    const keyFile = join(dir, "dev.keys.json");
    await initLocalKeyFile(keyFile, { force: true });
    const cryptoProvider = createLocalCryptoProvider({ keyFile });
    const keyPrefix = `haechi:tv:itest:${RUN}:`;

    // Two vaults (two "replicas") over one Redis, same crypto key file.
    const vaultA = createTokenVault({
      store: createRedisTokenStore({ client: clientA, keyPrefix }),
      cryptoProvider,
      revealPolicy: "local-dev"
    });
    const vaultB = createTokenVault({
      store: createRedisTokenStore({ client: clientB, keyPrefix }),
      cryptoProvider,
      revealPolicy: "local-dev"
    });

    const secret = "4242 4242 4242 4242";
    const { token } = await vaultA.tokenize({ plaintext: secret, type: "card" });

    // Replica B reveals the token replica A issued — the vault is shared.
    const revealed = await vaultB.reveal({ token });
    assert.equal(revealed.plaintext, secret, "replica B reveals replica A's token");
    assert.equal(revealed.type, "card");

    // Exercise the version-fence Lua's HDEL loop against REAL Redis (the A->B
    // case above only hits the HSET path): purge on B, then re-tokenize on A.
    const purged = await vaultB.purge({ token });
    assert.equal(purged.purged, true, "replica B purges replica A's token");
    await assert.rejects(() => vaultA.reveal({ token }), "purged token no longer reveals");
    const reissued = await vaultA.tokenize({ plaintext: secret, type: "card" });
    assert.equal((await vaultB.reveal({ token: reissued.token })).plaintext, secret, "re-tokenized after purge round-trips");
  } finally {
    await rm(dir, { recursive: true, force: true });
    await clientA.quit();
    await clientB.quit();
  }
});

test("redis audit store ready() write-probe is ok against real Redis", { skip: !REDIS_URL }, async () => {
  const client = await connect();
  try {
    const store = createRedisAuditStore({ client, keyPrefix: `haechi:audit:ready:${RUN}:` });
    // Exercises the ready() write-probe Lua (SET ... PX) against real Redis — a
    // reachable + writable store is ready.
    const probe = await store.ready();
    assert.deepEqual(probe, { ok: true }, `ready() must be ok against a live writable Redis: ${probe.reason ?? ""}`);
  } finally {
    await client.quit();
  }
});
