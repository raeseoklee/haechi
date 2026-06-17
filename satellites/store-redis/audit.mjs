// Redis audit store for haechi-store-redis (the 1.5.0 audit STORE seam).
//
// createRedisAuditStore({ client, keyPrefix = "haechi:audit:" }) adapts an
// INJECTED node-redis v4/v5 client into the core audit store contract consumed
// by createAuditSink (packages/audit/index.mjs):
//
//   async transaction(fn) — runs `fn` inside an EXCLUSIVE critical section that
//     serializes concurrent appends. `fn` receives { readLastIntegrity, persist }
//     where readLastIntegrity() -> the last record's auditIntegrity object (or
//     null) and persist(record) durably appends the built record. transaction()
//     returns fn's value.
//   async ready() — OPTIONAL health probe returning { ok, reason? }.
//
// The store knows NOTHING about the sha256 chain math, sanitization, or the
// anchor stream — those stay core-owned in createAuditSink. The store ONLY
// provides the exclusive read-previous + persist, made atomic ACROSS REPLICAS
// by a Redis lock so the shared chain never forks.
//
// Layout over Redis:
//   - `${keyPrefix}chain` : a LIST, one JSON-serialized record per element, in
//     append order (the JSONL chain, replicated). readChain() reads it whole.
//   - `${keyPrefix}head`  : the last record's auditIntegrity object (JSON), the
//     cheap "previous integrity" tail-read (no need to parse the whole list).
//   - `${keyPrefix}lock`  : the distributed lock key for the critical section.
//
// The `redis` package is an OPTIONAL peer dependency: the client is injected,
// so this module never imports `redis` at the top level. It works whether or
// not the SDK is installed; tests inject a fake client.

import { withRedisLock } from "./lock.mjs";

const REQUIRED_CLIENT_METHODS = ["get", "set", "rPush", "lRange", "eval"];

function assertClient(client) {
  if (!client) {
    throw new Error("createRedisAuditStore requires a node-redis v4/v5 client");
  }
  for (const method of REQUIRED_CLIENT_METHODS) {
    if (typeof client[method] !== "function") {
      throw new Error(`createRedisAuditStore requires a client with a ${method}() method`);
    }
  }
}

export function createRedisAuditStore({ client, keyPrefix = "haechi:audit:" } = {}) {
  assertClient(client);
  if (typeof keyPrefix !== "string") {
    throw new Error("createRedisAuditStore keyPrefix must be a string");
  }

  const chainKey = `${keyPrefix}chain`;
  const headKey = `${keyPrefix}head`;
  const lockKey = `${keyPrefix}lock`;

  return {
    // The lock makes read-previous + persist atomic across replicas: two sinks
    // on two connections can't both read the same head and append a forked
    // record, so the core chain math always builds on the true tail.
    async transaction(fn) {
      return withRedisLock(client, lockKey, async () => fn({
        // The last record's auditIntegrity object, or null for an empty chain.
        readLastIntegrity: async () => {
          const head = await client.get(headKey);
          return head ? JSON.parse(head) : null;
        },
        // Durably append the built record, then advance the head pointer to its
        // integrity. Both happen inside the lock, so the head a later holder
        // reads is always this record's integrity (never a stale tail).
        persist: async (record) => {
          await client.rPush(chainKey, JSON.stringify(record));
          await client.set(headKey, JSON.stringify(record.auditIntegrity));
        }
      }));
    },

    // Readiness probe: a security gateway whose shared audit store is
    // unreachable is NOT ready (fail closed). PING is the cheapest liveness
    // check; fall back to a GET of the head key if the client has no ping().
    // Returns the bare boolean + an enum reason — never a key or payload value.
    async ready() {
      try {
        if (typeof client.ping === "function") {
          await client.ping();
        } else {
          await client.get(headKey);
        }
        return { ok: true };
      } catch {
        return { ok: false, reason: "redis_unreachable" };
      }
    }
  };
}

// readChain(client, keyPrefix) -> the full ordered chain records.
//
// Reads `${keyPrefix}chain` whole via LRANGE 0 -1 and parses each element back
// into a record object. The integration test uses it to materialize the shared
// chain (written by interleaved replicas) and feed it to verifyAuditChain.
export async function readChain(client, keyPrefix = "haechi:audit:") {
  if (!client || typeof client.lRange !== "function") {
    throw new Error("readChain requires a node-redis v4/v5 client with an lRange() method");
  }
  if (typeof keyPrefix !== "string") {
    throw new Error("readChain keyPrefix must be a string");
  }
  const raw = await client.lRange(`${keyPrefix}chain`, 0, -1);
  return raw.map((line) => JSON.parse(line));
}
