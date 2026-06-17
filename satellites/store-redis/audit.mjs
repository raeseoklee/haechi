// Redis audit store for haechi-store-redis (the 1.5.0 audit STORE seam).
//
// createRedisAuditStore({ client, keyPrefix = "haechi:audit:" }) adapts an
// INJECTED node-redis v4/v5 client into the core audit store contract consumed
// by createAuditSink (packages/audit/index.mjs):
//
//   async transaction(fn) — runs `fn` to BUILD + persist a record, retrying it
//     on a head conflict. `fn` receives { readLastIntegrity, persist } where
//     readLastIntegrity() -> the last record's auditIntegrity object (or null)
//     and persist(record) durably appends the built record via a SERVER-SIDE
//     compare-and-append fenced on the head eventHash. transaction() returns
//     fn's value.
//   async ready() — OPTIONAL health probe returning { ok, reason? }: PING
//     liveness AND a server-side write probe (so an ACL/readonly/quota-denied
//     Redis that still answers reads reports not-ready).
//
// The store knows NOTHING about the sha256 chain math, sanitization, or the
// anchor stream — those stay core-owned in createAuditSink. The store ONLY
// provides the read-previous + fenced-append primitive.
//
// CORRECTNESS IS LOCK-INDEPENDENT. The chain never forks because persist() is a
// single Lua COMPARE-AND-APPEND fenced on the current head eventHash: it appends
// + advances the head ONLY when the head still equals the previousHash the record
// was built on. A stale/concurrent writer (whose record built on an older head)
// is REJECTED (eval returns 0 -> ConflictError) and transaction() retries `fn`,
// which re-reads the new head and rebuilds the record on the true tail. The
// Redis lock (below) is now only a CONTENTION-REDUCTION optimization — it lowers
// the rate of fence conflicts under load; it is NOT the safety mechanism.
//
// Layout over Redis:
//   - `${keyPrefix}chain`     : a LIST, one JSON-serialized record per element,
//     in append order (the JSONL chain, replicated). readChain() reads it whole.
//   - `${keyPrefix}head`      : the last record's auditIntegrity object (JSON),
//     the cheap "previous integrity" tail-read.
//   - `${keyPrefix}head:hash` : the last record's eventHash (a bare string), the
//     FENCE the compare-and-append guards on (absent === empty chain).
//   - `${keyPrefix}lock`      : the contention-reduction lock key.
//   - `${keyPrefix}ready:probe` : the dedicated key the ready() write-probe SETs.
//
// The `redis` package is an OPTIONAL peer dependency: the client is injected,
// so this module never imports `redis` at the top level. It works whether or
// not the SDK is installed; tests inject a fake client.

import { withRedisLock } from "./lock.mjs";

const REQUIRED_CLIENT_METHODS = ["get", "set", "rPush", "lRange", "eval"];

// How many times transaction() re-runs `fn` after a head conflict before it
// gives up (fail closed). A conflict means another writer won the head; the
// retry re-reads the new head and rebuilds the record, so progress is made each
// time a writer commits. 64 is far beyond any realistic concurrent-writer fan-in.
const MAX_APPEND_RETRIES = 64;

// COMPARE-AND-APPEND, fenced on the head eventHash. Appends the record and
// advances both head pointers ATOMICALLY, but ONLY if the current head hash
// still equals the previousHash the record was built on (ARGV[1]); the empty
// chain is the sentinel "" against an absent key. Returns 1 on commit, 0 on a
// fence conflict (the head moved — a concurrent writer appended first).
//   KEYS = [headHashKey, chainKey, headKey]
//   ARGV = [expectedPrevHash, recordJSON, integrityJSON, newEventHash]
// All three writes happen only after the fence check passes, so the script is
// all-or-nothing: a conflict advances NOTHING.
const APPEND_SCRIPT =
  "local cur = redis.call('GET', KEYS[1]); " +
  "if (cur == false and ARGV[1] == '') or cur == ARGV[1] then " +
  "redis.call('RPUSH', KEYS[2], ARGV[2]); " +
  "redis.call('SET', KEYS[3], ARGV[3]); " +
  "redis.call('SET', KEYS[1], ARGV[4]); " +
  "return 1 else return 0 end";

// A tiny server-side WRITE probe for ready(): proves the connection can WRITE
// (not just read), so an ACL/readonly/quota-denied Redis reports not-ready. The
// probe key carries a short PX so it self-expires and never accumulates.
//   KEYS = [readyProbeKey]
const READY_PROBE_SCRIPT =
  "redis.call('SET', KEYS[1], '1', 'PX', 2000); return 1";

// Tag for a fenced-append rejection so transaction() can distinguish a head
// conflict (retry) from any other error (propagate).
class AuditConflictError extends Error {
  constructor() {
    super("haechi-store-redis: audit head moved (fenced-append conflict)");
    this.name = "AuditConflictError";
    this.code = "HAECHI_AUDIT_CONFLICT";
  }
}

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
  const headHashKey = `${keyPrefix}head:hash`;
  const lockKey = `${keyPrefix}lock`;
  const readyProbeKey = `${keyPrefix}ready:probe`;

  return {
    // BOUNDED-RETRY around a fenced compare-and-append. `fn` reads the current
    // head and BUILDS a record on it (core-owned chain math), then calls
    // persist(record), which fences on the head: if the head still equals the
    // record's previousHash it appends + advances atomically (commit); otherwise
    // a concurrent writer won the head and persist() throws AuditConflictError,
    // so we re-run `fn` against the NEW head. This makes the chain fork-proof
    // EVEN IF two writers enter concurrently (the lock lapsed): the loser is
    // rejected and rebuilds onto the true tail. The lock only reduces how often
    // that conflict-retry happens under contention — it is not the safety net.
    async transaction(fn) {
      return withRedisLock(client, lockKey, async () => {
        let lastError;
        for (let attempt = 0; attempt < MAX_APPEND_RETRIES; attempt += 1) {
          try {
            return await fn({
              // The last record's auditIntegrity object, or null for an empty
              // chain. Read fresh on every (re)attempt so a retry builds on the
              // new tail a concurrent writer just committed.
              readLastIntegrity: async () => {
                const head = await client.get(headKey);
                return head ? JSON.parse(head) : null;
              },
              // Fenced compare-and-append: ONE Lua eval appends the record and
              // advances head + head:hash, but only if the head hash still equals
              // the previousHash this record was built on. The empty chain uses
              // the "" sentinel. eval -> 0 means the head moved; throw so the
              // retry loop rebuilds.
              persist: async (record) => {
                const expectedPrev = record.auditIntegrity.previousHash ?? "";
                const newEventHash = record.auditIntegrity.eventHash;
                const committed = await client.eval(APPEND_SCRIPT, {
                  keys: [headHashKey, chainKey, headKey],
                  arguments: [
                    expectedPrev,
                    JSON.stringify(record),
                    JSON.stringify(record.auditIntegrity),
                    newEventHash
                  ]
                });
                if (Number(committed) !== 1) {
                  throw new AuditConflictError();
                }
              }
            });
          } catch (error) {
            if (error instanceof AuditConflictError) {
              lastError = error;
              continue; // head moved — re-run fn against the new tail
            }
            throw error; // any other error propagates (fail closed)
          }
        }
        // Exhausted retries: fail closed rather than risk a silent fork.
        throw new Error(
          `haechi-store-redis: audit append failed after ${MAX_APPEND_RETRIES} head conflicts`,
          { cause: lastError }
        );
      });
    },

    // Readiness probe: a security gateway whose shared audit store is unreachable
    // OR not writable is NOT ready (fail closed). PING is the cheapest liveness
    // check; the write-probe then proves the connection can actually WRITE — an
    // ACL/readonly/quota-denied Redis answers PING/GET but fails the probe, and
    // the first real append would fail closed anyway, so we surface it here.
    // Returns the bare boolean + an enum reason — never a key or payload value.
    async ready() {
      try {
        if (typeof client.ping === "function") {
          await client.ping();
        } else {
          await client.get(headKey);
        }
      } catch {
        return { ok: false, reason: "redis_unreachable" };
      }
      try {
        await client.eval(READY_PROBE_SCRIPT, { keys: [readyProbeKey], arguments: [] });
      } catch {
        return { ok: false, reason: "redis_not_writable" };
      }
      return { ok: true };
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
