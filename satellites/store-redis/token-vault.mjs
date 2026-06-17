// Redis token store for haechi-store-redis (the 1.5.0 token-vault STORE seam).
//
// createRedisTokenStore({ client, keyPrefix = "haechi:tv:" }) adapts an INJECTED
// node-redis v4/v5 client into the core token store contract consumed by
// createTokenVault (packages/token-vault/index.mjs):
//
//   async mutate(fn) — runs `fn` to mutate the token-record map, persisted
//     ATOMICALLY and fenced on a version counter. `fn` receives a MUTABLE view
//     { get, set, delete, entries } over an in-memory snapshot; the diff is
//     applied by a single server-side compare-and-apply. mutate() retries the
//     whole body on a version conflict. Returns fn's value.
//   async read(fn)   — read-only access. `fn` receives { get, entries } over a
//     FRESH snapshot, NO lock. read() returns fn's value.
//
// The store knows NOTHING about crypto, reveal governance, retention, or audit
// — those stay core-owned in createTokenVault. The store ONLY supplies the
// exclusive-ish mutate / lock-free read primitive over the token-record map.
//
// CORRECTNESS IS LOCK-INDEPENDENT. A mutate() snapshots a version counter, runs
// the sync view to compute a diff (sets/deletes), then applies the diff with a
// single Lua COMPARE-AND-APPLY fenced on that version: it applies the diff and
// bumps the version ONLY if the version still equals the one snapshotted. A
// stale/concurrent writer (lock lapsed) whose version moved is REJECTED (eval
// returns 0) and the whole mutate() body retries over a FRESH snapshot — so no
// write is lost and no partial diff lands. The Redis lock (below) is now only a
// CONTENTION-REDUCTION optimization (fewer version conflicts under load); it is
// NOT the safety mechanism.
//
// IMPORTANT — the VIEW is SYNCHRONOUS. The core token-vault calls the view
// methods WITHOUT await (e.g. `const existing = view.get(token)` then mutates
// it and `view.set(token, existing)`; `for (const [t, r] of view.entries())`;
// `view.entries().filter(...)`). The seam was designed the file-store way:
// load the WHOLE record map into memory, hand a SYNC view over that in-memory
// snapshot, then persist the diff after `fn` resolves. So this adapter HGETALLs
// the hash up front, runs the sync view over a plain object, tracks
// dirty/deleted fields, and applies them via one fenced Lua eval. (An async view
// returning Promises WOULD break core — `view.get` would be a truthy Promise and
// `view.entries()` is iterated directly. This is the contract.)
//
// Layout:
//   - `${keyPrefix}tokens`  : a single Redis HASH (field = token id, value =
//     JSON record).
//   - `${keyPrefix}version` : a counter (string), the FENCE the diff-apply
//     guards on (absent === version 0, the empty/never-mutated vault).
//   - `${keyPrefix}lock`    : the contention-reduction lock key.
//
// The `redis` package is an OPTIONAL peer dependency: the client is injected,
// so this module never imports `redis` at the top level.

import { withRedisLock } from "./lock.mjs";

const REQUIRED_CLIENT_METHODS = ["get", "set", "eval", "hGet", "hSet", "hDel", "hGetAll"];

// Bound on how many times mutate() re-runs `fn` after a version conflict before
// it fails closed. Each conflict means a concurrent writer committed first; the
// retry re-snapshots and re-runs `fn`, so progress is made every commit.
const MAX_MUTATE_RETRIES = 64;

// COMPARE-AND-APPLY, fenced on the version counter. Applies the set/del diff and
// bumps the version ATOMICALLY, but ONLY if the current version still equals the
// one the snapshot was taken at (ARGV[1]); the never-mutated vault is the
// sentinel "" against an absent key. Returns 1 on commit, 0 on a version
// conflict (a concurrent writer applied a diff first). cjson is available in
// Redis. All HSET/HDELs happen only after the fence passes, so the script is
// all-or-nothing: a conflict applies NOTHING.
//   KEYS = [versionKey, hashKey]
//   ARGV = [expectedVersion, setPairsJSON, delFieldsJSON]
// setPairsJSON is [[field, recordJSON], ...]; delFieldsJSON is [field, ...].
const APPLY_SCRIPT =
  "local cur = redis.call('GET', KEYS[1]); " +
  "if (cur == false and ARGV[1] == '') or cur == ARGV[1] then " +
  "local sets = cjson.decode(ARGV[2]); " +
  "for _,p in ipairs(sets) do redis.call('HSET', KEYS[2], p[1], p[2]) end; " +
  "local dels = cjson.decode(ARGV[3]); " +
  "for _,f in ipairs(dels) do redis.call('HDEL', KEYS[2], f) end; " +
  "local nv = 1; if cur ~= false then nv = tonumber(cur) + 1 end; " +
  "redis.call('SET', KEYS[1], tostring(nv)); " +
  "return 1 else return 0 end";

function assertClient(client) {
  if (!client) {
    throw new Error("createRedisTokenStore requires a node-redis v4/v5 client");
  }
  for (const method of REQUIRED_CLIENT_METHODS) {
    if (typeof client[method] !== "function") {
      throw new Error(`createRedisTokenStore requires a client with a ${method}() method`);
    }
  }
}

// Load the whole hash into a plain { token: record } object. node-redis
// hGetAll returns { field: stringValue }; parse each value back to a record.
async function loadTokens(client, hashKey) {
  const all = await client.hGetAll(hashKey);
  const tokens = {};
  for (const [token, value] of Object.entries(all ?? {})) {
    tokens[token] = JSON.parse(value);
  }
  return tokens;
}

// A SYNC mutable view over the in-memory snapshot. set/delete record the change
// in `dirty` / `deleted` so mutate() can persist exactly the diff (and so a
// delete-then-set in one fn lands as a set). get/entries operate on the live
// snapshot, matching the file store's mutableView semantics.
function mutableView(tokens, dirty, deleted) {
  return {
    get: (token) => tokens[token],
    set: (token, record) => {
      tokens[token] = record;
      dirty.add(token);
      deleted.delete(token);
    },
    delete: (token) => {
      delete tokens[token];
      deleted.add(token);
      dirty.delete(token);
    },
    entries: () => Object.entries(tokens)
  };
}

function readView(tokens) {
  return {
    get: (token) => tokens[token],
    entries: () => Object.entries(tokens)
  };
}

export function createRedisTokenStore({ client, keyPrefix = "haechi:tv:" } = {}) {
  assertClient(client);
  if (typeof keyPrefix !== "string") {
    throw new Error("createRedisTokenStore keyPrefix must be a string");
  }

  const hashKey = `${keyPrefix}tokens`;
  const versionKey = `${keyPrefix}version`;
  const lockKey = `${keyPrefix}lock`;

  return {
    // BOUNDED-RETRY around a version-fenced diff-apply. Snapshot the version +
    // the whole token map, run the sync mutation over the snapshot, then apply
    // the computed diff with ONE Lua eval fenced on the version: it commits only
    // if the version is unchanged. If a concurrent writer (lock lapsed) bumped
    // the version first, eval returns 0 and we re-run the WHOLE body over a fresh
    // snapshot — so no write is lost and no partial diff lands. The lock only
    // reduces how often that conflict-retry happens; it is not the safety net.
    async mutate(fn) {
      return withRedisLock(client, lockKey, async () => {
        for (let attempt = 0; attempt < MAX_MUTATE_RETRIES; attempt += 1) {
          const expectedVersion = await client.get(versionKey); // null === never mutated
          const tokens = await loadTokens(client, hashKey);
          const dirty = new Set();
          const deleted = new Set();
          const result = await fn(mutableView(tokens, dirty, deleted));

          // Build the diff. Sets first, then deletes (a token can only be in one
          // set — the view keeps them mutually exclusive).
          const setPairs = [];
          for (const token of dirty) {
            setPairs.push([token, JSON.stringify(tokens[token])]);
          }
          const delFields = [...deleted];

          const committed = await client.eval(APPLY_SCRIPT, {
            keys: [versionKey, hashKey],
            arguments: [
              expectedVersion ?? "",
              JSON.stringify(setPairs),
              JSON.stringify(delFields)
            ]
          });
          if (Number(committed) === 1) {
            return result;
          }
          // Version moved — a concurrent writer committed first. Retry the whole
          // body (re-GET version, re-HGETALL, re-run fn over the fresh snapshot).
        }
        // Exhausted retries: fail closed rather than risk a lost update.
        throw new Error(
          `haechi-store-redis: token mutate failed after ${MAX_MUTATE_RETRIES} version conflicts`
        );
      });
    },

    // Lock-free read over a FRESH snapshot (matches how the file store's read()
    // reads the vault without the lock; reveal / detokenize / export use it).
    async read(fn) {
      const tokens = await loadTokens(client, hashKey);
      return fn(readView(tokens));
    }
  };
}
