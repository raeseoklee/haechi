// Redis token store for haechi-store-redis (the 1.5.0 token-vault STORE seam).
//
// createRedisTokenStore({ client, keyPrefix = "haechi:tv:" }) adapts an INJECTED
// node-redis v4/v5 client into the core token store contract consumed by
// createTokenVault (packages/token-vault/index.mjs):
//
//   async mutate(fn) — runs `fn` inside an EXCLUSIVE critical section that
//     serializes concurrent mutations. `fn` receives a MUTABLE view
//     { get, set, delete, entries } over the token-record map, persisted
//     ATOMICALLY when `fn` resolves. mutate() returns fn's value.
//   async read(fn)   — read-only access. `fn` receives { get, entries } over a
//     FRESH snapshot, NO lock. read() returns fn's value.
//
// The store knows NOTHING about crypto, reveal governance, retention, or audit
// — those stay core-owned in createTokenVault. The store ONLY supplies the
// exclusive mutate / lock-free read primitive over the token-record map.
//
// IMPORTANT — the VIEW is SYNCHRONOUS. The core token-vault calls the view
// methods WITHOUT await (e.g. `const existing = view.get(token)` then mutates
// it and `view.set(token, existing)`; `for (const [t, r] of view.entries())`;
// `view.entries().filter(...)`). The seam was designed the file-store way:
// load the WHOLE record map into memory inside the lock, hand a SYNC view over
// that in-memory snapshot, then persist the diff after `fn` resolves. So this
// adapter HGETALLs the hash up front, runs the sync view over a plain object,
// tracks dirty/deleted fields, and writes them back with hSet / hDel. (An async
// view returning Promises WOULD break core — `view.get` would be a truthy
// Promise and `view.entries()` is iterated directly. This is the contract.)
//
// Layout: a single Redis HASH `${keyPrefix}tokens` (field = token id, value =
// JSON record). `${keyPrefix}lock` is the mutate() critical-section lock key.
//
// The `redis` package is an OPTIONAL peer dependency: the client is injected,
// so this module never imports `redis` at the top level.

import { withRedisLock } from "./lock.mjs";

const REQUIRED_CLIENT_METHODS = ["set", "eval", "hGet", "hSet", "hDel", "hGetAll"];

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
  const lockKey = `${keyPrefix}lock`;

  return {
    // Exclusive across replicas via the Redis lock: load the whole token map,
    // run the sync mutation over it, then persist only the diff. The lock means
    // two replicas can't read the same snapshot and clobber each other's writes.
    async mutate(fn) {
      return withRedisLock(client, lockKey, async () => {
        const tokens = await loadTokens(client, hashKey);
        const dirty = new Set();
        const deleted = new Set();
        const result = await fn(mutableView(tokens, dirty, deleted));
        // Persist the diff. Sets first, then deletes (a token can only be in one
        // set — the view keeps them mutually exclusive). hSet per field keeps
        // the record JSON one value per token; hDel removes pruned/purged ones.
        for (const token of dirty) {
          await client.hSet(hashKey, token, JSON.stringify(tokens[token]));
        }
        for (const token of deleted) {
          await client.hDel(hashKey, token);
        }
        return result;
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
