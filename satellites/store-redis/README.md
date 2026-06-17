# `haechi-store-redis`

Shared-store (Redis-backed) **audit** and **token-vault** adapters for Haechi's 1.5.0 store-injection seams. It lives in the Haechi monorepo under `satellites/` and is published independently as `haechi-store-redis`. Core (`haechi`) stays zero-runtime-dependency, and so does this satellite by default: the Redis client SDK (`redis`) is an **optional peer dependency**, installed only by consumers who use the bundled Redis adapters.

It is the production consumer of the 1.5.0 audit + token-vault **store seams** — core added only the injection points (`createAuditSink({ store })` and `createTokenVault({ store, ... })`), deliberately leaving a production shared store as a future satellite. This satellite fills it.

## Why a shared store

Haechi's audit log and token vault are **file-backed and single-writer** by default:

- The **audit log** is a sha256 **hash chain**: each record links to the previous one's hash. Behind a load balancer with N replicas, each replica writing its own file produces N independent chains — there is no single tamper-evident history of the fleet.
- The **token vault** is a whole-file vault rewritten on every mutation. That is **not safe with multiple writers**: concurrent replicas racing the read-modify-write lose tokens.

A shared store (Redis) gives every replica **one authoritative chain** and **one vault**, serialized by a distributed lock so the chain never forks and no token is lost. The crypto, chain math, reveal governance, retention, and audit stay **core-owned** — the store only supplies the exclusive read-previous+persist (audit) and read-all+mutate+persist (token) primitives.

## Install

```sh
npm install haechi haechi-store-redis        # peer: haechi >=1.5.0 <2.0.0
```

**`haechi` (the core) must be installed** — it is a peer dependency, not bundled. The store seams are new in **1.5.0**, so the peer floor is `>=1.5.0 <2.0.0`. The satellite reuses your installed `haechi` instance.

## The store contracts

### Audit store (`haechi-store-redis/audit`)

```js
{
  // EXCLUSIVE critical section serializing concurrent appends. `fn` receives
  // { readLastIntegrity, persist }: readLastIntegrity() -> the last record's
  // auditIntegrity object (or null); persist(record) durably appends the built
  // record. Returns fn's value.
  async transaction(fn): Promise<any>,
  // OPTIONAL readiness probe: { ok: true } | { ok: false, reason }.
  async ready(): Promise<{ ok: boolean, reason?: string }>
}
```

The store knows **nothing** about the chain math, sanitization, or anchoring — `createAuditSink` owns those. The store only makes the read-previous+persist atomic across replicas (via a Redis lock) so the shared chain never forks.

### Token store (`haechi-store-redis/token-vault`)

```js
{
  // EXCLUSIVE critical section. `fn` receives a MUTABLE view
  // { get(token), set(token, record), delete(token), entries() } over the
  // token-record map, persisted ATOMICALLY when fn resolves. Returns fn's value.
  async mutate(fn): Promise<any>,
  // Lock-free read-only access. `fn` receives { get(token), entries() } over a
  // FRESH snapshot. Returns fn's value.
  async read(fn): Promise<any>
}
```

> **The view is synchronous.** Core calls the view methods without `await` (it loads the whole map inside the lock and operates on the in-memory snapshot, then the store persists the diff — exactly like the built-in file store). The Redis adapter therefore `HGETALL`s the hash up front, hands a sync view over the snapshot, and writes the diff back with `hSet` / `hDel`.

The store knows **nothing** about crypto, reveal governance, retention, or audit — `createTokenVault` owns those.

## Usage (Redis)

```js
import { createClient } from "redis";                        // optional peer
import { createAuditSink } from "haechi/audit";
import { createTokenVault } from "haechi/token-vault";
import { initLocalKeyFile, createLocalCryptoProvider } from "haechi/crypto";
import { createRedisAuditStore } from "haechi-store-redis/audit";
import { createRedisTokenStore } from "haechi-store-redis/token-vault";

const client = createClient({ url: process.env.REDIS_URL });
await client.connect();

// Shared, tamper-evident audit chain across replicas.
const auditSink = createAuditSink({
  store: createRedisAuditStore({ client })                   // keyPrefix defaults to "haechi:audit:"
});

// Shared, multi-writer-safe token vault across replicas.
await initLocalKeyFile("./.haechi/dev.keys.json");
const cryptoProvider = createLocalCryptoProvider({ keyFile: "./.haechi/dev.keys.json" });
const tokenVault = createTokenVault({
  store: createRedisTokenStore({ client }),                  // keyPrefix defaults to "haechi:tv:"
  cryptoProvider,
  revealPolicy: "local-dev",
  retentionDays: 30
});
```

Wire `auditSink` / `tokenVault` into `createRuntime(config, { auditSink, tokenVault })` (or use them directly).

### The Redis adapters

`createRedisAuditStore({ client, keyPrefix = "haechi:audit:" })` stores the chain as a Redis **LIST** (`${keyPrefix}chain`, one JSON record per element) plus a **head** key (`${keyPrefix}head`, the last record's `auditIntegrity` for the cheap tail-read). `transaction()` wraps the read-previous+persist in a distributed lock (`${keyPrefix}lock`). It also exports a helper:

```js
import { readChain } from "haechi-store-redis/audit";
const records = await readChain(client);   // the full ordered chain, parsed
```

`createRedisTokenStore({ client, keyPrefix = "haechi:tv:" })` stores the vault as a single Redis **HASH** (`${keyPrefix}tokens`, field = token id, value = JSON record). `mutate()` loads the whole hash inside the lock (`${keyPrefix}lock`), runs the sync view, and persists the diff; `read()` is lock-free.

**`redis` is an optional peer dependency.** The client is injected, so these modules never import `redis` at the top level — install it only if you use the Redis path:

```sh
npm install haechi-store-redis redis
```

The distributed lock (`haechi-store-redis` `withRedisLock`) acquires via `SET key <token> NX PX ttlMs`, spins until acquired or it times out (fail-closed), and releases via a Lua compare-and-delete so it never deletes another holder's lock.

For tests, inject a fake client exposing `set` / `get` / `del` / `eval` / `rPush` / `lRange` / `hSet` / `hGet` / `hDel` / `hGetAll` / `ping` — no SDK or live Redis required.

## The memory stores (`haechi-store-redis/memory`)

`createMemoryAuditStore()` and `createMemoryTokenStore()` are array/Map-backed implementations of the same contracts, with the exclusive section provided by a single-process promise-chain mutex (no Redis lock needed in one heap). They are **single-process references / test doubles**:

> **Not shared.** The memory stores live in one process's heap — they are **not** shared across processes or replicas (each replica gets its own array / Map, so the audit chain and vault are per-process). They exist to exercise the contracts and for tests; never use them as the production shared store. For a real shared store, use the Redis adapters.

## Self-test

```js
import { createAuditSink } from "haechi/audit";
import { createMemoryAuditStore } from "haechi-store-redis/memory";

const store = createMemoryAuditStore();
const sink = createAuditSink({ store });
await sink.record({ event: "demo" });
// store._records() holds the chained record(s).
```

## Validating against a real Redis

The unit tests use a fake client. To validate the bundled Redis adapters against a **real** Redis — and prove that two store instances (two replicas) sharing one Redis keep a single non-forked audit chain and a single vault — run the optional integration test, which is skipped unless `HAECHI_REDIS_URL` is set:

```bash
npm i -D redis   # once, in the repo root (redis is an optional peer)
HAECHI_REDIS_URL=redis://127.0.0.1:6379 \
  node --test satellites/store-redis/store-redis.integration.test.mjs
```

It asserts cross-replica shared enforcement: interleaved `record()` calls across two sinks build ONE chain that `verifyAuditChain` accepts (strictly increasing, non-forked sequences), and a token tokenized on replica A reveals on replica B — all against the live server.

See [`configuration.md`](https://github.com/raeseoklee/haechi/blob/main/docs/current/configuration.md) and [shared-responsibility.md](https://github.com/raeseoklee/haechi/blob/main/docs/current/shared-responsibility.md).
