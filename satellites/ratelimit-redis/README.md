# `haechi-ratelimit-redis`

A shared-store (Redis-backed) `rateLimiter` for Haechi's `providers.rateLimiter` injection seam. It lives in the Haechi monorepo under `satellites/` and is published independently as `haechi-ratelimit-redis`. Core (`haechi`) stays zero-runtime-dependency, and so does this satellite by default: the Redis client SDK (`redis`) is an **optional peer dependency**, installed only by consumers who use the bundled Redis adapter.

It is the production consumer of the WS3 rate-limiter seam — the Reliability Hardening Track deliberately left "a production shared-store is a future satellite" as a core non-goal, adding only the injection seam to core. This satellite fills it.

## Why a shared store

Haechi's built-in rate limiter is **per-process, in-memory**: behind a load balancer with N replicas, each replica counts independently, so the effective per-identity budget multiplies by N. A shared store (Redis) gives every replica one authoritative counter, so the budget holds across the whole fleet.

## How it works

`createSharedRateLimiter({ store, windowMs = 60000 })` implements a **fixed-window** counter. For each `(key, current window)` it asks the store to atomically increment the counter and apply the window TTL on the first hit, then **allows iff the returned count is ≤ limit**. The store/client is **injected** (like the crypto-kms satellite's KMS client), so this package adds no runtime dependency to core.

The proxy `await`s `rateLimiter.allow(key, limit)`, so this async limiter gates correctly. It satisfies the same contract as the built-in default — `allow(key, limit) -> boolean | Promise<boolean>`.

## Install

```sh
npm install haechi-ratelimit-redis        # peer: haechi >=0.8.0 <2.0.0
```

The satellite reuses your installed `haechi` instance (declared as a peer dependency).

## The store contract

Inject any store implementing one small async method:

```js
{
  // Post-increment counter for the CURRENT fixed window for `key`, with the
  // window TTL applied on the first hit (so the window is fixed, not sliding).
  async hit(key: string, windowMs: number): Promise<number>
}
```

## Usage (Redis)

```js
import { createRuntime } from "haechi/runtime";
import { createClient } from "redis";              // optional peer
import { createSharedRateLimiter } from "haechi-ratelimit-redis";
import { createRedisStore } from "haechi-ratelimit-redis/redis";

const client = createClient({ url: process.env.REDIS_URL });
await client.connect();

const rateLimiter = createSharedRateLimiter({
  store: createRedisStore({ client })              // keyPrefix defaults to "haechi:rl:"
});
const runtime = createRuntime(config, { rateLimiter });
```

### The Redis adapter (`haechi-ratelimit-redis/redis`)

`createRedisStore({ client, keyPrefix = "haechi:rl:" })` adapts an **injected** node-redis v4/v5 client. `hit(key, windowMs)` runs a single atomic Lua `EVAL`:

```lua
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n
```

The `INCR`+`PEXPIRE` are one atomic script, and the TTL is set **only on the first hit** (`n == 1`), so the window is **fixed** — the whole window expires from its start rather than resetting on every request. The key is bucketed by the current window (`${keyPrefix}${key}:${bucket}`) so a new window always starts a fresh counter.

**`redis` is an optional peer dependency.** The client is injected, so this module never imports `redis` at the top level — install it only if you use the Redis path:

```sh
npm install haechi-ratelimit-redis redis
```

For tests, inject a fake client exposing `eval(script, { keys, arguments })` — no SDK or live Redis required.

## The memory store (`haechi-ratelimit-redis/memory`)

`createMemoryStore({ now = Date.now } = {})` is a Map-backed implementation of the same `hit(key, windowMs)` contract. It is a **single-process reference / test double**:

> **Not shared.** The memory store lives in one process's heap — it is **not** shared across processes or replicas (each replica gets its own Map, enforcing the budget per-process). It exists to exercise the limiter contract and for tests; never use it as the production shared store. For a real shared store, use the Redis adapter.

`now` is injectable so tests can drive window rollover deterministically without sleeping.

## Self-test

```js
import { createSharedRateLimiter } from "haechi-ratelimit-redis";
import { createMemoryStore } from "haechi-ratelimit-redis/memory";

const limiter = createSharedRateLimiter({ store: createMemoryStore() });
await limiter.allow("alice", 3); // true, true, true, then false
```

See [`configuration.md` → Rate limiter injection](https://github.com/raeseoklee/haechi/blob/main/docs/current/configuration.md) and [shared-responsibility.md §4](https://github.com/raeseoklee/haechi/blob/main/docs/current/shared-responsibility.md).
