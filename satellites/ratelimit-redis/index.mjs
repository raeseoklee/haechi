// Shared-store rateLimiter for Haechi (providers.rateLimiter).
//
// Published as haechi-ratelimit-redis. It is the production consumer of the WS3
// `providers.rateLimiter` injection seam (the Reliability Hardening Track left
// "a production shared-store is a future satellite" as a core non-goal). The
// store/client is INJECTED (like the crypto-kms satellite's KMS client), so this
// package adds no runtime dependency to core — the optional `redis` peer is
// installed only by consumers using the bundled Redis adapter.
//
// Inject it:
//   import { createRuntime } from "haechi/runtime";
//   import { createSharedRateLimiter } from "haechi-ratelimit-redis";
//   import { createRedisStore } from "haechi-ratelimit-redis/redis";
//   const rateLimiter = createSharedRateLimiter({ store: createRedisStore({ client }) });
//   const runtime = createRuntime(config, { rateLimiter });
//
// The proxy `await`s rateLimiter.allow(key, limit), so an async limiter gates
// correctly (the WS3 core change). The limiter satisfies the same contract as
// the built-in default: allow(key, limit) -> boolean | Promise<boolean>.

// The injected store must implement a single small async method:
//   async hit(key: string, windowMs: number) -> Promise<number>
// returning the post-increment counter for the CURRENT fixed window, with the
// window TTL applied on the first hit (so the window is fixed, not sliding).
//
// createSharedRateLimiter({ store, windowMs = 60000 }) implements a FIXED-WINDOW
// counter: for each (key, current window) it asks the store to atomically
// increment the counter and set the window TTL on first hit, then allows iff the
// returned count is <= limit.
export function createSharedRateLimiter({ store, windowMs = 60000 } = {}) {
  if (!store || typeof store.hit !== "function") {
    throw new Error("createSharedRateLimiter requires a store with an async hit(key, windowMs) method");
  }
  if (!Number.isInteger(windowMs) || windowMs <= 0) {
    throw new Error("createSharedRateLimiter requires a positive integer windowMs");
  }

  return {
    // allow(key, limit) -> Promise<boolean>. Fail-closed on bad inputs: a
    // missing/non-positive limit or a non-string key denies rather than letting
    // a malformed request bypass the budget.
    async allow(key, limit) {
      if (typeof key !== "string" || key.length === 0) {
        return false;
      }
      if (!Number.isInteger(limit) || limit <= 0) {
        return false;
      }
      const count = await store.hit(key, windowMs);
      if (!Number.isFinite(count) || count <= 0) {
        // A store that returns a nonsensical count must not silently fail open.
        return false;
      }
      return count <= limit;
    }
  };
}
