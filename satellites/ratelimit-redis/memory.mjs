// In-memory reference store for haechi-ratelimit-redis.
//
// createMemoryStore({ now = Date.now } = {}) is a Map-backed implementation of
// the same `async hit(key, windowMs) -> Promise<number>` contract as the Redis
// adapter. It exists to exercise the limiter contract and as a test double.
//
// NOT SHARED: this store lives in a single process's heap. It is NOT shared
// across processes or replicas — two proxy replicas each get their own Map, so
// the per-identity budget is enforced per-process, exactly the limitation a
// shared-store (Redis) limiter exists to remove. Use it only as a single-process
// reference / for testing the limiter, never as the production shared store.
//
// `now` is injectable so tests can drive window rollover deterministically
// without sleeping; it defaults to Date.now.
export function createMemoryStore({ now = Date.now } = {}) {
  if (typeof now !== "function") {
    throw new Error("createMemoryStore now must be a function returning epoch ms");
  }
  // Map<key, { bucket: number, count: number }> — one live slot per key, replaced
  // when the window bucket advances (a fixed window, mirroring the Redis bucket).
  const windows = new Map();

  return {
    async hit(key, windowMs) {
      const bucket = Math.floor(now() / windowMs);
      const slot = windows.get(key);
      if (!slot || slot.bucket !== bucket) {
        // First hit of a new fixed window: reset the counter to 1 (matching
        // Redis INCR on a fresh/expired key returning 1).
        windows.set(key, { bucket, count: 1 });
        return 1;
      }
      slot.count += 1;
      return slot.count;
    },
    // Test-only introspection of the live key count. Innocuous: a bare integer,
    // never a key/identity value.
    _size() {
      return windows.size;
    }
  };
}
