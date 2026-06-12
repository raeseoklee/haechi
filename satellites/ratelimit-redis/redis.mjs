// Redis store adapter for haechi-ratelimit-redis.
//
// createRedisStore({ client, keyPrefix = "haechi:rl:" }) adapts an INJECTED
// node-redis v4/v5 client into the small store contract consumed by
// createSharedRateLimiter: `async hit(key, windowMs) -> Promise<number>`.
//
// The `redis` package is an OPTIONAL peer dependency: the client is injected, so
// this module never imports `redis` at the top level — it works whether or not
// the SDK is installed, and tests inject a fake client exposing `eval`.

// A single atomic Lua script: INCR the counter, and PEXPIRE the window TTL ONLY
// on the first hit (n == 1). Setting the TTL once per window — not on every hit —
// is what makes the window FIXED rather than a rolling reset. INCR creates the
// key at 0→1 on first hit, so the TTL bounds the whole window from its start.
const FIXED_WINDOW_SCRIPT =
  "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n";

// Bucket the key by the current fixed window so a new window starts a fresh
// counter even if a prior key's TTL has not yet been reaped by Redis. The bucket
// index is floor(now / windowMs); the Redis key is `${prefix}${key}:${bucket}`.
function windowKey(keyPrefix, key, windowMs, now) {
  const bucket = Math.floor(now / windowMs);
  return `${keyPrefix}${key}:${bucket}`;
}

export function createRedisStore({ client, keyPrefix = "haechi:rl:" } = {}) {
  if (!client || typeof client.eval !== "function") {
    throw new Error("createRedisStore requires a node-redis v4/v5 client with an eval() method");
  }
  if (typeof keyPrefix !== "string") {
    throw new Error("createRedisStore keyPrefix must be a string");
  }

  return {
    async hit(key, windowMs) {
      const redisKey = windowKey(keyPrefix, key, windowMs, Date.now());
      // node-redis v4/v5 EVAL signature: client.eval(script, { keys, arguments }).
      // ARGV[1] is the window TTL in milliseconds (string, as Redis args are).
      const result = await client.eval(FIXED_WINDOW_SCRIPT, {
        keys: [redisKey],
        arguments: [String(windowMs)]
      });
      // EVAL returns the script's integer reply; node-redis surfaces it as a
      // number (or a numeric string from some clients) — coerce defensively.
      return Number(result);
    }
  };
}
