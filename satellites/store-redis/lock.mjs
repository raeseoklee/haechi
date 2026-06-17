// Distributed-lock helper for haechi-store-redis.
//
// CONTENTION-REDUCTION OPTIMIZATION, NOT THE CORRECTNESS MECHANISM. This lock is
// a TTL lock (SET NX PX) with no fencing token renewal, so a holder whose `fn`
// runs longer than ttlMs can have its lock expire mid-operation and a second
// writer can enter concurrently. That is fine here: correctness NO LONGER
// depends on perfect mutual exclusion. The audit store appends with a SERVER-SIDE
// compare-and-append fenced on the head eventHash, and the token store applies
// its diff with a SERVER-SIDE compare-and-apply fenced on a version counter —
// each REJECTS a stale writer (and the caller retries onto the fresh state). So
// a forked hash chain or a lost token write is impossible EVEN IF the TTL lapses
// and two writers run at once. The lock just reduces how often those fences
// conflict-and-retry under contention; it is a throughput optimization layered
// over fences that are already safe on their own.
//
// `withRedisLock(client, lockKey, fn, opts)` implements the canonical
// single-instance Redlock-style lock:
//   - acquire: SET lockKey <token> NX PX ttlMs — set only if absent (NX), with
//     an expiry (PX) so a crashed holder cannot deadlock the key forever.
//   - spin:    retry every `retryMs` until acquired or `timeoutMs` elapses
//     (throw on timeout — fail closed, never run `fn` without the lock).
//   - release: a Lua compare-and-delete that deletes the key ONLY if its value
//     still equals OUR token, so we never delete a lock a later holder acquired
//     after our TTL lapsed.
//
// The `redis` package is an OPTIONAL peer: the client is injected, so this
// module imports nothing from `redis`. `node:crypto` is a builtin (this is
// satellite SOURCE, not a workflow script) — used for the unique lock token.

import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

// Compare-and-delete: only release the lock if we still own it (value match).
// Returns 1 if we deleted our own lock, 0 otherwise. Running this as one Lua
// script makes the get+del atomic so there is no check-then-delete race.
const RELEASE_SCRIPT =
  "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";

export async function withRedisLock(
  client,
  lockKey,
  fn,
  { ttlMs = 10000, retryMs = 20, timeoutMs = 5000 } = {}
) {
  if (!client || typeof client.set !== "function" || typeof client.eval !== "function") {
    throw new Error("withRedisLock requires a node-redis v4/v5 client with set() and eval() methods");
  }
  if (typeof lockKey !== "string" || lockKey.length === 0) {
    throw new Error("withRedisLock requires a non-empty string lockKey");
  }
  if (typeof fn !== "function") {
    throw new Error("withRedisLock requires a function fn");
  }
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new Error("withRedisLock ttlMs must be a positive integer");
  }
  if (!Number.isInteger(retryMs) || retryMs <= 0) {
    throw new Error("withRedisLock retryMs must be a positive integer");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 0) {
    throw new Error("withRedisLock timeoutMs must be a non-negative integer");
  }

  // A per-acquisition random token identifies THIS holder so release only ever
  // deletes our own lock (never a later holder's). 16 random bytes is ample.
  const token = randomBytes(16).toString("hex");

  // Acquire: spin on SET NX PX until we win the key or the timeout elapses.
  const deadline = Date.now() + timeoutMs;
  let acquired = false;
  for (;;) {
    // node-redis v4/v5: client.set(key, value, { NX: true, PX: ttlMs }) returns
    // "OK" when the key was set (we won) or null when NX failed (held).
    const ok = await client.set(lockKey, token, { NX: true, PX: ttlMs });
    if (ok) {
      acquired = true;
      break;
    }
    if (Date.now() >= deadline) {
      break;
    }
    await delay(retryMs);
  }
  if (!acquired) {
    // Fail closed: never run the critical section without the lock.
    throw new Error(`withRedisLock: timed out acquiring lock after ${timeoutMs}ms`);
  }

  try {
    return await fn();
  } finally {
    // Best-effort compare-and-delete. If our TTL already lapsed and another
    // holder owns the key, the value won't match and we delete nothing. A
    // release failure (e.g. transient disconnect) must not mask `fn`'s result
    // or error — the TTL guarantees the lock is eventually freed regardless.
    try {
      await client.eval(RELEASE_SCRIPT, { keys: [lockKey], arguments: [token] });
    } catch {
      // Swallow: the PX TTL is the backstop that frees a lock we couldn't
      // release. Never let a release hiccup propagate over fn's outcome.
    }
  }
}
