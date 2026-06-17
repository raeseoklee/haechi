// In-memory reference stores for haechi-store-redis.
//
// createMemoryAuditStore() and createMemoryTokenStore() are Map/array-backed
// implementations of the SAME 1.5.0 audit + token-vault STORE contracts as the
// Redis adapters. They exist to exercise the contracts and as test doubles.
//
// NOT SHARED: these stores live in a single process's heap. They are NOT shared
// across processes or replicas — two proxy replicas each get their own array /
// Map, so the audit chain and the token vault are per-process. That is exactly
// the limitation the Redis shared store exists to remove; use these only as a
// single-process reference / for tests, never as the production shared store.

// --- audit ----------------------------------------------------------------

// createMemoryAuditStore() implements the audit store contract:
//   transaction(fn) -> EXCLUSIVE critical section; fn receives
//     { readLastIntegrity, persist }. The exclusivity is a single-process
//     promise-chain mutex (no Redis lock needed — one heap, one event loop):
//     each transaction awaits the previous one before reading the tail and
//     appending, so concurrent record() calls can't fork the chain.
//   ready() -> always { ok: true } (an in-process array is always writable).
//
// The store stays chain-math-agnostic: it only keeps the appended records (for
// inspection) and the last record's auditIntegrity (the tail-read).
export function createMemoryAuditStore() {
  const records = [];
  let last = null;
  // Promise-chain mutex: serializes transaction() bodies in a single process.
  let queue = Promise.resolve();

  return {
    async transaction(fn) {
      const run = queue.then(() => fn({
        readLastIntegrity: () => last,
        persist: (record) => {
          records.push(record);
          last = record.auditIntegrity;
        }
      }));
      // Keep the chain healthy even if a body rejects: swallow on the queue tail
      // so one failed transaction doesn't wedge later ones, but still surface
      // the error to THIS caller via `run`.
      queue = run.then(() => {}, () => {});
      return run;
    },

    async ready() {
      return { ok: true };
    },

    // Test-only: the appended records in order (lets a test read the chain back
    // and feed verifyAuditChain), mirroring readChain over the Redis list.
    _records() {
      return records.slice();
    }
  };
}

// --- token vault ----------------------------------------------------------

// createMemoryTokenStore() implements the token store contract:
//   mutate(fn) -> EXCLUSIVE critical section (promise-chain mutex); fn receives
//     a SYNC mutable view { get, set, delete, entries } over the Map-backed
//     record store, persisted when fn resolves (the view writes the live Map).
//   read(fn)   -> lock-free; fn receives { get, entries } over a fresh snapshot.
//
// The view is SYNCHRONOUS to match how core calls it (no await on view methods).
export function createMemoryTokenStore() {
  const tokens = new Map();
  let queue = Promise.resolve();

  function mutableView() {
    return {
      get: (token) => tokens.get(token),
      set: (token, record) => {
        tokens.set(token, record);
      },
      delete: (token) => {
        tokens.delete(token);
      },
      entries: () => [...tokens.entries()]
    };
  }

  function readView() {
    return {
      get: (token) => tokens.get(token),
      entries: () => [...tokens.entries()]
    };
  }

  return {
    async mutate(fn) {
      const run = queue.then(() => fn(mutableView()));
      queue = run.then(() => {}, () => {});
      return run;
    },

    async read(fn) {
      // A fresh snapshot view over the live Map (no lock), matching the file
      // and Redis read() paths.
      return fn(readView());
    }
  };
}
