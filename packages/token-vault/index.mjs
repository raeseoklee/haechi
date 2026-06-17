import { mkdir, open, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const DETERMINISTIC_DOMAIN = "haechi:token-vault:deterministic:v1";
const AUDIT_ID_DOMAIN = "haechi:token-vault:audit-id:v1";

// Opaque vault token ids are `tok_<type>_<hexhash>` (random: 16 hex via
// shortHash; deterministic: 32 hex from hmac). Anything that does not match
// this shape is treated as a misused raw value and never written verbatim.
const VAULT_TOKEN_SHAPE = /^tok_[a-z0-9_]+_[a-f0-9]{16,}$/;

// A token STORE abstracts the token-record map + the exclusive mutation section
// so the SAME core-owned tokenization can sit on a whole-file vault today and a
// shared store (e.g. Redis) in a future satellite — the current whole-file
// rewrite is not safe with multiple writers, so a shared store needs its own
// exclusive critical section. The contract is:
//
//   async mutate(fn) — runs `fn` inside an EXCLUSIVE critical section that
//     serializes concurrent mutations. `fn` receives a MUTABLE view
//     { get(token), set(token, record), delete(token), entries() } over the
//     token-record map, and the store persists the changes ATOMICALLY when `fn`
//     resolves. mutate() returns `fn`'s return value. This is the
//     multi-writer-safety primitive.
//   async read(fn) — read-only access. `fn` receives { get(token), entries() }
//     over a FRESH snapshot (no lock, matching how reveal/detokenize/export read
//     today). read() returns `fn`'s value.
//
// The store deliberately knows NOTHING about crypto, reveal governance,
// retention, or audit — those stay core-owned in createTokenVault so a non-core
// store can never fork or weaken them. Prune-on-mutation is also core-owned: the
// core deletes expired entries from the view before each operation, so the file
// store persists the pruning on the trailing writeVault (no store cooperation
// needed) and the in-memory store sees the same deletions.

// createFileTokenStore implements the store contract over the CURRENT vault
// mechanism: a `${path}.lock` exclusive section wrapping mkdir + readVault +
// writeVault, with the view operating on vault.tokens in memory. The on-disk
// vault JSON format (version/createdAt/tokens, 2-space, trailing newline,
// temp+rename, 0600) stays byte-identical to the pre-seam vault.
export function createFileTokenStore({ path }) {
  if (!path) {
    throw new Error("file token store requires path");
  }

  return {
    async mutate(fn) {
      await mkdir(dirname(path), { recursive: true });
      return withFileLock(`${path}.lock`, async () => {
        const vault = await readVault(path);
        const result = await fn(mutableView(vault.tokens));
        await writeVault(path, vault);
        return result;
      });
    },

    async read(fn) {
      const vault = await readVault(path);
      return fn(readView(vault.tokens));
    }
  };
}

// A mutable view over a token-record map (the file store backs this with
// vault.tokens; the in-memory store with a Map). get/set/delete operate on the
// live map so the store persists whatever the mutation left behind.
function mutableView(tokens) {
  return {
    get: (token) => tokens[token],
    set: (token, record) => {
      tokens[token] = record;
    },
    delete: (token) => {
      delete tokens[token];
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

// createTokenVault holds ALL the SECURITY-CRITICAL, core-owned logic:
// mutationQueue serialization (cross-call), deterministic-vs-random token id
// derivation, encrypt/decrypt, reveal governance (revealPolicy gate +
// reasonCodes + safeAuditToken + recordVaultEvent), retention
// (expiresAt/prune-on-mutation), detokenize, purge/purgeExpired,
// exportMetadata, and capabilities. The store only supplies the exclusive
// mutate/read primitive over the token-record map.
export function createTokenVault({
  store,
  cryptoProvider,
  revealPolicy = "disabled",
  retentionDays = 30,
  auditSink = null,
  deterministic = false,
  deterministicTypes = null
}) {
  if (!store || typeof store.mutate !== "function" || typeof store.read !== "function") {
    throw new Error("token vault requires a store with mutate(fn) and read(fn) methods");
  }
  if (!cryptoProvider) {
    throw new Error("Local token vault requires cryptoProvider");
  }
  if (deterministic && typeof cryptoProvider.hmac !== "function") {
    throw new Error("Deterministic tokenization requires a cryptoProvider with hmac()");
  }

  function isDeterministicType(type) {
    if (!deterministic) {
      return false;
    }
    return !deterministicTypes || deterministicTypes.includes(type);
  }

  // The mutationQueue (cross-call serialization) stays in core, wrapping
  // store.mutate. Together with the store's own exclusive critical section this
  // keeps concurrent tokenize/purge from corrupting or losing tokens.
  let mutationQueue = Promise.resolve();
  async function enqueueMutation(operation) {
    const mutation = mutationQueue.then(() => store.mutate(operation));
    mutationQueue = mutation.catch(() => {});
    return mutation;
  }

  // Prune expired entries from the mutable view before each operation. For the
  // file store this deletes from the in-memory map so they are gone after the
  // trailing writeVault; for any store the deletions are persisted by mutate().
  // Returns the number pruned (purgeExpired counts on this).
  function pruneExpiredView(view, now = Date.now()) {
    let purged = 0;
    for (const [token, record] of view.entries()) {
      if (record.expiresAt && Date.parse(record.expiresAt) < now) {
        view.delete(token);
        purged += 1;
      }
    }
    return purged;
  }

  // The audit `token` field must never carry a raw secret. A legitimate token
  // id is a non-sensitive opaque `tok_<type>_<hexhash>` — recorded verbatim for
  // correlation. A caller who misuses the API and passes a raw value where a
  // token id is expected would otherwise leak that value into the hash-chained
  // log (sanitizeAudit strips by key name only). For non-matching inputs we
  // record a keyed-HMAC under a dedicated domain, or a fixed redaction marker
  // if no hmac is available — never the raw value.
  async function safeAuditToken(token) {
    if (token == null) {
      return null;
    }
    if (typeof token === "string" && VAULT_TOKEN_SHAPE.test(token)) {
      return token;
    }
    if (typeof cryptoProvider.hmac === "function") {
      const digest = await cryptoProvider.hmac({
        data: typeof token === "string" ? token : String(token),
        domain: AUDIT_ID_DOMAIN
      });
      return `nontoken_${digest.slice(0, 32)}`;
    }
    return "[REDACTED:non-token]";
  }

  // Reveal/purge governance events must be auditable. Events carry token ids
  // and decision metadata only — never plaintext values.
  async function recordVaultEvent({ operation, decision, token = null, tokenType = null, reason = null, count = null }) {
    if (typeof auditSink?.record !== "function") {
      return;
    }
    await auditSink.record({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      protocol: "token-vault",
      operation,
      identity: null,
      mode: "n/a",
      enforced: true,
      blocked: decision.endsWith("_denied"),
      decision,
      reason,
      token: await safeAuditToken(token),
      tokenType,
      count,
      revealPolicy,
      summary: {
        detectionCount: 0,
        byType: {},
        byAction: {
          [decision]: 1
        }
      }
    });
  }

  return {
    id: "haechi.token-vault.local",
    version: "0.2.0",
    capabilities: {
      readsPlaintext: true,
      storesPayload: true,
      storesPlaintext: false,
      networkEgress: false,
      revealPolicy
    },
    async tokenize({ plaintext, type, context = {}, metadata = {} }) {
      // Deterministic tokens are derived outside the mutation lock (HMAC reads
      // only the key file); the same (type, value) always maps to one token.
      const token = isDeterministicType(type)
        ? `tok_${type}_${(await cryptoProvider.hmac({
          data: `${type}:${plaintext}`,
          domain: DETERMINISTIC_DOMAIN
        })).slice(0, 32)}`
        : `tok_${type}_${shortHash(`${plaintext}:${randomBytes(16).toString("hex")}`)}`;

      return enqueueMutation(async (view) => {
        pruneExpiredView(view);

        const existing = view.get(token);
        if (existing) {
          existing.expiresAt = addDays(new Date(), retentionDays).toISOString();
          view.set(token, existing);
          return { token, type, reused: true };
        }

        const createdAt = new Date();
        const aad = {
          purpose: "token-vault",
          token,
          type,
          context
        };
        view.set(token, {
          type,
          createdAt: createdAt.toISOString(),
          expiresAt: addDays(createdAt, retentionDays).toISOString(),
          metadata: sanitizeMetadata(metadata),
          envelope: await cryptoProvider.encrypt({ plaintext, aad }),
          aad
        });
        return { token, type };
      });
    },
    async reveal({ token, context = null }) {
      if (revealPolicy === "disabled") {
        await recordVaultEvent({
          operation: "token-vault:reveal",
          decision: "reveal_denied",
          token,
          reason: "reveal_policy_disabled"
        });
        throw new Error("Token reveal is disabled by tokenVault.revealPolicy");
      }
      // Failure branches carry a stable reasonCode (never error.message / raw
      // token); the message itself never interpolates the token argument.
      let reasonCode = "reveal_error";
      try {
        const record = await store.read((view) => view.get(token));
        if (!record) {
          reasonCode = "unknown_token";
          throw new Error("Unknown token");
        }
        if (record.expiresAt && Date.parse(record.expiresAt) < Date.now()) {
          reasonCode = "token_expired";
          throw new Error("Token expired");
        }
        const aad = context ? { ...record.aad, context } : record.aad;
        let plaintext;
        try {
          plaintext = await cryptoProvider.decrypt({ envelope: record.envelope, aad });
        } catch {
          reasonCode = "decrypt_failed";
          throw new Error("Token decrypt failed");
        }
        await recordVaultEvent({
          operation: "token-vault:reveal",
          decision: "reveal_allowed",
          token,
          tokenType: record.type
        });
        return {
          token,
          type: record.type,
          plaintext
        };
      } catch (error) {
        await recordVaultEvent({
          operation: "token-vault:reveal",
          decision: "reveal_failed",
          token,
          reason: reasonCode
        });
        throw error;
      }
    },
    // Request-scoped response restoration. Deliberately NOT gated by
    // revealPolicy: that governs manual/CLI reveal, while detokenize is only
    // reachable through the proxy's explicit detokenizeResponses opt-in and is
    // limited to the caller-supplied token set. Audited by count, no plaintext.
    async detokenize({ tokens }) {
      const records = await store.read((view) => {
        const found = new Map();
        for (const token of tokens) {
          found.set(token, view.get(token));
        }
        return found;
      });

      const values = new Map();
      let skipped = 0;

      for (const token of tokens) {
        const record = records.get(token);
        if (!record || (record.expiresAt && Date.parse(record.expiresAt) < Date.now())) {
          skipped += 1;
          continue;
        }
        try {
          values.set(token, await cryptoProvider.decrypt({ envelope: record.envelope, aad: record.aad }));
        } catch {
          skipped += 1;
        }
      }

      await recordVaultEvent({
        operation: "token-vault:detokenize",
        decision: "detokenize",
        count: values.size,
        reason: skipped > 0 ? `${skipped} tokens not restored` : null
      });

      return values;
    },
    async purge({ token }) {
      const existed = await enqueueMutation(async (view) => {
        pruneExpiredView(view);
        const present = Boolean(view.get(token));
        view.delete(token);
        return present;
      });
      await recordVaultEvent({
        operation: "token-vault:purge",
        decision: "purge",
        token
      });
      return { token, purged: existed, purgedAt: new Date().toISOString() };
    },
    async purgeExpired() {
      const purged = await enqueueMutation(async (view) => pruneExpiredView(view));
      await recordVaultEvent({
        operation: "token-vault:purge-expired",
        decision: "purge_expired",
        count: purged
      });
      return { purged, purgedAt: new Date().toISOString() };
    },
    async exportMetadata({ type = null } = {}) {
      return store.read((view) => view.entries()
        .filter(([, record]) => !type || record.type === type)
        .map(([token, record]) => ({
          token,
          type: record.type,
          createdAt: record.createdAt,
          expiresAt: record.expiresAt,
          metadata: sanitizeMetadata(record.metadata ?? {})
        })));
    }
  };
}

// Thin back-compat wrapper: the original file-backed vault is now
// createTokenVault over createFileTokenStore. Its returned shape (id, version,
// capabilities, tokenize, reveal, detokenize, purge, purgeExpired,
// exportMetadata) and on-disk bytes are unchanged, so existing call sites
// (runtime.mjs injection, tests) keep working untouched.
export function createLocalTokenVault({
  path,
  cryptoProvider,
  revealPolicy = "disabled",
  retentionDays = 30,
  auditSink = null,
  deterministic = false,
  deterministicTypes = null
}) {
  if (!path) {
    throw new Error("Local token vault requires path");
  }
  return createTokenVault({
    store: createFileTokenStore({ path }),
    cryptoProvider,
    revealPolicy,
    retentionDays,
    auditSink,
    deterministic,
    deterministicTypes
  });
}

export async function readVault(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
    return {
      version: 1,
      createdAt: new Date().toISOString(),
      tokens: {}
    };
  }
}

async function writeVault(path, vault) {
  await mkdir(dirname(path), { recursive: true });
  const tempPath = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(vault, null, 2)}\n`, { mode: 0o600 });
  await rename(tempPath, path);
}

function sanitizeMetadata(metadata) {
  return Object.fromEntries(Object.entries(metadata).filter(([key]) => !["value", "plaintext", "payload"].includes(key)));
}

function shortHash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function addDays(date, days) {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

async function withFileLock(lockPath, operation) {
  const handle = await acquireLock(lockPath);
  try {
    return await operation();
  } finally {
    await handle.close();
    await unlink(lockPath).catch((error) => {
      if (error.code !== "ENOENT") {
        throw error;
      }
    });
  }
}

const STALE_LOCK_MS = 30000;

async function acquireLock(lockPath) {
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      return await open(lockPath, "wx", 0o600);
    } catch (error) {
      if (error.code !== "EEXIST") {
        throw error;
      }
      if (await isStaleLock(lockPath)) {
        await unlink(lockPath).catch(() => {});
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`Timed out acquiring token vault lock: ${lockPath}`);
      }
      await delay(10);
    }
  }
}

async function isStaleLock(lockPath) {
  try {
    const info = await stat(lockPath);
    return Date.now() - info.mtimeMs > STALE_LOCK_MS;
  } catch {
    return false;
  }
}
