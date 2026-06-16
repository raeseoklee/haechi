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

  let mutationQueue = Promise.resolve();
  async function enqueueMutation(operation) {
    const mutation = mutationQueue.then(async () => {
      await mkdir(dirname(path), { recursive: true });
      return withFileLock(`${path}.lock`, operation);
    });
    mutationQueue = mutation.catch(() => {});
    return mutation;
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

      return enqueueMutation(async () => {
        const vault = await readVault(path);
        pruneExpiredTokens(vault);

        const existing = vault.tokens[token];
        if (existing) {
          existing.expiresAt = addDays(new Date(), retentionDays).toISOString();
          await writeVault(path, vault);
          return { token, type, reused: true };
        }

        const createdAt = new Date();
        const aad = {
          purpose: "token-vault",
          token,
          type,
          context
        };
        vault.tokens[token] = {
          type,
          createdAt: createdAt.toISOString(),
          expiresAt: addDays(createdAt, retentionDays).toISOString(),
          metadata: sanitizeMetadata(metadata),
          envelope: await cryptoProvider.encrypt({ plaintext, aad }),
          aad
        };
        await writeVault(path, vault);
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
        const vault = await readVault(path);
        const record = vault.tokens[token];
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
      const vault = await readVault(path);
      const values = new Map();
      let skipped = 0;

      for (const token of tokens) {
        const record = vault.tokens[token];
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
      return enqueueMutation(async () => {
        const vault = await readVault(path);
        pruneExpiredTokens(vault);
        const existed = Boolean(vault.tokens[token]);
        delete vault.tokens[token];
        await writeVault(path, vault);
        await recordVaultEvent({
          operation: "token-vault:purge",
          decision: "purge",
          token
        });
        return { token, purged: existed, purgedAt: new Date().toISOString() };
      });
    },
    async purgeExpired() {
      return enqueueMutation(async () => {
        const vault = await readVault(path);
        const purged = pruneExpiredTokens(vault);
        await writeVault(path, vault);
        await recordVaultEvent({
          operation: "token-vault:purge-expired",
          decision: "purge_expired",
          count: purged
        });
        return { purged, purgedAt: new Date().toISOString() };
      });
    },
    async exportMetadata({ type = null } = {}) {
      const vault = await readVault(path);
      return Object.entries(vault.tokens)
        .filter(([, record]) => !type || record.type === type)
        .map(([token, record]) => ({
          token,
          type: record.type,
          createdAt: record.createdAt,
          expiresAt: record.expiresAt,
          metadata: sanitizeMetadata(record.metadata ?? {})
        }));
    }
  };
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

function pruneExpiredTokens(vault, now = Date.now()) {
  let purged = 0;
  for (const [token, record] of Object.entries(vault.tokens)) {
    if (record.expiresAt && Date.parse(record.expiresAt) < now) {
      delete vault.tokens[token];
      purged += 1;
    }
  }
  return purged;
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
