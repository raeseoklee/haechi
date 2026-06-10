import { mkdir, open, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

export function createLocalTokenVault({ path, cryptoProvider, revealPolicy = "disabled", retentionDays = 30, auditSink = null }) {
  if (!path) {
    throw new Error("Local token vault requires path");
  }
  if (!cryptoProvider) {
    throw new Error("Local token vault requires cryptoProvider");
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
      mode: "n/a",
      enforced: true,
      blocked: decision.endsWith("_denied"),
      decision,
      reason,
      token,
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
      return enqueueMutation(async () => {
        const vault = await readVault(path);
        pruneExpiredTokens(vault);
        const token = `tok_${type}_${shortHash(`${plaintext}:${randomBytes(16).toString("hex")}`)}`;
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
      try {
        const vault = await readVault(path);
        const record = vault.tokens[token];
        if (!record) {
          throw new Error(`Unknown token: ${token}`);
        }
        if (record.expiresAt && Date.parse(record.expiresAt) < Date.now()) {
          throw new Error(`Token expired: ${token}`);
        }
        const aad = context ? { ...record.aad, context } : record.aad;
        const plaintext = await cryptoProvider.decrypt({ envelope: record.envelope, aad });
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
          reason: error.message
        });
        throw error;
      }
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
