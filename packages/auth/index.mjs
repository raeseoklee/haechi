// Built-in bearer authentication and the authProvider contract.
//
// Tokens are never stored in plaintext: the store keeps a keyed-HMAC hash
// (domain-separated, never a bare hash) plus PII-safe metadata. The plaintext
// token is shown once at creation. Identity objects are PII-safe by
// construction — subject/issuer are keyed HMACs, never raw values.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

const TOKEN_DOMAIN = "haechi:auth:token:v1";
const IDENTITY_DOMAIN = "haechi:identity:hash:v1";
const TOKEN_PREFIX = "hae_";
const DEFAULT_ALLOWED_LABEL_KEYS = ["team", "env", "tier", "role"];
const VALID_IDENTITY_TYPES = new Set(["user", "service", "agent"]);
const MAX_LABEL_VALUE_LENGTH = 64;

export async function readAuthStore(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return { version: parsed.version ?? 1, tokens: parsed.tokens ?? [] };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { version: 1, tokens: [] };
    }
    throw error;
  }
}

async function writeAuthStore(path, store) {
  await mkdir(dirname(path), { recursive: true });
  const tempPath = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
  await rename(tempPath, path);
}

export function validateLabels(labels, allowedLabelKeys = DEFAULT_ALLOWED_LABEL_KEYS) {
  for (const [key, value] of Object.entries(labels)) {
    if (!allowedLabelKeys.includes(key)) {
      throw new Error(`Label key not allowed: ${key} (allowed: ${allowedLabelKeys.join(", ") || "none"})`);
    }
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_LABEL_VALUE_LENGTH) {
      throw new Error(`Label value for ${key} must be a non-empty string up to ${MAX_LABEL_VALUE_LENGTH} chars`);
    }
  }
  return labels;
}

export async function addToken({ path, cryptoProvider, type, scopes = [], labels = {}, allowedLabelKeys = DEFAULT_ALLOWED_LABEL_KEYS }) {
  if (!VALID_IDENTITY_TYPES.has(type)) {
    throw new Error(`Invalid token type: ${type} (expected user | service | agent)`);
  }
  if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === "string" && scope.trim())) {
    throw new Error("scopes must be an array of non-empty strings");
  }
  validateLabels(labels, allowedLabelKeys);

  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  const tokenHash = await cryptoProvider.hmac({ data: token, domain: TOKEN_DOMAIN });
  const record = {
    id: `tok_auth_${randomUUID().slice(0, 8)}`,
    tokenHash,
    type,
    scopes,
    labels,
    createdAt: new Date().toISOString(),
    disabled: false
  };

  const store = await readAuthStore(path);
  store.tokens.push(record);
  await writeAuthStore(path, store);

  // The plaintext token is returned to the caller for one-time display only.
  return { token, record: publicRecord(record) };
}

export async function listTokens(path) {
  const store = await readAuthStore(path);
  return store.tokens.map(publicRecord);
}

export async function revokeToken({ path, id }) {
  const store = await readAuthStore(path);
  const record = store.tokens.find((entry) => entry.id === id);
  if (!record) {
    throw new Error(`Unknown token id: ${id}`);
  }
  const changed = !record.disabled;
  record.disabled = true;
  await writeAuthStore(path, store);
  return { id, revoked: changed };
}

function publicRecord(record) {
  // Never expose the token or its hash.
  return {
    id: record.id,
    type: record.type,
    scopes: record.scopes,
    labels: record.labels,
    createdAt: record.createdAt,
    disabled: Boolean(record.disabled)
  };
}

export async function buildIdentity(record, cryptoProvider) {
  return {
    id: record.id,
    type: record.type,
    subjectHash: await cryptoProvider.hmac({ data: record.id, domain: IDENTITY_DOMAIN }),
    issuerHash: await cryptoProvider.hmac({ data: "bearer-local", domain: IDENTITY_DOMAIN }),
    provider: "bearer",
    scopes: record.scopes ?? [],
    labels: record.labels ?? {}
  };
}

// PII-safe identity builder for EXTERNAL auth providers (e.g. the haechi-auth-jwt
// satellite). Core owns identity construction so the keyed-HMAC domain and the
// identity shape stay authoritative here — a satellite supplies raw claims and
// never sees or stores the IDENTITY_DOMAIN. subject/issuer become keyed HMACs;
// the raw values are never returned. Throws (fail-closed) on a missing
// cryptoProvider.hmac, an empty subject/issuer, an invalid type, bad scopes, or
// a disallowed label.
export async function buildExternalIdentity(
  { provider, subject, issuer, type = "user", scopes = [], labels = {}, allowedLabelKeys = DEFAULT_ALLOWED_LABEL_KEYS },
  cryptoProvider
) {
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("buildExternalIdentity requires a cryptoProvider with hmac()");
  }
  if (!provider || typeof provider !== "string") {
    throw new Error("identity requires a non-empty provider string");
  }
  if (!subject || typeof subject !== "string") {
    throw new Error("identity requires a non-empty subject");
  }
  if (!issuer || typeof issuer !== "string") {
    throw new Error("identity requires a non-empty issuer");
  }
  if (!VALID_IDENTITY_TYPES.has(type)) {
    throw new Error(`Invalid identity type: ${type} (expected user | service | agent)`);
  }
  if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === "string" && scope.trim())) {
    throw new Error("scopes must be an array of non-empty strings");
  }
  validateLabels(labels, allowedLabelKeys);

  const subjectHash = await cryptoProvider.hmac({ data: subject, domain: IDENTITY_DOMAIN });
  const issuerHash = await cryptoProvider.hmac({ data: issuer, domain: IDENTITY_DOMAIN });
  return {
    // Non-PII, stable per subject: derived from the keyed subject hash.
    id: `${provider}:${subjectHash.slice(0, 16)}`,
    type,
    subjectHash,
    issuerHash,
    provider,
    scopes,
    labels
  };
}

function bearerTokenFromRequest(request) {
  const header = request?.headers?.authorization ?? request?.headers?.Authorization;
  if (typeof header !== "string") {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

function constantTimeHashMatch(candidateHash, storedHash) {
  const a = Buffer.from(candidateHash, "utf8");
  const b = Buffer.from(storedHash, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

// authProvider contract: authenticate(request) -> identity | null. Fails closed
// (null/deny) for a missing/invalid/disabled token; throws are treated as deny
// by the caller.
export function createBearerAuthProvider({ path, cryptoProvider }) {
  if (!path) {
    throw new Error("Bearer auth provider requires a store path");
  }
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("Bearer auth provider requires a cryptoProvider with hmac()");
  }
  return {
    id: "haechi.auth.bearer",
    async authenticate(request) {
      const token = bearerTokenFromRequest(request);
      if (!token) {
        return null;
      }
      const candidateHash = await cryptoProvider.hmac({ data: token, domain: TOKEN_DOMAIN });
      const store = await readAuthStore(path);
      let matched = null;
      // Scan every record (no early return) so timing does not reveal which
      // token matched.
      for (const record of store.tokens) {
        if (!record.disabled && constantTimeHashMatch(candidateHash, record.tokenHash)) {
          matched = record;
        }
      }
      if (!matched) {
        return null;
      }
      return buildIdentity(matched, cryptoProvider);
    }
  };
}

export { DEFAULT_ALLOWED_LABEL_KEYS };
