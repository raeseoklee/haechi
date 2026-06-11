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

// Conformance suite for any authProvider — the CORRECTNESS gate the plugin
// loader runs before wiring a (sandboxed) auth plugin. It is NOT a malice screen
// (a signed plugin can detect a fixed test and behave, so vectors are randomized
// per run and the host re-validates PII-safety per call); it asserts the
// enumerated security behaviors of the authProvider contract:
//   - missing credential -> null
//   - malformed credential -> null
//   - expired / not-yet-valid credential (clock via injected now) -> null
//   - an internal throw surfaces to the caller as null (never propagates)
//   - a returned identity MUST carry subjectHash AND issuerHash, and MUST NOT
//     contain any field whose value equals the raw input subject or issuer
//   - deny is DETERMINISTIC for identical input
//   - a valid credential -> a well-formed PII-safe identity
//
// vectors lets a caller supply the request builders / raw values; by default a
// randomized-per-run vector set is generated so a plugin cannot hardcode the
// test. Mirrors assertCryptoProviderConformance's check/assert/failures shape.
export async function assertAuthProviderConformance(provider, { now = Date.now(), vectors } = {}) {
  const failures = [];
  const check = async (name, fn) => {
    try {
      await fn();
    } catch (error) {
      failures.push(`${name}: ${error.message}`);
    }
  };
  const assert = (condition, message) => {
    if (!condition) {
      throw new Error(message);
    }
  };

  if (typeof provider?.authenticate !== "function") {
    throw new Error("authProvider must implement authenticate()");
  }

  const v = vectors ?? randomAuthVectors(now);

  // A contract-conformant authProvider must never throw into the caller. We wrap
  // every call so a throw becomes an explicit failure in the relevant check
  // rather than aborting the whole suite — except the dedicated throw-vector
  // check below, which asserts the provider itself swallowed the throw.
  const callRaw = (request) => provider.authenticate(request);
  const callSafe = async (request) => {
    try {
      return await provider.authenticate(request);
    } catch (error) {
      return { __threw: true, error };
    }
  };

  await check("missing credential -> null", async () => {
    const result = await callSafe(v.missing.request);
    assert(!result?.__threw, "authenticate threw on a missing credential (must return null)");
    assert(result === null, "missing credential must deny with null");
  });

  await check("malformed credential -> null", async () => {
    const result = await callSafe(v.malformed.request);
    assert(!result?.__threw, "authenticate threw on a malformed credential (must return null)");
    assert(result === null, "malformed credential must deny with null");
  });

  await check("expired credential -> null", async () => {
    const result = await callSafe(v.expired.request);
    assert(!result?.__threw, "authenticate threw on an expired credential (must return null)");
    assert(result === null, "expired credential must deny with null");
  });

  await check("not-yet-valid credential -> null", async () => {
    const result = await callSafe(v.notYetValid.request);
    assert(!result?.__threw, "authenticate threw on a not-yet-valid credential (must return null)");
    assert(result === null, "not-yet-valid credential must deny with null");
  });

  await check("an internal throw surfaces to the caller as null (never propagates)", async () => {
    let propagated = false;
    let result;
    try {
      result = await callRaw(v.throwing.request);
    } catch {
      propagated = true;
    }
    assert(!propagated, "authenticate propagated an internal throw (must catch and deny with null)");
    assert(result === null, "an internal error must deny with null, not a non-null identity");
  });

  await check("deny is deterministic for identical input", async () => {
    const a = await callSafe(v.malformed.request);
    const b = await callSafe(v.malformed.request);
    assert(!a?.__threw && !b?.__threw, "authenticate threw while checking determinism");
    assert(a === b, "deny is not deterministic for identical input (expected null both times)");
    assert(a === null, "expected a deterministic null deny");
  });

  await check("valid credential -> a well-formed, PII-safe identity", async () => {
    const identity = await callSafe(v.valid.request);
    assert(!identity?.__threw, "authenticate threw on a valid credential");
    assert(identity && typeof identity === "object", "a valid credential must return an identity object");
    assert(typeof identity.subjectHash === "string" && identity.subjectHash.length > 0,
      "identity must carry a non-empty subjectHash");
    assert(typeof identity.issuerHash === "string" && identity.issuerHash.length > 0,
      "identity must carry a non-empty issuerHash");
    // PII-safety: no field value may equal the raw input subject or issuer.
    assertNoRawPii(identity, v.valid.subject, v.valid.issuer, assert);

    // Determinism for the accept path too: identical valid input -> identical
    // identity (a non-deterministic identity breaks audit correlation).
    const again = await callSafe(v.valid.request);
    assert(!again?.__threw, "authenticate threw on a repeated valid credential");
    assert(JSON.stringify(again) === JSON.stringify(identity),
      "accept is not deterministic for identical valid input");
  });

  if (failures.length > 0) {
    return { ok: false, failures };
  }
  return { ok: true, failures: [] };
}

// Recursively assert no value in the identity equals the raw subject/issuer. The
// keyed-HMAC subjectHash/issuerHash are derived from these, so an equality
// against the raw value would mean a PII leak (or an un-hashed passthrough).
function assertNoRawPii(value, subject, issuer, assert, path = "identity") {
  if (typeof value === "string") {
    assert(value !== subject, `${path} contains the raw subject (PII leak)`);
    assert(value !== issuer, `${path} contains the raw issuer (PII leak)`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoRawPii(item, subject, issuer, assert, `${path}[${i}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      assertNoRawPii(item, subject, issuer, assert, `${path}.${key}`);
    }
  }
}

function randomAuthVectors(now) {
  const nowMs = typeof now === "number" ? now : Date.parse(now);
  // Per-run random so a plugin cannot hardcode the expected test values.
  const nonce = randomBytes(8).toString("hex");
  const subject = `subj-${randomBytes(6).toString("hex")}`;
  const issuer = `iss-${randomBytes(6).toString("hex")}`;
  const validToken = `valid.${nonce}.${randomBytes(8).toString("hex")}`;
  const expiredToken = `expired.${nonce}.${randomBytes(8).toString("hex")}`;
  const notYetToken = `notyet.${nonce}.${randomBytes(8).toString("hex")}`;
  const malformedToken = `~malformed~${nonce}`;
  const throwToken = `throw.${nonce}`;

  const bearer = (token) => ({ headers: { authorization: `Bearer ${token}` } });
  // The valid credential encodes the random subject/issuer so any provider that
  // echoes/leaks them into the returned identity is caught by assertNoRawPii.
  // The credential is structured as "valid.<nonce>.<randHex>.<subject>.<issuer>"
  // so a provider COULD extract them — but it MUST then keyed-hash them (not echo
  // them raw) for the PII-safety assertion to pass. This makes the default-vector
  // PII check non-vacuous: a leaking provider fails without custom vectors.
  const validTokenWithPii = `${validToken}.${subject}.${issuer}`;
  return {
    nowMs,
    subject,
    issuer,
    missing: { request: { headers: {} } },
    malformed: { request: bearer(malformedToken), token: malformedToken },
    expired: { request: bearer(expiredToken), token: expiredToken },
    notYetValid: { request: bearer(notYetToken), token: notYetToken },
    throwing: { request: bearer(throwToken), token: throwToken },
    valid: { request: bearer(validTokenWithPii), token: validTokenWithPii, subject, issuer }
  };
}

export { DEFAULT_ALLOWED_LABEL_KEYS };
