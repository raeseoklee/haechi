// Ed25519 signed-plugin primitive (the 1.0 cryptographic trust gate).
//
// This is ASYMMETRIC signing — the plugin AUTHOR holds the Ed25519 private key
// and signs offline; the OPERATOR allowlists the Ed25519 PUBLIC key as a trust
// anchor and verifies. It deliberately does NOT reuse packages/policy-bundle:
// that is symmetric HMAC keyed off the local AES key file, where the verifier
// holds the same secret that signs, so it cannot express third-party authorship.
//
// The signature binds the sha256 of the EXACT entry bytes plus kind,
// capabilities, the compatible core range, and a validity window — so signing a
// path, or omitting entrySha256/kind/capabilities, is a swap / capability-
// downgrade attack and is rejected by verifySignedPlugin.
//
// Zero new runtime dependency: node:crypto (Ed25519 is a builtin) + the core
// canonicalize() for the signed bytes so sign and verify agree byte-for-byte.

import { createHash, createPublicKey, sign as edSign, verify as edVerify, timingSafeEqual } from "node:crypto";
import { canonicalize } from "../crypto/index.mjs";

// Minimal node:-only semver satisfies for the ">=A.B.C <D.E.F" range shape.
// Inlined rather than imported from scripts/ — scripts/check-satellite-peer-ranges.mjs
// is NOT in the published `files` allowlist, so a cross-import would
// MODULE_NOT_FOUND in the haechi tarball at runtime.
function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim());
  if (!m) throw new Error(`unsupported version: ${JSON.stringify(v)}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
function cmpSemver(a, b) {
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}
function semverSatisfies(version, range) {
  const m = /^>=(\d+\.\d+\.\d+)\s+<(\d+\.\d+\.\d+)$/.exec(String(range).trim());
  if (!m) {
    throw new Error(`unsupported range shape (expected ">=A.B.C <D.E.F"): ${JSON.stringify(range)}`);
  }
  return cmpSemver(parseSemver(version), parseSemver(m[1])) >= 0
    && cmpSemver(parseSemver(version), parseSemver(m[2])) < 0;
}

// The verifySignedPlugin refusal reasons — security-critical and ordered.
// PluginLoadError.reason is guaranteed to be a member of this set.
export const PLUGIN_LOAD_REASONS = Object.freeze([
  "manifest-invalid",
  "alg-not-ed25519",
  "unknown-signer",
  "revoked",
  "tampered-entry",
  "invalid-signature",
  "expired-window",
  "below-version-floor",
  "pin-mismatch",
  "capability-not-allowlisted"
]);

const PLUGIN_LOAD_REASON_SET = new Set(PLUGIN_LOAD_REASONS);

// A typed, fail-closed error. Every refusal path throws this with a .reason in
// PLUGIN_LOAD_REASONS so the loader/audit can branch on a stable enum, never on
// a free-text message.
export class PluginLoadError extends Error {
  constructor(reason, message) {
    if (!PLUGIN_LOAD_REASON_SET.has(reason)) {
      // A programming error inside the verifier — never surface an off-contract
      // reason to a caller relying on the enum.
      throw new Error(`PluginLoadError got an off-contract reason: ${reason}`);
    }
    super(message ?? reason);
    this.name = "PluginLoadError";
    this.reason = reason;
  }
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toEntryBuffer(entryBytes) {
  if (Buffer.isBuffer(entryBytes)) {
    return entryBytes;
  }
  if (entryBytes instanceof Uint8Array) {
    return Buffer.from(entryBytes);
  }
  if (typeof entryBytes === "string") {
    return Buffer.from(entryBytes, "utf8");
  }
  throw new Error("entryBytes must be a Buffer, Uint8Array, or string");
}

// Compares two hex-encoded sha256 digests without leaking position-of-first-
// difference timing. Both are attacker-influenced/operator-supplied digests, so
// the constant-time compare is defense-in-depth (and required by the spec).
function constantTimeHexEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

// TEST/AUTHORING HELPER. Real authors sign offline with their own tooling; this
// exists so tests (and a future signing CLI) can produce a valid envelope.
//
// Returns { payload, signerKeyId, alg: "ed25519", signature } where
//   payload   = { pluginId, kind, version, capabilities, coreVersionRange,
//                 entrySha256: sha256hex(entryBytes), notBefore, notAfter }
//   signature = base64( ed25519.sign(canonicalize(payload)) )
export function signPluginManifest(
  { pluginId, kind, version, capabilities, coreVersionRange, entryBytes, notBefore, notAfter },
  privateKey,
  signerKeyId
) {
  if (!pluginId || typeof pluginId !== "string") {
    throw new Error("signPluginManifest requires a non-empty pluginId");
  }
  if (!kind || typeof kind !== "string") {
    throw new Error("signPluginManifest requires a non-empty kind");
  }
  if (!version || typeof version !== "string") {
    throw new Error("signPluginManifest requires a non-empty version");
  }
  if (!capabilities || typeof capabilities !== "object" || Array.isArray(capabilities)) {
    throw new Error("signPluginManifest requires a capabilities object");
  }
  if (!coreVersionRange || typeof coreVersionRange !== "string") {
    throw new Error("signPluginManifest requires a coreVersionRange string");
  }
  if (!signerKeyId || typeof signerKeyId !== "string") {
    throw new Error("signPluginManifest requires a signerKeyId");
  }
  if (entryBytes === undefined || entryBytes === null) {
    throw new Error("signPluginManifest requires entryBytes (the exact plugin source bytes)");
  }

  const entrySha256 = sha256Hex(toEntryBuffer(entryBytes));
  const payload = {
    pluginId,
    kind,
    version,
    capabilities,
    coreVersionRange,
    entrySha256,
    notBefore: notBefore ?? null,
    notAfter: notAfter ?? null
  };

  // Ed25519: the algorithm arg to crypto.sign is NULL.
  const signature = edSign(null, Buffer.from(canonicalize(payload), "utf8"), privateKey);
  return {
    payload,
    signerKeyId,
    alg: "ed25519",
    signature: signature.toString("base64")
  };
}

function resolveAnchorPublicKey(anchor) {
  // A trust anchor may be supplied as a KeyObject, a PEM/SPKI string, or a
  // { publicKey } wrapper. Resolve to a KeyObject; reject anything else.
  if (anchor && typeof anchor === "object" && anchor.publicKey !== undefined && anchor.type === undefined) {
    return resolveAnchorPublicKey(anchor.publicKey);
  }
  if (anchor && typeof anchor === "object" && anchor.asymmetricKeyType !== undefined) {
    // A KeyObject already.
    return anchor;
  }
  if (typeof anchor === "string") {
    return createPublicKey(anchor);
  }
  // Last resort: let createPublicKey try (e.g. a JWK object / DER buffer).
  return createPublicKey(anchor);
}

// Verify a signed plugin envelope against operator trust state. Returns the
// validated payload, or throws a PluginLoadError whose .reason is in
// PLUGIN_LOAD_REASONS. The CHECK ORDER is security-critical (see the design
// §2.2 / §7.3) and must not be reordered.
export function verifySignedPlugin({
  signed,
  entryBytes,
  trustAnchors = {},
  revoked = {},
  pin = null,
  versionFloor = {},
  allowCapabilities = [],
  coreVersion = null,
  now = Date.now()
} = {}) {
  // (0) Structural validity of the envelope itself.
  if (!signed || typeof signed !== "object") {
    throw new PluginLoadError("manifest-invalid", "signed envelope must be an object");
  }
  const { payload, signerKeyId, alg, signature } = signed;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PluginLoadError("manifest-invalid", "signed.payload must be an object");
  }
  if (typeof signerKeyId !== "string" || signerKeyId.length === 0) {
    throw new PluginLoadError("manifest-invalid", "signed.signerKeyId must be a non-empty string");
  }
  if (typeof signature !== "string" || signature.length === 0) {
    throw new PluginLoadError("manifest-invalid", "signed.signature must be a non-empty base64 string");
  }
  for (const field of ["pluginId", "kind", "version", "coreVersionRange", "entrySha256"]) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      throw new PluginLoadError("manifest-invalid", `signed.payload.${field} must be a non-empty string`);
    }
  }
  if (!payload.capabilities || typeof payload.capabilities !== "object" || Array.isArray(payload.capabilities)) {
    throw new PluginLoadError("manifest-invalid", "signed.payload.capabilities must be an object");
  }

  // (a) Algorithm is pinned to ed25519 — no alg agility, no HS/RS confusion.
  if (alg !== "ed25519") {
    throw new PluginLoadError("alg-not-ed25519", `unsupported signature alg: ${String(alg)}`);
  }

  // (b) Resolve the verification key ONLY from the operator's trustAnchors
  // allowlist, keyed by signed.signerKeyId. If the kid is not an allowlisted
  // anchor, refuse BEFORE any verify — never select a key by the object's own
  // claim against a broader keyring.
  const hasAnchor = Object.prototype.hasOwnProperty.call(trustAnchors, signerKeyId);
  if (!hasAnchor) {
    throw new PluginLoadError("unknown-signer", `signerKeyId not in trust anchors: ${signerKeyId}`);
  }
  let resolvedPublicKey;
  try {
    resolvedPublicKey = resolveAnchorPublicKey(trustAnchors[signerKeyId]);
    if (!resolvedPublicKey || resolvedPublicKey.asymmetricKeyType !== "ed25519") {
      throw new Error("trust anchor is not an ed25519 public key");
    }
  } catch (error) {
    // A malformed anchor is an operator config error, but the safe outcome is
    // still to refuse the load as an unusable signer.
    throw new PluginLoadError("unknown-signer", `trust anchor unusable for ${signerKeyId}: ${error.message}`);
  }

  // (c) Revoked signer denylist (fail-closed before the expensive verify).
  const revokedSignerKeyIds = Array.isArray(revoked.signerKeyIds) ? revoked.signerKeyIds : [];
  if (revokedSignerKeyIds.includes(signerKeyId)) {
    throw new PluginLoadError("revoked", `signerKeyId is revoked: ${signerKeyId}`);
  }

  // (d) Bind to the EXACT entry bytes: recompute the hash and compare in
  // constant time. A mutated entry (path unchanged) trips here BEFORE the
  // signature check, so a swap is "tampered-entry", not "invalid-signature".
  const entrySha256 = sha256Hex(toEntryBuffer(entryBytes));
  if (!constantTimeHexEqual(payload.entrySha256, entrySha256)) {
    throw new PluginLoadError("tampered-entry", "entry bytes do not match the signed entrySha256");
  }
  const revokedEntrySha256 = Array.isArray(revoked.entrySha256) ? revoked.entrySha256 : [];
  if (revokedEntrySha256.includes(entrySha256)) {
    throw new PluginLoadError("revoked", `entrySha256 is revoked: ${entrySha256}`);
  }

  // (e) Ed25519 signature over the canonical payload (algorithm arg NULL).
  let signatureValid = false;
  try {
    signatureValid = edVerify(
      null,
      Buffer.from(canonicalize(payload), "utf8"),
      resolvedPublicKey,
      Buffer.from(signature, "base64")
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    throw new PluginLoadError("invalid-signature", "ed25519 signature verification failed");
  }

  // (f) Validity window (notBefore/notAfter). Both are epoch-ms numbers (or
  // null = unbounded on that side).
  const nowMs = typeof now === "number" ? now : Date.parse(now);
  const notBefore = normalizeWindowBound(payload.notBefore);
  const notAfter = normalizeWindowBound(payload.notAfter);
  if (notBefore !== null && nowMs < notBefore) {
    throw new PluginLoadError("expired-window", "current time is before notBefore");
  }
  if (notAfter !== null && nowMs > notAfter) {
    throw new PluginLoadError("expired-window", "current time is after notAfter");
  }

  // (g) Per-pluginId version floor — reject rollback to an older signed artifact.
  const floor = versionFloor?.[payload.pluginId];
  if (floor !== undefined && floor !== null && compareVersions(payload.version, floor) < 0) {
    throw new PluginLoadError("below-version-floor", `version ${payload.version} below floor ${floor}`);
  }

  // (h) Pin (anti malicious-update / rollback): version / entrySha256 /
  // manifestSha256 must match the operator pin exactly.
  if (pin && typeof pin === "object") {
    if (pin.version !== undefined && pin.version !== null && pin.version !== payload.version) {
      throw new PluginLoadError("pin-mismatch", "version does not match pin");
    }
    if (pin.entrySha256 !== undefined && pin.entrySha256 !== null
      && !constantTimeHexEqual(pin.entrySha256, entrySha256)) {
      throw new PluginLoadError("pin-mismatch", "entrySha256 does not match pin");
    }
    if (pin.manifestSha256 !== undefined && pin.manifestSha256 !== null) {
      const manifestSha256 = sha256Hex(Buffer.from(canonicalize(payload), "utf8"));
      if (!constantTimeHexEqual(pin.manifestSha256, manifestSha256)) {
        throw new PluginLoadError("pin-mismatch", "manifestSha256 does not match pin");
      }
    }
  }

  // (i) Capability allowlist: every capability value MUST be a strict boolean
  // (non-boolean truthy values like 1/"true"/{} skip the === true gate and are
  // a bypass). Reject at the trust boundary before the allowlist check.
  const allowSet = new Set(Array.isArray(allowCapabilities) ? allowCapabilities : []);
  for (const [capability, requested] of Object.entries(payload.capabilities)) {
    if (typeof requested !== "boolean") {
      throw new PluginLoadError("manifest-invalid", `capability value must be a boolean, got ${typeof requested} for: ${capability}`);
    }
    if (requested === true && !allowSet.has(capability)) {
      throw new PluginLoadError("capability-not-allowlisted", `capability not allowlisted: ${capability}`);
    }
  }
  if (payload.kind === "authProvider" && payload.capabilities.readsCredentials !== true) {
    throw new PluginLoadError("capability-not-allowlisted", "authProvider must declare readsCredentials");
  }

  // (j) coreVersionRange enforcement: when the caller supplies coreVersion AND
  // the signed payload declares coreVersionRange, the version must satisfy the
  // range. A mismatch means this plugin was not signed for this core — refuse.
  if (coreVersion !== null && coreVersion !== undefined && payload.coreVersionRange) {
    let inRange;
    try {
      inRange = semverSatisfies(String(coreVersion), payload.coreVersionRange);
    } catch (err) {
      throw new PluginLoadError("manifest-invalid", `coreVersionRange is not a valid range: ${err.message}`);
    }
    if (!inRange) {
      throw new PluginLoadError("manifest-invalid", `coreVersion ${coreVersion} does not satisfy signed coreVersionRange ${payload.coreVersionRange}`);
    }
  }

  // The validated payload — frozen so a downstream consumer cannot mutate the
  // attested facts.
  return Object.freeze({ ...payload });
}

function normalizeWindowBound(bound) {
  if (bound === null || bound === undefined) {
    return null;
  }
  if (typeof bound === "number") {
    if (!Number.isFinite(bound)) {
      throw new PluginLoadError("manifest-invalid", `validity window bound is not a finite number: ${bound}`);
    }
    return bound;
  }
  if (typeof bound === "string" && bound.length > 0) {
    const parsed = Date.parse(bound);
    if (Number.isNaN(parsed)) {
      throw new PluginLoadError("manifest-invalid", `validity window bound is not a parseable date: ${JSON.stringify(bound)}`);
    }
    return parsed;
  }
  // Anything else (boolean, object, empty string, etc.) fails closed.
  throw new PluginLoadError("manifest-invalid", `validity window bound has an unacceptable type/value: ${JSON.stringify(bound)}`);
}

// Minimal numeric-dotted version comparison (e.g. "1.2.0" vs "1.10.0"). Returns
// -1 / 0 / 1. Non-numeric segments compare lexicographically as a fallback so a
// malformed version can never silently rank as "newer".
function compareVersions(a, b) {
  const pa = String(a).split(".");
  const pb = String(b).split(".");
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const sa = pa[i] ?? "0";
    const sb = pb[i] ?? "0";
    const na = Number(sa);
    const nb = Number(sb);
    if (Number.isInteger(na) && Number.isInteger(nb)) {
      if (na !== nb) {
        return na < nb ? -1 : 1;
      }
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}
