// Shared, security-critical primitives for the signed-authProvider sandboxes
// (Haechi 1.0 worker-isolated + 1.1 process-isolated).
//
// These helpers are the trust boundary that MUST behave identically for both
// runtimes — the null-prototype claims sanitizer, the bearer-only credential
// extraction, the signed-envelope reconstruction, and the full PR2 load gate.
// They live here so the worker and process sandboxes import ONE copy: a divergence
// between two private copies of the sanitizer would be a real prototype-pollution
// vulnerability. The transport-specific lifecycle (Worker vs child_process) stays
// in each sandbox module.
//
// Zero runtime dependency: node:crypto + node:fs + node:path only, plus the
// in-repo PR2 verifier (haechi/plugin/signing) and the manifest validator.

import { lstatSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve as resolvePath, sep as pathSep } from "node:path";
import { verifySignedPlugin } from "./signing.mjs";
import { validatePluginManifest } from "./index.mjs";

// The only own-enumerable keys the host accepts back from a sandboxed plugin.
// Anything else (incl. __proto__/constructor/prototype) is dropped at the boundary.
export const CLAIM_ALLOWLIST = ["subject", "issuer", "type", "scopes", "labels"];
// Defensive bounds so a hostile claims object cannot blow up the host build.
export const MAX_SCOPES = 64;
export const MAX_LABELS = 32;
export const MAX_STRING_LEN = 1024;
// A self-contained single-file plugin is loaded from a data: URL; refuse to read
// an unreasonably large entry into memory (a few MiB is generous for any auth
// plugin). Shared so both runtimes apply the identical bound.
export const MAX_ENTRY_BYTES = 4 * 1024 * 1024; // 4 MiB

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Same parsing the bearer provider uses — ONLY the Authorization header, never
// the request body. Returns the bearer token slice (the credential) or null.
export function bearerCredentialFromRequest(request) {
  const header = request?.headers?.authorization ?? request?.headers?.Authorization;
  if (typeof header !== "string") {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

// Reconstruct the PR2 signed envelope ({ payload, signerKeyId, alg, signature })
// from a manifest's stored fields. Authors produce this with signPluginManifest;
// the manifest persists it under haechiPlugin.signed and mirrors the flat fields
// so validatePluginManifest can check the shape.
export function envelopeFromManifest(plugin) {
  if (plugin.signed && typeof plugin.signed === "object") {
    return plugin.signed;
  }
  return {
    payload: plugin.signedPayload,
    signerKeyId: plugin.signerKeyId,
    alg: plugin.alg ?? "ed25519",
    signature: plugin.signature
  };
}

// Host-side claims sanitizer. The reply is parsed, then ONLY the allowlisted
// own-enumerable keys are copied onto a null-prototype object — __proto__/
// constructor/prototype can never reach buildExternalIdentity, and array/string
// sizes are bounded. Returns a plain {subject,issuer,type,scopes,labels} or
// throws (→ deny) on a structurally invalid claim.
export function sanitizeClaims(rawClaims) {
  if (!rawClaims || typeof rawClaims !== "object" || Array.isArray(rawClaims)) {
    throw new Error("claims must be an object");
  }
  const out = Object.create(null);
  for (const key of CLAIM_ALLOWLIST) {
    // Own-enumerable only; never walk the prototype.
    if (!Object.prototype.hasOwnProperty.call(rawClaims, key)) {
      continue;
    }
    out[key] = rawClaims[key];
  }
  // type-validate / bound each value at the boundary.
  if (typeof out.subject !== "string" || out.subject.length === 0 || out.subject.length > MAX_STRING_LEN) {
    throw new Error("claims.subject must be a bounded non-empty string");
  }
  if (typeof out.issuer !== "string" || out.issuer.length === 0 || out.issuer.length > MAX_STRING_LEN) {
    throw new Error("claims.issuer must be a bounded non-empty string");
  }
  if (out.type !== undefined && typeof out.type !== "string") {
    throw new Error("claims.type must be a string");
  }
  if (out.scopes !== undefined) {
    if (!Array.isArray(out.scopes) || out.scopes.length > MAX_SCOPES
      || !out.scopes.every((s) => typeof s === "string" && s.length > 0 && s.length <= MAX_STRING_LEN)) {
      throw new Error("claims.scopes must be a bounded array of non-empty strings");
    }
  }
  if (out.labels !== undefined) {
    if (!out.labels || typeof out.labels !== "object" || Array.isArray(out.labels)) {
      throw new Error("claims.labels must be an object");
    }
    const labelKeys = Object.keys(out.labels);
    if (labelKeys.length > MAX_LABELS) {
      throw new Error("claims.labels exceeds the size bound");
    }
    const bounded = Object.create(null);
    for (const k of labelKeys) {
      const v = out.labels[k];
      if (typeof v !== "string" || v.length === 0 || v.length > MAX_STRING_LEN) {
        throw new Error(`claims.labels.${k} must be a bounded non-empty string`);
      }
      bounded[k] = v;
    }
    out.labels = bounded;
  }
  return out;
}

// A fire-and-forget audit wrapper. Lifecycle audit must NEVER make the auth path
// throw, so a sink that throws or rejects is swallowed.
export function makeFireAndForgetAudit(auditSink) {
  return (event) => {
    try {
      const out = auditSink.record(event);
      if (out && typeof out.then === "function") {
        out.catch(() => {});
      }
    } catch {
      // swallow — auditing is best-effort and never blocks fail-closed behavior
    }
  };
}

// Read+validate the manifest, resolve the entry path, read the entry bytes into
// memory, and run the FULL PR2 gate. Returns { verified, entrySource,
// entrySha256, pluginId, signerKeyId }. Throws (after emitting plugin.load.refused
// via `audit`) on any refusal. Both sandboxes call this; `expectedRuntime` is the
// manifest runtime string the caller requires ("worker-isolated" | "process-isolated").
// Re-run on every (re)spawn — the gate is not a one-time check.
export function loadAndVerifyPlugin({
  manifestPath,
  expectedRuntime,
  trustAnchors,
  allowCapabilities = [],
  pin = null,
  revoked = {},
  versionFloor = {},
  coreVersion = null,
  now,
  audit
}) {
  // A tagged-throw helper so a refusal emits the audit at one site.
  function refuse(reason, message, pluginId) {
    const err = new Error(message);
    err.reason = reason;
    audit({ type: "plugin.load.refused", decision: "plugin.load.refused", reason, pluginId });
    return { __haechiRefusal: true, cause: err };
  }

  let plugin;
  let entrySource;
  let entrySha256;
  let pluginIdForAudit;
  let signerKeyIdForAudit;
  try {
    const manifestRaw = JSON.parse(readFileSync(manifestPath, "utf8"));
    plugin = manifestRaw?.haechiPlugin;
    pluginIdForAudit = plugin?.id;
    const validation = validatePluginManifest(manifestRaw);
    if (!validation.valid) {
      throw refuse("manifest-invalid", `manifest invalid: ${validation.errors.join("; ")}`);
    }
    if (plugin.runtime !== expectedRuntime) {
      throw refuse("manifest-invalid", `sandbox requires runtime ${expectedRuntime}`);
    }
    if (plugin.kind !== "authProvider") {
      throw refuse("manifest-invalid", "sandbox requires kind authProvider");
    }

    // Resolve the entry against the manifest dir. Reject a symlinked entry
    // (anti-TOCTOU / swap): we hash and spawn from the in-memory bytes only.
    const manifestDir = resolvePath(dirname(resolvePath(manifestPath)));
    const entryPath = resolvePath(manifestDir, plugin.entrypoint);

    // Entrypoint confinement: the resolved entry path MUST be inside the manifest
    // directory. An absolute path or a `../`-escaping value resolves outside
    // manifestDir and is an arbitrary-file-read primitive. Checked BEFORE any I/O.
    if (!entryPath.startsWith(manifestDir + pathSep) && entryPath !== manifestDir) {
      throw refuse("manifest-invalid", `entry path escapes the manifest directory: ${plugin.entrypoint}`);
    }

    const st = lstatSync(entryPath);
    if (st.isSymbolicLink()) {
      throw refuse("tampered-entry", "entry path is a symlink (refused)");
    }

    const entrySize = statSync(entryPath).size;
    if (entrySize > MAX_ENTRY_BYTES) {
      throw refuse("manifest-invalid", `entry file exceeds maximum size (${entrySize} > ${MAX_ENTRY_BYTES} bytes)`);
    }

    const entryBytes = readFileSync(entryPath); // INTO MEMORY — read exactly once.
    entrySource = entryBytes.toString("utf8");
    entrySha256 = sha256Hex(entryBytes);

    signerKeyIdForAudit = envelopeFromManifest(plugin)?.signerKeyId;
  } catch (error) {
    if (error?.__haechiRefusal) {
      throw error.cause;
    }
    const refusal = refuse("manifest-invalid", `manifest load failed: ${error.message}`, pluginIdForAudit);
    throw refusal.cause;
  }

  // The PR2 gate (signature + anchor + revocation + tamper + window + floor +
  // pin + capability allowlist + coreVersionRange). Any failure throws a
  // PluginLoadError whose .reason is the audit reason.
  let verified;
  try {
    verified = verifySignedPlugin({
      signed: envelopeFromManifest(plugin),
      entryBytes: Buffer.from(entrySource, "utf8"),
      trustAnchors,
      revoked,
      pin,
      versionFloor,
      allowCapabilities,
      coreVersion,
      now
    });
  } catch (error) {
    const reason = typeof error?.reason === "string" ? error.reason : "manifest-invalid";
    audit({ type: "plugin.load.refused", decision: "plugin.load.refused", reason, pluginId: pluginIdForAudit, signerKeyId: signerKeyIdForAudit });
    throw error;
  }

  return {
    verified,
    entrySource,
    entrySha256,
    pluginId: verified.pluginId,
    signerKeyId: envelopeFromManifest(plugin).signerKeyId
  };
}
