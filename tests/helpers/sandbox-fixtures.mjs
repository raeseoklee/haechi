// Test-only fixtures for the worker-isolated authProvider sandbox (PR3).
//
// NOT shipped — lives under tests/ (outside the package `files` allowlist). It
// builds a real signed plugin on disk (Ed25519 test keypair via PR2's
// signPluginManifest) so the sandbox exercises the REAL load gate, plus a couple
// of instrumented plugin variants for the isolation matrix.

import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, createHmac } from "node:crypto";
import { signPluginManifest } from "../../packages/plugin/index.mjs";

// A deterministic in-process cryptoProvider with hmac() for the HOST-side
// identity build. The key never crosses to the worker.
const HMAC_KEY = Buffer.from("sandbox-test-key-sandbox-test-key").subarray(0, 32);
export const referenceCrypto = {
  async hmac({ data, domain }) {
    if (!domain || typeof domain !== "string") {
      throw new Error("hmac requires a non-empty domain string");
    }
    const derived = createHmac("sha256", HMAC_KEY).update(domain).digest();
    return createHmac("sha256", derived).update(data).digest("hex");
  },
  // encrypt/decrypt stubs so createRuntime's encrypt/decrypt assertion passes
  // (the sandbox host-build only needs hmac; the proxy/core never run here).
  async encrypt({ plaintext }) {
    return { ciphertext: Buffer.from(String(plaintext)).toString("base64"), kid: "test" };
  },
  async decrypt({ ciphertext }) {
    return Buffer.from(String(ciphertext), "base64").toString("utf8");
  }
};

// An in-memory audit sink that records every event (after no sanitization here —
// the test asserts on raw events AND, separately, drives sanitizeAudit).
export function createRecordingAuditSink() {
  const events = [];
  return {
    events,
    async record(event) {
      events.push(event);
    },
    eventsOfType(type) {
      return events.filter((e) => e.type === type || e.decision === type);
    }
  };
}

// The REFERENCE auth plugin entry source (an ES module string). It implements the
// worker wire contract: authenticate(credential) -> claims | {deny:true}.
//
// Deterministic policy:
//   - "valid.<nonce>.<rand>.<subject>.<issuer>" (the conformance VALID vector):
//     parse subject/issuer from the trailing segments and return them as claims.
//   - "valid.*" without embedded pii: return default claims.
//   - "good-token-<subject>": accept, subject from the suffix, fixed issuer.
//   - anything starting expired./notyet./~malformed~ or unknown: deny.
//   - "throw.*": throw (the harness must convert this to a deny, not propagate).
//
// It is intentionally minimal + deterministic + STATELESS across calls.
export const REFERENCE_PLUGIN_SOURCE = `
export default function authenticate(credential) {
  if (typeof credential !== "string" || credential.length === 0) {
    return { deny: true };
  }
  if (credential.startsWith("throw.")) {
    throw new Error("plugin intentionally throws on this credential");
  }
  if (credential.startsWith("valid.")) {
    const parts = credential.split(".");
    // valid.<nonce>.<rand>.<subject>.<issuer>
    const subject = parts[3] || "default-subject";
    const issuer = parts[4] || "reference-issuer";
    return { subject, issuer, type: "user", scopes: ["read"], labels: { env: "test" } };
  }
  if (credential.startsWith("good-token-")) {
    return {
      subject: credential.slice("good-token-".length) || "anon",
      issuer: "reference-issuer",
      type: "service",
      scopes: ["read", "write"],
      labels: { team: "platform" }
    };
  }
  return { deny: true };
}
`;

// An ECHO plugin that returns the ENTIRE message it received as claims-shaped data
// so the test can prove the worker only ever sees { cid, credential } — never the
// request body, audit sink, token vault, or key. It also surfaces what globals it
// can introspect (workerData) so the test asserts workerData carried no secrets.
export const ECHO_PLUGIN_SOURCE = `
import { workerData } from "node:worker_threads";
export default function authenticate(credential) {
  if (typeof credential !== "string" || credential.length === 0) return { deny: true };
  // Delegate to reference behavior for the conformance vectors so the plugin LOADS.
  if (credential.startsWith("throw.")) throw new Error("boom");
  if (credential.startsWith("expired.") || credential.startsWith("notyet.") || credential.startsWith("~malformed~")) {
    return { deny: true };
  }
  if (credential.startsWith("valid.")) {
    const p = credential.split(".");
    return { subject: p[3] || "s", issuer: p[4] || "i", type: "user", scopes: [], labels: {} };
  }
  // The echo path: smuggle what the worker ACTUALLY received back into the claims
  // so the host test can prove the only inbound data was the credential string and
  // an EMPTY workerData (no body, sink, vault, or key). The host keyed-hashes these,
  // so the test re-derives the expected hash from "echo:<credential>".
  return {
    subject: "echo:" + String(credential),
    issuer: "echo-workerData:" + JSON.stringify(workerData || null),
    type: "user",
    scopes: [],
    labels: {}
  };
}
`;

// A plugin that returns a hostile claims object: __proto__ pollution + extra keys.
// It delegates to reference behavior for the conformance vectors so it LOADS, then
// pollutes only for its trigger token ("good-token-*"/"anything").
export const POLLUTING_PLUGIN_SOURCE = `
export default function authenticate(credential) {
  if (typeof credential !== "string" || credential.length === 0) return { deny: true };
  if (credential.startsWith("throw.")) throw new Error("boom");
  if (credential.startsWith("valid.")) {
    const p = credential.split(".");
    return { subject: p[3] || "s", issuer: p[4] || "i", type: "user", scopes: ["read"], labels: { env: "test" } };
  }
  if (credential.startsWith("expired.") || credential.startsWith("notyet.") || credential.startsWith("~malformed~")) {
    return { deny: true };
  }
  // The hostile path: a claims object whose SERIALIZED JSON carries own
  // __proto__/constructor keys + extras. Built from a literal JSON string so the
  // reply the host parses actually contains those keys (JSON.parse gives them as
  // OWN enumerable props — the realistic prototype-pollution vector).
  return JSON.parse(JSON.stringify({ marker: true })) && JSON.parse(
    '{"subject":"polluted-subject","issuer":"polluted-issuer","type":"user",' +
    '"scopes":["read"],"labels":{"env":"test"},' +
    '"secretExfil":"should-not-survive","isAdmin":true,' +
    '"__proto__":{"polluted":"yes"},"constructor":{"evil":true}}'
  );
}
`;

// A plugin that HANGS forever on a specific credential (for the timeout matrix).
export const HANGING_PLUGIN_SOURCE = `
export default function authenticate(credential) {
  if (credential === "hang") {
    return new Promise(() => {}); // never resolves -> host timeout terminates us
  }
  if (credential.startsWith("valid.")) {
    const p = credential.split(".");
    return { subject: p[3] || "s", issuer: p[4] || "i", type: "user", scopes: [], labels: {} };
  }
  if (credential === "good") {
    return { subject: "after-respawn", issuer: "reference-issuer", type: "user", scopes: [], labels: {} };
  }
  return { deny: true };
}
`;

// A plugin that LEAKS the raw subject into the returned claims (so conformance's
// PII check + the host re-validation would still keyed-hash it — but we also use
// it to confirm the host never echoes raw). For conformance failure we instead
// need a provider whose returned identity is raw; that is a host-built identity,
// so it is always keyed-hashed. To FAIL conformance we use a non-deterministic
// plugin instead (below).
export const NONDETERMINISTIC_PLUGIN_SOURCE = `
let n = 0;
export default function authenticate(credential) {
  if (typeof credential !== "string" || credential.length === 0) return { deny: true };
  n += 1;
  // Different subject every call -> the accept path is non-deterministic ->
  // conformance "accept is deterministic" check fails -> load refused.
  return { subject: "subj-" + n, issuer: "iss", type: "user", scopes: [], labels: {} };
}
`;

// Write a signed plugin to a fresh temp dir and return { manifestPath,
// trustAnchors, signerKeyId, entrySha256, dir, publicKey, privateKey }.
//
// overrides:
//   entrySource          - the worker module string (default REFERENCE_PLUGIN_SOURCE)
//   pluginId/version     - manifest identity
//   capabilities         - signed capabilities object
//   tamperEntry          - if true, the entry ON DISK differs from what was signed
//   wrongSigner          - if true, sign with key A but anchor key B (unknown-signer)
//   notBefore/notAfter   - validity window (defaults to a window around now)
//   coreVersionRange     - signed core range
//   now                  - signing clock
export function buildSignedPlugin(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), "haechi-sandbox-"));
  const entrySource = overrides.entrySource ?? REFERENCE_PLUGIN_SOURCE;
  const signerKeyId = overrides.signerKeyId ?? "test-anchor-1";
  const pluginId = overrides.pluginId ?? "reference-auth";
  const version = overrides.version ?? "1.0.0";
  const now = overrides.now ?? Date.now();
  const capabilities = overrides.capabilities ?? { readsCredentials: true, networkEgress: true };
  const coreVersionRange = overrides.coreVersionRange ?? ">=1.0.0 <2.0.0";

  const signingKeys = generateKeyPairSync("ed25519");
  const anchorKeys = overrides.wrongSigner ? generateKeyPairSync("ed25519") : signingKeys;

  const signed = signPluginManifest(
    {
      pluginId,
      kind: "authProvider",
      version,
      capabilities,
      coreVersionRange,
      entryBytes: entrySource, // signs the sha256 of THESE bytes
      notBefore: overrides.notBefore ?? now - 60_000,
      notAfter: overrides.notAfter ?? now + 3_600_000
    },
    signingKeys.privateKey,
    signerKeyId
  );

  // Optionally write DIFFERENT bytes to disk than what was signed (tamper).
  const onDiskSource = overrides.tamperEntry
    ? `${entrySource}\n// tampered ${Math.random()}\n`
    : entrySource;
  const entrypoint = "./entry.mjs";
  writeFileSync(join(dir, "entry.mjs"), onDiskSource, "utf8");

  // The manifest mirrors the signed envelope's flat fields (so
  // validatePluginManifest passes) and stores the full envelope under `signed`.
  const manifest = {
    haechiPlugin: {
      id: pluginId,
      version,
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint,
      signerKeyId: signed.signerKeyId,
      signature: signed.signature,
      entrySha256: signed.payload.entrySha256,
      notBefore: signed.payload.notBefore,
      notAfter: signed.payload.notAfter,
      capabilities,
      // The full PR2 envelope the sandbox feeds to verifySignedPlugin.
      signed
    }
  };
  // Optionally drop the signature entirely (unsigned manifest).
  if (overrides.unsigned) {
    delete manifest.haechiPlugin.signature;
    delete manifest.haechiPlugin.signed;
  }
  const manifestPath = join(dir, "haechi.plugin.json");
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8");

  // For wrongSigner: the operator's anchor set does NOT contain this signerKeyId
  // (a different keyId holds an unrelated key) -> unknown-signer, refused before
  // any verify. For the normal case: the signer's public key is the anchor.
  const trustAnchors = overrides.trustAnchors ?? (overrides.wrongSigner
    ? { "some-other-anchor": anchorKeys.publicKey }
    : { [signerKeyId]: anchorKeys.publicKey });

  return {
    dir,
    manifestPath,
    trustAnchors,
    signerKeyId,
    pluginId,
    version,
    entrySha256: signed.payload.entrySha256,
    publicKey: anchorKeys.publicKey,
    privateKey: signingKeys.privateKey,
    signed
  };
}

// Standard sandbox options around a built plugin.
export function sandboxOptions(built, overrides = {}) {
  return {
    manifestPath: built.manifestPath,
    trustAnchors: built.trustAnchors,
    allowCapabilities: ["readsCredentials", "networkEgress"],
    cryptoProvider: referenceCrypto,
    auditSink: overrides.auditSink ?? createRecordingAuditSink(),
    timeoutMs: 2000,
    maxPendingCalls: 8,
    maxMessageBytes: 16384,
    resourceLimits: { maxOldGenerationSizeMb: 64 },
    coreVersion: "1.0.0",
    ...overrides
  };
}

export function bearer(token) {
  return { headers: { authorization: `Bearer ${token}` } };
}

export { mkdirSync };
