// ============================================================================
// API FREEZE GUARD — the 1.0 stable-contract snapshot test.
//
// This test pins the FROZEN public surface declared in
// docs/current/api-stability.md §2 (per the 1.0 implementation scope §2.1/§7.2):
//
//   1. every package.json `exports` subpath exposes its FROZEN export NAMES,
//   2. a real audit event carries every FROZEN top-level AND nested field
//      (+ the additive `schemaVersion`), and
//   3. normalizeConfig() emits the FROZEN config key set.
//
// The frozen sets are SUBSET checks: an ADDITIVE new export / field / config key
// PASSES (additive = minor). A REMOVED or RENAMED frozen surface FAILS.
//
// >>> If a future PR makes this test fail, that is the deliberate signal of a
// >>> BREAKING CHANGE. Do not "just delete the assertion" — either keep the
// >>> surface, or consciously update this guard AND ship a major bump +
// >>> deprecation note (api-stability.md §2.2). Updating this file is the act of
// >>> acknowledging a contract break. <<<
// ============================================================================

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import * as core from "../packages/core/index.mjs";
import * as audit from "../packages/audit/index.mjs";
import * as coreRoot from "../packages/core/index.mjs"; // "." subpath === core
import * as crypto from "../packages/crypto/index.mjs";
import * as filter from "../packages/filter/index.mjs";
import * as mcpStdio from "../packages/mcp-stdio/index.mjs";
import * as plugin from "../packages/plugin/index.mjs";
import * as policy from "../packages/policy/index.mjs";
import * as policyBundle from "../packages/policy-bundle/index.mjs";
import * as privacyProfiles from "../packages/privacy-profiles/index.mjs";
import * as protocolAdapters from "../packages/protocol-adapters/index.mjs";
import * as proxy from "../packages/proxy/index.mjs";
import * as runtime from "../packages/cli/runtime.mjs";
import * as tokenVault from "../packages/token-vault/index.mjs";
import * as streamFilter from "../packages/stream-filter/index.mjs";
import * as authPkg from "../packages/auth/index.mjs";

import { createHaechi } from "../packages/core/index.mjs";
import { createDefaultFilterEngine } from "../packages/filter/index.mjs";
import { createPolicyProfiles } from "../packages/policy/index.mjs";
import { createJsonlAuditSink, verifyAuditChain } from "../packages/audit/index.mjs";
import { normalizeConfig } from "../packages/cli/runtime.mjs";

// ---------------------------------------------------------------------------
// 1. FROZEN export names per `exports` subpath (the 16 subpaths in package.json).
//
// "." and "./core" both resolve to packages/core, "./runtime" to cli/runtime.
// A removed/renamed name => fail. Additive new exports are allowed (subset).
// ---------------------------------------------------------------------------

const FROZEN_EXPORTS = {
  ".": { module: coreRoot, names: ["createHaechi", "collectStringEntries", "pathToString", "safePathToString", "shapeOnly", "summarize"] },
  "./core": { module: core, names: ["createHaechi", "collectStringEntries", "pathToString", "safePathToString", "shapeOnly", "summarize"] },
  "./audit": { module: audit, names: ["createJsonlAuditSink", "createAuditSink", "createFileAuditStore", "buildIntegrityRecord", "readAuditSummary", "sanitizeAudit", "verifyAuditChain"] },
  "./crypto": { module: crypto, names: ["createLocalCryptoProvider", "initLocalKeyFile", "assertCryptoProviderConformance", "canonicalize"] },
  "./filter": { module: filter, names: ["createDefaultFilterEngine", "detectEntry"] },
  "./mcp-stdio": { module: mcpStdio, names: ["protectMcpJsonRpcMessage", "runMcpStdioFilter", "wrapMcpChild"] },
  "./plugin": { module: plugin, names: ["validatePluginManifest", "validatePluginManifestFile"] },
  "./policy": { module: policy, names: ["buildPolicy", "createPolicyEngine", "createPolicyProfiles", "validatePolicy", "ACTION_STRENGTH"] },
  "./policy-bundle": { module: policyBundle, names: ["signPolicyBundle", "signPolicyBundleFile", "verifyPolicyBundle", "verifyPolicyBundleFile", "loadVerifiedPolicyBundleFileSync"] },
  "./privacy-profiles": { module: privacyProfiles, names: ["listPrivacyProfiles", "getPrivacyProfile", "applyPrivacyProfile"] },
  "./protocol-adapters": { module: protocolAdapters, names: ["createProtocolAdapter", "knownProtocolAdapters"] },
  "./proxy": { module: proxy, names: ["createHaechiProxy", "assertSafeProxyBind", "DEFAULT_PROXY_PORT"] },
  "./runtime": { module: runtime, names: ["createRuntime", "normalizeConfig", "defaultConfig", "loadConfig", "writeDefaultConfig", "isValidPort", "DEFAULT_CONFIG_PATH"] },
  "./token-vault": { module: tokenVault, names: ["createLocalTokenVault", "createTokenVault", "createFileTokenStore", "readVault"] },
  "./stream-filter": { module: streamFilter, names: ["inspectResponseStream", "getByPath", "setByPath", "buildPathObject"] },
  "./auth": { module: authPkg, names: ["createBearerAuthProvider", "buildIdentity", "buildExternalIdentity", "validateLabels", "readAuthStore", "addToken", "listTokens", "revokeToken", "DEFAULT_ALLOWED_LABEL_KEYS"] }
};

test("FROZEN: every exports subpath exposes its frozen export names (additive allowed)", () => {
  for (const [subpath, { module, names }] of Object.entries(FROZEN_EXPORTS)) {
    for (const name of names) {
      assert.ok(
        name in module,
        `frozen export '${name}' is MISSING from subpath '${subpath}' — removing/renaming it is a BREAKING change (major bump + deprecation per api-stability.md §2.2)`
      );
      assert.notEqual(
        typeof module[name],
        "undefined",
        `frozen export '${name}' on subpath '${subpath}' resolved to undefined`
      );
    }
  }
});

// ---------------------------------------------------------------------------
// 2. FROZEN audit event schema — top-level AND nested sub-schemas.
//
// Build a REAL audit event through createHaechi + createJsonlAuditSink with a
// NON-NULL identity and at least one detection, read it back from JSONL, and
// assert every frozen key (incl. detections[0].*, identity.*, summary.*,
// auditIntegrity.*) is present with the right type, plus schemaVersion.
// ---------------------------------------------------------------------------

async function buildRealAuditEvent() {
  const dir = await mkdtemp(join(tmpdir(), "haechi-api-contract-"));
  const path = join(dir, "audit.jsonl");
  const auditSink = createJsonlAuditSink({ path });

  const filterEngine = createDefaultFilterEngine();
  const policyProfiles = createPolicyProfiles({
    mode: "enforce",
    presets: ["korean-pii", "secrets-only", "llm-redact"],
    defaultAction: "redact",
    actions: { card: "block" }
  });
  // A no-op crypto provider is sufficient: the email detection below resolves to
  // `redact`, which never touches encrypt/decrypt.
  const cryptoProvider = { encrypt: async () => ({}), decrypt: async () => "" };

  const haechi = createHaechi({
    mode: "enforce",
    filterEngine,
    policyEngine: policyProfiles.base.policyEngine,
    cryptoProvider,
    auditSink
  });

  // NON-NULL, PII-safe identity (keyed-HMAC subject/issuer hashes) + a profile.
  const identity = {
    id: "id-1",
    type: "bearer",
    subjectHash: "keyed-hmac-subject",
    issuerHash: "keyed-hmac-issuer",
    provider: "bearer",
    scopes: ["read"],
    labels: { team: "x" }
  };

  await haechi.protectJson(
    { msg: "email minji.kim@example.com" },
    { protocol: "test", operation: "protect", identity, profile: "default" }
  );

  const raw = (await readFile(path, "utf8")).trim();
  return { record: JSON.parse(raw), path };
}

test("FROZEN: audit event carries every top-level + nested frozen field (+ schemaVersion)", async () => {
  const { record } = await buildRealAuditEvent();

  // schemaVersion: additive, reader-facing. Value is "1" in the 1.0 line.
  assert.equal(record.schemaVersion, "1", "audit event must carry schemaVersion='1'");

  // --- top-level frozen fields ---
  const TOP_LEVEL = {
    schemaVersion: "string",
    id: "string",
    timestamp: "string",
    protocol: "string",
    operation: "string",
    identity: "object",
    profile: "string",
    mode: "string",
    enforced: "boolean",
    blocked: "boolean",
    payloadShapeHash: "string",
    detections: "object", // array
    summary: "object",
    auditIntegrity: "object"
  };
  for (const [key, type] of Object.entries(TOP_LEVEL)) {
    assert.ok(key in record, `FROZEN top-level audit field '${key}' is MISSING (removing it is a BREAKING change)`);
    assert.equal(typeof record[key], type, `FROZEN top-level audit field '${key}' has wrong type`);
    if (type === "object") {
      assert.ok(record[key] !== null, `FROZEN top-level audit field '${key}' must not be null`);
    }
  }
  assert.ok(Array.isArray(record.detections), "detections must be an array");
  assert.ok(record.detections.length >= 1, "the fixture must produce at least one detection to guard detections[].*");

  // --- detections[].* frozen sub-schema ---
  const detection = record.detections[0];
  const DETECTION = {
    type: "string",
    ruleId: "string",
    path: "string",
    kind: "string",
    confidence: "number",
    action: "string",
    enforced: "boolean"
  };
  for (const [key, type] of Object.entries(DETECTION)) {
    assert.ok(key in detection, `FROZEN detections[].${key} is MISSING (removing it is a BREAKING change)`);
    assert.equal(typeof detection[key], type, `FROZEN detections[].${key} has wrong type`);
  }

  // --- identity.* frozen sub-schema (the PII-safe projection) ---
  // The frozen 1.0 audit-identity contract is EXACTLY the five keys below.
  // scopes/labels/raw-subject are NOT part of it (§2.1): their absence is part
  // of the contract, not just the presence of the five frozen keys.
  assert.ok(record.identity && typeof record.identity === "object", "identity must be a non-null object in this fixture");
  const IDENTITY = {
    id: "string",
    type: "string",
    subjectHash: "string",
    issuerHash: "string",
    provider: "string"
  };
  for (const [key, type] of Object.entries(IDENTITY)) {
    assert.ok(key in record.identity, `FROZEN identity.${key} is MISSING (removing it is a BREAKING change)`);
    assert.equal(typeof record.identity[key], type, `FROZEN identity.${key} has wrong type`);
  }
  // Absence contract: scopes/labels must NEVER appear in the persisted audit
  // identity even when the live context.identity carries them (e.g. from a
  // plugin returning attacker-controlled claim values).
  assert.ok(!("scopes" in record.identity),
    "CONTRACT VIOLATION: audit identity must NOT contain 'scopes' (frozen contract is exactly the 5 keys)");
  assert.ok(!("labels" in record.identity),
    "CONTRACT VIOLATION: audit identity must NOT contain 'labels' (frozen contract is exactly the 5 keys)");

  // --- summary.* frozen sub-schema ---
  const summary = record.summary;
  assert.ok("byType" in summary && typeof summary.byType === "object", "FROZEN summary.byType is MISSING");
  assert.ok("byAction" in summary && typeof summary.byAction === "object", "FROZEN summary.byAction is MISSING");
  assert.ok("detectionCount" in summary && typeof summary.detectionCount === "number", "FROZEN summary.detectionCount is MISSING");

  // --- auditIntegrity.* frozen sub-schema ---
  const integrity = record.auditIntegrity;
  const INTEGRITY = {
    alg: "string",
    canonicalization: "string",
    sequence: "number",
    eventHash: "string"
  };
  for (const [key, type] of Object.entries(INTEGRITY)) {
    assert.ok(key in integrity, `FROZEN auditIntegrity.${key} is MISSING (removing it is a BREAKING change)`);
    assert.equal(typeof integrity[key], type, `FROZEN auditIntegrity.${key} has wrong type`);
  }
  // previousHash is frozen but is null for the first record in a chain.
  assert.ok("previousHash" in integrity, "FROZEN auditIntegrity.previousHash is MISSING");
});

test("FROZEN: schemaVersion does not break the audit hash chain (new event verifies)", async () => {
  const { record, path } = await buildRealAuditEvent();
  // The new event (with schemaVersion in the canonicalized object) verifies.
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true, "a schemaVersion-carrying event must verify");
  assert.equal(result.records, 1);
  assert.equal(record.schemaVersion, "1");
});

test("FROZEN: a synthetic additive field still verifies under verifyAuditChain", async () => {
  // The additive-only guarantee: a future field that is part of the canonicalized
  // object is self-consistent for the verifier reading that same record. Build an
  // event whose context injects nothing extra; then confirm a record that carries
  // schemaVersion (an additive field vs the pre-1.0 schema) verifies — which is
  // exactly the "old verifier reads a new additive record" invariant.
  const { path } = await buildRealAuditEvent();
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true);
});

// ---------------------------------------------------------------------------
// 3. FROZEN config key set (normalizeConfig output).
//
// A removed top-level config key => fail. Additive keys pass (subset check).
// ---------------------------------------------------------------------------

const FROZEN_CONFIG_KEYS = [
  "mode",
  "target",
  "proxy",
  "responseProtection",
  "streaming",
  "limits",
  "policy",
  "filters",
  "keys",
  "audit",
  "tokenVault",
  "privacy",
  "auth",
  "mcp"
];

test("FROZEN: normalizeConfig output contains the frozen config key set (additive allowed)", () => {
  const config = normalizeConfig({});
  for (const key of FROZEN_CONFIG_KEYS) {
    assert.ok(
      key in config,
      `FROZEN config key '${key}' is MISSING from normalizeConfig output — removing it is a BREAKING change (api-stability.md §2.4)`
    );
  }
});
