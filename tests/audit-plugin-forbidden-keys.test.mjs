import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createJsonlAuditSink, sanitizeAudit, verifyAuditChain } from "../packages/audit/index.mjs";

// The plugin/claims surface added to FORBIDDEN_KEYS in 1.0 (§2.4) — additive to
// the value/plaintext/... + OIDC sets.
const PLUGIN_FORBIDDEN_KEYS = [
  "claims", "subject", "issuer", "credential", "authorization", "signature", "entry"
];

test("sanitizeAudit strips the plugin/claims surface at every depth", () => {
  const event = {
    id: "plugin-e1",
    operation: "plugin.authenticate.deny",
    pluginId: "acme-auth",
    signerKeyId: "anchor-1",
    // A future/hostile plugin event carrying raw claim / credential / signer
    // material that must never enter the chained log.
    claims: { sub: "raw-subject", iss: "raw-issuer" },
    subject: "raw-subject-value",
    issuer: "raw-issuer-value",
    credential: "Bearer raw-token",
    authorization: "Bearer raw-token",
    signature: "ed25519-sig-bytes",
    entry: "export default { backdoor }",
    nested: { credential: "nested-token", reasonCode: "ok" },
    list: [{ signature: "sig-in-array", keep: 1 }]
  };

  const sanitized = sanitizeAudit(event);

  for (const key of PLUGIN_FORBIDDEN_KEYS) {
    assert.equal(key in sanitized, false, `top-level ${key} must be stripped`);
  }
  assert.equal("credential" in sanitized.nested, false, "nested credential must be stripped");
  assert.equal("signature" in sanitized.list[0], false, "array-nested signature must be stripped");

  // Safe id/hash fields survive untouched.
  assert.equal(sanitized.pluginId, "acme-auth");
  assert.equal(sanitized.signerKeyId, "anchor-1");
  assert.equal(sanitized.nested.reasonCode, "ok");
  assert.equal(sanitized.list[0].keep, 1);
});

test("the audit sink strips a synthetic plugin event's raw claims and the chain stays valid", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-plugin-"));
  const path = join(dir, "audit.jsonl");
  const sink = createJsonlAuditSink({ path });

  // Two events so the chain links a previous->current hash.
  await sink.record({
    id: "p-load",
    timestamp: new Date(0).toISOString(),
    protocol: "plugin",
    operation: "plugin.load.refused",
    mode: "enforce",
    enforced: true,
    blocked: true,
    pluginId: "acme-auth",
    signerKeyId: "anchor-1",
    reason: "tampered-entry",
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  });

  await sink.record({
    id: "p-deny",
    timestamp: new Date(1).toISOString(),
    protocol: "plugin",
    operation: "plugin.authenticate.deny",
    mode: "enforce",
    enforced: true,
    blocked: true,
    pluginId: "acme-auth",
    // Hostile/raw material that MUST be stripped:
    claims: { sub: "RAW-SUBJECT", iss: "RAW-ISSUER" },
    subject: "RAW-SUBJECT",
    issuer: "RAW-ISSUER",
    credential: "Bearer RAW-TOKEN",
    authorization: "Bearer RAW-TOKEN",
    signature: "RAW-SIG",
    entry: "RAW-ENTRY-BYTES",
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  });

  const raw = await readFile(path, "utf8");
  const lines = raw.trim().split("\n");
  const denyRecord = JSON.parse(lines[1]);

  // None of the forbidden keys survive into the persisted record...
  for (const key of PLUGIN_FORBIDDEN_KEYS) {
    assert.equal(key in denyRecord, false, `${key} must not be persisted`);
  }
  // ...and none of their raw values appear anywhere in the serialized log.
  for (const secret of ["RAW-SUBJECT", "RAW-ISSUER", "RAW-TOKEN", "RAW-SIG", "RAW-ENTRY-BYTES"]) {
    assert.equal(raw.includes(secret), false, `raw value ${secret} must not leak into the audit line`);
  }

  // The safe fields persist and the hash chain still verifies.
  assert.equal(denyRecord.pluginId, "acme-auth");
  assert.equal(denyRecord.operation, "plugin.authenticate.deny");
  const verification = await verifyAuditChain(path);
  assert.equal(verification.valid, true, verification.reason);
  assert.equal(verification.records, 2);
});
