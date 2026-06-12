import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { applyPrecisionControls } from "../packages/core/index.mjs";
import { HARD_BLOCK_TYPES } from "../packages/filter/index.mjs";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

// Helper: a minimal detection record of the shape the filter engine emits.
function detection({ type, confidence = 0.7, value = "x", pathText = "content" }) {
  return { type, ruleId: `rule-${type}`, path: ["content"], pathText, kind: "value", start: 0, end: value.length, confidence, value };
}

// ---------------------------------------------------------------------------
// applyPrecisionControls — the WS2c gate (pure logic).
// ---------------------------------------------------------------------------

test("minConfidence drops a low-confidence SOFT detection but never a hard-block type", () => {
  const detections = [
    detection({ type: "phone", confidence: 0.75 }),   // soft, below 0.8 -> dropped
    detection({ type: "email", confidence: 0.95 }),   // soft, above 0.8 -> kept
    detection({ type: "card", confidence: 0.75 }),    // HARD-BLOCK, low conf -> KEPT (fail-closed)
    detection({ type: "secret", confidence: 0.6 }),   // HARD-BLOCK -> KEPT
    detection({ type: "api_key", confidence: 0.1 }),  // HARD-BLOCK -> KEPT
    detection({ type: "kr_rrn", confidence: 0.1 })    // HARD-BLOCK -> KEPT
  ];
  const { detections: kept, precisionAudit } = applyPrecisionControls(detections, { minConfidence: 0.8 });
  const keptTypes = kept.map((d) => d.type).sort();
  assert.deepEqual(keptTypes, ["api_key", "card", "email", "kr_rrn", "secret"], "only the low-confidence SOFT phone is dropped");
  assert.equal(precisionAudit.droppedCount, 1);
  assert.deepEqual(precisionAudit.droppedByType, { phone: 1 });
  // Every hard-block type survived the dial regardless of confidence.
  for (const type of HARD_BLOCK_TYPES) {
    assert.ok(kept.some((d) => d.type === type), `hard-block type ${type} must never be dropped by minConfidence`);
  }
});

test("minConfidence default 0 keeps everything (current 1.1 behavior)", () => {
  const detections = [detection({ type: "phone", confidence: 0.6 }), detection({ type: "email", confidence: 0.6 })];
  const { detections: kept, precisionAudit } = applyPrecisionControls(detections, {});
  assert.equal(kept.length, 2);
  assert.equal(precisionAudit.droppedCount, 0);
  assert.equal(precisionAudit.suppressedCount, 0);
});

test("allowlist suppresses a SOFT detection by value and by path, and AUDITS the suppression", () => {
  const detections = [
    detection({ type: "phone", value: "01099887766", pathText: "orderId" }),
    detection({ type: "email", value: "ok@example.com", pathText: "to" })
  ];
  // Suppress the phone by exact value; leave the email.
  const byValue = applyPrecisionControls(detections, { allowlist: { values: new Set(["01099887766"]), paths: new Set(), pairs: [] } });
  assert.deepEqual(byValue.detections.map((d) => d.type), ["email"]);
  assert.equal(byValue.precisionAudit.suppressedCount, 1);
  assert.deepEqual(byValue.precisionAudit.suppressedByType, { phone: 1 });

  // Suppress by PII-safe path instead.
  const byPath = applyPrecisionControls(detections, { allowlist: { values: new Set(), paths: new Set(["orderId"]), pairs: [] } });
  assert.deepEqual(byPath.detections.map((d) => d.type), ["email"]);
  assert.equal(byPath.precisionAudit.suppressedCount, 1);
});

test("allowlist NEVER suppresses a hard-block type even on an exact value/path match", () => {
  const card = detection({ type: "card", value: "4242424242424242", pathText: "orderNumber" });
  const secret = detection({ type: "secret", value: "Bearer abcdef0123456789", pathText: "note" });
  const apiKey = detection({ type: "api_key", value: "sk_live_xxx", pathText: "k" });
  const rrn = detection({ type: "kr_rrn", value: "900101-1234568", pathText: "id" });
  const allowlist = {
    values: new Set(["4242424242424242", "Bearer abcdef0123456789", "sk_live_xxx", "900101-1234568"]),
    paths: new Set(["orderNumber", "note", "k", "id"]),
    pairs: []
  };
  const { detections: kept, precisionAudit } = applyPrecisionControls([card, secret, apiKey, rrn], { allowlist });
  // All four hard-block detections still fire — the allowlist entry is ignored.
  assert.deepEqual(kept.map((d) => d.type).sort(), ["api_key", "card", "kr_rrn", "secret"]);
  assert.equal(precisionAudit.suppressedCount, 0, "no hard-block detection may be suppressed");
});

// ---------------------------------------------------------------------------
// normalizeConfig — fail-closed validation of the additive config.
// ---------------------------------------------------------------------------

test("normalizeConfig defaults: minConfidence 0, allowlist [] (additive, 1.1-preserving)", () => {
  const config = normalizeConfig({});
  assert.equal(config.filters.minConfidence, 0);
  assert.deepEqual(config.filters.allowlist, []);
});

test("normalizeConfig rejects an out-of-range minConfidence and a malformed allowlist (fail-closed)", () => {
  assert.throws(() => normalizeConfig({ filters: { minConfidence: 1.5 } }), /minConfidence must be a number in \[0, 1\]/);
  assert.throws(() => normalizeConfig({ filters: { minConfidence: -0.1 } }), /minConfidence must be a number in \[0, 1\]/);
  assert.throws(() => normalizeConfig({ filters: { minConfidence: "high" } }), /minConfidence must be a number/);
  assert.throws(() => normalizeConfig({ filters: { allowlist: "nope" } }), /allowlist must be an array/);
  assert.throws(() => normalizeConfig({ filters: { allowlist: [123] } }), /must be a string or a \{ value\?, path\? \} object/);
  assert.throws(() => normalizeConfig({ filters: { allowlist: [{}] } }), /must set value and\/or path/);
  assert.throws(() => normalizeConfig({ filters: { allowlist: [{ value: "" }] } }), /entry.value must be a non-empty string/);
});

test("normalizeConfig accepts a well-formed allowlist (string + object entries)", () => {
  const config = normalizeConfig({ filters: { minConfidence: 0.8, allowlist: ["01099887766", { value: "x", path: "y" }, { path: "z" }] } });
  assert.equal(config.filters.minConfidence, 0.8);
  assert.equal(config.filters.allowlist.length, 3);
});

// ---------------------------------------------------------------------------
// End-to-end through createRuntime: the control runs in the detect→decide path
// and the suppression/drop is recorded in the (no-plaintext) audit event.
// ---------------------------------------------------------------------------

async function runtimeFor(filters) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-precision-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    filters,
    keys: { keyFile },
    audit: { path: auditPath }
  });
  return { runtime, auditPath };
}

test("allowlist clears a benign phone FP end-to-end; the audit records the suppression by count/type, never the value", async () => {
  const { runtime, auditPath } = await runtimeFor({ allowlist: ["01099887766"] });
  const result = await runtime.haechi.protectJson({ note: "order id 01099887766 shipped, contact 010-1234-5678" });
  // The allowlisted order id is no longer transformed; the real mobile still is.
  assert.match(result.payload.note, /order id 01099887766 shipped/, "allowlisted FP value is left intact");
  assert.doesNotMatch(result.payload.note, /010-1234-5678/, "the real mobile is still redacted");
  assert.equal(result.summary.suppressedCount, 1);
  assert.deepEqual(result.summary.suppressedByType, { phone: 1 });

  const audit = await readFile(auditPath, "utf8");
  const event = JSON.parse(audit.trim());
  assert.equal(event.summary.suppressedCount, 1);
  assert.deepEqual(event.summary.suppressedByType, { phone: 1 });
  // No raw value of the suppressed detection in the audit log.
  assert.doesNotMatch(audit, /01099887766/, "the suppressed value must never appear in the audit log");
  assert.doesNotMatch(audit, /010-1234-5678/, "no plaintext PII in audit");
});

test("allowlist CANNOT clear a card (hard-block) end-to-end — the card is still blocked and not suppressed", async () => {
  const { runtime } = await runtimeFor({ allowlist: ["4242424242424242"] });
  const result = await runtime.haechi.protectJson({ note: "please process order 4242424242424242 today" });
  // card defaults to block (the runtime default actions set card: "block").
  assert.equal(result.blocked, true, "an allowlisted card still blocks — hard-block is fail-closed");
  assert.ok(!result.summary.suppressedCount, "the card detection is not suppressed");
});

test("minConfidence end-to-end: a sub-threshold SOFT detection is dropped and audited as a drop", async () => {
  // The us-phone rule emits confidence 0.75; minConfidence 0.8 drops it (phone is soft).
  const { runtime } = await runtimeFor({ minConfidence: 0.8 });
  const result = await runtime.haechi.protectJson({ note: "call (415) 555-2671 today" });
  assert.equal(result.summary.detectionCount, 0, "the 0.75-confidence US phone is dropped below minConfidence 0.8");
  assert.equal(result.summary.droppedCount, 1);
  assert.deepEqual(result.summary.droppedByType, { phone: 1 });
  assert.match(result.payload.note, /\(415\) 555-2671/, "the dropped detection is not transformed");
});

test("minConfidence does NOT drop a low-confidence hard-block detection end-to-end (fail-closed)", async () => {
  // The card-like rule emits confidence 0.75; a high minConfidence must not drop it.
  const { runtime } = await runtimeFor({ minConfidence: 0.99 });
  const result = await runtime.haechi.protectJson({ note: "card 4242 4242 4242 4242 on file" });
  assert.equal(result.blocked, true, "a 0.75-confidence card is kept and acted on despite minConfidence 0.99");
});
