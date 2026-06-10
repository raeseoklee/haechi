import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { createJsonlAuditSink, verifyAuditChain } from "../packages/audit/index.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { buildPolicy } from "../packages/policy/index.mjs";

test("pipeline redacts and masks in enforce mode without audit plaintext", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pipeline-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      actions: {
        phone: "mask"
      }
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const input = {
    messages: [
      {
        role: "user",
        content: "email minji.kim@example.com phone 010-1234-5678"
      }
    ]
  };

  const result = await runtime.haechi.protectJson(input, { protocol: "llm-http", operation: "test" });
  const content = result.payload.messages[0].content;

  assert.match(content, /\[REDACTED:email\]/);
  assert.doesNotMatch(content, /minji\.kim@example\.com/);
  assert.doesNotMatch(content, /010-1234-5678/);

  const audit = await readFile(auditPath, "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  assert.doesNotMatch(audit, /010-1234-5678/);
  assert.equal((await verifyAuditChain(auditPath)).valid, true);
});

test("pipeline blocks configured secrets in enforce mode", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pipeline-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["secrets-only"],
      defaultAction: "allow"
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const result = await runtime.haechi.protectJson({
    prompt: "token sk_demo_1234567890abcdef1234567890abcdef"
  });

  assert.equal(result.blocked, true);
  assert.equal(result.payload, null);
  assert.equal(result.summary.byAction.block, 1);

  const audit = await readFile(auditPath, "utf8");
  assert.doesNotMatch(audit, /sk_demo_/);
});

test("pipeline audit paths do not expose sensitive object key names", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-pipeline-path-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact"
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const result = await runtime.haechi.protectJson({
    "minji.kim@example.com": "contact seoul@example.com"
  });

  // PII used as an object key is transformed too, not forwarded in plaintext.
  assert.equal(result.payload["minji.kim@example.com"], undefined);
  assert.equal(result.payload["[REDACTED:email]"], "contact [REDACTED:email]");

  const audit = await readFile(auditPath, "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  assert.doesNotMatch(audit, /seoul@example\.com/);
});

test("policy rejects unsafe action downgrades by default", () => {
  assert.throws(
    () => buildPolicy({
      presets: ["secrets-only"],
      actions: {
        api_key: "allow"
      }
    }),
    /Policy action conflict/
  );
});

test("audit hash chain detects tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-chain-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  await runtime.haechi.protectJson({ message: "seoul@example.com" });
  assert.deepEqual(await verifyAuditChain(auditPath), { valid: true, records: 2 });

  const lines = (await readFile(auditPath, "utf8")).trim().split("\n");
  const first = JSON.parse(lines[0]);
  first.summary.detectionCount = 99;
  await writeFile(auditPath, `${JSON.stringify(first)}\n${lines[1]}\n`, "utf8");

  const verification = await verifyAuditChain(auditPath);
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, "event hash mismatch");
});

test("audit hash chain remains valid under concurrent writes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-concurrent-"));
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const sink = createJsonlAuditSink({ path: auditPath });

  await Promise.all(Array.from({ length: 20 }, (_, index) => sink.record({
    id: `event-${index}`,
    timestamp: new Date(0).toISOString(),
    protocol: "test",
    operation: "concurrent",
    mode: "enforce",
    enforced: true,
    blocked: false,
    summary: {
      detectionCount: 0,
      byType: {},
      byAction: {}
    }
  })));

  assert.deepEqual(await verifyAuditChain(auditPath), { valid: true, records: 20 });
});
