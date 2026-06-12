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

// WS2d — Unicode-evasion enforcement. Proves the TRANSFORM (not just detection):
// an evaded value is actually redacted/blocked, and neither the evaded nor the
// folded form leaks into the payload or the audit. SYNTHETIC values throughout.
const fwDigits = (s) => [...s].map((c) => (/[0-9]/.test(c) ? String.fromCharCode(0xFF10 + Number(c)) : c)).join("");
const mathDigits = (s) => [...s].map((c) => (/[0-9]/.test(c) ? String.fromCodePoint(0x1D7CE + Number(c)) : c)).join("");
const FW_AT = String.fromCharCode(0xFF20);

test("WS2d: a full-width-@ email (same-length NFKC) is redacted in enforce mode; nothing leaks to payload or audit", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-ws2d-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const evadedEmail = `minji.kim${FW_AT}example.com`;
  const result = await runtime.haechi.protectJson({ message: `contact ${evadedEmail} now` });

  assert.match(result.payload.message, /\[REDACTED:email\]/);
  // Neither the evaded full-width form nor its ASCII fold remains in the output.
  assert.doesNotMatch(result.payload.message, /minji\.kim/);
  assert.ok(!result.payload.message.includes(evadedEmail), "the evaded span is gone from the payload");

  const audit = await readFile(auditPath, "utf8");
  assert.ok(!audit.includes(evadedEmail), "the evaded value never reaches the audit log");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  assert.equal((await verifyAuditChain(auditPath)).valid, true);
});

test("WS2d: a full-width-digit card (same-length, Case 2) and a mathematical-bold KR RRN (length-divergent, Case 3) both BLOCK in enforce mode", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-ws2d-block-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    // korean-pii pins kr_rrn->block; default card->block via secrets/llm presets.
    policy: { mode: "enforce", presets: ["korean-pii", "secrets-only", "llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  // Case 2: full-width card folds to a Luhn-valid PAN -> hard-block.
  const fwCard = fwDigits("4242424242424242");
  const cardResult = await runtime.haechi.protectJson({ note: `card ${fwCard} on file` });
  assert.equal(cardResult.blocked, true, "a full-width card is blocked, not forwarded");
  assert.equal(cardResult.payload, null);

  // Case 3: mathematical-bold RRN folds to a checksum-valid RRN; offsets diverge
  // so the whole leaf is blocked fail-closed.
  const mathRrn = `${mathDigits("900101")}-${mathDigits("1234568")}`;
  const rrnResult = await runtime.haechi.protectJson({ note: `rrn ${mathRrn} here` });
  assert.equal(rrnResult.blocked, true, "a length-divergent evaded RRN blocks the whole leaf fail-closed");
  assert.equal(rrnResult.payload, null);

  // No evaded value reaches the audit log.
  const audit = await readFile(auditPath, "utf8");
  assert.ok(!audit.includes(fwCard), "the full-width card never reaches the audit log");
  assert.ok(!audit.includes(mathRrn), "the math-bold RRN never reaches the audit log");
  assert.equal((await verifyAuditChain(auditPath)).valid, true);
});

test("WS2d: a normal multi-field ASCII payload still redacts the EXACT span (offset integrity, no regression)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-ws2d-ascii-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact", actions: { phone: "redact" } },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  // NFKC-stable ASCII: the surrounding text is preserved verbatim, only the exact
  // PII spans are replaced (proves offsets index the original string precisely).
  const input = { content: "ping minji.kim@example.com at 010-1234-5678 before noon" };
  assert.equal(input.content, input.content.normalize("NFKC"), "fixture is NFKC-stable");
  const result = await runtime.haechi.protectJson(input);
  assert.equal(result.payload.content, "ping [REDACTED:email] at [REDACTED:phone] before noon");
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
  const chain = await verifyAuditChain(auditPath);
  assert.equal(chain.valid, true);
  assert.equal(chain.records, 2);
  assert.match(chain.headHash, /^[A-Za-z0-9_-]{43}$/);

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

  const chain = await verifyAuditChain(auditPath);
  assert.equal(chain.valid, true);
  assert.equal(chain.records, 20);
});
