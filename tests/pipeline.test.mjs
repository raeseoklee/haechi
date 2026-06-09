import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

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
