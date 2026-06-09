import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

test("tokenize action stores encrypted mapping in local token vault", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-token-vault-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: {
        email: "tokenize"
      }
    },
    keys: { keyFile },
    audit: { path: auditPath },
    tokenVault: { path: vaultPath }
  });

  const result = await runtime.haechi.protectJson({
    message: "contact minji.kim@example.com"
  }, { protocol: "llm-http", operation: "tokenize-test" });

  const token = result.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];
  const vault = await readFile(vaultPath, "utf8");

  assert.doesNotMatch(vault, /minji\.kim@example\.com/);
  assert.equal((await runtime.tokenVault.reveal({ token })).plaintext, "minji.kim@example.com");
});
