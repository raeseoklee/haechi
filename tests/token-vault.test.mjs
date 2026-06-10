import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { createLocalCryptoProvider, initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createLocalTokenVault } from "../packages/token-vault/index.mjs";

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
    tokenVault: {
      path: vaultPath,
      revealPolicy: "local-dev"
    }
  });

  const result = await runtime.haechi.protectJson({
    message: "contact minji.kim@example.com"
  }, { protocol: "llm-http", operation: "tokenize-test" });

  const token = result.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];
  const vault = await readFile(vaultPath, "utf8");

  assert.doesNotMatch(vault, /minji\.kim@example\.com/);
  assert.equal((await runtime.tokenVault.reveal({ token })).plaintext, "minji.kim@example.com");
  const metadata = await runtime.tokenVault.exportMetadata({ type: "email" });
  assert.equal(metadata.length, 1);
  assert.equal(metadata[0].token, token);
  assert.equal(metadata[0].type, "email");
  assert.doesNotMatch(JSON.stringify(metadata), /minji\.kim@example\.com/);
});

test("token reveal is disabled by default", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-token-vault-disabled-"));
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
  await assert.rejects(
    () => runtime.tokenVault.reveal({ token }),
    /Token reveal is disabled/
  );
});

test("token vault metadata does not expose sensitive object key names", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-token-vault-path-"));
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
    tokenVault: {
      path: vaultPath,
      revealPolicy: "local-dev"
    }
  });

  const result = await runtime.haechi.protectJson({
    "minji.kim@example.com": "contact seoul@example.com"
  });

  const metadata = await runtime.tokenVault.exportMetadata({ type: "email" });
  const serializedMetadata = JSON.stringify(metadata);
  const audit = await readFile(auditPath, "utf8");

  // Both the email key and the email inside the value are tokenized.
  assert.equal(metadata.length, 2);
  assert.equal(result.payload["minji.kim@example.com"], undefined);
  assert.doesNotMatch(serializedMetadata, /minji\.kim@example\.com/);
  assert.doesNotMatch(serializedMetadata, /seoul@example\.com/);
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  assert.doesNotMatch(audit, /seoul@example\.com/);
});

test("token vault keeps all records under concurrent tokenization", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-token-vault-concurrent-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const vaultPath = join(dir, ".haechi", "token-vault.json");
  await initLocalKeyFile(keyFile, { force: true });
  const vault = createLocalTokenVault({
    path: vaultPath,
    cryptoProvider: createLocalCryptoProvider({ keyFile }),
    revealPolicy: "local-dev"
  });

  const results = await Promise.all(Array.from({ length: 20 }, (_, index) => vault.tokenize({
    plaintext: `user-${index}@example.com`,
    type: "email",
    context: { test: "concurrent" },
    metadata: { path: `entries[${index}]` }
  })));

  const metadata = await vault.exportMetadata({ type: "email" });
  assert.equal(new Set(results.map((result) => result.token)).size, 20);
  assert.equal(metadata.length, 20);
});
