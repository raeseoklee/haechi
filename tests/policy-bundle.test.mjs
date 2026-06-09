import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { signPolicyBundleFile, verifyPolicyBundleFile } from "../packages/policy-bundle/index.mjs";
import { createRuntime } from "../packages/cli/runtime.mjs";

test("signed policy bundle verifies and can be loaded by runtime", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-policy-bundle-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const policyPath = join(dir, "policy.json");
  const bundlePath = join(dir, "policy.bundle.json");
  await initLocalKeyFile(keyFile, { force: true });
  await writeFile(policyPath, JSON.stringify({
    mode: "enforce",
    presets: [],
    defaultAction: "allow",
    actions: {
      email: "redact"
    }
  }), "utf8");

  await signPolicyBundleFile({ policyPath, keyFile, outPath: bundlePath });
  const verified = await verifyPolicyBundleFile({ bundlePath, keyFile });
  assert.equal(verified.valid, true);

  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      bundlePath
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  const result = await runtime.haechi.protectJson({ message: "minji.kim@example.com" });
  assert.equal(result.payload.message, "[REDACTED:email]");
});

test("signed policy bundle rejects tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-policy-bundle-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const policyPath = join(dir, "policy.json");
  const bundlePath = join(dir, "policy.bundle.json");
  await initLocalKeyFile(keyFile, { force: true });
  await writeFile(policyPath, JSON.stringify({
    mode: "enforce",
    actions: {
      email: "redact"
    }
  }), "utf8");

  await signPolicyBundleFile({ policyPath, keyFile, outPath: bundlePath });
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  bundle.policy.actions.email = "allow";
  await writeFile(bundlePath, JSON.stringify(bundle), "utf8");

  await assert.rejects(
    () => verifyPolicyBundleFile({ bundlePath, keyFile }),
    /signature verification failed/i
  );
});
