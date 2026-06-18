import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";

const CLI = fileURLToPath(new URL("../packages/cli/bin/haechi.mjs", import.meta.url));

function run(args, cwd) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
  return { ...result, json: result.stdout ? JSON.parse(result.stdout) : null };
}

async function initProject(dir) {
  const init = run(["init", "--force"], dir);
  assert.equal(init.status, 0);
}

test("audit-verify reports a valid chain with its head hash", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-verify-"));
  await initProject(dir);
  await writeFile(join(dir, "input.json"), JSON.stringify({ message: "mail minji.kim@example.com" }), "utf8");
  assert.equal(run(["protect", "input.json"], dir).status, 0);
  assert.equal(run(["protect", "input.json"], dir).status, 0);

  const verify = run(["audit-verify"], dir);
  assert.equal(verify.status, 0);
  assert.equal(verify.json.ok, true);
  assert.equal(verify.json.result.valid, true);
  assert.equal(verify.json.result.records, 2);
  assert.match(verify.json.result.headHash, /^[A-Za-z0-9_-]{43}$/);
});

test("audit-verify fails closed on a tampered chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-tamper-"));
  await initProject(dir);
  await writeFile(join(dir, "input.json"), JSON.stringify({ message: "mail minji.kim@example.com" }), "utf8");
  assert.equal(run(["protect", "input.json"], dir).status, 0);

  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const record = JSON.parse((await readFile(auditPath, "utf8")).trim());
  record.summary.detectionCount = 99;
  await writeFile(auditPath, `${JSON.stringify(record)}\n`, "utf8");

  const verify = run(["audit-verify"], dir);
  assert.equal(verify.status, 4);
  assert.equal(verify.json.ok, false);
  assert.equal(verify.json.result.reason, "event hash mismatch");
});

test("status reports non-enforcing defaults with explicit warnings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-status-dryrun-"));
  await initProject(dir);

  const status = run(["status"], dir);
  assert.equal(status.status, 0);
  const body = status.json;

  assert.equal(body.protection.policyMode, "dry-run");
  assert.equal(body.protection.enforced, false);
  assert.equal(body.protection.responseProtection.enabled, false);
  assert.equal(body.keys.exists, true);
  assert.equal(body.keys.permissions, "0600");
  // A freshly initialized local key surfaces an unused nonce budget (no warning).
  assert.equal(body.keys.nonceBudget.used, 0);
  assert.equal(body.keys.nonceBudget.exhausted, false);
  assert.equal(body.keys.nonceBudget.usedPercent, 0);
  assert.ok(body.keys.nonceBudget.limit > 0 && body.keys.nonceBudget.remaining === body.keys.nonceBudget.limit);
  assert.ok(!body.warnings.some((line) => line.includes("safe encryption budget")));
  assert.equal(body.tokenVault.detokenizeResponses, false);
  assert.ok(body.warnings.some((line) => line.includes("dry-run")));
  assert.ok(body.warnings.some((line) => line.includes("responseProtection")));
});

test("status flags detokenization that can never run and verifies the audit chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-status-misconfig-"));
  await initProject(dir);

  const configPath = join(dir, "haechi.config.json");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  config.mode = "enforce";
  config.policy.mode = "enforce";
  config.tokenVault.detokenizeResponses = true;
  config.responseProtection.enabled = false;
  await writeFile(configPath, JSON.stringify(config, null, 2), "utf8");

  await writeFile(join(dir, "input.json"), JSON.stringify({ message: "mail minji.kim@example.com" }), "utf8");
  assert.equal(run(["protect", "input.json"], dir).status, 0);

  const status = run(["status"], dir);
  const body = status.json;

  assert.equal(body.protection.enforced, true);
  assert.ok(body.warnings.some((line) => line.includes("detokenization never runs")));
  assert.equal(body.audit.exists, true);
  assert.equal(body.audit.chain.valid, true);
  assert.equal(body.audit.chain.records, 1);
  // Enforce mode with the dry-run warning gone.
  assert.ok(!body.warnings.some((line) => line.includes("dry-run")));
});
