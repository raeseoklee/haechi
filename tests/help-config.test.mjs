import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../packages/cli/bin/haechi.mjs", import.meta.url));

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("help lists every command and exits clean", () => {
  const result = run(["help"]);
  assert.equal(result.status ?? 0, 0);
  for (const name of ["init", "protect", "status", "audit-verify", "proxy", "mcp-wrap", "config"]) {
    assert.match(result.stdout, new RegExp(`\\b${name}\\b`));
  }
});

test("no args prints help", () => {
  const result = run([]);
  assert.match(result.stdout, /Usage:/);
});

test("help <command> prints command-specific usage", () => {
  const result = run(["help", "proxy"]);
  assert.match(result.stdout, /haechi proxy —/);
  assert.match(result.stdout, /--allow-remote-bind/);
});

test("config guide covers binding and key settings", () => {
  const result = run(["config"]);
  assert.equal(result.status ?? 0, 0);
  assert.match(result.stdout, /configuration guide/i);
  assert.match(result.stdout, /--allow-remote-bind/);
  assert.match(result.stdout, /detokenizeResponses/);
  assert.match(result.stdout, /docs\/current\/configuration\.md/);
});

test("unknown command fails with guidance", () => {
  const result = run(["frobnicate"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unknown command: frobnicate/);
  assert.match(result.stderr, /haechi help/);
});
