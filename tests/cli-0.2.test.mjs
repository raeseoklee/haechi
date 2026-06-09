import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const CLI = resolve("packages/cli/bin/haechi.mjs");
const PLUGIN_EXAMPLE = resolve("examples/plugins/custom-filter.plugin.json");

test("0.2 CLI policy bundle, plugin validation, and token reveal work", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-cli-02-"));
  assert.equal(spawnSync(process.execPath, [CLI, "init", "--force"], { cwd: dir }).status, 0);

  const policyPath = join(dir, "policy.json");
  const bundlePath = join(dir, "policy.bundle.json");
  await writeFile(policyPath, JSON.stringify({
    mode: "enforce",
    presets: [],
    defaultAction: "allow",
    actions: {
      email: "tokenize"
    }
  }), "utf8");

  const sign = spawnSync(process.execPath, [CLI, "policy-sign", policyPath, "--out", bundlePath], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(sign.status, 0, sign.stderr);

  const verify = spawnSync(process.execPath, [CLI, "policy-verify", bundlePath], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(verify.status, 0, verify.stderr);

  const plugin = spawnSync(process.execPath, [CLI, "plugin-validate", PLUGIN_EXAMPLE], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(plugin.status, 0, plugin.stderr);

  const config = JSON.parse(await readFile(join(dir, "haechi.config.json"), "utf8"));
  config.mode = "enforce";
  config.policy = {
    mode: "enforce",
    bundlePath
  };
  await writeFile(join(dir, "haechi.config.json"), JSON.stringify(config), "utf8");

  const inputPath = join(dir, "input.json");
  await writeFile(inputPath, JSON.stringify({
    message: "contact minji.kim@example.com"
  }), "utf8");

  const protect = spawnSync(process.execPath, [CLI, "protect", inputPath], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(protect.status, 0, protect.stderr);
  const protectedOutput = JSON.parse(protect.stdout);
  const token = protectedOutput.payload.message.match(/\[TOKEN:(tok_email_[a-f0-9]+)\]/)[1];

  const deniedReveal = spawnSync(process.execPath, [CLI, "token-reveal", token], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.notEqual(deniedReveal.status, 0);
  assert.match(deniedReveal.stderr, /Token reveal is disabled/);

  const reveal = spawnSync(process.execPath, [CLI, "token-reveal", token, "--allow-dev-reveal"], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(reveal.status, 0, reveal.stderr);
  assert.equal(JSON.parse(reveal.stdout).plaintext, "minji.kim@example.com");

  const exported = spawnSync(process.execPath, [CLI, "token-export", "--type", "email"], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(exported.status, 0, exported.stderr);
  assert.equal(JSON.parse(exported.stdout).tokens[0].token, token);
  assert.doesNotMatch(exported.stdout, /minji\.kim@example\.com/);
});
