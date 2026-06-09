import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const CLI = resolve("packages/cli/bin/haechi.mjs");

test("CLI init/protect/report quickstart works", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-cli-"));
  const inputPath = join(dir, "input.json");
  await writeFile(inputPath, JSON.stringify({
    messages: [
      {
        role: "user",
        content: "email minji.kim@example.com phone 010-1234-5678"
      }
    ]
  }), "utf8");

  const init = spawnSync(process.execPath, [CLI, "init", "--force"], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(init.status, 0, init.stderr);

  const protect = spawnSync(process.execPath, [CLI, "protect", inputPath], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(protect.status, 0, protect.stderr);
  const output = JSON.parse(protect.stdout);
  assert.equal(output.summary.detectionCount, 2);

  const report = spawnSync(process.execPath, [CLI, "report"], {
    cwd: dir,
    encoding: "utf8"
  });
  assert.equal(report.status, 0, report.stderr);
  const summary = JSON.parse(report.stdout);
  assert.equal(summary.summary.events, 1);
  assert.equal(summary.summary.detections, 2);

  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
});
