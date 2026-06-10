#!/usr/bin/env node
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

const sizeKb = Number(process.env.HAECHI_BENCH_SIZE_KB ?? 256);
const iterations = Number(process.env.HAECHI_BENCH_ITERATIONS ?? 10);
const dir = await mkdtemp(join(tmpdir(), "haechi-bench-"));
const keyFile = join(dir, ".haechi", "dev.keys.json");
await initLocalKeyFile(keyFile, { force: true });

const runtime = createRuntime({
  mode: "enforce",
  policy: {
    mode: "enforce",
    presets: ["llm-redact"]
  },
  keys: { keyFile },
  audit: { path: join(dir, ".haechi", "audit.jsonl") }
});

const filler = "a".repeat(Math.max(0, sizeKb * 1024 - 64));
const payload = {
  messages: [
    {
      role: "user",
      content: `${filler} minji.kim@example.com`
    }
  ]
};

const started = performance.now();
for (let index = 0; index < iterations; index += 1) {
  await runtime.haechi.protectJson(payload, {
    protocol: "bench",
    operation: "payload"
  });
}
const elapsedMs = performance.now() - started;

process.stdout.write(`${JSON.stringify({
  sizeKb,
  iterations,
  totalMs: Math.round(elapsedMs),
  averageMs: Math.round((elapsedMs / iterations) * 100) / 100
}, null, 2)}\n`);
