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

// Worst-case shape knobs. Kept well under the default limits.maxNestingDepth
// (256) and a sane fan-out so the bench exercises the hot path, not the
// fail-closed guard. Override via env to probe the boundary.
const nestingDepth = Number(process.env.HAECHI_BENCH_NESTING_DEPTH ?? 200);
const fanOutKeys = Number(process.env.HAECHI_BENCH_FANOUT_KEYS ?? 5000);

function buildDeeplyNested(depth) {
  // A linear chain `depth` levels deep with a PII leaf at the bottom — stresses
  // the recursive tree walk without a large byte footprint.
  let node = { content: "minji.kim@example.com" };
  for (let level = 0; level < depth; level += 1) {
    node = { nested: node };
  }
  return node;
}

function buildHighFanOut(keys) {
  // A single shallow object with many sibling keys + a many-element array —
  // stresses the per-leaf overhead (key + value entries) at high cardinality.
  const wide = {};
  for (let index = 0; index < keys; index += 1) {
    wide[`field_${index}`] = `value_${index}`;
  }
  return { wide, list: Array.from({ length: keys }, (_unused, index) => `item_${index}`) };
}

const cases = {
  flat: {
    messages: [
      {
        role: "user",
        content: `${filler} minji.kim@example.com`
      }
    ]
  },
  deeplyNested: buildDeeplyNested(nestingDepth),
  highFanOut: buildHighFanOut(fanOutKeys)
};

const results = {};
for (const [name, payload] of Object.entries(cases)) {
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) {
    await runtime.haechi.protectJson(payload, {
      protocol: "bench",
      operation: `payload:${name}`
    });
  }
  const elapsedMs = performance.now() - started;
  results[name] = {
    totalMs: Math.round(elapsedMs),
    averageMs: Math.round((elapsedMs / iterations) * 100) / 100
  };
}

process.stdout.write(`${JSON.stringify({
  sizeKb,
  iterations,
  nestingDepth,
  fanOutKeys,
  cases: results
}, null, 2)}\n`);
