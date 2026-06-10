import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createJsonlAuditSink, verifyAuditChain } from "../packages/audit/index.mjs";
import { normalizeConfig } from "../packages/cli/runtime.mjs";

const CLI = fileURLToPath(new URL("../packages/cli/bin/haechi.mjs", import.meta.url));

function event(id) {
  return {
    id, timestamp: new Date(0).toISOString(), protocol: "test", operation: "anchor",
    mode: "enforce", enforced: true, blocked: false,
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  };
}

async function writeRecords(sink, n) {
  for (let i = 0; i < n; i += 1) {
    await sink.record(event(`e-${i}`));
  }
}

test("file anchoring writes one anchor line per record by default", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 1 } });
  await writeRecords(sink, 3);

  const anchors = (await readFile(anchorPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(anchors.length, 3);
  assert.deepEqual(anchors.map((a) => a.sequence), [1, 2, 3]);
  // Each anchor's eventHash equals the chain record's eventHash at that sequence.
  const records = (await readFile(path, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  for (const a of anchors) {
    assert.equal(a.eventHash, records[a.sequence - 1].auditIntegrity.eventHash);
  }
});

test("everyRecords batches anchors", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-batch-"));
  const anchorPath = join(dir, "a.jsonl");
  const sink = createJsonlAuditSink({ path: join(dir, "audit.jsonl"), anchor: { mode: "file", path: anchorPath, everyRecords: 2 } });
  await writeRecords(sink, 5);
  const anchors = (await readFile(anchorPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(anchors.map((a) => a.sequence), [2, 4]);
});

test("verifyAuditChain with an anchor detects tail truncation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-trunc-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 1 } });
  await writeRecords(sink, 5);

  // Intact chain verifies and reports the anchored summary.
  const intact = await verifyAuditChain(path, { anchorPath });
  assert.equal(intact.valid, true);
  assert.equal(intact.records, 5);
  assert.equal(intact.anchored.lastSequence, 5);

  // Truncate the last two records from the chain (but not the anchor stream).
  const kept = (await readFile(path, "utf8")).trim().split("\n").slice(0, 3);
  await writeFile(path, `${kept.join("\n")}\n`, "utf8");

  // Without the anchor the shortened chain still "verifies" (the gap).
  const noAnchor = await verifyAuditChain(path);
  assert.equal(noAnchor.valid, true);
  assert.equal(noAnchor.records, 3);

  // With the anchor, truncation is caught.
  const withAnchor = await verifyAuditChain(path, { anchorPath });
  assert.equal(withAnchor.valid, false);
  assert.match(withAnchor.reason, /tail truncation: chain has 3 records but anchor attests sequence 5/);
});

test("verifyAuditChain catches an anchor that disagrees with an internally-valid chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-mismatch-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 1 } });
  await writeRecords(sink, 3);

  // The chain itself is intact (internally valid). Corrupt the anchor's
  // eventHash at sequence 2 so it disagrees with the chain — this isolates the
  // anchor cross-check branch (not the internal hash check, which still passes).
  const anchors = (await readFile(anchorPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  anchors[1].eventHash = "deadbeef".repeat(8);
  await writeFile(anchorPath, `${anchors.map((a) => JSON.stringify(a)).join("\n")}\n`, "utf8");

  // Without the anchor the chain is valid; with the divergent anchor it fails.
  assert.equal((await verifyAuditChain(path)).valid, true);
  const result = await verifyAuditChain(path, { anchorPath });
  assert.equal(result.valid, false);
  assert.match(result.reason, /anchor hash mismatch at sequence 2/);
});

test("truncation between anchors (everyRecords > 1) is detected by the last anchor", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-between-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 2 } });
  await writeRecords(sink, 5); // anchors at sequences 2 and 4

  // Truncate to 3 records — below the last anchor (4) → caught.
  const kept = (await readFile(path, "utf8")).trim().split("\n").slice(0, 3);
  await writeFile(path, `${kept.join("\n")}\n`, "utf8");
  const result = await verifyAuditChain(path, { anchorPath });
  assert.equal(result.valid, false);
  assert.match(result.reason, /chain has 3 records but anchor attests sequence 4/);
});

test("the residual gap (records after the last anchor) is an accepted, silent bound", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-gap-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 2 } });
  await writeRecords(sink, 5); // last anchor at sequence 4

  // Drop only record 5 (in the residual gap above the last anchor) → NOT caught.
  const kept = (await readFile(path, "utf8")).trim().split("\n").slice(0, 4);
  await writeFile(path, `${kept.join("\n")}\n`, "utf8");
  const result = await verifyAuditChain(path, { anchorPath });
  assert.equal(result.valid, true);
  assert.equal(result.records, 4);
});

test("readAnchors tolerates a partial trailing anchor line (crash) and malformed lines", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-partial-"));
  const path = join(dir, "audit.jsonl");
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path, anchor: { mode: "file", path: anchorPath, everyRecords: 1 } });
  await writeRecords(sink, 3);

  // Simulate a crash mid-write: append a partial JSON line for sequence 4.
  await writeFile(anchorPath, `${(await readFile(anchorPath, "utf8")).trim()}\n{"sequence":4,"eventH`, "utf8");

  // The partial line is skipped; the three valid anchors still verify the chain.
  const result = await verifyAuditChain(path, { anchorPath });
  assert.equal(result.valid, true);
  assert.equal(result.anchored.lastSequence, 3);
});

test("stdout anchoring emits one anchor line per record to stdout", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-stdout-"));
  const path = join(dir, "audit.jsonl");
  const written = [];
  const original = process.stdout.write;
  process.stdout.write = (chunk) => { written.push(chunk.toString()); return true; };
  try {
    const sink = createJsonlAuditSink({ path, anchor: { mode: "stdout", everyRecords: 1 } });
    await writeRecords(sink, 2);
  } finally {
    process.stdout.write = original;
  }
  const anchors = written.join("").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(anchors.map((a) => a.sequence), [1, 2]);
  assert.ok(anchors.every((a) => typeof a.eventHash === "string"));
});

test("the anchor file is created 0600", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-perm-"));
  const anchorPath = join(dir, "audit.anchor.jsonl");
  const sink = createJsonlAuditSink({ path: join(dir, "audit.jsonl"), anchor: { mode: "file", path: anchorPath, everyRecords: 1 } });
  await writeRecords(sink, 1);
  const { stat } = await import("node:fs/promises");
  assert.equal((await stat(anchorPath)).mode & 0o777, 0o600);
});

test("mode none keeps the pre-anchor behavior (no anchor file)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-none-"));
  const path = join(dir, "audit.jsonl");
  const sink = createJsonlAuditSink({ path });
  await writeRecords(sink, 2);
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true);
  assert.equal(result.records, 2);
  assert.equal(result.anchored, undefined);
});

test("config validation covers the audit.anchor block", () => {
  assert.throws(() => normalizeConfig({ audit: { anchor: { mode: "weird" } } }), /audit.anchor.mode/);
  assert.throws(() => normalizeConfig({ audit: { anchor: { mode: "file", path: "" } } }), /requires audit.anchor.path/);
  assert.throws(() => normalizeConfig({ audit: { anchor: { everyRecords: 0 } } }), /everyRecords/);
  const ok = normalizeConfig({ audit: { anchor: { mode: "stdout" } } });
  assert.equal(ok.audit.anchor.mode, "stdout");
  assert.equal(ok.audit.anchor.everyRecords, 1);
});

test("the sink rejects an inconsistent anchor config at construction", () => {
  assert.throws(() => createJsonlAuditSink({ path: "/tmp/x", anchor: { mode: "bogus" } }), /anchor mode/);
  assert.throws(() => createJsonlAuditSink({ path: "/tmp/x", anchor: { mode: "file" } }), /requires an anchor path/);
  // everyRecords is validated by the sink itself (injection bypasses normalizeConfig).
  assert.throws(() => createJsonlAuditSink({ path: "/tmp/x", anchor: { mode: "stdout", everyRecords: 0 } }), /everyRecords/);
  assert.throws(() => createJsonlAuditSink({ path: "/tmp/x", anchor: { mode: "stdout", everyRecords: 1.5 } }), /everyRecords/);
});

test("CLI audit-verify --anchor reports truncation with exit 4", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-cli-"));
  const init = spawnSync(process.execPath, [CLI, "init", "--force"], { cwd: dir, encoding: "utf8" });
  assert.equal(init.status, 0);

  // Enable file anchoring in the config.
  const configPath = join(dir, "haechi.config.json");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  config.audit.anchor.mode = "file";
  await writeFile(configPath, JSON.stringify(config, null, 2), "utf8");

  await writeFile(join(dir, "input.json"), JSON.stringify({ message: "mail minji.kim@example.com" }), "utf8");
  for (let i = 0; i < 3; i += 1) {
    assert.equal(spawnSync(process.execPath, [CLI, "protect", "input.json"], { cwd: dir, encoding: "utf8" }).status, 0);
  }

  const before = JSON.parse(spawnSync(process.execPath, [CLI, "audit-verify", "--anchor"], { cwd: dir, encoding: "utf8" }).stdout);
  assert.equal(before.ok, true);
  assert.equal(before.result.anchored.lastSequence, 3);

  const auditPath = join(dir, ".haechi", "audit.jsonl");
  const kept = (await readFile(auditPath, "utf8")).trim().split("\n").slice(0, 1);
  await writeFile(auditPath, `${kept.join("\n")}\n`, "utf8");

  const after = spawnSync(process.execPath, [CLI, "audit-verify", "--anchor"], { cwd: dir, encoding: "utf8" });
  assert.equal(after.status, 4);
  assert.match(JSON.parse(after.stdout).result.reason, /tail truncation/);
});

test("status reports anchor mode and warns when anchoring is off", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-anchor-status-"));
  assert.equal(spawnSync(process.execPath, [CLI, "init", "--force"], { cwd: dir, encoding: "utf8" }).status, 0);
  const status = JSON.parse(spawnSync(process.execPath, [CLI, "status"], { cwd: dir, encoding: "utf8" }).stdout);
  assert.equal(status.audit.anchor.mode, "none");
  assert.ok(status.warnings.some((w) => w.includes("tail truncation")));
});
