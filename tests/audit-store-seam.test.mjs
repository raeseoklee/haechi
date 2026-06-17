import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createAuditSink,
  createFileAuditStore,
  createJsonlAuditSink,
  buildIntegrityRecord,
  verifyAuditChain
} from "../packages/audit/index.mjs";

// The audit sink now sits on a pluggable STORE seam: the security-critical chain
// math (buildIntegrityRecord), sanitize, and anchor logic stay core-owned in
// createAuditSink, while the store only abstracts the exclusive
// "read-previous + persist" primitive. These tests prove the seam is real (a
// non-file store backs the SAME chain) and behavior-preserving (file path stays
// byte-identical, concurrency stays sequential, chain math stays pure).

function event(id) {
  return {
    id, timestamp: new Date(0).toISOString(), protocol: "test", operation: "seam",
    mode: "enforce", enforced: true, blocked: false,
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  };
}

async function readRecords(path) {
  return (await readFile(path, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
}

// Local mirror of the sink's canonicalize+sha256 so case (b) can verify the
// in-memory store's chain independently of the production helpers.
function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("base64url");
}

// A custom store that keeps the chain entirely in memory — no fs at all. This is
// the shared-store precondition: if the seam is correct, the SAME core chain
// math works over this store. transaction() serializes via a promise queue so an
// exclusive critical section is preserved like the file lock.
function createMemoryAuditStore() {
  const records = [];
  let queue = Promise.resolve();
  function transaction(fn) {
    const run = queue.then(() => fn({
      readLastIntegrity: async () => records.at(-1)?.auditIntegrity ?? null,
      persist: async (record) => { records.push(record); }
    }));
    queue = run.catch(() => {});
    return run;
  }
  return { transaction, records };
}

// ---------------------------------------------------------------------------
// (a) createAuditSink over createFileAuditStore -> a chain verifyAuditChain accepts.
// ---------------------------------------------------------------------------
test("seam: createAuditSink over createFileAuditStore produces a verifiable chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-seam-file-"));
  const path = join(dir, "audit.jsonl");
  const sink = createAuditSink({ store: createFileAuditStore({ path }) });

  for (let i = 0; i < 5; i += 1) {
    await sink.record(event(`e-${i}`));
  }

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true);
  assert.equal(result.records, 5);
});

test("seam: createJsonlAuditSink wrapper is byte-identical to the explicit composition", async () => {
  // The thin wrapper must produce the SAME on-disk bytes as createAuditSink over
  // createFileAuditStore for the same event sequence (back-compat guarantee).
  const wrapperDir = await mkdtemp(join(tmpdir(), "haechi-seam-wrap-"));
  const explicitDir = await mkdtemp(join(tmpdir(), "haechi-seam-expl-"));
  const wrapperPath = join(wrapperDir, "audit.jsonl");
  const explicitPath = join(explicitDir, "audit.jsonl");

  const wrapperSink = createJsonlAuditSink({ path: wrapperPath });
  const explicitSink = createAuditSink({ store: createFileAuditStore({ path: explicitPath }) });

  for (let i = 0; i < 4; i += 1) {
    await wrapperSink.record(event(`e-${i}`));
    await explicitSink.record(event(`e-${i}`));
  }

  assert.equal(await readFile(wrapperPath, "utf8"), await readFile(explicitPath, "utf8"));

  // Returned shape unchanged: id/version/capabilities/record/ready.
  assert.equal(wrapperSink.id, "haechi.audit.jsonl");
  assert.equal(wrapperSink.version, "0.1.0");
  assert.deepEqual(wrapperSink.capabilities, {
    writesAudit: true, writesPlaintext: false, appendOnly: true, integrity: "sha256-hash-chain"
  });
  assert.equal(typeof wrapperSink.record, "function");
  assert.equal(typeof wrapperSink.ready, "function");
});

// ---------------------------------------------------------------------------
// (b) A custom IN-MEMORY store yields a correctly chained sequence (non-file
//     store works through the SAME core sink — the shared-store precondition).
// ---------------------------------------------------------------------------
test("seam: an in-memory store produces a correctly chained sequence", async () => {
  const store = createMemoryAuditStore();
  const sink = createAuditSink({ store });

  for (let i = 0; i < 6; i += 1) {
    await sink.record(event(`m-${i}`));
  }

  const records = store.records;
  assert.equal(records.length, 6);

  let previousHash = null;
  for (let i = 0; i < records.length; i += 1) {
    const integrity = records[i].auditIntegrity;
    // sequence increments from 1.
    assert.equal(integrity.sequence, i + 1);
    // previousHash links to the prior record's eventHash.
    assert.equal(integrity.previousHash ?? null, previousHash);

    // eventHash verifies over the unsigned record.
    const { eventHash, ...unsignedIntegrity } = integrity;
    const expected = sha256(canonicalize({ ...records[i], auditIntegrity: unsignedIntegrity }));
    assert.equal(eventHash, expected);

    previousHash = eventHash;
  }
});

// ---------------------------------------------------------------------------
// (c) Concurrent record() calls through ONE sink -> strictly sequential,
//     non-forked chain (writeQueue + exclusive transaction serialization).
// ---------------------------------------------------------------------------
test("seam: concurrent record() calls produce a strictly sequential, non-forked chain (file store)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-seam-conc-"));
  const path = join(dir, "audit.jsonl");
  const sink = createAuditSink({ store: createFileAuditStore({ path }) });

  await Promise.all(Array.from({ length: 25 }, (_, i) => sink.record(event(`c-${i}`))));

  const records = await readRecords(path);
  assert.equal(records.length, 25);

  // Sequences are 1..25 with no gaps/dupes, and previousHash forms one line.
  const seqs = records.map((r) => r.auditIntegrity.sequence);
  assert.deepEqual(seqs, Array.from({ length: 25 }, (_, i) => i + 1));

  let previousHash = null;
  for (const r of records) {
    assert.equal(r.auditIntegrity.previousHash ?? null, previousHash);
    previousHash = r.auditIntegrity.eventHash;
  }

  // And the production verifier accepts the concurrently-written chain.
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true);
  assert.equal(result.records, 25);
});

test("seam: concurrent record() calls through an in-memory store also stay sequential", async () => {
  const store = createMemoryAuditStore();
  const sink = createAuditSink({ store });

  await Promise.all(Array.from({ length: 20 }, (_, i) => sink.record(event(`mc-${i}`))));

  const seqs = store.records.map((r) => r.auditIntegrity.sequence);
  assert.deepEqual(seqs, Array.from({ length: 20 }, (_, i) => i + 1));

  let previousHash = null;
  for (const r of store.records) {
    assert.equal(r.auditIntegrity.previousHash ?? null, previousHash);
    previousHash = r.auditIntegrity.eventHash;
  }
});

// ---------------------------------------------------------------------------
// (d) buildIntegrityRecord(previousIntegrity, event) is PURE — same input maps
//     to same output, with no fs access.
// ---------------------------------------------------------------------------
test("seam: buildIntegrityRecord is pure (deterministic, no fs)", () => {
  const ev = event("pure-1");

  // From null previous: sequence 1, previousHash null.
  const first = buildIntegrityRecord(null, ev);
  assert.equal(first.auditIntegrity.sequence, 1);
  assert.equal(first.auditIntegrity.previousHash, null);

  // Same inputs -> deeply equal outputs (no hidden state, no IO).
  const firstAgain = buildIntegrityRecord(null, event("pure-1"));
  assert.deepEqual(first, firstAgain);

  // Chaining off the first record's integrity advances sequence + links hash.
  const second = buildIntegrityRecord(first.auditIntegrity, event("pure-2"));
  assert.equal(second.auditIntegrity.sequence, 2);
  assert.equal(second.auditIntegrity.previousHash, first.auditIntegrity.eventHash);

  const secondAgain = buildIntegrityRecord(first.auditIntegrity, event("pure-2"));
  assert.deepEqual(second, secondAgain);

  // The function is synchronous (no promise/fs round-trip).
  assert.notEqual(typeof first.then, "function");
});
