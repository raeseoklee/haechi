import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createJsonlAuditSink, verifyAuditChain } from "../packages/audit/index.mjs";

// Focused middle-record tamper coverage for verifyAuditChain. The existing
// audit-anchoring suite exercises the ANCHOR cross-check + tail truncation;
// this file isolates the chain's own integrity branches against a real, on-disk
// multi-record log (written by the actual sink, never hand-fabricated), then
// mutates a MIDDLE record so we exercise propagation through the chain rather
// than the trivial last-record case.

function event(id) {
  return {
    id, timestamp: new Date(0).toISOString(), protocol: "test", operation: "tamper",
    mode: "enforce", enforced: true, blocked: false,
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  };
}

async function writeRecords(sink, n) {
  for (let i = 0; i < n; i += 1) {
    await sink.record(event(`e-${i}`));
  }
}

async function freshLog(label) {
  const dir = await mkdtemp(join(tmpdir(), `haechi-tamper-${label}-`));
  const path = join(dir, "audit.jsonl");
  // mode none → pure chain, no anchor stream, so every failure we assert below
  // is the CHAIN catching the tamper on its own (not the anchor cross-check).
  const sink = createJsonlAuditSink({ path });
  return { dir, path, sink };
}

async function readRecords(path) {
  return (await readFile(path, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
}

async function writeRecordsToDisk(path, records) {
  await writeFile(path, `${records.map((r) => JSON.stringify(r)).join("\n")}\n`, "utf8");
}

// Mirror the sink's eventHash construction so a content mutation can be made
// SELF-CONSISTENT (record recomputes to its own stored eventHash) — that is the
// only way a middle mutation passes its own record and breaks at the NEXT one.
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

function recomputeEventHash(record) {
  const { eventHash, ...unsignedIntegrity } = record.auditIntegrity;
  return sha256(canonicalize({ ...record, auditIntegrity: unsignedIntegrity }));
}

test("baseline: an untampered 5-record chain verifies", async () => {
  const { path, sink } = await freshLog("baseline");
  await writeRecords(sink, 5);
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true);
  assert.equal(result.records, 5);
  // No anchor stream was used, so no anchored summary is attached.
  assert.equal(result.anchored, undefined);
});

test("(a1) middle-record CONTENT mutation with a STALE eventHash fails at that record", async () => {
  const { path, sink } = await freshLog("content-stale");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Tamper the MIDDLE record's content but leave its recorded eventHash stale.
  // The verifier recomputes the hash from the (now-altered) content, so the
  // mismatch is caught AT the mutated record's own sequence (3).
  records[2].operation = "tampered-operation";
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "event hash mismatch");
  // Failure surfaces at the mutated record: two clean records preceded it.
  assert.equal(result.records, 2);
});

test("(a2) middle-record CONTENT mutation with a RECOMPUTED eventHash breaks at the NEXT record", async () => {
  const { path, sink } = await freshLog("content-recomputed");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Mutate the middle record's content AND recompute its eventHash so the record
  // is internally self-consistent. The chain still breaks because record 4's
  // previousHash points at the ORIGINAL record-3 hash, not the recomputed one —
  // i.e. an attacker who only re-hashes the edited record cannot re-stitch the
  // forward link without also rewriting every following record.
  records[2].operation = "tampered-operation";
  records[2].auditIntegrity.eventHash = recomputeEventHash(records[2]);
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "previous hash mismatch");
  // Records 1..3 pass (record 3 is now self-consistent); record 4's back-link
  // is the first to disagree.
  assert.equal(result.records, 3);
});

test("(b) MISSING previousHash on a middle record fails with a previous hash mismatch", async () => {
  const { path, sink } = await freshLog("missing-prev");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Drop the back-link entirely on the middle record. `previousHash ?? null`
  // becomes null while the expected value is record-2's non-null hash.
  delete records[2].auditIntegrity.previousHash;
  // Keep the record otherwise self-consistent so the previousHash branch (not
  // the eventHash branch) is what trips: recompute its eventHash over the
  // now-missing-previousHash integrity object.
  records[2].auditIntegrity.eventHash = recomputeEventHash(records[2]);
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "previous hash mismatch");
  assert.equal(result.records, 2);
});

test("(c) WRONG previousHash on a middle record fails with a previous hash mismatch", async () => {
  const { path, sink } = await freshLog("wrong-prev");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Point the middle record's back-link at a plausible-but-wrong hash, then keep
  // the record self-consistent so the previousHash check is the one that fails.
  records[2].auditIntegrity.previousHash = "wrongprevioushash".padEnd(43, "0");
  records[2].auditIntegrity.eventHash = recomputeEventHash(records[2]);
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "previous hash mismatch");
  assert.equal(result.records, 2);
});

test("(d) WRONG integrity.eventHash on a middle record fails with an event hash mismatch", async () => {
  const { path, sink } = await freshLog("wrong-hash");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Corrupt ONLY the stored eventHash on the middle record (content untouched).
  // The recomputed hash over the unchanged content no longer matches.
  records[2].auditIntegrity.eventHash = "deadbeef".repeat(8);
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "event hash mismatch");
  assert.equal(result.records, 2);
});

test("(e) sequence renumbering on a middle record fails with a sequence mismatch", async () => {
  const { path, sink } = await freshLog("seq");
  await writeRecords(sink, 5);
  const records = await readRecords(path);

  // Renumber the middle record's sequence; the verifier expects strictly
  // increasing sequences starting at 1, so the gap is caught before the hash
  // checks run. (Recompute its eventHash so it is the sequence branch — not the
  // eventHash branch — that we are isolating here.)
  records[2].auditIntegrity.sequence = 99;
  records[2].auditIntegrity.eventHash = recomputeEventHash(records[2]);
  await writeRecordsToDisk(path, records);

  const result = await verifyAuditChain(path);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "sequence mismatch");
  assert.equal(result.records, 2);
});

test("KNOWN LIMITATION: tail truncation of trailing records is NOT caught by the chain alone", async () => {
  // The hash chain links each record to the one before it, so it can detect any
  // EDIT or REORDER of records that remain on disk. It canNOT detect that
  // trailing records were simply DELETED: a shorter prefix of an honest chain is
  // itself a perfectly valid chain. Catching that requires the SEPARATE,
  // append-only ANCHOR stream (which records the chain head at past sequences) —
  // see verifyAuditChain(path, { anchorPath }) and audit-anchoring.test.mjs.
  // This test pins the limitation so it stays explicit and intentional.
  const { path, sink } = await freshLog("tail-trunc");
  await writeRecords(sink, 5);

  // Drop the last two records (no anchor stream exists for this log).
  const kept = (await readFile(path, "utf8")).trim().split("\n").slice(0, 3);
  await writeFile(path, `${kept.join("\n")}\n`, "utf8");

  // The chain alone still reports VALID — the deletion is invisible to it.
  const result = await verifyAuditChain(path);
  assert.equal(result.valid, true, "chain-only verification cannot see deleted trailing records");
  assert.equal(result.records, 3);
});
