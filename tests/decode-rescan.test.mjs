import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createDefaultFilterEngine } from "../packages/filter/index.mjs";
import { collectStringEntries } from "../packages/core/index.mjs";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

// WS2d residual — opt-in base64/percent decode-and-rescan (filters.decodeAndRescan).
// A card/RRN/secret that is base64- or percent-encoded before sending passes every
// regex rule by default (Haechi matches NFKC-normalized text but does not decode).
// With the flag ON, the leaf is decoded and rescanned; a decoded hit fails closed to
// a WHOLE-LEAF detection of the original encoded leaf and only fires for a validator-
// backed / hard-block match (precision guard). Default OFF => byte-identical.

// A synthetic Luhn-valid card and a checksum-valid KR RRN (never real values).
const CARD = "4111111111111111";
const RRN = "900101-1234568";

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const b64url = (s) => Buffer.from(s, "utf8").toString("base64url");

function scan(engine, payload, context = {}) {
  return engine.detect({ entries: collectStringEntries(payload), context });
}

// ---------------------------------------------------------------------------
// Detection-level: flag ON detects encoded leaks; flag OFF detects none.
// ---------------------------------------------------------------------------

test("flag ON: a base64-encoded card is detected as a WHOLE-LEAF card", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const leaf = b64(CARD);
  const detections = await scan(engine, { note: leaf });
  const card = detections.find((d) => d.type === "card");
  assert.ok(card, "the encoded card must be detected");
  // Whole-leaf: spans the entire ORIGINAL encoded leaf, value is the encoded string.
  assert.equal(card.start, 0);
  assert.equal(card.end, leaf.length);
  assert.equal(card.value, leaf, "the recorded value is the original encoded leaf, not the decoded card");
});

test("flag ON: a url-safe base64-encoded card is detected", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const leaf = b64url(CARD);
  const detections = await scan(engine, { note: leaf });
  assert.ok(detections.some((d) => d.type === "card" && d.value === leaf), "url-safe base64 card must be detected as whole-leaf");
});

test("flag ON: a base64-encoded KR RRN is detected (checksum validator runs on decoded text)", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const leaf = b64(RRN);
  const detections = await scan(engine, { note: leaf });
  assert.ok(detections.some((d) => d.type === "kr_rrn" && d.value === leaf), "encoded RRN must be detected");
});

test("flag ON: a percent-encoded card is detected as a WHOLE-LEAF card", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const leaf = encodeURIComponent(`card ${CARD} on file`);
  const detections = await scan(engine, { note: leaf });
  assert.ok(detections.some((d) => d.type === "card" && d.start === 0 && d.end === leaf.length && d.value === leaf),
    "percent-encoded card must be detected as a whole-leaf");
});

test("flag OFF (default): NONE of the encoded leaks are detected — byte-identical to before", async () => {
  const engine = createDefaultFilterEngine(); // default: decodeAndRescan off
  const leaves = [b64(CARD), b64url(CARD), b64(RRN), encodeURIComponent(`card ${CARD} on file`)];
  for (const leaf of leaves) {
    const detections = await scan(engine, { note: leaf });
    assert.equal(detections.length, 0, `flag OFF must not decode/rescan: ${leaf.slice(0, 24)}…`);
  }
});

test("flag OFF and ON produce identical detections on un-encoded input (no behavior change off the encoded path)", async () => {
  const on = createDefaultFilterEngine({ decodeAndRescan: true });
  const off = createDefaultFilterEngine({ decodeAndRescan: false });
  const payload = { msg: `email a@b.com, card ${CARD}, rrn ${RRN}` };
  const onDet = (await scan(on, payload)).map((d) => `${d.type}:${d.start}:${d.end}`).sort();
  const offDet = (await scan(off, payload)).map((d) => `${d.type}:${d.start}:${d.end}`).sort();
  assert.deepEqual(onDet, offDet, "plaintext PII detection is unchanged by the flag");
});

// ---------------------------------------------------------------------------
// FALSE-POSITIVE HUNT: the precision guard must keep random/benign input clean.
// ---------------------------------------------------------------------------

test("FP hunt: random base64 (true random bytes) does NOT fire", async () => {
  const { randomBytes } = await import("node:crypto");
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  // True random BYTES — the realistic "random base64" case. Most decode to non-UTF-8
  // (rejected by the isUtf8 guard); the rare UTF-8 case almost never carries a
  // validator-backed hit. (A contrived plaintext that happens to embed a Luhn-valid
  // 16-digit run is NOT random base64 — it is an encoded card, and firing on it is
  // correct; the precision guard targets random bytes, per the threat model.)
  for (let i = 0; i < 500; i += 1) {
    const leaf = randomBytes(24 + (i % 24)).toString("base64");
    const detections = await scan(engine, { note: leaf });
    assert.equal(detections.length, 0, `random base64 must not fire: ${leaf}`);
  }
});

test("FP hunt: a benign base64 blob decoding to valid UTF-8 prose does NOT fire", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const leaf = Buffer.from("the quick brown fox jumps over the lazy dog every day").toString("base64");
  const detections = await scan(engine, { note: leaf });
  assert.equal(detections.length, 0, "benign UTF-8 prose in base64 must not fire (no validator-backed hit)");
});

test("FP hunt: a benign JWT (claims with no PII) gets no EXTRA detection from the decode pass", async () => {
  const on = createDefaultFilterEngine({ decodeAndRescan: true });
  const off = createDefaultFilterEngine({ decodeAndRescan: false });
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ sub: "user-123", name: "Reader", role: "viewer" }));
  const sig = b64url("signature-bytes-aaaaaaaaaaaaaaaa");
  const jwt = `${header}.${payload}.${sig}`;
  // The dotted JWT is not a single base64 alphabet leaf, so the decode pass adds
  // nothing. The base `jwt` rule still flags it as `secret` (pre-existing), so we
  // assert the flag does not CHANGE the detection set, not that nothing fires.
  const onDet = (await scan(on, { token: jwt })).map((d) => `${d.type}:${d.ruleId}`).sort();
  const offDet = (await scan(off, { token: jwt })).map((d) => `${d.type}:${d.ruleId}`).sort();
  assert.deepEqual(onDet, offDet, "the decode pass must not add a detection for a benign JWT");
});

test("FP hunt: ordinary prose does NOT fire", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  const detections = await scan(engine, { note: "This is ordinary prose without any sensitive values at all." });
  assert.equal(detections.length, 0);
});

test("FP hunt: a malformed percent-escape does not throw and does not fire", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  // A lone `%` and a bad `%zz` would make decodeURIComponent throw — must be caught.
  const detections = await scan(engine, { note: "value with a bad %zz escape and a lone % here in it" });
  assert.equal(detections.length, 0);
});

test("precision guard: a decoded soft-type-only match (phone-shaped) does NOT fire", async () => {
  const engine = createDefaultFilterEngine({ decodeAndRescan: true });
  // A KR-mobile-shaped run with no validator-backed/hard-block type. Decoding it
  // yields a `phone` candidate only, which the guard rejects.
  const leaf = b64("call me at 010-1234-5678 tomorrow");
  const detections = await scan(engine, { note: leaf });
  assert.equal(detections.filter((d) => d.type === "phone").length, 0, "a decoded bare phone must not fire (precision guard)");
});

// ---------------------------------------------------------------------------
// End-to-end through createRuntime (enforce): the encoded leak is redacted/blocked.
// ---------------------------------------------------------------------------

async function makeRuntime(dir, filters, actions) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    filters
  });
}

test("end-to-end enforce: a base64-encoded card BLOCKS the whole payload (card => block)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-decode-block-"));
  const runtime = await makeRuntime(dir, { decodeAndRescan: true }, { card: "block" });
  const leaf = b64(CARD);
  const result = await runtime.haechi.protectJson({ note: leaf }, { direction: "request" });
  assert.equal(result.blocked, true, "an encoded card under card:block must block");
  assert.equal(result.payload, null, "a blocked payload is nulled");
});

test("end-to-end enforce: a percent-encoded card under card:redact redacts the WHOLE encoded leaf", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-decode-redact-"));
  const runtime = await makeRuntime(dir, { decodeAndRescan: true }, { card: "redact" });
  const leaf = encodeURIComponent(`card ${CARD} on file`);
  const result = await runtime.haechi.protectJson({ note: leaf }, { direction: "request" });
  assert.equal(result.blocked, false);
  // Whole-leaf redaction: the encoded value is gone and a redaction marker remains.
  assert.ok(!result.payload.note.includes(leaf), "the encoded leaf must be redacted");
  assert.match(result.payload.note, /\[REDACTED:card\]/, "a whole-leaf card redaction marker remains");
});

test("end-to-end enforce: flag OFF (default) passes the encoded card through UNCHANGED", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-decode-off-"));
  const runtime = await makeRuntime(dir, {}, { card: "block" }); // decodeAndRescan defaults off
  const leaf = b64(CARD);
  const result = await runtime.haechi.protectJson({ note: leaf }, { direction: "request" });
  assert.equal(result.blocked, false, "default OFF must not block an encoded card");
  assert.deepEqual(result.payload, { note: leaf }, "default OFF leaves the encoded leaf byte-identical");
});

// ---------------------------------------------------------------------------
// Config: the new key is normalized + fail-closed validated.
// ---------------------------------------------------------------------------

test("config: filters.decodeAndRescan defaults false and is fail-closed validated", () => {
  assert.equal(normalizeConfig({}).filters.decodeAndRescan, false);
  assert.equal(normalizeConfig({ filters: { decodeAndRescan: true } }).filters.decodeAndRescan, true);
  assert.throws(() => normalizeConfig({ filters: { decodeAndRescan: "yes" } }), /filters\.decodeAndRescan must be a boolean/);
  assert.throws(() => normalizeConfig({ filters: { decodeAndRescan: 1 } }), /filters\.decodeAndRescan must be a boolean/);
});
