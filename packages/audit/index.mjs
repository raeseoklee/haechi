import { createReadStream, constants as fsConstants } from "node:fs";
import { access, appendFile, mkdir, open, stat, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";

const FORBIDDEN_KEYS = new Set([
  "value", "plaintext", "payload", "content", "message", "prompt", "secret",
  // OIDC-broker / OAuth token, secret, and authorization-flow parameter keys.
  // These are never part of a current audit event shape; the membership is a
  // defense-in-depth guard so a future audit field can never leak a token,
  // client secret, or flow parameter through the core sink. `sub`/`email` are
  // intentionally NOT listed — they can be legitimate non-secret field names
  // elsewhere, and the broker already self-guards them via its own allowlist
  // projection.
  "access_token", "id_token", "refresh_token", "code", "code_verifier",
  "client_secret", "state", "nonce",
  // Plugin/claims surface (1.0): a dynamically-loaded auth plugin's lifecycle
  // events carry only ids/hashes/counts, but this additive membership is
  // defense-in-depth so a future plugin event can never leak a raw claim, the
  // received credential/authorization, the signer's signature, or the entry
  // source into the chained log.
  "claims", "subject", "issuer", "credential", "authorization", "signature", "entry",
  // The frozen 1.0 audit-identity contract is exactly {id,type,subjectHash,
  // issuerHash,provider} — scopes/labels are NOT part of it. This additive
  // guard ensures that even if a future code path passes an un-projected
  // identity object, scopes/labels (which can carry attacker-controlled plugin
  // claim values) can never enter the hash-chained audit record.
  "scopes", "labels"
]);

// An audit STORE abstracts the exclusive "read-previous + persist" primitive so
// the SAME core-owned sha256 hash chain can sit on top of a file today and a
// shared store (e.g. Redis) in a future satellite. The contract is:
//
//   async transaction(fn) — runs `fn` inside an EXCLUSIVE critical section that
//     serializes concurrent appends. `fn` receives { readLastIntegrity, persist }
//     where readLastIntegrity() -> the last record's auditIntegrity (or null) and
//     persist(record) durably appends the built record. transaction() returns
//     fn's return value.
//   async ready() — OPTIONAL health/writability probe returning { ok, reason? };
//     the sink falls back to { ok: true } when the store omits it.
//
// The store deliberately knows NOTHING about anchoring, sanitization, or the
// chain math — those stay core-owned in createAuditSink so a non-core store can
// never fork or weaken the chain.

// createFileAuditStore implements the store contract over the CURRENT JSONL
// mechanism: a `${path}.lock` exclusive section wrapping mkdir + the critical
// section, a tail-read for the previous integrity, and an appendFile persist.
// The on-disk bytes are identical to the pre-seam sink.
export function createFileAuditStore({ path }) {
  if (!path) {
    throw new Error("file audit store requires path");
  }

  return {
    async transaction(fn) {
      await mkdir(dirname(path), { recursive: true });
      return withFileLock(`${path}.lock`, () => fn({
        readLastIntegrity: () => readLastIntegrity(path),
        persist: (record) => appendFile(path, `${JSON.stringify(record)}\n`, "utf8")
      }));
    },

    // WS4-A readiness probe: a CHEAP writability check used by /__haechi/ready.
    // A security gateway that cannot append to its audit log is NOT ready
    // (fail-closed), so this confirms the audit directory exists and is writable
    // WITHOUT writing an event (no audit-chain side effect). It returns the bare
    // boolean and an enum reason — never a path value or any payload/PII.
    async ready() {
      try {
        const dir = dirname(path);
        await mkdir(dir, { recursive: true });
        await access(dir, fsConstants.W_OK);
        // If the audit file already exists, confirm it is writable too.
        try {
          await access(path, fsConstants.W_OK);
        } catch (error) {
          if (error.code !== "ENOENT") {
            return { ok: false, reason: "audit_file_not_writable" };
          }
        }
        return { ok: true };
      } catch {
        return { ok: false, reason: "audit_dir_not_writable" };
      }
    }
  };
}

// createAuditSink holds the SECURITY-CRITICAL, core-owned logic: writeQueue
// serialization, sanitizeAudit, the sha256 chain build, the anchor stream, and
// the capabilities object. The store only supplies the exclusive
// read-previous + persist primitive; anchor config never leaks into it.
export function createAuditSink({ store, anchor = null }) {
  if (!store || typeof store.transaction !== "function") {
    throw new Error("audit sink requires a store with a transaction(fn) method");
  }
  const anchorMode = anchor?.mode ?? "none";
  const anchorPath = anchor?.path ?? null;
  const everyRecords = anchor?.everyRecords ?? 1;
  if (!["none", "file", "stdout"].includes(anchorMode)) {
    throw new Error(`Invalid audit anchor mode: ${anchorMode}`);
  }
  if (anchorMode === "file" && !anchorPath) {
    throw new Error("audit anchor mode 'file' requires an anchor path");
  }
  // The sink is a public export reachable via auditSink injection, so it
  // validates everyRecords itself rather than trusting normalizeConfig.
  if (!Number.isInteger(everyRecords) || everyRecords < 1) {
    throw new Error("audit anchor everyRecords must be a positive integer");
  }

  let writeQueue = Promise.resolve();

  async function writeAnchor(record) {
    const { sequence, eventHash } = record.auditIntegrity;
    // Tamper-evidence against tail truncation: the chain head is appended to a
    // separate append-only stream, so deleting trailing records leaves the
    // chain shorter than the last anchored sequence.
    if (anchorMode === "none" || sequence % everyRecords !== 0) {
      return;
    }
    const line = `${JSON.stringify({ sequence, eventHash, timestamp: record.timestamp })}\n`;
    if (anchorMode === "stdout") {
      process.stdout.write(line);
    } else {
      await mkdir(dirname(anchorPath), { recursive: true });
      // 0600 on creation, like the key/lock files. Note this only matters for
      // confidentiality of the timeline — tamper-evidence still requires the
      // anchor to live on append-only/separate media (see docs).
      await appendFile(anchorPath, line, { mode: 0o600 });
    }
  }

  return {
    id: "haechi.audit.jsonl",
    version: "0.1.0",
    capabilities: {
      writesAudit: true,
      writesPlaintext: false,
      appendOnly: true,
      integrity: anchorMode === "none" ? "sha256-hash-chain" : "sha256-hash-chain+anchor"
    },
    async record(event) {
      // The writeQueue serializes record() calls on this sink, and the store's
      // transaction() adds the exclusive critical section; together they keep
      // the chain strictly sequential and never forked under concurrency.
      const write = writeQueue.then(() => store.transaction(async ({ readLastIntegrity, persist }) => {
        const record = buildIntegrityRecord(await readLastIntegrity(), sanitizeAudit(event));
        await persist(record);
        await writeAnchor(record);
        return record;
      }));
      writeQueue = write.catch(() => {});
      await write;
    },

    async ready() {
      // Delegate to the store's writability probe; a store that omits it is
      // treated as ready (the chain math has no readiness side effect of its own).
      if (typeof store.ready === "function") {
        return store.ready();
      }
      return { ok: true };
    }
  };
}

// Thin back-compat wrapper: the original file-backed sink is now createAuditSink
// over createFileAuditStore. Its returned shape (id, version, capabilities,
// record, ready) and on-disk bytes are unchanged, so existing call sites
// (runtime.mjs injection, tests) keep working untouched.
export function createJsonlAuditSink({ path, anchor = null }) {
  if (!path) {
    throw new Error("JSONL audit sink requires path");
  }
  return createAuditSink({ store: createFileAuditStore({ path }), anchor });
}

export async function readAuditSummary(path) {
  const summary = {
    events: 0,
    blocked: 0,
    detections: 0,
    byType: {},
    byAction: {}
  };

  try {
    const lines = createInterface({
      input: createReadStream(path, { encoding: "utf8" }),
      crlfDelay: Infinity
    });

    for await (const line of lines) {
      if (!line.trim()) {
        continue;
      }
      const event = JSON.parse(line);
      summary.events += 1;
      if (event.blocked) {
        summary.blocked += 1;
      }
      summary.detections += event.summary?.detectionCount ?? 0;
      mergeCounts(summary.byType, event.summary?.byType);
      mergeCounts(summary.byAction, event.summary?.byAction);
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  return summary;
}

export function sanitizeAudit(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAudit(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !FORBIDDEN_KEYS.has(key))
      .map(([key, item]) => [key, sanitizeAudit(item)]));
  }

  return value;
}

export async function verifyAuditChain(path, { anchorPath = null } = {}) {
  // The anchor stream (if provided) records the chain head at past points; a
  // chain shorter than the last anchor, or a hash that disagrees with an
  // anchor, is tail truncation / tampering the chain alone cannot catch.
  const anchors = anchorPath ? await readAnchors(anchorPath) : null;

  const lines = createInterface({
    input: createReadStream(path, { encoding: "utf8" }),
    crlfDelay: Infinity
  });

  let expectedPreviousHash = null;
  let expectedSequence = 1;
  let records = 0;

  for await (const line of lines) {
    if (!line.trim()) {
      continue;
    }
    const record = JSON.parse(line);
    const integrity = record.auditIntegrity;
    if (!integrity) {
      return { valid: false, records, reason: "missing auditIntegrity" };
    }
    if (integrity.sequence !== expectedSequence) {
      return { valid: false, records, reason: "sequence mismatch" };
    }
    if ((integrity.previousHash ?? null) !== expectedPreviousHash) {
      return { valid: false, records, reason: "previous hash mismatch" };
    }

    const { eventHash, ...unsignedIntegrity } = integrity;
    const expectedHash = sha256(canonicalize({
      ...record,
      auditIntegrity: unsignedIntegrity
    }));
    if (eventHash !== expectedHash) {
      return { valid: false, records, reason: "event hash mismatch" };
    }

    if (anchors && anchors.bySequence.has(expectedSequence)
      && anchors.bySequence.get(expectedSequence) !== eventHash) {
      return { valid: false, records, reason: `anchor hash mismatch at sequence ${expectedSequence}` };
    }

    expectedPreviousHash = eventHash;
    expectedSequence += 1;
    records += 1;
  }

  if (anchors && anchors.lastSequence > records) {
    return {
      valid: false,
      records,
      reason: `tail truncation: chain has ${records} records but anchor attests sequence ${anchors.lastSequence}`
    };
  }

  // headHash anchors the chain externally. With anchorPath, truncation back to
  // the last anchor is now detected; the residual gap is records written after
  // the last anchor.
  const result = { valid: true, records, headHash: expectedPreviousHash };
  if (anchors) {
    result.anchored = { count: anchors.bySequence.size, lastSequence: anchors.lastSequence };
  }
  return result;
}

async function readAnchors(anchorPath) {
  const bySequence = new Map();
  let lastSequence = 0;
  try {
    const lines = createInterface({
      input: createReadStream(anchorPath, { encoding: "utf8" }),
      crlfDelay: Infinity
    });
    for await (const line of lines) {
      if (!line.trim()) {
        continue;
      }
      // A crash can leave a partial trailing anchor line; tolerate it (skip)
      // rather than failing the whole verification. The chain check plus the
      // remaining valid anchors still bound truncation detection.
      let anchor;
      try {
        anchor = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof anchor.sequence === "number" && typeof anchor.eventHash === "string") {
        bySequence.set(anchor.sequence, anchor.eventHash);
        lastSequence = Math.max(lastSequence, anchor.sequence);
      }
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
  return { bySequence, lastSequence };
}

// PURE chain math: given the previous record's auditIntegrity (or null) and a
// sanitized event, deterministically computes the next chained record. No fs,
// no IO — the store supplies `previousIntegrity` (via its read-previous
// primitive) so the SAME computation backs a file or a shared store. Exported
// for store/satellite tests.
export function buildIntegrityRecord(previousIntegrity, event) {
  const previous = previousIntegrity ?? null;
  const sequence = previous ? previous.sequence + 1 : 1;
  const unsigned = {
    ...event,
    auditIntegrity: {
      alg: "sha256",
      canonicalization: "json-stable-v1",
      sequence,
      previousHash: previous?.eventHash ?? null
    }
  };

  return {
    ...unsigned,
    auditIntegrity: {
      ...unsigned.auditIntegrity,
      eventHash: sha256(canonicalize(unsigned))
    }
  };
}

// Reads only the tail of the audit file so chained appends stay O(1) instead
// of re-reading the whole log on every record.
async function readLastIntegrity(path) {
  let handle;
  try {
    handle = await open(path, "r");
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }

  try {
    const { size } = await handle.stat();
    if (size === 0) {
      return null;
    }

    let chunkSize = 65536;
    while (true) {
      const start = Math.max(0, size - chunkSize);
      const length = size - start;
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, start);
      const lines = buffer.toString("utf8").split(/\r?\n/).filter((line) => line.trim());

      // The last line is only known to be complete when the chunk covers the
      // whole file or contains a newline before it.
      if (lines.length > 0 && (start === 0 || lines.length > 1)) {
        const last = JSON.parse(lines.at(-1));
        return last.auditIntegrity ?? null;
      }
      if (start === 0) {
        return null;
      }
      chunkSize *= 2;
    }
  } finally {
    await handle.close();
  }
}

function mergeCounts(target, source = {}) {
  for (const [key, count] of Object.entries(source)) {
    target[key] = (target[key] ?? 0) + count;
  }
}

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

async function withFileLock(lockPath, operation) {
  const handle = await acquireLock(lockPath);
  try {
    return await operation();
  } finally {
    await handle.close();
    await unlink(lockPath).catch((error) => {
      if (error.code !== "ENOENT") {
        throw error;
      }
    });
  }
}

const STALE_LOCK_MS = 30000;

async function acquireLock(lockPath) {
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      return await open(lockPath, "wx", 0o600);
    } catch (error) {
      if (error.code !== "EEXIST") {
        throw error;
      }
      if (await isStaleLock(lockPath)) {
        await unlink(lockPath).catch(() => {});
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`Timed out acquiring audit lock: ${lockPath}`);
      }
      await delay(10);
    }
  }
}

async function isStaleLock(lockPath) {
  try {
    const info = await stat(lockPath);
    return Date.now() - info.mtimeMs > STALE_LOCK_MS;
  } catch {
    return false;
  }
}
