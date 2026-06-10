import { createReadStream } from "node:fs";
import { appendFile, mkdir, open, stat, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";

const FORBIDDEN_KEYS = new Set(["value", "plaintext", "payload", "content", "message", "prompt", "secret"]);

export function createJsonlAuditSink({ path }) {
  if (!path) {
    throw new Error("JSONL audit sink requires path");
  }

  let writeQueue = Promise.resolve();

  return {
    id: "haechi.audit.jsonl",
    version: "0.1.0",
    capabilities: {
      writesAudit: true,
      writesPlaintext: false,
      integrity: "sha256-hash-chain"
    },
    async record(event) {
      const write = writeQueue.then(async () => {
        await mkdir(dirname(path), { recursive: true });
        await withFileLock(`${path}.lock`, async () => {
          const record = await buildIntegrityRecord(path, sanitizeAudit(event));
          await appendFile(path, `${JSON.stringify(record)}\n`, "utf8");
        });
      });
      writeQueue = write.catch(() => {});
      await write;
    }
  };
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

export async function verifyAuditChain(path) {
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

    expectedPreviousHash = eventHash;
    expectedSequence += 1;
    records += 1;
  }

  // headHash anchors the chain externally: publishing it out-of-band is the
  // only defense against tail truncation, which the chain alone cannot detect.
  return { valid: true, records, headHash: expectedPreviousHash };
}

async function buildIntegrityRecord(path, event) {
  const previous = await readLastIntegrity(path);
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
