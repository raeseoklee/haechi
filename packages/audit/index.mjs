import { createReadStream } from "node:fs";
import { mkdir, appendFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

const FORBIDDEN_KEYS = new Set(["value", "plaintext", "payload", "content", "message", "prompt", "secret"]);

export function createJsonlAuditSink({ path }) {
  if (!path) {
    throw new Error("JSONL audit sink requires path");
  }

  return {
    id: "haechi.audit.jsonl",
    version: "0.1.0",
    capabilities: {
      writesAudit: true,
      writesPlaintext: false,
      integrity: "sha256-hash-chain"
    },
    async record(event) {
      await mkdir(dirname(path), { recursive: true });
      const record = await buildIntegrityRecord(path, sanitizeAudit(event));
      await appendFile(path, `${JSON.stringify(record)}\n`, "utf8");
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

  return { valid: true, records };
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

async function readLastIntegrity(path) {
  try {
    const lines = (await readFile(path, "utf8")).split(/\r?\n/).filter((line) => line.trim());
    if (lines.length === 0) {
      return null;
    }
    const last = JSON.parse(lines.at(-1));
    return last.auditIntegrity ?? null;
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
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
