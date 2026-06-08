import { createReadStream } from "node:fs";
import { mkdir, appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

const FORBIDDEN_KEYS = new Set(["value", "plaintext", "payload", "content", "message", "prompt", "secret"]);

export function createJsonlAuditSink({ path }) {
  if (!path) {
    throw new Error("JSONL audit sink requires path");
  }

  return {
    id: "aicel.audit.jsonl",
    version: "0.1.0",
    capabilities: {
      writesAudit: true,
      writesPlaintext: false
    },
    async record(event) {
      await mkdir(dirname(path), { recursive: true });
      await appendFile(path, `${JSON.stringify(sanitizeAudit(event))}\n`, "utf8");
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

function mergeCounts(target, source = {}) {
  for (const [key, count] of Object.entries(source)) {
    target[key] = (target[key] ?? 0) + count;
  }
}
