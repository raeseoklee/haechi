import { createHash, randomUUID } from "node:crypto";

const NO_ENFORCE_MODES = new Set(["dry-run", "report-only"]);

export function createHaechi({ filterEngine, policyEngine, cryptoProvider, auditSink, tokenVault = null, mode = "dry-run" }) {
  if (!filterEngine || !policyEngine || !cryptoProvider || !auditSink) {
    throw new Error("Haechi requires filterEngine, policyEngine, cryptoProvider, and auditSink");
  }

  async function protectJson(payload, context = {}) {
    const effectiveMode = context.mode ?? mode;
    const entries = collectStringEntries(payload);
    const detections = await filterEngine.detect({ entries, context });
    const decisions = [];

    for (const detection of detections) {
      decisions.push(await policyEngine.decide({ detection, context, mode: effectiveMode }));
    }

    const enforced = !NO_ENFORCE_MODES.has(effectiveMode);
    const blocked = enforced && decisions.some((decision) => decision.action === "block");
    const protectedPayload = blocked ? null : await transformPayload(payload, detections, decisions, {
      context,
      cryptoProvider,
      tokenVault,
      enforced
    });

    const auditEvent = buildAuditEvent({
      context,
      mode: effectiveMode,
      enforced,
      blocked,
      payload,
      detections,
      decisions
    });

    await auditSink.record(auditEvent);

    return {
      payload: protectedPayload,
      blocked,
      summary: summarize(detections, decisions),
      auditEvent
    };
  }

  return { protectJson };
}

export function collectStringEntries(value, path = []) {
  if (typeof value === "string") {
    return [{ path, pathText: pathToString(path), value }];
  }

  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectStringEntries(item, path.concat(index)));
  }

  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([key, item]) => collectStringEntries(item, path.concat(key)));
  }

  return [];
}

export function pathToString(path) {
  return path.reduce((text, part, index) => {
    if (typeof part === "number") {
      return `${text}[${part}]`;
    }
    return index === 0 ? String(part) : `${text}.${part}`;
  }, "");
}

export function shapeOnly(value) {
  if (typeof value === "string") {
    return { type: "string", length: value.length };
  }
  if (Array.isArray(value)) {
    return value.map((item) => shapeOnly(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shapeOnly(item)]));
  }
  return { type: value === null ? "null" : typeof value };
}

export function summarize(detections, decisions) {
  const byType = {};
  const byAction = {};

  for (const detection of detections) {
    byType[detection.type] = (byType[detection.type] ?? 0) + 1;
  }

  for (const decision of decisions) {
    byAction[decision.action] = (byAction[decision.action] ?? 0) + 1;
  }

  return {
    detectionCount: detections.length,
    byType,
    byAction
  };
}

async function transformPayload(payload, detections, decisions, { context, cryptoProvider, tokenVault, enforced }) {
  if (!enforced || detections.length === 0) {
    return structuredClone(payload);
  }

  const output = structuredClone(payload);
  const byPath = new Map();

  detections.forEach((detection, index) => {
    const key = JSON.stringify(detection.path);
    const field = byPath.get(key) ?? [];
    field.push({ detection, decision: decisions[index] });
    byPath.set(key, field);
  });

  for (const [pathKey, items] of byPath.entries()) {
    const path = JSON.parse(pathKey);
    const original = getByPath(output, path);
    if (typeof original !== "string") {
      continue;
    }
    const transformed = await transformString(original, items, { context, cryptoProvider, tokenVault });
    setByPath(output, path, transformed);
  }

  return output;
}

async function transformString(value, items, { context, cryptoProvider, tokenVault }) {
  const sorted = items
    .filter(({ decision }) => decision.action !== "allow" && decision.action !== "block")
    .sort((left, right) => left.detection.start - right.detection.start);

  let cursor = 0;
  let output = "";

  for (const { detection, decision } of sorted) {
    if (detection.start < cursor) {
      continue;
    }

    output += value.slice(cursor, detection.start);
    const segment = value.slice(detection.start, detection.end);
    output += await replacementFor(segment, detection, decision, { context, cryptoProvider, tokenVault });
    cursor = detection.end;
  }

  output += value.slice(cursor);
  return output;
}

async function replacementFor(segment, detection, decision, { context, cryptoProvider, tokenVault }) {
  switch (decision.action) {
    case "redact":
      return `[REDACTED:${detection.type}]`;
    case "mask":
      return maskSensitive(segment);
    case "tokenize":
      if (tokenVault) {
        const result = await tokenVault.tokenize({
          plaintext: segment,
          type: detection.type,
          context,
          metadata: {
            path: detection.pathText,
            ruleId: detection.ruleId
          }
        });
        return `[TOKEN:${result.token}]`;
      }
      return `[TOKEN:${detection.type}:${shortHash(segment)}]`;
    case "encrypt": {
      const envelope = await cryptoProvider.encrypt({
        plaintext: segment,
        aad: {
          context,
          path: detection.pathText,
          type: detection.type,
          ruleId: detection.ruleId
        }
      });
      return `[HAECHI_ENC:${base64UrlEncode(JSON.stringify(envelope))}]`;
    }
    default:
      return segment;
  }
}

function buildAuditEvent({ context, mode, enforced, blocked, payload, detections, decisions }) {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    protocol: context.protocol ?? "custom",
    operation: context.operation ?? "protect",
    mode,
    enforced,
    blocked,
    payloadShapeHash: shortHash(JSON.stringify(shapeOnly(payload))),
    detections: detections.map((detection, index) => ({
      type: detection.type,
      ruleId: detection.ruleId,
      path: detection.pathText,
      confidence: detection.confidence,
      action: decisions[index]?.action ?? "unknown",
      enforced
    })),
    summary: summarize(detections, decisions)
  };
}

function getByPath(value, path) {
  return path.reduce((current, part) => current?.[part], value);
}

function setByPath(value, path, nextValue) {
  let current = value;
  for (let index = 0; index < path.length - 1; index += 1) {
    current = current[path[index]];
  }
  current[path[path.length - 1]] = nextValue;
}

function maskSensitive(value) {
  if (value.length <= 4) {
    return "*".repeat(value.length);
  }
  return `${value.slice(0, 2)}${"*".repeat(Math.max(4, value.length - 4))}${value.slice(-2)}`;
}

function shortHash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

function base64UrlEncode(value) {
  return Buffer.from(value, "utf8").toString("base64url");
}
