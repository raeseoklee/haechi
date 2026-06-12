import { createHash, randomUUID } from "node:crypto";

const NO_ENFORCE_MODES = new Set(["dry-run", "report-only"]);

// Safe built-in ceiling on JSON nesting depth. collectStringEntries walks the
// tree recursively, so an attacker-shaped deeply-nested payload (within
// limits.maxRequestBytes) would otherwise overflow the call stack and crash the
// process uncaught. This default protects direct callers of the exported
// collectStringEntries; the proxy path threads the configurable
// limits.maxNestingDepth through createHaechi → protectJson instead.
export const DEFAULT_MAX_NESTING_DEPTH = 256;

export function createHaechi({ filterEngine, policyEngine, cryptoProvider, auditSink, tokenVault = null, mode = "dry-run", limits = {} }) {
  if (!filterEngine || !policyEngine || !cryptoProvider || !auditSink) {
    throw new Error("Haechi requires filterEngine, policyEngine, cryptoProvider, and auditSink");
  }

  // Resolve once at construction; protectJson and the stream protector reuse it.
  const maxNestingDepth = Number.isInteger(limits.maxNestingDepth) && limits.maxNestingDepth > 0
    ? limits.maxNestingDepth
    : DEFAULT_MAX_NESTING_DEPTH;

  async function protectJson(payload, rawContext = {}) {
    // A per-request policy engine (a named profile selected from identity)
    // overrides the default. It is a control object, NOT data: strip it before
    // anything downstream (tokenize AAD, audit) sees the context.
    const { policyEngine: contextEngine, ...context } = rawContext;
    const effectiveMode = context.mode ?? mode;
    const engine = contextEngine ?? policyEngine;
    // Fail closed on an over-deep payload BEFORE any detection/transform work,
    // mirroring the byte-limit path: the thrown error carries statusCode 413 so
    // the proxy surfaces a clean 4xx rather than a stack-overflow 500.
    const entries = collectStringEntries(payload, [], { maxDepth: maxNestingDepth });
    // `context` is threaded into detection as-is and is LOAD-BEARING: e.g.
    // `context.direction` ("request" | "response") gates direction-scoped rules
    // (injection) and the response-only marker exclusion in the filter engine.
    // The proxy sets it per direction; do not drop it here.
    const detections = await filterEngine.detect({ entries, context });
    const decisions = [];

    for (const detection of detections) {
      decisions.push(await engine.decide({ detection, context, mode: effectiveMode }));
    }

    const enforced = !NO_ENFORCE_MODES.has(effectiveMode);
    const blocked = enforced && decisions.some((decision) => decision.action === "block");
    // Tokens issued or reused while protecting THIS payload; the proxy uses
    // this request-scoped set to restore only these tokens in the response.
    const issuedTokens = new Set();
    const protectedPayload = blocked ? null : await transformPayload(payload, detections, decisions, {
      context,
      cryptoProvider,
      tokenVault,
      enforced,
      issuedTokens
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
      auditEvent,
      issuedTokens: [...issuedTokens]
    };
  }

  // Stateful protector for an incremental text stream (SSE/NDJSON deltas).
  // Holds a bounded raw tail so a detection split across chunk boundaries is
  // caught before the leading part is emitted. maxMatchBytes bounds the
  // guarantee: a single match longer than it may still split across frames.
  function createStreamProtector(rawContext = {}) {
    // Strip the control-object policy engine from the data context (see
    // protectJson) so it cannot leak into tokenize AAD or audit.
    const { policyEngine: contextEngine, ...context } = rawContext;
    const effectiveMode = context.mode ?? mode;
    const engine = contextEngine ?? policyEngine;
    const enforced = !NO_ENFORCE_MODES.has(effectiveMode);
    const maxMatchBytes = context.maxMatchBytes ?? 256;
    const byType = {};
    const byAction = {};
    let detectionCount = 0;
    let pending = "";

    function tally(detections, decisions) {
      detections.forEach((detection, index) => {
        byType[detection.type] = (byType[detection.type] ?? 0) + 1;
        const action = decisions[index]?.action ?? "unknown";
        byAction[action] = (byAction[action] ?? 0) + 1;
        detectionCount += 1;
      });
    }

    async function decideAll(detections) {
      const decisions = [];
      for (const detection of detections) {
        decisions.push(await engine.decide({ detection, context, mode: effectiveMode }));
      }
      return decisions;
    }

    // Transform a complete, committed text segment.
    async function transformSegment(text) {
      const detections = await filterEngine.detect({
        entries: collectStringEntries(text, [], { maxDepth: maxNestingDepth }),
        context
      });
      const decisions = await decideAll(detections);
      tally(detections, decisions);
      const blocked = enforced && decisions.some((decision) => decision.action === "block");
      if (blocked) {
        return { text: "", blocked: true };
      }
      if (!enforced || detections.length === 0) {
        return { text, blocked: false };
      }
      const items = detections.map((detection, index) => ({ detection, decision: decisions[index] }));
      const transformed = await transformString(text, items, { context, cryptoProvider, tokenVault, issuedTokens: null });
      return { text: transformed, blocked: false };
    }

    return {
      // Protect string leaves of a parsed frame OTHER than the incremental
      // delta text (e.g. tool-call arguments). Returns the mutated object.
      async protectFrameExtras(value) {
        const detections = await filterEngine.detect({
          entries: collectStringEntries(value, [], { maxDepth: maxNestingDepth }),
          context
        });
        if (detections.length === 0) {
          return { value, blocked: false };
        }
        const decisions = await decideAll(detections);
        tally(detections, decisions);
        const blocked = enforced && decisions.some((decision) => decision.action === "block");
        if (blocked) {
          return { value: null, blocked: true };
        }
        if (!enforced) {
          return { value, blocked: false };
        }
        const transformed = await transformPayload(value, detections, decisions, {
          context, cryptoProvider, tokenVault, enforced
        });
        return { value: transformed, blocked: false };
      },
      // Append incremental text; return the portion safe to emit now.
      async push(text) {
        pending += text;
        const detections = await filterEngine.detect({
          entries: collectStringEntries(pending, [], { maxDepth: maxNestingDepth }),
          context
        });
        let commit = Math.max(0, pending.length - maxMatchBytes);
        const straddlers = detections.filter((detection) => detection.end > commit);
        if (straddlers.length > 0) {
          commit = Math.min(commit, ...straddlers.map((detection) => detection.start));
        }
        if (commit <= 0) {
          return { text: "", blocked: false };
        }
        const head = pending.slice(0, commit);
        pending = pending.slice(commit);
        return transformSegment(head);
      },
      // Drain the held tail at end of stream (no more cross-frame risk).
      async flush() {
        const tail = pending;
        pending = "";
        if (!tail) {
          return { text: "", blocked: false };
        }
        return transformSegment(tail);
      },
      summary() {
        return { detectionCount, byType, byAction };
      }
    };
  }

  return { protectJson, createStreamProtector };
}

export function collectStringEntries(value, path = [], options = {}) {
  // `options.maxDepth` bounds recursion to fail closed on a deeply-nested
  // payload (which would otherwise overflow the call stack → uncaught crash).
  // Additive third arg: existing 2-arg callers get DEFAULT_MAX_NESTING_DEPTH.
  const maxDepth = Number.isInteger(options.maxDepth) && options.maxDepth > 0
    ? options.maxDepth
    : DEFAULT_MAX_NESTING_DEPTH;

  if (typeof value === "string") {
    return [{ path, pathText: safePathToString(path), value, kind: "value" }];
  }

  // Long digit runs (e.g. card numbers) can arrive as JSON numbers; scan their
  // string form so numeric leaves are not a detection blind spot.
  if (typeof value === "number" && Number.isFinite(value)) {
    return [{ path, pathText: safePathToString(path), value: String(value), kind: "number" }];
  }

  // Descending into an array/object would exceed the configured depth. Throw a
  // fail-closed error carrying statusCode 413 (mirroring the byte-limit path) so
  // the proxy returns a clean 4xx instead of a stack-overflow 500.
  if ((Array.isArray(value) || (value && typeof value === "object")) && path.length >= maxDepth) {
    throw nestingDepthError(maxDepth);
  }

  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectStringEntries(item, path.concat(index), { maxDepth }));
  }

  if (value && typeof value === "object") {
    // Object keys are scanned too: a PII/secret used as a map key would
    // otherwise be forwarded upstream in plaintext.
    return Object.entries(value).flatMap(([key, item]) => [
      { path: path.concat(key), pathText: safePathToString(path.concat(key)), value: key, kind: "key" },
      ...collectStringEntries(item, path.concat(key), { maxDepth })
    ]);
  }

  return [];
}

function nestingDepthError(maxDepth) {
  const error = new Error(`Request JSON nesting exceeds limits.maxNestingDepth (${maxDepth})`);
  // statusCode/errorCode let the proxy catch-all surface this as a clean 4xx,
  // exactly like the request-body-too-large guard in the proxy body reader.
  error.statusCode = 413;
  error.errorCode = "haechi_request_too_deeply_nested";
  return error;
}

export function pathToString(path) {
  return path.reduce((text, part, index) => {
    if (typeof part === "number") {
      return `${text}[${part}]`;
    }
    return index === 0 ? String(part) : `${text}.${part}`;
  }, "");
}

export function safePathToString(path) {
  return path.reduce((text, part, index) => {
    if (typeof part === "number") {
      return `${text}[${part}]`;
    }
    const safePart = `key_${shortHash(String(part))}`;
    return index === 0 ? safePart : `${text}.${safePart}`;
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

async function transformPayload(payload, detections, decisions, { context, cryptoProvider, tokenVault, enforced, issuedTokens = null }) {
  if (!enforced || detections.length === 0) {
    return structuredClone(payload);
  }

  const output = structuredClone(payload);
  const byPath = new Map();

  detections.forEach((detection, index) => {
    const key = JSON.stringify([detection.kind ?? "value", detection.path]);
    const field = byPath.get(key) ?? [];
    field.push({ detection, decision: decisions[index] });
    byPath.set(key, field);
  });

  const valueGroups = [];
  const keyGroups = [];
  for (const [groupKey, items] of byPath.entries()) {
    const [kind, path] = JSON.parse(groupKey);
    (kind === "key" ? keyGroups : valueGroups).push({ kind, path, items });
  }

  for (const { kind, path, items } of valueGroups) {
    const original = getByPath(output, path);
    if (kind === "number") {
      if (typeof original !== "number") {
        continue;
      }
      const transformed = await transformString(String(original), items, { context, cryptoProvider, tokenVault, issuedTokens });
      if (transformed !== String(original)) {
        setByPath(output, path, transformed);
      }
      continue;
    }
    if (typeof original !== "string") {
      continue;
    }
    const transformed = await transformString(original, items, { context, cryptoProvider, tokenVault, issuedTokens });
    setByPath(output, path, transformed);
  }

  // Key renames run after value transforms (value paths reference original
  // keys), deepest first so ancestor paths stay valid while renaming.
  keyGroups.sort((left, right) => right.path.length - left.path.length);
  for (const { path, items } of keyGroups) {
    const parentPath = path.slice(0, -1);
    const parent = parentPath.length > 0 ? getByPath(output, parentPath) : output;
    const originalKey = path.at(-1);
    if (!parent || typeof parent !== "object" || Array.isArray(parent)
      || !Object.prototype.hasOwnProperty.call(parent, originalKey)) {
      continue;
    }
    const transformedKey = await transformString(String(originalKey), items, { context, cryptoProvider, tokenVault, issuedTokens });
    if (transformedKey === originalKey) {
      continue;
    }
    const childValue = parent[originalKey];
    delete parent[originalKey];
    let nextKey = transformedKey;
    let suffix = 2;
    while (Object.prototype.hasOwnProperty.call(parent, nextKey)) {
      nextKey = `${transformedKey}#${suffix}`;
      suffix += 1;
    }
    parent[nextKey] = childValue;
  }

  return output;
}

async function transformString(value, items, { context, cryptoProvider, tokenVault, issuedTokens = null }) {
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
    output += await replacementFor(segment, detection, decision, { context, cryptoProvider, tokenVault, issuedTokens });
    cursor = detection.end;
  }

  output += value.slice(cursor);
  return output;
}

async function replacementFor(segment, detection, decision, { context, cryptoProvider, tokenVault, issuedTokens = null }) {
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
        issuedTokens?.add(result.token);
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
    // Reader-facing audit-event schema version (frozen as part of the 1.0 API
    // contract — see docs/current/api-stability.md). Additive-only: a new field
    // bumps nothing here; only a canonicalization change is a MAJOR schema bump
    // (a new value + a reader migration). It is part of the canonicalized object
    // and so is self-consistent for hash-chain verification of new events.
    schemaVersion: "1",
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    protocol: context.protocol ?? "custom",
    operation: context.operation ?? "protect",
    // PII-safe identity — projected to the five frozen 1.0 audit-identity keys
    // (id, type, subjectHash, issuerHash, provider). scopes/labels are available
    // to the live policy engine via context.identity but are NOT part of the
    // frozen audit schema (§2.1) and must never be persisted to the hash-chained
    // log (an untrusted plugin's attacker-controlled label/scope value would
    // otherwise enter the immutable audit record via this path).
    identity: context.identity ? {
      id: context.identity.id,
      type: context.identity.type,
      subjectHash: context.identity.subjectHash,
      issuerHash: context.identity.issuerHash,
      provider: context.identity.provider
    } : null,
    profile: context.profile ?? null,
    mode,
    enforced,
    blocked,
    payloadShapeHash: shortHash(JSON.stringify(shapeOnly(payload))),
    detections: detections.map((detection, index) => ({
      type: detection.type,
      ruleId: detection.ruleId,
      path: detection.pathText,
      kind: detection.kind ?? "value",
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
  // Short values would leak most of their content through partial masking.
  if (value.length <= 8) {
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
