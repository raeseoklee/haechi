// SSE / NDJSON streaming response inspection.
//
// Frames are parsed incrementally, the primary delta-text channel is run
// through a bounded sliding buffer (cross-frame matches caught up to
// streaming.maxMatchBytes), and all other string leaves in a frame get
// within-frame protection. The whole stream is audited once at the end.
//
// P1-CR-005 — a frame whose data: payload is not JSON is NOT raw-passed. A
// CONTROL frame (the [DONE] sentinel, comment-only, empty/keepalive) has no
// inspectable text and passes through; a non-JSON CONTENT frame is inspected as
// text (single-shot protector.protectText, distinct from the delta buffer) so
// plain-text PII/secrets cannot bypass protection in inspect mode.

const SSE_DONE = "[DONE]";

export async function inspectResponseStream({ source, sink, streaming, protector, format }) {
  const wireFormat = format ?? streaming?.format ?? "ndjson";
  const deltaPath = streaming?.deltaPath ?? null;
  // Frame types that TERMINATE a delta sequence (declared per-adapter, e.g.
  // Anthropic's content_block_stop/message_delta/message_stop). Before such a
  // frame the held cross-frame buffer tail is flushed as a valid delta frame, so
  // the residual lands in-order BEFORE the terminator — never after message_stop.
  // Keepalives (ping) are deliberately NOT listed, so a match split across a ping
  // is still caught by the sliding buffer.
  const flushOnType = streaming?.flushOnType ?? null;
  const decoder = new TextDecoder("utf-8");
  const frames = createFrameSplitter(wireFormat);

  let blocked = false;
  // A structural template of the last frame that carried delta text, used to
  // re-emit a held buffer tail as a VALID delta frame (preserving its wire
  // wrapper — Anthropic's `event:` line — plus sibling fields like type/index).
  let lastDeltaTemplate = null;

  async function flushHeldTail() {
    const flushed = await protector.flush();
    if (flushed.blocked) {
      blocked = true;
      return;
    }
    if (!flushed.text || !deltaPath) {
      return;
    }
    if (lastDeltaTemplate) {
      const object = structuredClone(lastDeltaTemplate.object);
      setByPath(object, deltaPath, flushed.text);
      sink.write(serializeFrame(object, wireFormat, lastDeltaTemplate.original));
    } else {
      // No prior delta frame to model — fall back to a minimal synthesized frame.
      sink.write(serializeFrame(buildPathObject(deltaPath, flushed.text), wireFormat, null));
    }
  }

  async function handleFrame(raw) {
    const frame = { raw, body: raw.trim() };
    const parsed = parseFrame(frame, wireFormat);
    if (!parsed.ok) {
      // P1-CR-005 — a parse-failed frame is one of two things:
      //  (1) a CONTROL frame with no inspectable text (the SSE [DONE] sentinel,
      //      a comment-only frame, an empty/whitespace/keepalive frame) — there
      //      is genuinely nothing to protect, so pass it through verbatim; or
      //  (2) a CONTENT frame whose data: payload is NOT JSON (plain text,
      //      partial/malformed JSON, provider-specific text). That text CAN carry
      //      PII/secrets, so it must be INSPECTED AS TEXT, not raw-passed.
      if (parsed.control || parsed.text == null) {
        sink.write(frame.raw);
        return;
      }
      // Inspect the reconstructed data text as a single self-contained payload.
      // protectText is DISTINCT from the delta-channel push/flush buffer, so a
      // non-JSON frame's text never corrupts the JSON delta sliding buffer. A
      // block-action detection fails the stream closed; otherwise re-emit the
      // protected text (preserving the original wire wrapper / event: lines).
      const protectedText = await protector.protectText(parsed.text);
      if (protectedText.blocked) {
        blocked = true;
        return;
      }
      sink.write(serializeTextFrame(protectedText.text, wireFormat, frame));
      return;
    }

    const json = parsed.json;

    // A bare PRIMITIVE JSON value (string/number/boolean/null) has no object
    // structure for the delta/extras object path — a deltaPath setByPath on a
    // string root would throw an uncaught TypeError on an attacker-influenceable
    // frame. A JSON string can itself carry PII, so inspect the re-serialized
    // value as text (same single-shot path as a non-JSON content frame).
    if (json === null || typeof json !== "object") {
      const protectedPrimitive = await protector.protectText(JSON.stringify(json));
      if (protectedPrimitive.blocked) {
        blocked = true;
        return;
      }
      sink.write(serializeTextFrame(protectedPrimitive.text, wireFormat, frame));
      return;
    }

    // A delta-terminating frame: flush the held tail (as a valid delta frame)
    // before emitting it, so the residual is correctly ordered.
    if (flushOnType && flushOnType.values.includes(getByPath(json, flushOnType.path))) {
      await flushHeldTail();
      if (blocked) {
        return;
      }
    }

    let deltaText = null;
    if (deltaPath) {
      const found = getByPath(json, deltaPath);
      if (typeof found === "string") {
        deltaText = found;
        setByPath(json, deltaPath, "");
      }
    }

    // Within-frame protection for everything except the delta channel.
    const extras = await protector.protectFrameExtras(json);
    if (extras.blocked) {
      blocked = true;
      return;
    }
    const frameObject = extras.value;

    if (deltaText !== null) {
      const pushed = await protector.push(deltaText);
      if (pushed.blocked) {
        blocked = true;
        return;
      }
      setByPath(frameObject, deltaPath, pushed.text);
      // Snapshot this frame's structure + wire wrapper as the flush template.
      lastDeltaTemplate = { object: structuredClone(frameObject), original: frame };
    }

    sink.write(serializeFrame(frameObject, wireFormat, frame));
  }

  for await (const chunk of source) {
    for (const frame of frames.push(decoder.decode(chunk, { stream: true }))) {
      await handleFrame(frame);
      if (blocked) {
        break;
      }
    }
    if (blocked) {
      break;
    }
  }

  if (!blocked) {
    for (const frame of frames.end(decoder.decode())) {
      await handleFrame(frame);
      if (blocked) {
        break;
      }
    }
  }

  if (!blocked) {
    // Flush any remaining held tail (a stream that ended on a delta frame).
    await flushHeldTail();
  }

  // The caller closes the sink AFTER recording the stream decision, so the
  // audit write is durable before the client connection ends.
  return { blocked, summary: protector.summary() };
}

function createFrameSplitter(format) {
  const delimiter = format === "sse" ? "\n\n" : "\n";
  let buffer = "";
  return {
    // Append text and return the raw text of every complete frame now
    // available; the trailing partial is retained for the next push.
    push(text) {
      buffer += text;
      const out = [];
      let index;
      while ((index = buffer.indexOf(delimiter)) !== -1) {
        const raw = buffer.slice(0, index + delimiter.length);
        buffer = buffer.slice(index + delimiter.length);
        if (raw.trim()) {
          out.push(raw);
        }
      }
      return out;
    },
    // Flush any trailing partial frame at end of stream.
    end(text) {
      buffer += text;
      const remainder = buffer;
      buffer = "";
      return remainder.trim() ? [remainder] : [];
    }
  };
}

// Parse a frame. On success: { ok:true, json }. On failure the caller needs to
// know WHICH kind of failure it is (P1-CR-005):
//   - { ok:false, control:true }          → a CONTROL frame (no inspectable
//                                             text: [DONE], comment-only, empty/
//                                             whitespace/keepalive) → pass raw.
//   - { ok:false, control:false, text }   → a CONTENT frame whose data: payload
//                                             is non-JSON → inspect `text` as text.
// Recognize an SSE `data:` field line LENIENTLY — allowing (non-spec) leading
// whitespace before the field name — and return its payload (one leading space
// after the colon stripped per the SSE spec), or null if the line is not a data
// field. SECURITY (P1-CR-005 follow-up): recognition MUST be identical in the
// parser (which inspects/redacts) and the serializers (which re-emit). If the
// serializer used a stricter `line.startsWith("data:")` it would fail to match a
// `  data: <pii>` line, emit it VERBATIM, and leak the original plaintext while
// separately appending the redacted copy. Both sides use this one helper.
const SSE_DATA_LINE = /^[ \t]*data:/;
function sseDataPayload(line) {
  const match = /^[ \t]*data:(.*)$/.exec(line);
  return match ? match[1].replace(/^ /, "") : null;
}

function parseFrame(frame, format) {
  if (!frame) {
    return { ok: false, control: true, text: null };
  }
  let payload = frame.body;
  if (format === "sse") {
    // An empty/whitespace/comment-only/keepalive frame has no data: line → a
    // CONTROL frame with nothing to inspect.
    if (payload === "") {
      return { ok: false, control: true, text: null };
    }
    const dataLines = payload
      .split("\n")
      .map(sseDataPayload)
      .filter((value) => value !== null);
    if (dataLines.length === 0) {
      // Comment-only (`:` lines) or field-only (event:/id:/retry:) frame.
      return { ok: false, control: true, text: null };
    }
    // P2-CR-013 — the SSE model joins multiple data: lines with a NEWLINE, not
    // "". Newlines are valid JSON whitespace between tokens / inside a string, so
    // a multi-line JSON event still JSON.parses; a multi-line plain-text event is
    // reconstructed with its newlines before text inspection.
    payload = dataLines.join("\n");
    if (payload === SSE_DONE) {
      // The [DONE] sentinel: a CONTROL frame, never inspected.
      return { ok: false, control: true, text: null };
    }
  } else if (payload === "") {
    // NDJSON: an empty/whitespace line is a CONTROL/keepalive frame.
    return { ok: false, control: true, text: null };
  }
  try {
    return { ok: true, json: JSON.parse(payload) };
  } catch {
    // Non-JSON CONTENT: surface the reconstructed payload text for inspection.
    return { ok: false, control: false, text: payload };
  }
}

function serializeFrame(json, format, original) {
  const body = JSON.stringify(json);
  if (format === "sse") {
    // Preserve the original SSE field lines (`event:`, `id:`, `retry:`, `:`
    // comments) and substitute only the data payload. Event-typed streams
    // (Anthropic Messages) dispatch on the `event:` line, so dropping it would
    // make the stream unconsumable. OpenAI-style frames carry only a `data:`
    // line, so the output is byte-identical to `data: ${body}\n\n`.
    if (original && typeof original.raw === "string") {
      const lines = original.raw.replace(/\n+$/, "").split("\n");
      const out = [];
      let dataWritten = false;
      for (const line of lines) {
        if (SSE_DATA_LINE.test(line)) {
          // Collapse any (multi-line) data payload into the single new body. Use
          // the SAME lenient match as the parser so a `  data:` line is replaced,
          // never emitted verbatim (which would leak the original plaintext).
          if (!dataWritten) {
            out.push(`data: ${body}`);
            dataWritten = true;
          }
        } else {
          out.push(line);
        }
      }
      if (!dataWritten) {
        out.push(`data: ${body}`);
      }
      return `${out.join("\n")}\n\n`;
    }
    return `data: ${body}\n\n`;
  }
  // NDJSON: preserve the original trailing newline style when available.
  return original && original.raw.endsWith("\n") ? `${body}\n` : `${body}\n`;
}

// P1-CR-005 — re-serialize a parse-failed CONTENT frame after its data text has
// been inspected/transformed. Unlike serializeFrame (which JSON.stringifies an
// object), this carries through ARBITRARY text. For SSE it preserves the
// original non-data field lines (event:/id:/retry:/`:` comments) and re-emits the
// protected text as data: lines — one per text line, per the SSE spec, so a
// multi-line payload round-trips correctly. For NDJSON the frame body IS the
// text, so emit the protected text plus a newline.
function serializeTextFrame(text, format, original) {
  if (format !== "sse") {
    return `${text}\n`;
  }
  const dataLines = text.split("\n").map((line) => `data: ${line}`);
  if (original && typeof original.raw === "string") {
    const lines = original.raw.replace(/\n+$/, "").split("\n");
    const out = [];
    let dataWritten = false;
    for (const line of lines) {
      if (SSE_DATA_LINE.test(line)) {
        // Replace the (possibly multi-line) data block with the protected lines.
        // Lenient match (same as the parser) so a `  data:` line is replaced, not
        // emitted verbatim (which would leak the original plaintext PII).
        if (!dataWritten) {
          out.push(...dataLines);
          dataWritten = true;
        }
      } else {
        out.push(line);
      }
    }
    if (!dataWritten) {
      out.push(...dataLines);
    }
    return `${out.join("\n")}\n\n`;
  }
  return `${dataLines.join("\n")}\n\n`;
}

export function getByPath(value, path) {
  let current = value;
  for (const part of path) {
    if (current == null) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

export function setByPath(value, path, next) {
  let current = value;
  for (let index = 0; index < path.length - 1; index += 1) {
    const part = path[index];
    if (current[part] == null || typeof current[part] !== "object") {
      return false;
    }
    current = current[part];
  }
  if (current == null || typeof current !== "object") {
    return false;
  }
  current[path[path.length - 1]] = next;
  return true;
}

export function buildPathObject(path, leaf) {
  const root = typeof path[0] === "number" ? [] : {};
  let current = root;
  for (let index = 0; index < path.length - 1; index += 1) {
    const nextIsIndex = typeof path[index + 1] === "number";
    current[path[index]] = nextIsIndex ? [] : {};
    current = current[path[index]];
  }
  current[path[path.length - 1]] = leaf;
  return root;
}
