// SSE / NDJSON streaming response inspection.
//
// Frames are parsed incrementally, the primary delta-text channel is run
// through a bounded sliding buffer (cross-frame matches caught up to
// streaming.maxMatchBytes), and all other string leaves in a frame get
// within-frame protection. The whole stream is audited once at the end.

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
      // Non-JSON frame (e.g. `data: [DONE]`, comments, keep-alives): pass
      // through verbatim — there is nothing to inspect.
      sink.write(frame.raw);
      return;
    }

    const json = parsed.json;

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

function parseFrame(frame, format) {
  if (!frame) {
    return { ok: false };
  }
  let payload = frame.body;
  if (format === "sse") {
    const dataLines = payload
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());
    if (dataLines.length === 0) {
      return { ok: false };
    }
    payload = dataLines.join("");
    if (payload === SSE_DONE) {
      return { ok: false };
    }
  }
  try {
    return { ok: true, json: JSON.parse(payload) };
  } catch {
    return { ok: false };
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
        if (line.startsWith("data:")) {
          // Collapse any (multi-line) data payload into the single new body.
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
