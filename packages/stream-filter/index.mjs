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
  const decoder = new TextDecoder("utf-8");
  const frames = createFrameSplitter(wireFormat);

  let blocked = false;

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
    // Flush the held tail of the delta buffer as a synthesized final frame.
    const flushed = await protector.flush();
    if (flushed.blocked) {
      blocked = true;
    } else if (flushed.text && deltaPath) {
      sink.write(serializeFrame(buildPathObject(deltaPath, flushed.text), wireFormat, null));
    }
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
