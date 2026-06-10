import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { inspectResponseStream, getByPath, setByPath, buildPathObject } from "../packages/stream-filter/index.mjs";

const SSE_CHAT = { format: "sse", deltaPath: ["choices", 0, "delta", "content"] };
const NDJSON_CHAT = { format: "ndjson", deltaPath: ["message", "content"] };

async function makeRuntime(dir, policyOverrides = {}) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact",
      ...policyOverrides
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
}

function sourceFrom(chunks) {
  const encoder = new TextEncoder();
  return (async function* () {
    for (const chunk of chunks) {
      yield encoder.encode(chunk);
    }
  })();
}

function collectingSink() {
  let out = "";
  return { write(text) { out += text; }, end() {}, get text() { return out; } };
}

function sseChat(content) {
  return `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`;
}
function ndjsonChat(content, done = false) {
  return `${JSON.stringify({ message: { role: "assistant", content }, done })}\n`;
}

async function runStream({ runtime, chunks, streaming, mode = "enforce" }) {
  const sink = collectingSink();
  const protector = runtime.haechi.createStreamProtector({ direction: "response", mode, maxMatchBytes: 256 });
  const result = await inspectResponseStream({ source: sourceFrom(chunks), sink, streaming, protector });
  return { ...result, text: sink.text };
}

test("path helpers round-trip nested delta locations", () => {
  const frame = { choices: [{ delta: { content: "hi" } }] };
  assert.equal(getByPath(frame, ["choices", 0, "delta", "content"]), "hi");
  assert.equal(setByPath(frame, ["choices", 0, "delta", "content"], "bye"), true);
  assert.equal(frame.choices[0].delta.content, "bye");
  assert.deepEqual(buildPathObject(["choices", 0, "delta", "content"], "x"), { choices: [{ delta: { content: "x" } }] });
  assert.deepEqual(buildPathObject(["message", "content"], "y"), { message: { content: "y" } });
});

test("NDJSON within-frame PII in the delta channel is redacted", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-ndjson-"));
  const runtime = await makeRuntime(dir);
  const { text, blocked } = await runStream({
    runtime,
    streaming: NDJSON_CHAT,
    chunks: [ndjsonChat("reach me at minji.kim@example.com "), ndjsonChat("today", true)]
  });

  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
  // The non-PII text survives and frames stay valid NDJSON.
  const restored = text.trim().split("\n").map((line) => JSON.parse(line).message.content).join("");
  assert.match(restored, /reach me at \[REDACTED:email\] today/);
});

test("SSE cross-frame PII split across deltas is still caught", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-sse-xframe-"));
  const runtime = await makeRuntime(dir);
  // "minji.kim@example.com" is split across three SSE deltas.
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [sseChat("contact minji"), sseChat(".kim@exa"), sseChat("mple.com now"), "data: [DONE]\n\n"]
  });

  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[DONE\]/);
  const restored = text
    .split("\n\n")
    .filter((frame) => frame.startsWith("data:") && !frame.includes("[DONE]"))
    .map((frame) => JSON.parse(frame.slice(5).trim()).choices[0].delta.content)
    .join("");
  assert.match(restored, /contact \[REDACTED:email\] now/);
});

test("cross-frame match split byte-by-byte is caught", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-byte-"));
  const runtime = await makeRuntime(dir);
  const email = "minji.kim@example.com";
  const chunks = [...email].map((ch) => sseChat(ch));
  chunks.unshift(sseChat("x "));
  chunks.push("data: [DONE]\n\n");
  const { text } = await runStream({ runtime, streaming: SSE_CHAT, chunks });
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("[DONE] and keep-alive frames pass through untouched", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-done-"));
  const runtime = await makeRuntime(dir);
  const { text } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [": keep-alive\n\n", sseChat("hello"), "data: [DONE]\n\n"]
  });
  assert.match(text, /: keep-alive/);
  assert.match(text, /data: \[DONE\]/);
  assert.match(text, /hello/);
});

test("PII outside the delta channel (tool-call args) is protected within-frame", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-tool-"));
  const runtime = await makeRuntime(dir);
  const frame = `data: ${JSON.stringify({
    choices: [{ delta: { tool_calls: [{ function: { arguments: "{\"to\":\"seoul@example.com\"}" } }] } }]
  })}\n\n`;
  const { text } = await runStream({ runtime, streaming: SSE_CHAT, chunks: [frame, "data: [DONE]\n\n"] });
  assert.doesNotMatch(text, /seoul@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("block action stops the stream before emitting the blocked value", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-block-"));
  const runtime = await makeRuntime(dir, { defaultAction: "allow", actions: { api_key: "block" } });
  const { text, blocked, summary } = await runStream({
    runtime,
    streaming: NDJSON_CHAT,
    chunks: [
      ndjsonChat("here is safe text "),
      ndjsonChat("token sk_demo_0123456789abcdef0123456789 oops"),
      ndjsonChat("trailing", true)
    ]
  });
  assert.equal(blocked, true);
  assert.doesNotMatch(text, /sk_demo_0123456789abcdef0123456789/);
  assert.doesNotMatch(text, /trailing/);
  assert.ok(summary.byAction.block >= 1);
});

test("report-only mode detects but does not transform the stream", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-reportonly-"));
  const runtime = await makeRuntime(dir);
  const { text, summary } = await runStream({
    runtime,
    streaming: NDJSON_CHAT,
    mode: "report-only",
    chunks: [ndjsonChat("mail minji.kim@example.com", true)]
  });
  assert.match(text, /minji\.kim@example\.com/);
  assert.ok(summary.byType.email >= 1);
});
