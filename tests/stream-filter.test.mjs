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

// --- P1-CR-005: non-JSON CONTENT frames are inspected as text ---------------

test("P1-CR-005: a plain-text SSE data frame with PII is redacted, not leaked", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-plaintext-"));
  const runtime = await makeRuntime(dir);
  const { text, blocked, summary } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    // The data: payload is NOT JSON — a bare email address.
    chunks: ["data: minji.kim@example.com\n\n", "data: [DONE]\n\n"]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /data: \[REDACTED:email\]/);
  assert.match(text, /data: \[DONE\]/);
  assert.ok(summary.byType.email >= 1);
});

test("P1-CR-005: a plain-text SSE frame with a block action BLOCKS the stream", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-plaintext-block-"));
  const runtime = await makeRuntime(dir, { defaultAction: "allow", actions: { card: "block" } });
  const { text, blocked, summary } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [
      "data: safe so far\n\n",
      "data: card 4242424242424242 leaked\n\n",
      "data: trailing\n\n",
      "data: [DONE]\n\n"
    ]
  });
  assert.equal(blocked, true);
  assert.doesNotMatch(text, /4242424242424242/);
  assert.doesNotMatch(text, /trailing/);
  assert.ok(summary.byAction.block >= 1);
});

test("P1-CR-005: malformed/partial JSON with PII is inspected as text", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-malformed-"));
  const runtime = await makeRuntime(dir);
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    // A truncated JSON object (unterminated) carrying an email — JSON.parse fails.
    chunks: [`data: {"partial": "reach minji.kim@example.com\n\n`, "data: [DONE]\n\n"]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("P1-CR-005: an NDJSON non-JSON content frame with PII is inspected as text", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-ndjson-text-"));
  const runtime = await makeRuntime(dir);
  const { text, blocked } = await runStream({
    runtime,
    streaming: NDJSON_CHAT,
    // A bare non-JSON line (provider-specific text) carrying an email.
    chunks: ["plain text minji.kim@example.com here\n"]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("P1-CR-005: comment-only and keepalive control frames pass untouched", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-control-"));
  const runtime = await makeRuntime(dir);
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [
      ": this is a comment\n\n",
      ": keep-alive ping\n\n",
      "event: ping\n\n",
      "data: [DONE]\n\n"
    ]
  });
  assert.equal(blocked, false);
  assert.match(text, /: this is a comment/);
  assert.match(text, /: keep-alive ping/);
  assert.match(text, /event: ping/);
  assert.match(text, /data: \[DONE\]/);
});

test("P1-CR-005: a tokenized round-trip echoed by the model is not re-flagged", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-marker-"));
  const runtime = await makeRuntime(dir);
  // A response-direction marker (a prior redaction) echoed back as plain text.
  const { text, blocked, summary } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: ["data: I sent it to [REDACTED:email] earlier\n\n", "data: [DONE]\n\n"]
  });
  assert.equal(blocked, false);
  assert.match(text, /\[REDACTED:email\]/);
  // The marker is skipped on the response direction — no email re-detection.
  assert.equal(summary.byType.email ?? 0, 0);
});

// --- P2-CR-013: multi-line SSE data: join semantics -------------------------

test("P2-CR-013: a multi-line data: JSON event still parses and is protected", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-multiline-json-"));
  const runtime = await makeRuntime(dir);
  // The JSON object is split across two data: lines (joined with \n by spec).
  const frame = `data: {"choices": [{"delta":\ndata: {"content": "mail minji.kim@example.com"}}]}\n\n`;
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [frame, "data: [DONE]\n\n"]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("P2-CR-013: a multi-line plain-text data: event with PII is caught", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-multiline-text-"));
  const runtime = await makeRuntime(dir);
  // Two data: lines of plain text; the email is on the second line. With join("")
  // the two lines would merge ("line oneminji...") — with join("\n") the email
  // stays a clean token and the newline is preserved on re-emit.
  const frame = `data: first line of text\ndata: then minji.kim@example.com here\n\n`;
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [frame, "data: [DONE]\n\n"]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /minji\.kim@example\.com/);
  assert.match(text, /\[REDACTED:email\]/);
  assert.match(text, /first line of text/);
  // The re-emitted frame keeps two data: lines (the newline survives).
  assert.match(text, /data: first line of text\ndata: then \[REDACTED:email\] here/);
});

test("P1-CR-005 follow-up: a leading-whitespace `data:` line is inspected, never emitted verbatim (no trim-mismatch leak)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-ws-"));
  const runtime = await makeRuntime(dir);
  // The parser trims the body so a `  data: <pii>` line IS recognized + redacted;
  // the serializer must use the SAME lenient match or it emits the original line
  // verbatim (leaking the plaintext) while appending the redacted copy.
  for (const lead of [" ", "\t", "  \t"]) {
    const { text, blocked } = await runStream({
      runtime,
      streaming: SSE_CHAT,
      chunks: [`${lead}data: minji.kim@example.com\n\n`, "data: [DONE]\n\n"]
    });
    assert.equal(blocked, false);
    assert.doesNotMatch(text, /minji\.kim@example\.com/, `leading ${JSON.stringify(lead)} must not leak`);
    assert.match(text, /\[REDACTED:email\]/);
  }
});

test("P1-CR-005 follow-up: a leading-whitespace JSON delta frame does not leak a non-delta PII field verbatim", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-ws-json-"));
  const runtime = await makeRuntime(dir);
  const frame = ` data: ${JSON.stringify({ choices: [{ delta: { content: "hi" } }], note: "reach me at boss@corp.com" })}\n\n`;
  const { text, blocked } = await runStream({ runtime, streaming: SSE_CHAT, chunks: [frame] });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /boss@corp\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});

test("P1-CR-005 follow-up: a bare primitive JSON frame (string root) is inspected as text, not an uncaught throw", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-stream-prim-"));
  const runtime = await makeRuntime(dir);
  // A bare top-level JSON string under a configured deltaPath used to throw on
  // setByPath(stringRoot); it must instead be inspected as text and redacted.
  const { text, blocked } = await runStream({
    runtime,
    streaming: SSE_CHAT,
    chunks: [`data: ${JSON.stringify("call me at jane@x.com")}\n\n`]
  });
  assert.equal(blocked, false);
  assert.doesNotMatch(text, /jane@x\.com/);
  assert.match(text, /\[REDACTED:email\]/);
});
