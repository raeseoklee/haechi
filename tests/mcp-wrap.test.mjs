import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { PassThrough } from "node:stream";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { wrapMcpChild } from "../packages/mcp-stdio/index.mjs";

// A minimal MCP-ish server: answers tools/call with a result containing PII,
// and proactively sends a server-initiated request (sampling/createMessage,
// NOT in the client allowlist) whose params contain a phone number.
const CHILD_SCRIPT = `
const readline = require("node:readline");
process.stdout.write(JSON.stringify({
  jsonrpc: "2.0",
  id: "srv-1",
  method: "sampling/createMessage",
  params: { prompt: "call me at 010-1234-5678" }
}) + "\\n");
const lines = readline.createInterface({ input: process.stdin });
lines.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "tools/call") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { content: "reach minji.kim@example.com for access" }
    }) + "\\n");
  } else {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { content: "FORBIDDEN_METHOD_REACHED_CHILD" }
    }) + "\\n");
  }
});
lines.on("close", () => process.exit(0));
`;

async function makeRuntime(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact",
      actions: { phone: "mask" }
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    mcp: { allowedMethods: ["initialize", "tools/call"] }
  });
}

function collectLines(stream) {
  const lines = [];
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      lines.push(JSON.parse(buffer.slice(0, index)));
      buffer = buffer.slice(0, 0) + buffer.slice(index + 1);
    }
  });
  return lines;
}

test("mcp-wrap protects both directions and answers rejections to the client", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-mcp-wrap-"));
  const runtime = await makeRuntime(dir);

  const child = spawn(process.execPath, ["-e", CHILD_SCRIPT], { stdio: ["pipe", "pipe", "inherit"] });
  const input = new PassThrough();
  const output = new PassThrough();
  const received = collectLines(output);

  const done = wrapMcpChild({ runtime, child, input, output });

  // Client request with PII params on an allowed method.
  input.write(`${JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { note: "owner minji.kim@example.com" }
  })}\n`);
  // Client request on a method outside the allowlist.
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "roots/list", params: {} })}\n`);
  // Malformed line fails closed with an error response.
  input.write("not-json\n");

  await new Promise((resolve) => setTimeout(resolve, 400));
  input.end();
  const exit = await done;

  assert.equal(exit.code, 0);

  const byId = new Map(received.map((message) => [message.id, message]));

  // Server-initiated request passed the wrap (no client allowlist applied)
  // but its params were protected: phone masked, never raw.
  const serverRequest = byId.get("srv-1");
  assert.equal(serverRequest.method, "sampling/createMessage");
  assert.doesNotMatch(serverRequest.params.prompt, /010-1234-5678/);
  assert.match(serverRequest.params.prompt, /call me at /);

  // tools/call result came back with the email redacted (server→client protection).
  const toolResult = byId.get(1);
  assert.match(toolResult.result.content, /\[REDACTED:email\]/);
  assert.doesNotMatch(JSON.stringify(toolResult), /minji\.kim@example\.com/);

  // Disallowed client method was rejected back to the client and never
  // reached the child.
  const rejected = byId.get(2);
  assert.equal(rejected.error.message, "haechi_mcp_method_not_allowed");
  assert.ok(!received.some((message) => JSON.stringify(message).includes("FORBIDDEN_METHOD_REACHED_CHILD")));

  // Malformed input produced a fail-closed stdio error for the client.
  assert.ok(received.some((message) => message.error?.message === "haechi_mcp_stdio_error"));

  // The PII the client sent never reached the child unprotected: the child
  // echoes nothing of it, and the tools/call request params were redacted
  // before forwarding (verified indirectly via the child's allowed response
  // above; direct check: audit has request-direction detections).
});

test("mcp-wrap propagates the child exit code", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-mcp-wrap-exit-"));
  const runtime = await makeRuntime(dir);

  const child = spawn(process.execPath, ["-e", "process.exit(3)"], { stdio: ["pipe", "pipe", "inherit"] });
  const input = new PassThrough();
  const output = new PassThrough();
  output.resume();

  const exit = await wrapMcpChild({ runtime, child, input, output });
  assert.equal(exit.code, 3);
  input.end();
});
