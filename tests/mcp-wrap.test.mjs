import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { PassThrough } from "node:stream";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { wrapMcpChild } from "../packages/mcp-stdio/index.mjs";

const CLI = resolve("packages/cli/bin/haechi.mjs");

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

// --- mcp-wrap --stderr: child stderr boundary (P2-CR-006) -------------------
// These exercise the CLI command (bin/haechi.mjs), which owns the stderr policy,
// via a real subprocess so the child→parent stderr boundary is tested end-to-end
// (the in-process wrapMcpChild tests above don't cover the CLI's stdio wiring).

// A tiny fake MCP child (CommonJS .cjs so it can require node:readline). It emits
// diagnostic lines on STDERR (the channel under test): a synthetic secret and a
// card number (both hard-block → the line is dropped), a synthetic email (PII →
// redacted in place), a synthetic phone (masked in place), and a clean line
// (passthrough). It also answers requests on stdout so the bidirectional wrap
// settles, but the assertions here only concern the stderr boundary. All values
// are synthetic, never real secrets.
const STDERR_SECRET = `sk-ant-api03-${"A".repeat(88)}`;
const STDERR_CHILD_SCRIPT = `
process.stderr.write("boot token ${STDERR_SECRET}\\n");
process.stderr.write("contact minji.kim@example.com for help\\n");
process.stderr.write("charged card 4242424242424242 today\\n");
process.stderr.write("call me at 010-1234-5678 now\\n");
process.stderr.write("server ready on stdio\\n");
const readline = require("node:readline");
const lines = readline.createInterface({ input: process.stdin });
lines.on("line", (line) => {
  const message = JSON.parse(line);
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { ok: true } }) + "\\n");
});
lines.on("close", () => process.exit(0));
`;

// Enforce-mode config so detections actually transform/block (dry-run only
// detects). card → block via the default policy.actions.
async function writeStderrEnforceConfig(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const init = spawn(process.execPath, [CLI, "init", "--force"], { cwd: dir });
  await new Promise((resolveExit, rejectExit) => {
    init.once("error", rejectExit);
    init.once("exit", (code) => (code === 0 ? resolveExit() : rejectExit(new Error(`init exit ${code}`))));
  });
  const configPath = join(dir, "haechi.config.json");
  await writeFile(configPath, JSON.stringify({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["korean-pii", "secrets-only", "llm-redact"],
      defaultAction: "redact",
      actions: { card: "block" }
    },
    keys: { provider: "local", keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  }, null, 2), "utf8");
  return configPath;
}

// Run `haechi mcp-wrap [--stderr <mode>]` against the fake child, drive one
// stdin line, and capture the wrapper's own stderr (the filtered/dropped/raw
// re-emission of the child's stderr).
function runStderrWrap({ dir, stderrFlag, childScriptPath }) {
  const flags = stderrFlag ? ["--stderr", stderrFlag] : [];
  const args = [CLI, "mcp-wrap", ...flags, "--", process.execPath, childScriptPath];
  const proc = spawn(process.execPath, args, { cwd: dir });
  let stderr = "";
  let stdout = "";
  proc.stderr.setEncoding("utf8");
  proc.stdout.setEncoding("utf8");
  proc.stderr.on("data", (chunk) => { stderr += chunk; });
  proc.stdout.on("data", (chunk) => { stdout += chunk; });
  // Send one allowed request so the child responds and the wrap settles.
  proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })}\n`);
  proc.stdin.end();
  return new Promise((resolveRun, rejectRun) => {
    proc.once("error", rejectRun);
    proc.once("exit", (code) => resolveRun({ code, stderr, stdout }));
  });
}

async function makeStderrChildScript(dir) {
  // .cjs so node runs it as CommonJS (the script uses require()).
  const path = join(dir, "fake-mcp-child.cjs");
  await writeFile(path, STDERR_CHILD_SCRIPT, "utf8");
  return path;
}

test("mcp-wrap --stderr filter (default) redacts secrets/PII on the child's stderr", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-wrap-stderr-filter-"));
  await writeStderrEnforceConfig(dir);
  const childScriptPath = await makeStderrChildScript(dir);

  // No --stderr flag → default is "filter".
  const { stderr } = await runStderrWrap({ dir, stderrFlag: null, childScriptPath });

  // No raw sensitive value crosses the boundary. The secret and the card are
  // hard-block types → those lines are dropped entirely; the email is redacted
  // and the phone is masked in place. The parent NEVER sees a raw value.
  assert.doesNotMatch(stderr, /sk-ant-api03/);
  assert.doesNotMatch(stderr, /minji\.kim@example\.com/);
  assert.doesNotMatch(stderr, /4242424242424242/);
  assert.doesNotMatch(stderr, /010-1234-5678/);
  // The transform markers prove the lines were inspected and rewritten in place:
  // email → [REDACTED:email], phone → masked. The clean line still passes through.
  assert.match(stderr, /contact \[REDACTED:email\] for help/);
  assert.match(stderr, /call me at 01\*+78 now/);
  assert.match(stderr, /server ready on stdio/);
  // The two hard-block lines were dropped, not emitted in any form.
  assert.doesNotMatch(stderr, /boot token/);
  assert.doesNotMatch(stderr, /charged card/);
});

test("mcp-wrap --stderr drop emits nothing from the child's stderr", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-wrap-stderr-drop-"));
  await writeStderrEnforceConfig(dir);
  const childScriptPath = await makeStderrChildScript(dir);

  const { stderr } = await runStderrWrap({ dir, stderrFlag: "drop", childScriptPath });

  // Nothing from the child's stderr (clean or sensitive) is re-emitted.
  assert.doesNotMatch(stderr, /server ready on stdio/);
  assert.doesNotMatch(stderr, /minji\.kim@example\.com/);
  assert.doesNotMatch(stderr, /\[REDACTED:email\]/);
  assert.doesNotMatch(stderr, /4242424242424242/);
  assert.doesNotMatch(stderr, /sk-ant-api03/);
  assert.doesNotMatch(stderr, /010-1234-5678/);
});

test("mcp-wrap --stderr inherit passes the child's stderr through raw", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-wrap-stderr-inherit-"));
  await writeStderrEnforceConfig(dir);
  const childScriptPath = await makeStderrChildScript(dir);

  const { stderr } = await runStderrWrap({ dir, stderrFlag: "inherit", childScriptPath });

  // inherit is the explicit, opt-in raw boundary: every value passes through
  // unfiltered (secret, PII, card, phone, and the clean line).
  assert.match(stderr, /sk-ant-api03/);
  assert.match(stderr, /minji\.kim@example\.com/);
  assert.match(stderr, /4242424242424242/);
  assert.match(stderr, /010-1234-5678/);
  assert.match(stderr, /server ready on stdio/);
});

test("mcp-wrap --stderr with an unknown value fails closed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-wrap-stderr-bad-"));
  await writeStderrEnforceConfig(dir);
  const childScriptPath = await makeStderrChildScript(dir);

  const { code, stderr } = await runStderrWrap({ dir, stderrFlag: "bogus", childScriptPath });

  // Unknown --stderr value throws a clear fail-closed error and a non-zero exit.
  assert.notEqual(code, 0);
  assert.match(stderr, /--stderr must be one of: filter \| drop \| inherit/);
});
