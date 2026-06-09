import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { protectMcpJsonRpcMessage } from "../packages/mcp-stdio/index.mjs";

test("MCP stdio JSON-RPC params are protected", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-mcp-stdio-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact"
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });

  const message = await protectMcpJsonRpcMessage({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      email: "minji.kim@example.com"
    }
  }, runtime);

  assert.equal(message.params.email, "[REDACTED:email]");
});
