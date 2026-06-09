import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";

test("optional vLLM/OpenAI-compatible server integration", {
  skip: !process.env.HAECHI_VLLM_URL
}, async () => {
  const response = await proxyRequest({
    adapter: "vllm-openai",
    upstream: process.env.HAECHI_VLLM_URL,
    path: "/v1/chat/completions",
    body: {
      model: process.env.HAECHI_VLLM_MODEL ?? "local-model",
      messages: [{ role: "user", content: "contact minji.kim@example.com" }]
    }
  });

  assert.ok(response.status >= 200 && response.status < 500);
});

test("optional Ollama native API integration", {
  skip: !process.env.HAECHI_OLLAMA_URL
}, async () => {
  const response = await proxyRequest({
    adapter: "ollama",
    upstream: process.env.HAECHI_OLLAMA_URL,
    path: "/api/generate",
    body: {
      model: process.env.HAECHI_OLLAMA_MODEL ?? "llama3",
      prompt: "contact minji.kim@example.com",
      stream: false
    }
  });

  assert.ok(response.status >= 200 && response.status < 500);
});

async function proxyRequest({ adapter, upstream, path, body }) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-local-inference-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: adapter,
      adapter,
      upstream
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const address = await proxy.listen();
  try {
    return await fetch(`http://${address.host}:${address.port}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  } finally {
    await proxy.close();
  }
}
