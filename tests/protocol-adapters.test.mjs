import test from "node:test";
import assert from "node:assert/strict";
import { createProtocolAdapter, knownProtocolAdapters } from "../packages/protocol-adapters/index.mjs";

test("protocol adapters classify local inference routes", () => {
  assert.deepEqual(knownProtocolAdapters(), [
    "openai-compatible",
    "vllm-openai",
    "llama-cpp",
    "ollama",
    "anthropic",
    "gemini"
  ]);

  const vllm = createProtocolAdapter({ adapter: "vllm-openai" });
  assert.deepEqual(vllm.classifyRequest(request("/v1/chat/completions")), {
    adapterId: "vllm-openai",
    protocol: "vllm-openai",
    routeId: "chat-completions",
    path: "/v1/chat/completions",
    operation: "POST chat-completions",
    protectRequest: true,
    protectResponse: true,
    streamingByDefault: false,
    streaming: { format: "sse", deltaPath: ["choices", 0, "delta", "content"] }
  });

  const ollama = createProtocolAdapter({ adapter: "ollama" });
  assert.equal(ollama.classifyRequest(request("/api/chat")).protocol, "ollama");
  assert.equal(ollama.classifyRequest(request("/api/generate")).routeId, "generate");
  assert.equal(ollama.classifyRequest(request("/api/chat")).streamingByDefault, true);
  assert.equal(ollama.classifyRequest(request("/api/generate")).streamingByDefault, true);
  assert.equal(ollama.classifyRequest(request("/api/embed")).streamingByDefault, false);
  assert.equal(ollama.classifyRequest(request("/api/chat")).streaming.format, "ndjson");
  assert.deepEqual(ollama.classifyRequest(request("/api/generate")).streaming.deltaPath, ["response"]);
  assert.equal(ollama.classifyRequest(request("/api/embed")).streaming, null);

  const llamaCpp = createProtocolAdapter({ adapter: "llama-cpp" });
  assert.equal(llamaCpp.classifyRequest(request("/completion")).routeId, "legacy-completion");
});

test("a specific target.type wins over a default openai-compatible adapter", () => {
  // Mirrors the deep-merged default config (adapter: openai-compatible).
  const adapter = createProtocolAdapter({ type: "ollama", adapter: "openai-compatible" });
  assert.equal(adapter.id, "ollama");
  assert.equal(adapter.classifyRequest(request("/api/chat")).routeId, "chat");
});

test("unknown target.type fails closed", () => {
  assert.throws(
    () => createProtocolAdapter({ type: "olama-typo" }),
    /Unknown target.type/
  );
});

test("target.type can select protocol adapter", () => {
  const adapter = createProtocolAdapter({ type: "vllm-openai" });
  assert.equal(adapter.id, "vllm-openai");
});

function request(url) {
  return {
    method: "POST",
    url
  };
}
