// CI-only protocol stub for the local-inference integration test.
//
// A real vLLM needs a GPU and a real Ollama needs a model pull, so neither runs
// on a CI runner. This minimal node:http server speaks just enough of the
// OpenAI-compatible (`/v1/chat/completions`) and Ollama (`/api/generate`) wire
// shapes to let tests/local-inference.integration.test.mjs exercise the REAL
// proxy -> upstream path (adapter routing, header forwarding, request + response
// protection over a real socket) deterministically. It is NOT a model: it is a
// protocol conformance target. Real-model validation stays the lab/manual path.
//
// Not shipped (tests/ is outside the npm `files` allowlist). Bind port comes from
// STUB_PORT (default 8717); it prints "listening <port>" on ready.

import { createServer } from "node:http";

const PORT = Number(process.env.STUB_PORT ?? 8717);

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const server = createServer((req, res) => {
  if (req.method !== "POST") {
    send(res, 405, { error: "method not allowed" });
    return;
  }
  let raw = "";
  req.on("data", (c) => { raw += c; });
  req.on("end", () => {
    if (req.url === "/v1/chat/completions") {
      // OpenAI / vLLM-OpenAI non-streaming chat completion shape.
      send(res, 200, {
        id: "stub-cmpl",
        object: "chat.completion",
        model: "stub-model",
        choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }
      });
      return;
    }
    if (req.url === "/api/generate") {
      // Ollama native non-streaming generate shape.
      send(res, 200, { model: "stub-model", response: "ok", done: true });
      return;
    }
    send(res, 404, { error: "not found", path: req.url });
  });
});

server.listen(PORT, "127.0.0.1", () => {
  // eslint-disable-next-line no-console
  console.log(`listening ${server.address().port}`);
});
