import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { assertSafeProxyBind, createHaechiProxy } from "../packages/proxy/index.mjs";

test("vLLM-compatible proxy protects request and JSON response", async () => {
  const upstream = createServer(async (request, response) => {
    const body = JSON.parse(await readBody(request));
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      id: "cmpl-test",
      requestContent: body.messages[0].content,
      choices: [
        {
          message: {
            role: "assistant",
            content: "I found minji.kim@example.com in the result"
          }
        }
      ]
    }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-03-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      defaultAction: "redact"
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        messages: [
          {
            role: "user",
            content: "contact minji.kim@example.com"
          }
        ]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 200);
    assert.match(json.requestContent, /\[REDACTED:email\]/);
    assert.match(json.choices[0].message.content, /\[REDACTED:email\]/);
    assert.doesNotMatch(JSON.stringify(json), /minji\.kim@example\.com/);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /request:POST chat-completions/);
    assert.match(audit, /response:POST chat-completions/);
    assert.doesNotMatch(audit, /minji\.kim@example\.com/);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("proxy refuses non-loopback bind unless explicitly allowed", () => {
  assert.throws(
    () => assertSafeProxyBind({ host: "0.0.0.0" }),
    /Refusing to bind/
  );

  assert.doesNotThrow(() => assertSafeProxyBind({ host: "0.0.0.0", allowRemoteBind: true }));
});

test("proxy blocks streaming requests by default", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-stream-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        stream: true,
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 501);
    assert.equal(json.error, "haechi_streaming_unsupported");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("responseProtection fails closed for uninspectable responses", async () => {
  const upstream = createServer(async (_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("minji.kim@example.com");
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-response-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    responseProtection: {
      enabled: true,
      mode: "enforce"
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-model",
        messages: [{ role: "user", content: "hello" }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 502);
    assert.equal(json.error, "haechi_response_unprotected");
    assert.equal(json.reason, "non_json_response");
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test("proxy rejects request bodies over configured limit", async () => {
  let upstreamHit = false;
  const upstream = createServer(async (_request, response) => {
    upstreamHit = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  const upstreamAddress = await listen(upstream);

  const dir = await mkdtemp(join(tmpdir(), "haechi-proxy-limit-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    target: {
      type: "vllm-openai",
      upstream: `http://127.0.0.1:${upstreamAddress.port}`
    },
    limits: {
      maxRequestBytes: 64
    },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"]
    },
    keys: { keyFile },
    audit: { path: auditPath }
  });

  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();

  try {
    const response = await fetch(`http://${proxyAddress.host}:${proxyAddress.port}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        messages: [{ role: "user", content: "a".repeat(128) }]
      })
    });
    const json = await response.json();

    assert.equal(response.status, 413);
    assert.equal(json.error, "haechi_request_body_too_large");
    assert.equal(upstreamHit, false);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}
