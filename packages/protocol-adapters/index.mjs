// Streaming descriptors: `format` is the wire framing, `deltaPath` is the
// primary incremental-text channel (index 0 of choices for OpenAI-style).
// A null deltaPath means "no known channel" — frames still get within-frame
// protection but no cross-frame buffering.
const SSE_CHAT = { format: "sse", deltaPath: ["choices", 0, "delta", "content"] };
const SSE_COMPLETION = { format: "sse", deltaPath: ["choices", 0, "text"] };
const SSE_RESPONSES = { format: "sse", deltaPath: null };
const SSE_LLAMA_LEGACY = { format: "sse", deltaPath: ["content"] };
const NDJSON_OLLAMA_CHAT = { format: "ndjson", deltaPath: ["message", "content"] };
const NDJSON_OLLAMA_GENERATE = { format: "ndjson", deltaPath: ["response"] };

const ADAPTERS = {
  "openai-compatible": {
    id: "openai-compatible",
    protocol: "llm-http",
    routes: [
      route("/v1/chat/completions", "chat-completions", { streaming: SSE_CHAT }),
      route("/v1/completions", "completions", { streaming: SSE_COMPLETION }),
      route("/v1/responses", "responses", { streaming: SSE_RESPONSES }),
      route("/v1/embeddings", "embeddings")
    ]
  },
  "vllm-openai": {
    id: "vllm-openai",
    protocol: "vllm-openai",
    routes: [
      route("/v1/chat/completions", "chat-completions", { streaming: SSE_CHAT }),
      route("/v1/completions", "completions", { streaming: SSE_COMPLETION }),
      route("/v1/responses", "responses", { streaming: SSE_RESPONSES }),
      route("/v1/embeddings", "embeddings")
    ]
  },
  "llama-cpp": {
    id: "llama-cpp",
    protocol: "llama-cpp",
    routes: [
      route("/v1/chat/completions", "chat-completions", { streaming: SSE_CHAT }),
      route("/v1/completions", "completions", { streaming: SSE_COMPLETION }),
      route("/v1/embeddings", "embeddings"),
      route("/completion", "legacy-completion", { streaming: SSE_LLAMA_LEGACY })
    ]
  },
  "ollama": {
    id: "ollama",
    protocol: "ollama",
    routes: [
      // Ollama streams /api/chat and /api/generate unless the request sets stream:false.
      route("/api/chat", "chat", { streamingDefault: true, streaming: NDJSON_OLLAMA_CHAT }),
      route("/api/generate", "generate", { streamingDefault: true, streaming: NDJSON_OLLAMA_GENERATE }),
      route("/api/embed", "embed"),
      route("/api/embeddings", "embeddings")
    ]
  }
};

const TARGET_TYPE_ALIASES = {
  "llm-http": "openai-compatible"
};

export function createProtocolAdapter(target = {}) {
  // A specific target.type (vllm-openai, ollama, llama-cpp) names its own
  // adapter and wins over a generic/default target.adapter — otherwise the
  // default config's adapter ("openai-compatible") would shadow the type after
  // a deep merge and silently route an Ollama target to OpenAI paths.
  const adapterId = ADAPTERS[target.type]
    ? target.type
    : (target.adapter ?? adapterFromTargetType(target.type));
  const adapter = ADAPTERS[adapterId];
  if (!adapter) {
    throw new Error(`Unknown protocol adapter: ${adapterId}`);
  }

  return {
    id: adapter.id,
    protocol: adapter.protocol,
    classifyRequest(request) {
      const pathname = pathFromRequestUrl(request.url);
      const matched = matchRoute(adapter.routes, pathname);
      const operation = matched
        ? `${request.method} ${matched.operation}`
        : `${request.method} ${pathname}`;

      return {
        adapterId: adapter.id,
        protocol: adapter.protocol,
        routeId: matched?.id ?? "unknown",
        path: pathname,
        operation,
        protectRequest: matched?.protectRequest ?? true,
        protectResponse: matched?.protectResponse ?? true,
        streamingByDefault: matched?.streamingDefault ?? false,
        streaming: matched?.streaming ?? null
      };
    }
  };
}

export function knownProtocolAdapters() {
  return Object.keys(ADAPTERS);
}

function adapterFromTargetType(type = "llm-http") {
  if (ADAPTERS[type]) {
    return type;
  }
  if (TARGET_TYPE_ALIASES[type]) {
    return TARGET_TYPE_ALIASES[type];
  }
  throw new Error(`Unknown target.type: ${type}. Known types: ${["llm-http", ...Object.keys(ADAPTERS)].join(", ")}`);
}

function route(path, operation, options = {}) {
  return {
    id: operation,
    path,
    operation,
    protectRequest: options.protectRequest ?? true,
    protectResponse: options.protectResponse ?? true,
    streamingDefault: options.streamingDefault ?? false,
    streaming: options.streaming ?? null
  };
}

function pathFromRequestUrl(url) {
  return new URL(url, "http://haechi.local").pathname;
}

function matchRoute(routes, pathname) {
  return routes.find((candidate) => candidate.path === pathname);
}
