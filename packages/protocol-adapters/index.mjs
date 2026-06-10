const ADAPTERS = {
  "openai-compatible": {
    id: "openai-compatible",
    protocol: "llm-http",
    routes: [
      route("/v1/chat/completions", "chat-completions"),
      route("/v1/completions", "completions"),
      route("/v1/responses", "responses"),
      route("/v1/embeddings", "embeddings")
    ]
  },
  "vllm-openai": {
    id: "vllm-openai",
    protocol: "vllm-openai",
    routes: [
      route("/v1/chat/completions", "chat-completions"),
      route("/v1/completions", "completions"),
      route("/v1/responses", "responses"),
      route("/v1/embeddings", "embeddings")
    ]
  },
  "llama-cpp": {
    id: "llama-cpp",
    protocol: "llama-cpp",
    routes: [
      route("/v1/chat/completions", "chat-completions"),
      route("/v1/completions", "completions"),
      route("/v1/embeddings", "embeddings"),
      route("/completion", "legacy-completion")
    ]
  },
  "ollama": {
    id: "ollama",
    protocol: "ollama",
    routes: [
      // Ollama streams /api/chat and /api/generate unless the request sets stream:false.
      route("/api/chat", "chat", { streamingDefault: true }),
      route("/api/generate", "generate", { streamingDefault: true }),
      route("/api/embed", "embed"),
      route("/api/embeddings", "embeddings")
    ]
  }
};

const TARGET_TYPE_ALIASES = {
  "llm-http": "openai-compatible"
};

export function createProtocolAdapter(target = {}) {
  const adapterId = target.adapter ?? adapterFromTargetType(target.type);
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
        streamingByDefault: matched?.streamingDefault ?? false
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
    streamingDefault: options.streamingDefault ?? false
  };
}

function pathFromRequestUrl(url) {
  return new URL(url, "http://haechi.local").pathname;
}

function matchRoute(routes, pathname) {
  return routes.find((candidate) => candidate.path === pathname);
}
