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
      route("/api/chat", "chat"),
      route("/api/generate", "generate"),
      route("/api/embed", "embed"),
      route("/api/embeddings", "embeddings")
    ]
  }
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
        protectResponse: matched?.protectResponse ?? true
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
  return "openai-compatible";
}

function route(path, operation, options = {}) {
  return {
    id: operation,
    path,
    operation,
    protectRequest: options.protectRequest ?? true,
    protectResponse: options.protectResponse ?? true
  };
}

function pathFromRequestUrl(url) {
  return new URL(url, "http://haechi.local").pathname;
}

function matchRoute(routes, pathname) {
  return routes.find((candidate) => candidate.path === pathname);
}
