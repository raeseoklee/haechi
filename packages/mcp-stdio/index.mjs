import { createInterface } from "node:readline";

// Tagged core used by both the one-direction line filter and mcp-wrap.
// kinds: "forward" (deliver the protected message), "reject" (send the error
// back to the CLIENT instead of delivering), "drop" (notification — deliver
// nothing, per JSON-RPC).
async function protectTagged(message, runtime, { enforceMethodAllowlist = true } = {}) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw new Error(Array.isArray(message)
      ? "JSON-RPC batch messages are not supported by the MCP stdio filter"
      : "MCP message must be a JSON object");
  }
  const policy = runtime.config.mcp;
  const isNotification = message.method !== undefined
    && !Object.prototype.hasOwnProperty.call(message, "id");

  function reject(error) {
    return isNotification ? { kind: "drop" } : { kind: "reject", message: error };
  }

  if (policy.requireJsonRpc && message.jsonrpc !== "2.0") {
    return reject(errorJsonRpc(message.id, -32002, "haechi_mcp_invalid_jsonrpc", {
      reason: "MCP messages must use JSON-RPC 2.0"
    }));
  }
  // The allowlist describes CLIENT-callable methods. Server-initiated requests
  // (e.g. sampling/createMessage) are exempted by the caller via
  // enforceMethodAllowlist: false, but their params are still protected.
  if (enforceMethodAllowlist && message.method && !methodAllowed(message.method, policy.allowedMethods)) {
    return reject(errorJsonRpc(message.id, -32003, "haechi_mcp_method_not_allowed", {
      method: message.method
    }));
  }

  const next = structuredClone(message);

  if (policy.protectParams && Object.prototype.hasOwnProperty.call(next, "params")) {
    const result = await runtime.haechi.protectJson(next.params, {
      protocol: "mcp-stdio",
      operation: next.method ?? "params",
      mode: runtime.config.policy.mode ?? runtime.config.mode
    });
    if (result.blocked) {
      return reject(blockedJsonRpc(next.id, result));
    }
    next.params = result.payload;
  }

  if (policy.protectResults && Object.prototype.hasOwnProperty.call(next, "result")) {
    const result = await runtime.haechi.protectJson(next.result, {
      protocol: "mcp-stdio",
      operation: "result",
      mode: runtime.config.policy.mode ?? runtime.config.mode
    });
    if (result.blocked) {
      return { kind: "reject", message: blockedJsonRpc(next.id, result) };
    }
    next.result = result.payload;
  }

  return { kind: "forward", message: next };
}

export async function protectMcpJsonRpcMessage(message, runtime, options = {}) {
  const tagged = await protectTagged(message, runtime, options);
  return tagged.kind === "drop" ? null : tagged.message;
}

export async function runMcpStdioFilter({ input = process.stdin, output = process.stdout, runtime }) {
  const lines = createInterface({ input, crlfDelay: Infinity });

  for await (const line of lines) {
    if (!line.trim()) {
      continue;
    }
    try {
      const message = JSON.parse(line);
      const protectedMessage = await protectMcpJsonRpcMessage(message, runtime);
      if (protectedMessage === null) {
        continue;
      }
      output.write(`${JSON.stringify(protectedMessage)}\n`);
    } catch (error) {
      output.write(`${JSON.stringify(stdioError(error))}\n`);
    }
  }
}

// Bidirectional wrap around a spawned MCP server child process:
//   client → (allowlist + params protection) → child stdin
//   child stdout → (params/result protection, no client allowlist) → client
// Rejections in BOTH directions are answered to the client; nothing reaches
// the child for a rejected client message. Resolves with the child exit code.
export function wrapMcpChild({ runtime, child, input = process.stdin, output = process.stdout }) {
  const clientLines = createInterface({ input, crlfDelay: Infinity });
  const serverLines = createInterface({ input: child.stdout, crlfDelay: Infinity });

  const clientPump = (async () => {
    for await (const line of clientLines) {
      if (!line.trim()) {
        continue;
      }
      try {
        const tagged = await protectTagged(JSON.parse(line), runtime, { enforceMethodAllowlist: true });
        if (tagged.kind === "forward" && child.stdin.writable) {
          child.stdin.write(`${JSON.stringify(tagged.message)}\n`);
        } else if (tagged.kind === "reject") {
          output.write(`${JSON.stringify(tagged.message)}\n`);
        }
      } catch (error) {
        output.write(`${JSON.stringify(stdioError(error))}\n`);
      }
    }
    if (child.stdin.writable) {
      child.stdin.end();
    }
  })();

  const serverPump = (async () => {
    for await (const line of serverLines) {
      if (!line.trim()) {
        continue;
      }
      try {
        const tagged = await protectTagged(JSON.parse(line), runtime, { enforceMethodAllowlist: false });
        if (tagged.kind !== "drop") {
          output.write(`${JSON.stringify(tagged.message)}\n`);
        }
      } catch (error) {
        output.write(`${JSON.stringify(stdioError(error))}\n`);
      }
    }
  })();

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      // The child is gone: stop consuming client input so the pumps can
      // settle even when the caller's input stream stays open.
      clientLines.close();
      serverLines.close();
      Promise.allSettled([clientPump, serverPump]).then(() => {
        resolve({ code: code ?? (signal ? 1 : 0), signal });
      });
    });
  });
}

function stdioError(error) {
  return {
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message: "haechi_mcp_stdio_error",
      data: {
        reason: error.message
      }
    },
    id: null
  };
}

function blockedJsonRpc(id, result) {
  return errorJsonRpc(id, -32001, "haechi_policy_block", {
    auditId: result.auditEvent.id,
    summary: result.summary
  });
}

function errorJsonRpc(id, code, message, data) {
  return {
    jsonrpc: "2.0",
    error: {
      code,
      message,
      data
    },
    id: id ?? null
  };
}

function methodAllowed(method, allowedMethods) {
  return allowedMethods.includes("*") || allowedMethods.includes(method);
}
