import { createInterface } from "node:readline";

export async function protectMcpJsonRpcMessage(message, runtime) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw new Error(Array.isArray(message)
      ? "JSON-RPC batch messages are not supported by the MCP stdio filter"
      : "MCP message must be a JSON object");
  }
  const policy = runtime.config.mcp;
  // JSON-RPC notifications (method, no id) must not receive responses; a
  // rejected or blocked notification is dropped (returns null) instead.
  const isNotification = message.method !== undefined
    && !Object.prototype.hasOwnProperty.call(message, "id");
  if (policy.requireJsonRpc && message.jsonrpc !== "2.0") {
    return isNotification ? null : errorJsonRpc(message.id, -32002, "haechi_mcp_invalid_jsonrpc", {
      reason: "MCP messages must use JSON-RPC 2.0"
    });
  }
  if (message.method && !methodAllowed(message.method, policy.allowedMethods)) {
    return isNotification ? null : errorJsonRpc(message.id, -32003, "haechi_mcp_method_not_allowed", {
      method: message.method
    });
  }

  const next = structuredClone(message);

  if (policy.protectParams && Object.prototype.hasOwnProperty.call(next, "params")) {
    const result = await runtime.haechi.protectJson(next.params, {
      protocol: "mcp-stdio",
      operation: next.method ?? "params",
      mode: runtime.config.policy.mode ?? runtime.config.mode
    });
    if (result.blocked) {
      return isNotification ? null : blockedJsonRpc(next.id, result);
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
      return blockedJsonRpc(next.id, result);
    }
    next.result = result.payload;
  }

  return next;
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
      output.write(`${JSON.stringify({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "haechi_mcp_stdio_error",
          data: {
            reason: error.message
          }
        },
        id: null
      })}\n`);
    }
  }
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
