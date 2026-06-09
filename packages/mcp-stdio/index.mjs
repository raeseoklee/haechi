import { createInterface } from "node:readline";

export async function protectMcpJsonRpcMessage(message, runtime) {
  if (!message || typeof message !== "object") {
    throw new Error("MCP message must be a JSON object");
  }

  const next = structuredClone(message);

  if (Object.prototype.hasOwnProperty.call(next, "params")) {
    const result = await runtime.haechi.protectJson(next.params, {
      protocol: "mcp-stdio",
      operation: next.method ?? "params",
      mode: runtime.config.policy.mode ?? runtime.config.mode
    });
    if (result.blocked) {
      return blockedJsonRpc(next.id, result);
    }
    next.params = result.payload;
  }

  if (Object.prototype.hasOwnProperty.call(next, "result")) {
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
  return {
    jsonrpc: "2.0",
    error: {
      code: -32001,
      message: "haechi_policy_block",
      data: {
        auditId: result.auditEvent.id,
        summary: result.summary
      }
    },
    id: id ?? null
  };
}
