#!/usr/bin/env node
// Thin executable for haechi-dashboard. Reads --audit/--anchor/--host/--port/
// --allow-remote-bind from argv (or HAECHI_* env) and starts the server.
//
// It does NOT support TLS termination or a sessionGuard from the CLI (those are
// injected programmatically via createDashboardServer); a remote bind from the
// CLI therefore fails closed at construction, which is intentional.

import { createDashboardServer } from "../index.mjs";

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--allow-remote-bind") {
      args.allowRemoteBind = true;
    } else if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(token);
    }
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  const auditPath = args.audit ?? process.env.HAECHI_AUDIT_PATH;
  if (!auditPath) {
    process.stderr.write("haechi-dashboard: --audit <path> (or HAECHI_AUDIT_PATH) is required\n");
    process.exit(2);
    return;
  }

  const anchorPath = args.anchor ?? process.env.HAECHI_ANCHOR_PATH ?? null;
  const host = args.host ?? process.env.HAECHI_HOST ?? "127.0.0.1";

  let port = 1018;
  const rawPort = args.port ?? process.env.HAECHI_PORT;
  if (rawPort !== undefined) {
    const parsed = Number(rawPort);
    if (!Number.isInteger(parsed)) {
      process.stderr.write("haechi-dashboard: --port must be an integer\n");
      process.exit(2);
      return;
    }
    port = parsed;
  }

  const allowRemoteBind = args.allowRemoteBind === true
    || process.env.HAECHI_ALLOW_REMOTE_BIND === "1"
    || process.env.HAECHI_ALLOW_REMOTE_BIND === "true";

  let server;
  try {
    server = createDashboardServer({ auditPath, anchorPath, host, port, allowRemoteBind });
  } catch (error) {
    process.stderr.write(`haechi-dashboard: ${error.message}\n`);
    process.exit(2);
    return;
  }

  server
    .listen()
    .then(({ host: boundHost, port: boundPort }) => {
      process.stdout.write(`haechi-dashboard listening on http://${boundHost}:${boundPort}\n`);
    })
    .catch((error) => {
      process.stderr.write(`haechi-dashboard: failed to listen: ${error.message}\n`);
      process.exit(1);
    });

  const shutdown = () => {
    server.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
