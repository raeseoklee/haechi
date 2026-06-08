#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { readAuditSummary } from "../../audit/index.mjs";
import { createAicelProxy } from "../../proxy/index.mjs";
import { DEFAULT_CONFIG_PATH, createRuntime, loadConfig, writeDefaultConfig } from "../runtime.mjs";

const [command, ...argv] = process.argv.slice(2);

try {
  switch (command) {
    case "init":
      await initCommand(argv);
      break;
    case "protect":
      await protectCommand(argv);
      break;
    case "report":
      await reportCommand(argv);
      break;
    case "proxy":
      await proxyCommand(argv);
      break;
    case "help":
    case "--help":
    case "-h":
    case undefined:
      printHelp();
      break;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
} catch (error) {
  console.error(`aicel: ${error.message}`);
  process.exitCode = process.exitCode || 1;
}

async function initCommand(argv) {
  const options = parseOptions(argv);
  const configPath = options.config ?? DEFAULT_CONFIG_PATH;
  const result = await writeDefaultConfig(configPath, { force: Boolean(options.force) });
  writeJson({
    ok: true,
    command: "init",
    configPath: result.configPath,
    created: result.created,
    keyFile: result.config.keys.keyFile,
    auditPath: result.config.audit.path,
    mode: result.config.mode
  });
}

async function protectCommand(argv) {
  const [inputPath, ...rest] = argv;
  if (!inputPath || inputPath.startsWith("--")) {
    throw new Error("protect requires an input JSON file path");
  }

  const options = parseOptions(rest);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  const input = JSON.parse(await readFile(inputPath, "utf8"));
  const result = await runtime.aicel.protectJson(input, {
    protocol: config.target.type,
    operation: "cli protect",
    mode: config.policy.mode ?? config.mode
  });

  writeJson({
    ok: !result.blocked,
    blocked: result.blocked,
    auditId: result.auditEvent.id,
    summary: result.summary,
    payload: result.payload
  });

  if (result.blocked) {
    process.exitCode = 3;
  }
}

async function reportCommand(argv) {
  const options = parseOptions(argv);
  const auditPath = options.audit ?? options.path ?? ".aicel/audit.jsonl";
  writeJson({
    ok: true,
    auditPath,
    summary: await readAuditSummary(auditPath)
  });
}

async function proxyCommand(argv) {
  const options = parseOptions(argv);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  const port = Number(options.port ?? 8787);
  const host = options.host ?? "127.0.0.1";
  const proxy = createAicelProxy({ runtime, port, host });
  const address = await proxy.listen();

  console.log(`AICEL proxy listening on http://${address.host}:${address.port}`);
  console.log(`Upstream: ${config.target.upstream}`);
  console.log(`Mode: ${config.policy.mode ?? config.mode}`);

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, async () => {
      await proxy.close();
      process.exit(0);
    });
  }
}

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = true;
      continue;
    }
    options[key] = next;
    index += 1;
  }
  return options;
}

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function printHelp() {
  console.log(`AICEL MVP CLI

Usage:
  aicel init [--config aicel.config.json] [--force]
  aicel protect <input.json> [--config aicel.config.json]
  aicel report [--audit .aicel/audit.jsonl]
  aicel proxy [--config aicel.config.json] [--host 127.0.0.1] [--port 8787]

The default policy mode is dry-run. Change policy.mode to enforce to mutate or block payloads.
`);
}
