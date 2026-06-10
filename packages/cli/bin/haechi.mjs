#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { readAuditSummary } from "../../audit/index.mjs";
import { createHaechiProxy } from "../../proxy/index.mjs";
import { signPolicyBundleFile, verifyPolicyBundleFile } from "../../policy-bundle/index.mjs";
import { validatePluginManifestFile } from "../../plugin/index.mjs";
import { runMcpStdioFilter } from "../../mcp-stdio/index.mjs";
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
    case "policy-sign":
      await policySignCommand(argv);
      break;
    case "policy-verify":
      await policyVerifyCommand(argv);
      break;
    case "token-reveal":
      await tokenRevealCommand(argv);
      break;
    case "token-purge":
      await tokenPurgeCommand(argv);
      break;
    case "token-export":
      await tokenExportCommand(argv);
      break;
    case "plugin-validate":
      await pluginValidateCommand(argv);
      break;
    case "mcp-stdio":
      await mcpStdioCommand(argv);
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
  console.error(`haechi: ${error.message}`);
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
    mode: result.config.mode,
    warnings: [
      "The generated .haechi/dev.keys.json file is for local development only.",
      "Haechi 0.3.x does not include a production KMS/HSM/Vault key provider."
    ]
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
  const effectiveMode = config.policy.mode ?? config.mode;
  const result = await runtime.haechi.protectJson(input, {
    protocol: config.target.type,
    operation: "cli protect",
    mode: effectiveMode
  });

  const enforced = !["dry-run", "report-only"].includes(effectiveMode);
  writeJson({
    ok: !result.blocked,
    mode: effectiveMode,
    enforced,
    blocked: result.blocked,
    auditId: result.auditEvent.id,
    summary: result.summary,
    payload: result.payload,
    warnings: enforced ? [] : [
      `policy mode is ${effectiveMode}: detections were audited but the payload was NOT modified or blocked. Set policy.mode to "enforce" to protect payloads.`
    ]
  });

  if (result.blocked) {
    process.exitCode = 3;
  }
}

async function reportCommand(argv) {
  const options = parseOptions(argv);
  const auditPath = options.audit ?? options.path ?? ".haechi/audit.jsonl";
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
  const allowRemoteBind = Boolean(options["allow-remote-bind"]);
  const proxy = createHaechiProxy({ runtime, port, host, allowRemoteBind });
  const address = await proxy.listen();

  const effectiveMode = config.policy.mode ?? config.mode;
  console.log(`Haechi proxy listening on http://${address.host}:${address.port}`);
  console.log(`Upstream: ${config.target.upstream}`);
  console.log(`Mode: ${effectiveMode}`);
  if (allowRemoteBind) {
    console.error("warning: --allow-remote-bind exposes the proxy beyond loopback. Put Haechi behind explicit network access controls.");
  }
  if (effectiveMode !== "enforce") {
    console.error(`warning: policy mode is ${effectiveMode}. Payloads are inspected and audited but NOT modified or blocked. Set policy.mode to "enforce" to protect traffic.`);
  }
  if (!config.responseProtection.enabled) {
    console.error("warning: responseProtection.enabled is false. Upstream responses are forwarded without inspection.");
  }

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, async () => {
      await proxy.close();
      process.exit(0);
    });
  }
}

async function policySignCommand(argv) {
  const [policyPath, ...rest] = argv;
  if (!policyPath || policyPath.startsWith("--")) {
    throw new Error("policy-sign requires a policy JSON file path");
  }
  const options = parseOptions(rest);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const outPath = options.out ?? "policy.bundle.json";
  const bundle = await signPolicyBundleFile({
    policyPath,
    keyFile: config.keys.keyFile,
    outPath
  });
  writeJson({
    ok: true,
    command: "policy-sign",
    outPath,
    kid: bundle.kid,
    signedAt: bundle.signedAt
  });
}

async function policyVerifyCommand(argv) {
  const [bundlePath, ...rest] = argv;
  if (!bundlePath || bundlePath.startsWith("--")) {
    throw new Error("policy-verify requires a policy bundle JSON file path");
  }
  const options = parseOptions(rest);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  writeJson({
    ok: true,
    command: "policy-verify",
    bundlePath,
    result: await verifyPolicyBundleFile({
      bundlePath,
      keyFile: config.keys.keyFile
    })
  });
}

async function tokenRevealCommand(argv) {
  const [token, ...rest] = argv;
  if (!token || token.startsWith("--")) {
    throw new Error("token-reveal requires a token");
  }
  const options = parseOptions(rest);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  if (options["allow-dev-reveal"]) {
    config.tokenVault.revealPolicy = "local-dev";
  }
  const runtime = createRuntime(config);
  const result = await runtime.tokenVault.reveal({ token });
  writeJson({
    ok: true,
    token: result.token,
    type: result.type,
    plaintext: result.plaintext
  });
}

async function tokenPurgeCommand(argv) {
  const options = parseOptions(argv);

  if (options.expired) {
    const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
    const runtime = createRuntime(config);
    if (typeof runtime.tokenVault.purgeExpired !== "function") {
      throw new Error("Configured token vault provider does not support purgeExpired");
    }
    writeJson({
      ok: true,
      command: "token-purge",
      result: await runtime.tokenVault.purgeExpired()
    });
    return;
  }

  const [token] = argv;
  if (!token || token.startsWith("--")) {
    throw new Error("token-purge requires a token or --expired");
  }
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  writeJson({
    ok: true,
    command: "token-purge",
    result: await runtime.tokenVault.purge({ token })
  });
}

async function tokenExportCommand(argv) {
  const options = parseOptions(argv);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  writeJson({
    ok: true,
    command: "token-export",
    tokens: await runtime.tokenVault.exportMetadata({
      type: typeof options.type === "string" ? options.type : null
    })
  });
}

async function pluginValidateCommand(argv) {
  const [manifestPath] = argv;
  if (!manifestPath || manifestPath.startsWith("--")) {
    throw new Error("plugin-validate requires a plugin manifest JSON file path");
  }
  const result = await validatePluginManifestFile(manifestPath);
  writeJson({
    ok: result.valid,
    command: "plugin-validate",
    manifestPath,
    result
  });
  if (!result.valid) {
    process.exitCode = 2;
  }
}

async function mcpStdioCommand(argv) {
  const options = parseOptions(argv);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  await runMcpStdioFilter({ runtime });
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
  console.log(`Haechi MVP CLI

Usage:
  haechi init [--config haechi.config.json] [--force]
  haechi protect <input.json> [--config haechi.config.json]
  haechi report [--audit .haechi/audit.jsonl]
  haechi proxy [--config haechi.config.json] [--host 127.0.0.1] [--port 8787] [--allow-remote-bind]
  haechi policy-sign <policy.json> [--config haechi.config.json] [--out policy.bundle.json]
  haechi policy-verify <policy.bundle.json> [--config haechi.config.json]
  haechi token-reveal <token> [--config haechi.config.json] [--allow-dev-reveal]
  haechi token-purge <token> [--config haechi.config.json]
  haechi token-purge --expired [--config haechi.config.json]
  haechi token-export [--config haechi.config.json] [--type email]
  haechi plugin-validate <plugin-manifest.json>
  haechi mcp-stdio [--config haechi.config.json]

The default policy mode is dry-run. Change policy.mode to enforce to mutate or block payloads.
`);
}
