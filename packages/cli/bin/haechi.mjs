#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { readAuditSummary, verifyAuditChain } from "../../audit/index.mjs";
import { DEFAULT_PROXY_PORT, createHaechiProxy } from "../../proxy/index.mjs";
import { signPolicyBundleFile, verifyPolicyBundleFile } from "../../policy-bundle/index.mjs";
import { validatePluginManifestFile } from "../../plugin/index.mjs";
import { runMcpStdioFilter, wrapMcpChild } from "../../mcp-stdio/index.mjs";
import { spawn } from "node:child_process";
import { DEFAULT_CONFIG_PATH, createRuntime, isValidPort, loadConfig, writeDefaultConfig } from "../runtime.mjs";

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
    case "audit-verify":
      await auditVerifyCommand(argv);
      break;
    case "status":
      await statusCommand(argv);
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
    case "mcp-wrap":
      await mcpWrapCommand(argv);
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

async function auditVerifyCommand(argv) {
  const options = parseOptions(argv);
  let auditPath = options.audit ?? options.path;
  if (!auditPath) {
    try {
      auditPath = (await loadConfig(options.config ?? DEFAULT_CONFIG_PATH)).audit.path;
    } catch {
      auditPath = ".haechi/audit.jsonl";
    }
  }

  const result = await verifyAuditChain(auditPath);
  writeJson({
    ok: result.valid,
    command: "audit-verify",
    auditPath,
    result
  });
  if (!result.valid) {
    process.exitCode = 4;
  }
}

async function statusCommand(argv) {
  const options = parseOptions(argv);
  const configPath = options.config ?? DEFAULT_CONFIG_PATH;
  const config = await loadConfig(configPath);
  const effectiveMode = config.policy.mode ?? config.mode;
  const enforced = !["dry-run", "report-only"].includes(effectiveMode);
  const warnings = [];

  if (!enforced) {
    warnings.push(`policy mode is ${effectiveMode}: payloads are inspected and audited but NOT modified or blocked`);
  }
  if (!config.responseProtection.enabled) {
    warnings.push("responseProtection.enabled is false: upstream responses are forwarded without inspection");
  }
  if (config.streaming.requestMode === "pass-through") {
    warnings.push("streaming.requestMode is pass-through: streaming payloads are not protected");
  }
  if (config.tokenVault.revealPolicy !== "disabled") {
    warnings.push(`tokenVault.revealPolicy is ${config.tokenVault.revealPolicy}: manual token reveal is enabled`);
  }
  if (config.tokenVault.detokenizeResponses && !config.responseProtection.enabled) {
    warnings.push("tokenVault.detokenizeResponses is true but responseProtection.enabled is false: detokenization never runs");
  }

  const keys = {
    provider: config.keys.provider,
    keyFile: config.keys.keyFile,
    exists: false,
    permissions: null
  };
  try {
    const info = await stat(config.keys.keyFile);
    keys.exists = true;
    keys.permissions = `0${(info.mode & 0o777).toString(8)}`;
    if ((info.mode & 0o077) !== 0) {
      warnings.push(`key file ${config.keys.keyFile} is group/world accessible (${keys.permissions}); expected 0600`);
    }
  } catch {
    warnings.push(`key file ${config.keys.keyFile} does not exist; run haechi init`);
  }

  const audit = { path: config.audit.path, exists: false, chain: null };
  try {
    await stat(config.audit.path);
    audit.exists = true;
    audit.chain = await verifyAuditChain(config.audit.path);
    if (!audit.chain.valid) {
      warnings.push(`audit chain verification failed: ${audit.chain.reason}`);
    }
  } catch {
    // No audit file yet is a normal pre-first-run state, not a warning.
  }

  writeJson({
    ok: true,
    command: "status",
    configPath,
    protection: {
      policyMode: effectiveMode,
      enforced,
      responseProtection: {
        enabled: config.responseProtection.enabled,
        mode: config.responseProtection.mode,
        failureMode: config.responseProtection.failureMode
      },
      streamingRequestMode: config.streaming.requestMode
    },
    target: {
      type: config.target.type,
      adapter: config.target.adapter,
      upstream: config.target.upstream
    },
    proxy: config.proxy,
    tokenVault: {
      revealPolicy: config.tokenVault.revealPolicy,
      retentionDays: config.tokenVault.retentionDays,
      deterministic: config.tokenVault.deterministic,
      deterministicTypes: config.tokenVault.deterministicTypes,
      detokenizeResponses: config.tokenVault.detokenizeResponses
    },
    privacyProfile: config.privacy.profile,
    keys,
    audit,
    warnings
  });
}

async function proxyCommand(argv) {
  const options = parseOptions(argv);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);
  const port = parsePort(options.port ?? config.proxy.port);
  const host = options.host ?? config.proxy.host;
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

async function mcpWrapCommand(argv) {
  const separator = argv.indexOf("--");
  if (separator === -1 || !argv[separator + 1]) {
    throw new Error("mcp-wrap requires a child command after --, e.g. haechi mcp-wrap -- npx some-mcp-server");
  }
  const options = parseOptions(argv.slice(0, separator));
  const command = argv[separator + 1];
  const commandArgs = argv.slice(separator + 2);

  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  const runtime = createRuntime(config);

  const child = spawn(command, commandArgs, {
    stdio: ["pipe", "pipe", "inherit"]
  });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => child.kill(signal));
  }

  const { code } = await wrapMcpChild({ runtime, child });
  process.exitCode = code;
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

function parsePort(value) {
  if (typeof value === "boolean") {
    throw new Error("proxy port must be an integer from 0 to 65535");
  }
  if (typeof value === "string" && !/^\d+$/.test(value.trim())) {
    throw new Error("proxy port must be an integer from 0 to 65535");
  }
  const port = typeof value === "number" ? value : Number(value);
  if (!isValidPort(port)) {
    throw new Error("proxy port must be an integer from 0 to 65535");
  }
  return port;
}

function printHelp() {
  console.log(`Haechi MVP CLI

Usage:
  haechi init [--config haechi.config.json] [--force]
  haechi protect <input.json> [--config haechi.config.json]
  haechi report [--audit .haechi/audit.jsonl]
  haechi audit-verify [--audit .haechi/audit.jsonl] [--config haechi.config.json]
  haechi status [--config haechi.config.json]
  haechi proxy [--config haechi.config.json] [--host 127.0.0.1] [--port ${DEFAULT_PROXY_PORT}] [--allow-remote-bind]
  haechi policy-sign <policy.json> [--config haechi.config.json] [--out policy.bundle.json]
  haechi policy-verify <policy.bundle.json> [--config haechi.config.json]
  haechi token-reveal <token> [--config haechi.config.json] [--allow-dev-reveal]
  haechi token-purge <token> [--config haechi.config.json]
  haechi token-purge --expired [--config haechi.config.json]
  haechi token-export [--config haechi.config.json] [--type email]
  haechi plugin-validate <plugin-manifest.json>
  haechi mcp-stdio [--config haechi.config.json]
  haechi mcp-wrap [--config haechi.config.json] -- <command> [args...]

The default policy mode is dry-run. Change policy.mode to enforce to mutate or block payloads.
`);
}
