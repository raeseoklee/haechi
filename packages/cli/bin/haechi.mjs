#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { readAuditSummary, verifyAuditChain } from "../../audit/index.mjs";
import { DEFAULT_PROXY_PORT, HAECHI_VERSION, createHaechiProxy } from "../../proxy/index.mjs";
import { signPolicyBundleFile, verifyPolicyBundleFile } from "../../policy-bundle/index.mjs";
import { validatePluginManifestFile } from "../../plugin/index.mjs";
import { runMcpStdioFilter, wrapMcpChild } from "../../mcp-stdio/index.mjs";
import { addToken, listTokens, revokeToken } from "../../auth/index.mjs";
import { createLocalCryptoProvider } from "../../crypto/index.mjs";
import { spawn } from "node:child_process";
import { DEFAULT_CONFIG_PATH, createRuntime, isValidPort, loadConfig, writeDefaultConfig } from "../runtime.mjs";

const [command, ...argv] = process.argv.slice(2);

async function main(command, argv) {
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
    case "auth":
      await authCommand(argv);
      break;
    case "config":
      printConfigGuide();
      break;
    case "help":
    case "--help":
    case "-h":
    case undefined:
      printHelp(argv[0]);
      break;
    default:
      throw new Error(`Unknown command: ${command}. Run 'haechi help' for usage.`);
  }
} catch (error) {
  console.error(`haechi: ${error.message}`);
  process.exitCode = process.exitCode || 1;
}
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
      "Core ships no production KMS/HSM/Vault key provider; KMS/Vault-backed custody is available via the haechi-crypto-kms satellite (external cryptoProvider)."
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
    direction: "request",
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
  let anchorPath = typeof options.anchor === "string" ? options.anchor : null;
  if (!auditPath || (options.anchor === true && !anchorPath)) {
    try {
      const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
      auditPath = auditPath ?? config.audit.path;
      // --anchor with no value (or no flag at all) falls back to the configured
      // anchor path when anchoring is enabled.
      if (!anchorPath && config.audit.anchor.mode === "file") {
        anchorPath = config.audit.anchor.path;
      }
    } catch {
      auditPath = auditPath ?? ".haechi/audit.jsonl";
    }
  }

  const result = await verifyAuditChain(auditPath, { anchorPath });
  writeJson({
    ok: result.valid,
    command: "audit-verify",
    auditPath,
    anchorPath,
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

  const anchorEnabled = config.audit.anchor.mode === "file";
  const audit = {
    path: config.audit.path,
    exists: false,
    chain: null,
    anchor: { mode: config.audit.anchor.mode, path: anchorEnabled ? config.audit.anchor.path : null }
  };
  try {
    await stat(config.audit.path);
    audit.exists = true;
    audit.chain = await verifyAuditChain(config.audit.path, {
      anchorPath: anchorEnabled ? config.audit.anchor.path : null
    });
    if (!audit.chain.valid) {
      warnings.push(`audit chain verification failed: ${audit.chain.reason}`);
    }
  } catch {
    // No audit file yet is a normal pre-first-run state, not a warning.
  }
  if (config.audit.anchor.mode === "none") {
    warnings.push("audit.anchor.mode is none: tail truncation of the audit log cannot be detected");
  } else if (config.audit.anchor.mode === "file") {
    warnings.push("audit.anchor: real tail-truncation defense requires the anchor on append-only or separate media; on the same writable filesystem an attacker can truncate both files together");
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
      streamingRequestMode: config.streaming.requestMode,
      streamingResponseMode: config.streaming.responseMode
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
  // proxy.tls / proxy.trustForwardedProto come from the normalized config (the
  // TLS material is loaded from file paths at load time); createHaechiProxy reads
  // them from runtime.config.proxy, so the CLI does not re-pass them. The bind
  // guard inside createHaechiProxy throws fail-closed for a remote bind without
  // TLS and without trustForwardedProto.
  const proxy = createHaechiProxy({ runtime, port, host, allowRemoteBind });
  const address = await proxy.listen();
  const scheme = address.tls ? "https" : "http";

  const effectiveMode = config.policy.mode ?? config.mode;
  const jsonLogs = config.logging?.format === "json";
  // Structured startup/shutdown logs honor logging.format. JSON mode emits one
  // line per event carrying only non-secret operational fields (host/port/mode/
  // version/warning codes) — never a payload, token, or PII value.
  const logEvent = (level, event, fields = {}) => {
    if (jsonLogs) {
      const stream = level === "warn" ? process.stderr : process.stdout;
      stream.write(`${JSON.stringify({ level, event, ...fields })}\n`);
    }
  };

  if (jsonLogs) {
    logEvent("info", "proxy_listening", {
      host: address.host,
      port: address.port,
      scheme,
      tls: Boolean(address.tls),
      upstream: config.target.upstream,
      mode: effectiveMode,
      version: HAECHI_VERSION
    });
  } else {
    console.log(`Haechi proxy listening on ${scheme}://${address.host}:${address.port}`);
    console.log(`Upstream: ${config.target.upstream}`);
    console.log(`Mode: ${effectiveMode}`);
  }
  if (allowRemoteBind) {
    if (jsonLogs) {
      logEvent("warn", "remote_bind_enabled", { tls: Boolean(address.tls), trustForwardedProto: Boolean(config.proxy?.trustForwardedProto) });
    } else if (address.tls) {
      console.error("warning: --allow-remote-bind exposes the proxy beyond loopback (TLS terminated by Haechi). Put Haechi behind explicit network access controls.");
    } else {
      console.error("warning: --allow-remote-bind exposes the proxy beyond loopback behind a trusted TLS-terminating reverse proxy (proxy.trustForwardedProto). Requests without X-Forwarded-Proto: https are refused. Put Haechi behind explicit network access controls.");
    }
  }
  if (effectiveMode !== "enforce") {
    if (jsonLogs) {
      logEvent("warn", "non_enforce_mode", { mode: effectiveMode });
    } else {
      console.error(`warning: policy mode is ${effectiveMode}. Payloads are inspected and audited but NOT modified or blocked. Set policy.mode to "enforce" to protect traffic.`);
    }
  }
  if (!config.responseProtection.enabled) {
    if (jsonLogs) {
      logEvent("warn", "response_protection_disabled");
    } else {
      console.error("warning: responseProtection.enabled is false. Upstream responses are forwarded without inspection.");
    }
  }

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, async () => {
      logEvent("info", "proxy_shutdown", { signal });
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

async function authCommand(argv) {
  const [sub, ...rest] = argv;
  const options = parseOptions(rest);
  const config = await loadConfig(options.config ?? DEFAULT_CONFIG_PATH);
  if (config.keys.provider !== "local") {
    throw new Error("haechi auth requires keys.provider local (the bearer store is hashed with the local key)");
  }
  const cryptoProvider = createLocalCryptoProvider({ keyFile: config.keys.keyFile });
  const storePath = config.auth.store;

  switch (sub) {
    case "add": {
      if (!options.type || options.type === true) {
        throw new Error("auth add requires --type user|service|agent");
      }
      const { token, record } = await addToken({
        path: storePath,
        cryptoProvider,
        type: options.type,
        scopes: asList(options.scope),
        labels: asLabels(options.label),
        allowedLabelKeys: config.auth.allowedLabelKeys
      });
      writeJson({
        ok: true,
        command: "auth add",
        id: record.id,
        type: record.type,
        scopes: record.scopes,
        labels: record.labels,
        token,
        warning: "This token is shown only once. Store it now; it is not recoverable."
      });
      return;
    }
    case "list":
      writeJson({ ok: true, command: "auth list", tokens: await listTokens(storePath) });
      return;
    case "revoke": {
      const [id] = rest;
      if (!id || id.startsWith("--")) {
        throw new Error("auth revoke requires a token id");
      }
      writeJson({ ok: true, command: "auth revoke", result: await revokeToken({ path: storePath, id }) });
      return;
    }
    default:
      throw new Error("auth requires a subcommand: add | list | revoke");
  }
}

function asList(value) {
  if (!value || value === true) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function asLabels(value) {
  const labels = {};
  for (const entry of asList(value)) {
    const index = entry.indexOf("=");
    if (index === -1) {
      throw new Error(`Invalid --label (expected key=value): ${entry}`);
    }
    labels[entry.slice(0, index)] = entry.slice(index + 1);
  }
  return labels;
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
    const value = (!next || next.startsWith("--")) ? true : next;
    if (value !== true) {
      index += 1;
    }
    // Repeated flags accumulate into an array (e.g. --scope a --scope b);
    // a single occurrence stays scalar for backward compatibility.
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      options[key] = Array.isArray(options[key]) ? [...options[key], value] : [options[key], value];
    } else {
      options[key] = value;
    }
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

const COMMAND_HELP = {
  init: {
    usage: "haechi init [--config haechi.config.json] [--force]",
    summary: "Create a local key, sample config, and audit path.",
    detail: "Writes haechi.config.json and .haechi/dev.keys.json (0600). --force rotates the key (prior keys are retired, not deleted) and overwrites the config."
  },
  protect: {
    usage: "haechi protect <input.json> [--config haechi.config.json]",
    summary: "Inspect and protect a JSON payload, printing the result.",
    detail: "Reads input.json, applies the policy, and prints the protected payload, audit id, and warnings. Exit 3 if the payload is blocked."
  },
  report: {
    usage: "haechi report [--audit .haechi/audit.jsonl]",
    summary: "Summarize audit events without raw payloads."
  },
  "audit-verify": {
    usage: "haechi audit-verify [--audit .haechi/audit.jsonl] [--anchor [path]] [--config haechi.config.json]",
    summary: "Verify the audit hash chain; print validity, record count, and head hash.",
    detail: "Exit 4 on a broken chain. With --anchor (or audit.anchor.mode: file in config) it cross-checks the anchor stream and detects tail truncation back to the last anchor. The anchor only adds real defense when kept on append-only or separate media — on the same writable filesystem an attacker can truncate both files together."
  },
  status: {
    usage: "haechi status [--config haechi.config.json]",
    summary: "Show what is and is not protected under the current config.",
    detail: "Prints effective policy mode, response/streaming protection, target, token vault governance, key file permissions, audit chain status, and a consolidated warnings list."
  },
  proxy: {
    usage: `haechi proxy [--config haechi.config.json] [--host 127.0.0.1] [--port ${DEFAULT_PROXY_PORT}] [--allow-remote-bind]`,
    summary: "Run the local HTTP JSON proxy in front of an upstream LLM.",
    detail: "Binds loopback (plain http) by default; --allow-remote-bind is required (and must be a CLI flag, not config) to bind non-loopback hosts. A remote bind additionally requires TLS: set proxy.tls ({ keyFile, certFile } or { pfxFile, passphrase? }) so Haechi serves https, OR set proxy.trustForwardedProto: true when a trusted reverse proxy terminates TLS in front of Haechi (Haechi then refuses any request without X-Forwarded-Proto: https). Configure client auth via auth.provider — see 'haechi config'."
  },
  "policy-sign": {
    usage: "haechi policy-sign <policy.json> [--config haechi.config.json] [--out policy.bundle.json]",
    summary: "Sign a policy file into a verifiable bundle."
  },
  "policy-verify": {
    usage: "haechi policy-verify <policy.bundle.json> [--config haechi.config.json]",
    summary: "Verify a signed policy bundle against the configured key."
  },
  "token-reveal": {
    usage: "haechi token-reveal <token> [--config haechi.config.json] [--allow-dev-reveal]",
    summary: "Reveal a tokenized value (governed by tokenVault.revealPolicy; audited).",
    detail: "Fails unless revealPolicy is local-dev or --allow-dev-reveal is passed."
  },
  "token-purge": {
    usage: "haechi token-purge <token> [--config haechi.config.json]\n  haechi token-purge --expired [--config haechi.config.json]",
    summary: "Purge a specific token, or all expired tokens with --expired."
  },
  "token-export": {
    usage: "haechi token-export [--config haechi.config.json] [--type email]",
    summary: "Export token metadata (never plaintext), optionally filtered by type."
  },
  "plugin-validate": {
    usage: "haechi plugin-validate <plugin-manifest.json>",
    summary: "Validate a plugin manifest (manifest-only; dynamic runtime is rejected)."
  },
  "mcp-stdio": {
    usage: "haechi mcp-stdio [--config haechi.config.json]",
    summary: "Filter MCP JSON-RPC traffic on stdin/stdout (one direction)."
  },
  "mcp-wrap": {
    usage: "haechi mcp-wrap [--config haechi.config.json] -- <command> [args...]",
    summary: "Wrap an MCP server with bidirectional stdio protection.",
    detail: "Spawns <command>, applies the method allowlist + params protection client→server, and result protection + injection heuristics server→client. Drop-in for MCP client configs."
  },
  auth: {
    usage: "haechi auth add --type user|service|agent [--scope k:v ...] [--label k=v ...]\n  haechi auth list [--config haechi.config.json]\n  haechi auth revoke <id> [--config haechi.config.json]",
    summary: "Manage built-in bearer tokens (separate store, hashed).",
    detail: "Tokens are stored hashed in auth.store (default .haechi/auth.json, 0600). `add` prints the plaintext token once — it cannot be recovered. `list` never reveals tokens; `revoke` disables one by id."
  },
  config: {
    usage: "haechi config",
    summary: "Print the configuration guide (keys, defaults, common setups)."
  }
};

function printHelp(topic) {
  if (topic && COMMAND_HELP[topic]) {
    const entry = COMMAND_HELP[topic];
    console.log(`haechi ${topic} — ${entry.summary}\n\nUsage:\n  ${entry.usage}${entry.detail ? `\n\n${entry.detail}` : ""}`);
    return;
  }

  const order = [
    "init", "protect", "report", "status", "audit-verify", "proxy",
    "policy-sign", "policy-verify",
    "token-reveal", "token-purge", "token-export",
    "plugin-validate", "mcp-stdio", "mcp-wrap", "auth", "config"
  ];
  const lines = order.map((name) => `  ${name.padEnd(16)}${COMMAND_HELP[name].summary}`);
  console.log(`Haechi — self-hosted AI context enforcement

Usage:
  haechi <command> [options]
  haechi help <command>     show usage for one command

Commands:
${lines.join("\n")}

Getting started:
  haechi init               write config + local key
  haechi status             see what is protected
  haechi config             configuration guide

The default policy mode is dry-run (detect + audit only). Set policy.mode to
"enforce" to transform or block. Run 'haechi config' for all settings.
`);
}

function printConfigGuide() {
  console.log(`Haechi configuration guide

Config file: haechi.config.json (override with --config <path>); template at
haechi.config.example.json. All values are validated fail-closed — unknown or
malformed settings refuse to start. 'haechi status' prints the EFFECTIVE state.

Enforcement
  mode / policy.mode        dry-run | report-only | enforce   (default dry-run)
                            dry-run/report-only detect + audit only.
                            policy.mode overrides mode.

Upstream + proxy
  target.type               llm-http | openai-compatible | vllm-openai |
                            ollama | llama-cpp                 (unknown = fail)
  target.upstream           the only upstream the proxy forwards to
  proxy.host / proxy.port   127.0.0.1 / ${DEFAULT_PROXY_PORT}
                            non-loopback host needs --allow-remote-bind (CLI flag)

Response + streaming
  responseProtection.enabled  inspect upstream responses        (default false)
  responseProtection.failureMode  fail-closed | allow           (default fail-closed)
  streaming.requestMode     block | pass-through | inspect       (default block)
                            inspect = stream-filter SSE/NDJSON responses
  streaming.maxMatchBytes   cross-frame match window             (default 256)
  limits.upstreamTimeoutMs  upstream timeout in ms              (default 120000)

Detection policy
  policy.presets            korean-pii, secrets-only, llm-redact,
                            strict-block, mcp-basic, local-inference, local-only
  policy.defaultAction      allow | redact | mask | tokenize | encrypt | block
  policy.actions            per-type overrides; merges may strengthen, not weaken
  filters.customRules       extra regex rules (ReDoS-screened)
  filters.minConfidence     [0,1] drop soft detections below this (not hard-block)
  filters.allowlist         FP exceptions [value|{value?,path?}] (not hard-block)

Tokenization (model sees token, caller sees plaintext)
  tokenVault.revealPolicy   disabled | local-dev               (manual reveal gate)
  tokenVault.deterministic  same value -> same token           (default false)
  tokenVault.detokenizeResponses  restore request-issued tokens in the response
                            (needs responseProtection.enabled)

Audit integrity
  audit.anchor.mode         none | file | stdout                (default none)
                            file/stdout anchor the chain head so tail
                            truncation is detected (haechi audit-verify --anchor).
                            Real defense needs the anchor on append-only or
                            separate media; same-filesystem anchors can be
                            truncated together. stdout mode is for long-running
                            commands (proxy), not JSON-emitting ones.
  audit.anchor.path         .haechi/audit.anchor.jsonl          (mode: file)
  audit.anchor.everyRecords anchor cadence                      (default 1)

Privacy + MCP
  privacy.profile           kr-pipa | eu-gdpr | us-general | null
  mcp.allowedMethods        client-callable method allowlist

Binding beyond loopback (0.0.0.0):
  haechi proxy --host 0.0.0.0 --allow-remote-bind
  There is NO client auth yet (planned 0.6). Use only behind network controls:
  bind 0.0.0.0 in a container and map -p 127.0.0.1:${DEFAULT_PROXY_PORT}:${DEFAULT_PROXY_PORT}, or front
  it with a firewall/VPN/authenticating reverse proxy.

Full reference: docs/current/configuration.md
`);
}

await main(command, argv);
