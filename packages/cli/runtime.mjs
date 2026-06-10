import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHaechi } from "../core/index.mjs";
import { createDefaultFilterEngine } from "../filter/index.mjs";
import { buildPolicy, createPolicyEngine } from "../policy/index.mjs";
import { createLocalCryptoProvider, initLocalKeyFile } from "../crypto/index.mjs";
import { createJsonlAuditSink } from "../audit/index.mjs";
import { createLocalTokenVault } from "../token-vault/index.mjs";
import { loadVerifiedPolicyBundleFileSync } from "../policy-bundle/index.mjs";
import { createProtocolAdapter } from "../protocol-adapters/index.mjs";
import { applyPrivacyProfile, getPrivacyProfile } from "../privacy-profiles/index.mjs";
import { DEFAULT_PROXY_PORT } from "../proxy/index.mjs";

export const DEFAULT_CONFIG_PATH = "haechi.config.json";

export function defaultConfig() {
  return {
    mode: "dry-run",
    target: {
      type: "llm-http",
      adapter: "openai-compatible",
      upstream: "http://127.0.0.1:9999"
    },
    proxy: {
      host: "127.0.0.1",
      port: DEFAULT_PROXY_PORT
    },
    responseProtection: {
      enabled: false,
      mode: "enforce",
      failureMode: "fail-closed",
      allowNonJson: false,
      allowCompressed: false,
      maxBytes: 1048576
    },
    streaming: {
      requestMode: "block",
      responseMode: "enforce",
      maxMatchBytes: 256
    },
    limits: {
      maxRequestBytes: 1048576,
      upstreamTimeoutMs: 120000
    },
    policy: {
      mode: "dry-run",
      presets: ["korean-pii", "secrets-only", "llm-redact"],
      defaultAction: "redact",
      actions: {
        card: "block"
      }
    },
    filters: {
      customRules: []
    },
    keys: {
      provider: "local",
      keyFile: ".haechi/dev.keys.json"
    },
    audit: {
      sink: "jsonl",
      path: ".haechi/audit.jsonl"
    },
    tokenVault: {
      provider: "local",
      path: ".haechi/token-vault.json",
      revealPolicy: "disabled",
      retentionDays: 30,
      deterministic: false,
      deterministicTypes: null,
      detokenizeResponses: false
    },
    privacy: {
      profile: null
    },
    mcp: {
      allowedMethods: ["initialize", "tools/call", "resources/read", "prompts/get"],
      protectParams: true,
      protectResults: true,
      requireJsonRpc: true
    }
  };
}

export async function loadConfig(configPath = DEFAULT_CONFIG_PATH) {
  const raw = JSON.parse(await readFile(configPath, "utf8"));
  return normalizeConfig(raw);
}

export async function writeDefaultConfig(configPath = DEFAULT_CONFIG_PATH, { force = false } = {}) {
  const config = defaultConfig();
  await mkdir(dirname(config.keys.keyFile), { recursive: true });
  await initLocalKeyFile(config.keys.keyFile, { force });

  if (!force) {
    try {
      await readFile(configPath, "utf8");
      return { created: false, configPath, config };
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  return { created: true, configPath, config };
}

export function createRuntime(config, providers = {}) {
  const normalized = normalizeConfig(config);
  const cryptoProvider = providers.cryptoProvider ?? createConfiguredCryptoProvider(normalized);
  assertProvider("cryptoProvider", cryptoProvider, ["encrypt", "decrypt"]);
  const auditSink = providers.auditSink ?? createJsonlAuditSink({ path: normalized.audit.path });
  assertProvider("auditSink", auditSink, ["record"]);
  const tokenVault = providers.tokenVault ?? createLocalTokenVault({
    path: normalized.tokenVault.path,
    cryptoProvider,
    revealPolicy: normalized.tokenVault.revealPolicy,
    retentionDays: normalized.tokenVault.retentionDays,
    deterministic: normalized.tokenVault.deterministic,
    deterministicTypes: normalized.tokenVault.deterministicTypes,
    auditSink
  });
  assertProvider("tokenVault", tokenVault, ["tokenize", "reveal", "purge"]);
  const policySource = normalized.policy.bundlePath
    ? {
      ...loadVerifiedPolicyBundleFileSync({
        bundlePath: normalized.policy.bundlePath,
        keyFile: normalized.keys.keyFile
      }).policy,
      mode: normalized.policy.mode ?? normalized.mode
    }
    : {
      ...normalized.policy,
      mode: normalized.policy.mode ?? normalized.mode
    };
  const policy = buildPolicy(normalized.privacy.profile
    ? applyPrivacyProfile(policySource, normalized.privacy.profile)
    : policySource);

  const filterEngine = providers.filterEngine ?? createDefaultFilterEngine(normalized.filters);
  assertProvider("filterEngine", filterEngine, ["detect"]);
  const policyEngine = providers.policyEngine ?? createPolicyEngine(policy);
  assertProvider("policyEngine", policyEngine, ["decide"]);

  return {
    config: normalized,
    tokenVault,
    auditSink,
    protocolAdapter: createProtocolAdapter(normalized.target),
    haechi: createHaechi({
      mode: normalized.mode,
      filterEngine,
      policyEngine,
      cryptoProvider,
      tokenVault,
      auditSink
    })
  };
}

export function normalizeConfig(config) {
  const merged = {
    ...defaultConfig(),
    ...config,
    target: {
      ...defaultConfig().target,
      ...(config.target ?? {})
    },
    proxy: {
      ...defaultConfig().proxy,
      ...(config.proxy ?? {})
    },
    responseProtection: {
      ...defaultConfig().responseProtection,
      ...(config.responseProtection ?? {})
    },
    streaming: {
      ...defaultConfig().streaming,
      ...(config.streaming ?? {})
    },
    limits: {
      ...defaultConfig().limits,
      ...(config.limits ?? {})
    },
    policy: {
      ...defaultConfig().policy,
      ...(config.policy ?? {}),
      actions: {
        ...defaultConfig().policy.actions,
        ...(config.policy?.actions ?? {})
      }
    },
    filters: {
      ...defaultConfig().filters,
      ...(config.filters ?? {})
    },
    keys: {
      ...defaultConfig().keys,
      ...(config.keys ?? {})
    },
    audit: {
      ...defaultConfig().audit,
      ...(config.audit ?? {})
    },
    tokenVault: {
      ...defaultConfig().tokenVault,
      ...(config.tokenVault ?? {})
    },
    privacy: {
      ...defaultConfig().privacy,
      ...(config.privacy ?? {})
    },
    mcp: {
      ...defaultConfig().mcp,
      ...(config.mcp ?? {}),
      allowedMethods: config.mcp?.allowedMethods ?? defaultConfig().mcp.allowedMethods
    }
  };

  if (!["local", "external"].includes(merged.keys.provider)) {
    throw new Error(`Unsupported key provider: ${merged.keys.provider}`);
  }
  if (typeof merged.proxy.host !== "string" || !merged.proxy.host.trim()) {
    throw new Error("proxy.host must be a non-empty string");
  }
  if (!isValidPort(merged.proxy.port)) {
    throw new Error("proxy.port must be an integer from 0 to 65535");
  }
  if (merged.audit.sink !== "jsonl") {
    throw new Error("Current implementation only supports jsonl audit sink");
  }
  if (merged.tokenVault.provider !== "local") {
    throw new Error("0.2 only supports local token vault provider");
  }
  if (!["disabled", "local-dev"].includes(merged.tokenVault.revealPolicy)) {
    throw new Error(`Invalid tokenVault.revealPolicy: ${merged.tokenVault.revealPolicy}`);
  }
  if (typeof merged.tokenVault.retentionDays !== "number" || merged.tokenVault.retentionDays < 1) {
    throw new Error("tokenVault.retentionDays must be a positive number");
  }
  if (typeof merged.tokenVault.deterministic !== "boolean") {
    throw new Error("tokenVault.deterministic must be boolean");
  }
  if (merged.tokenVault.deterministicTypes !== null
    && (!Array.isArray(merged.tokenVault.deterministicTypes)
      || merged.tokenVault.deterministicTypes.length === 0
      || !merged.tokenVault.deterministicTypes.every((type) => typeof type === "string" && type.trim()))) {
    throw new Error("tokenVault.deterministicTypes must be null or a non-empty array of type strings");
  }
  if (typeof merged.tokenVault.detokenizeResponses !== "boolean") {
    throw new Error("tokenVault.detokenizeResponses must be boolean");
  }
  if (!Array.isArray(merged.mcp.allowedMethods) || merged.mcp.allowedMethods.length === 0) {
    throw new Error("mcp.allowedMethods must be a non-empty array");
  }
  if (!merged.mcp.allowedMethods.every((method) => typeof method === "string" && method.trim())) {
    throw new Error("mcp.allowedMethods must contain only non-empty strings");
  }
  if (typeof merged.mcp.protectParams !== "boolean" || typeof merged.mcp.protectResults !== "boolean") {
    throw new Error("mcp.protectParams and mcp.protectResults must be boolean");
  }
  if (typeof merged.mcp.requireJsonRpc !== "boolean") {
    throw new Error("mcp.requireJsonRpc must be boolean");
  }
  if (merged.privacy.profile) {
    getPrivacyProfile(merged.privacy.profile);
  }
  if (!["fail-closed", "allow"].includes(merged.responseProtection.failureMode)) {
    throw new Error(`Invalid responseProtection.failureMode: ${merged.responseProtection.failureMode}`);
  }
  if (typeof merged.responseProtection.maxBytes !== "number" || merged.responseProtection.maxBytes < 1) {
    throw new Error("responseProtection.maxBytes must be a positive number");
  }
  if (!["block", "pass-through", "inspect"].includes(merged.streaming.requestMode)) {
    throw new Error(`Invalid streaming.requestMode: ${merged.streaming.requestMode}`);
  }
  if (!["dry-run", "report-only", "enforce"].includes(merged.streaming.responseMode)) {
    throw new Error(`Invalid streaming.responseMode: ${merged.streaming.responseMode}`);
  }
  if (typeof merged.streaming.maxMatchBytes !== "number" || merged.streaming.maxMatchBytes < 1) {
    throw new Error("streaming.maxMatchBytes must be a positive number");
  }
  if (typeof merged.limits.maxRequestBytes !== "number" || merged.limits.maxRequestBytes < 1) {
    throw new Error("limits.maxRequestBytes must be a positive number");
  }
  if (typeof merged.limits.upstreamTimeoutMs !== "number" || merged.limits.upstreamTimeoutMs < 1) {
    throw new Error("limits.upstreamTimeoutMs must be a positive number");
  }
  createProtocolAdapter(merged.target);
  return merged;
}

export function isValidPort(port) {
  return Number.isInteger(port) && port >= 0 && port <= 65535;
}

function createConfiguredCryptoProvider(config) {
  if (config.keys.provider === "external") {
    throw new Error("keys.provider external requires createRuntime(config, { cryptoProvider })");
  }
  return createLocalCryptoProvider({ keyFile: config.keys.keyFile });
}

function assertProvider(name, provider, methods) {
  for (const method of methods) {
    if (typeof provider?.[method] !== "function") {
      throw new Error(`${name} provider must implement ${method}()`);
    }
  }
}
