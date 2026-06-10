import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHaechi } from "../core/index.mjs";
import { createDefaultFilterEngine } from "../filter/index.mjs";
import { createPolicyProfiles } from "../policy/index.mjs";
import { createLocalCryptoProvider, initLocalKeyFile } from "../crypto/index.mjs";
import { createJsonlAuditSink } from "../audit/index.mjs";
import { createLocalTokenVault } from "../token-vault/index.mjs";
import { loadVerifiedPolicyBundleFileSync } from "../policy-bundle/index.mjs";
import { createProtocolAdapter } from "../protocol-adapters/index.mjs";
import { applyPrivacyProfile, getPrivacyProfile } from "../privacy-profiles/index.mjs";
import { createBearerAuthProvider } from "../auth/index.mjs";
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
      path: ".haechi/audit.jsonl",
      anchor: {
        mode: "none",
        path: ".haechi/audit.anchor.jsonl",
        everyRecords: 1
      }
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
    auth: {
      provider: "none",
      store: ".haechi/auth.json",
      allowedLabelKeys: ["team", "env", "tier", "role"]
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
  const auditSink = providers.auditSink ?? createJsonlAuditSink({
    path: normalized.audit.path,
    anchor: normalized.audit.anchor
  });
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
  const policyProfiles = createPolicyProfiles(policySource, {
    transform: (source) => normalized.privacy.profile
      ? applyPrivacyProfile(source, normalized.privacy.profile)
      : source
  });

  const filterEngine = providers.filterEngine ?? createDefaultFilterEngine(normalized.filters);
  assertProvider("filterEngine", filterEngine, ["detect"]);
  const policyEngine = providers.policyEngine ?? policyProfiles.base.policyEngine;
  assertProvider("policyEngine", policyEngine, ["decide"]);

  const authProvider = resolveAuthProvider(normalized, providers, cryptoProvider);

  return {
    config: normalized,
    tokenVault,
    auditSink,
    authProvider,
    policyProfiles,
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
      ...(config.audit ?? {}),
      anchor: {
        ...defaultConfig().audit.anchor,
        ...(config.audit?.anchor ?? {})
      }
    },
    tokenVault: {
      ...defaultConfig().tokenVault,
      ...(config.tokenVault ?? {})
    },
    privacy: {
      ...defaultConfig().privacy,
      ...(config.privacy ?? {})
    },
    auth: {
      ...defaultConfig().auth,
      ...(config.auth ?? {}),
      allowedLabelKeys: config.auth?.allowedLabelKeys ?? defaultConfig().auth.allowedLabelKeys
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
  if (!["none", "file", "stdout"].includes(merged.audit.anchor.mode)) {
    throw new Error(`Invalid audit.anchor.mode: ${merged.audit.anchor.mode}`);
  }
  if (merged.audit.anchor.mode === "file"
    && (typeof merged.audit.anchor.path !== "string" || !merged.audit.anchor.path.trim())) {
    throw new Error("audit.anchor.mode 'file' requires audit.anchor.path");
  }
  if (!Number.isInteger(merged.audit.anchor.everyRecords) || merged.audit.anchor.everyRecords < 1) {
    throw new Error("audit.anchor.everyRecords must be a positive integer");
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
  validatePolicyExtras(merged.policy);
  if (!["none", "bearer", "external"].includes(merged.auth.provider)) {
    throw new Error(`Invalid auth.provider: ${merged.auth.provider}`);
  }
  if (typeof merged.auth.store !== "string" || !merged.auth.store.trim()) {
    throw new Error("auth.store must be a non-empty string");
  }
  if (!Array.isArray(merged.auth.allowedLabelKeys)
    || !merged.auth.allowedLabelKeys.every((key) => typeof key === "string" && key.trim())) {
    throw new Error("auth.allowedLabelKeys must be an array of non-empty strings");
  }
  createProtocolAdapter(merged.target);
  return merged;
}

export function isValidPort(port) {
  return Number.isInteger(port) && port >= 0 && port <= 65535;
}

function validatePolicyExtras(policy) {
  if (policy.modelAllowlist !== undefined) {
    assertModelAllowlist(policy.modelAllowlist, "policy.modelAllowlist");
  }
  if (policy.rate !== undefined) {
    assertRate(policy.rate, "policy.rate");
  }
  if (policy.profiles !== undefined) {
    if (typeof policy.profiles !== "object" || policy.profiles === null || Array.isArray(policy.profiles)) {
      throw new Error("policy.profiles must be an object of named profiles");
    }
    for (const [name, profile] of Object.entries(policy.profiles)) {
      if (typeof profile !== "object" || profile === null || Array.isArray(profile)) {
        throw new Error(`policy.profiles.${name} must be an object`);
      }
      if (profile.modelAllowlist !== undefined) {
        assertModelAllowlist(profile.modelAllowlist, `policy.profiles.${name}.modelAllowlist`);
      }
      if (profile.rate !== undefined) {
        assertRate(profile.rate, `policy.profiles.${name}.rate`);
      }
    }
  }
  if (policy.profileBinding !== undefined) {
    const binding = policy.profileBinding;
    if (typeof binding !== "object" || binding === null || Array.isArray(binding)) {
      throw new Error("policy.profileBinding must be an object");
    }
    if (typeof binding.default !== "string" || !binding.default.trim()) {
      throw new Error("policy.profileBinding.default must be a profile name");
    }
    for (const field of ["byScope", "byLabel"]) {
      if (binding[field] !== undefined
        && (typeof binding[field] !== "object" || binding[field] === null || Array.isArray(binding[field]))) {
        throw new Error(`policy.profileBinding.${field} must be an object`);
      }
    }
  }
}

function assertModelAllowlist(value, label) {
  if (!Array.isArray(value) || !value.every((model) => typeof model === "string" && model.trim())) {
    throw new Error(`${label} must be an array of non-empty strings`);
  }
}

function assertRate(value, label) {
  if (typeof value !== "object" || value === null
    || typeof value.requestsPerMinute !== "number" || value.requestsPerMinute < 1) {
    throw new Error(`${label}.requestsPerMinute must be a positive number`);
  }
}

function resolveAuthProvider(config, providers, cryptoProvider) {
  if (config.auth.provider === "external") {
    if (typeof providers.authProvider?.authenticate !== "function") {
      throw new Error("auth.provider external requires createRuntime(config, { authProvider })");
    }
    return providers.authProvider;
  }
  if (providers.authProvider) {
    // An injected provider overrides the built-in selection.
    return providers.authProvider;
  }
  if (config.auth.provider === "bearer") {
    return createBearerAuthProvider({ path: config.auth.store, cryptoProvider });
  }
  return null;
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
