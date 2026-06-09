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

export const DEFAULT_CONFIG_PATH = "haechi.config.json";

export function defaultConfig() {
  return {
    mode: "dry-run",
    target: {
      type: "llm-http",
      adapter: "openai-compatible",
      upstream: "http://127.0.0.1:9999"
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
      requestMode: "block"
    },
    limits: {
      maxRequestBytes: 1048576
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
      path: ".haechi/token-vault.json"
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

export function createRuntime(config) {
  const normalized = normalizeConfig(config);
  const cryptoProvider = createLocalCryptoProvider({ keyFile: normalized.keys.keyFile });
  const tokenVault = createLocalTokenVault({ path: normalized.tokenVault.path, cryptoProvider });
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
  const policy = buildPolicy({
    ...policySource
  });

  return {
    config: normalized,
    tokenVault,
    protocolAdapter: createProtocolAdapter(normalized.target),
    haechi: createHaechi({
      mode: normalized.mode,
      filterEngine: createDefaultFilterEngine(normalized.filters),
      policyEngine: createPolicyEngine(policy),
      cryptoProvider,
      tokenVault,
      auditSink: createJsonlAuditSink({ path: normalized.audit.path })
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
    }
  };

  if (merged.keys.provider !== "local") {
    throw new Error("Current implementation only supports local key provider");
  }
  if (merged.audit.sink !== "jsonl") {
    throw new Error("Current implementation only supports jsonl audit sink");
  }
  if (merged.tokenVault.provider !== "local") {
    throw new Error("0.2 only supports local token vault provider");
  }
  if (!["fail-closed", "allow"].includes(merged.responseProtection.failureMode)) {
    throw new Error(`Invalid responseProtection.failureMode: ${merged.responseProtection.failureMode}`);
  }
  if (typeof merged.responseProtection.maxBytes !== "number" || merged.responseProtection.maxBytes < 1) {
    throw new Error("responseProtection.maxBytes must be a positive number");
  }
  if (!["block", "pass-through"].includes(merged.streaming.requestMode)) {
    throw new Error(`Invalid streaming.requestMode: ${merged.streaming.requestMode}`);
  }
  if (typeof merged.limits.maxRequestBytes !== "number" || merged.limits.maxRequestBytes < 1) {
    throw new Error("limits.maxRequestBytes must be a positive number");
  }
  createProtocolAdapter(merged.target);
  return merged;
}
