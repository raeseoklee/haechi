import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createAicel } from "../core/index.mjs";
import { createDefaultFilterEngine } from "../filter/index.mjs";
import { buildPolicy, createPolicyEngine } from "../policy/index.mjs";
import { createLocalCryptoProvider, initLocalKeyFile } from "../crypto/index.mjs";
import { createJsonlAuditSink } from "../audit/index.mjs";

export const DEFAULT_CONFIG_PATH = "aicel.config.json";

export function defaultConfig() {
  return {
    mode: "dry-run",
    target: {
      type: "llm-http",
      upstream: "http://127.0.0.1:9999"
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
      keyFile: ".aicel/dev.keys.json"
    },
    audit: {
      sink: "jsonl",
      path: ".aicel/audit.jsonl"
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
  const policy = buildPolicy({
    ...normalized.policy,
    mode: normalized.policy.mode ?? normalized.mode
  });

  return {
    config: normalized,
    aicel: createAicel({
      mode: normalized.mode,
      filterEngine: createDefaultFilterEngine(normalized.filters),
      policyEngine: createPolicyEngine(policy),
      cryptoProvider,
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
    }
  };

  if (merged.keys.provider !== "local") {
    throw new Error("Current implementation only supports local key provider");
  }
  if (merged.audit.sink !== "jsonl") {
    throw new Error("Current implementation only supports jsonl audit sink");
  }
  return merged;
}
