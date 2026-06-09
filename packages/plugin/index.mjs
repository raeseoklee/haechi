import { readFile } from "node:fs/promises";

const VALID_KINDS = new Set([
  "crypto-provider",
  "key-provider",
  "policy-engine",
  "filter-engine",
  "token-vault",
  "audit-sink",
  "protocol-adapter",
  "classifier-plugin"
]);

const CAPABILITY_KEYS = [
  "readsPlaintext",
  "writesPlaintext",
  "networkEgress",
  "fileWrite",
  "auditWrite",
  "externalSecrets"
];

export async function validatePluginManifestFile(path) {
  const manifest = JSON.parse(await readFile(path, "utf8"));
  return validatePluginManifest(manifest);
}

export function validatePluginManifest(manifest) {
  const plugin = manifest?.haechiPlugin;
  const errors = [];

  if (!plugin) {
    errors.push("missing haechiPlugin root");
  } else {
    requireString(plugin, "id", errors);
    requireString(plugin, "version", errors);
    requireString(plugin, "kind", errors);
    requireString(plugin, "runtime", errors);
    requireString(plugin, "entrypoint", errors);

    if (plugin.kind && !VALID_KINDS.has(plugin.kind)) {
      errors.push(`invalid kind: ${plugin.kind}`);
    }

    if (!plugin.compatibility?.haechiCore) {
      errors.push("missing compatibility.haechiCore");
    }

    if (!plugin.capabilities || typeof plugin.capabilities !== "object") {
      errors.push("missing capabilities");
    } else {
      for (const key of CAPABILITY_KEYS) {
        if (typeof plugin.capabilities[key] !== "boolean") {
          errors.push(`capabilities.${key} must be boolean`);
        }
      }
    }

    if (plugin.capabilities?.networkEgress && plugin.capabilities.readsPlaintext && !plugin.dataHandling?.retention) {
      errors.push("plaintext-reading network plugins must declare dataHandling.retention");
    }

    if (plugin.dataHandling?.logsRawPayload === true) {
      errors.push("dataHandling.logsRawPayload must not be true");
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

function requireString(object, key, errors) {
  if (!object[key] || typeof object[key] !== "string") {
    errors.push(`missing ${key}`);
  }
}
