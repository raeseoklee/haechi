import { readFile } from "node:fs/promises";

export {
  signPluginManifest,
  verifySignedPlugin,
  PluginLoadError,
  PLUGIN_LOAD_REASONS
} from "./signing.mjs";

export {
  createSandboxedAuthProvider,
  createSandboxedAuthProviderSync
} from "./sandbox.mjs";

const VALID_KINDS = new Set([
  "crypto-provider",
  "key-provider",
  "policy-engine",
  "filter-engine",
  "token-vault",
  "audit-sink",
  "protocol-adapter",
  "classifier-plugin",
  // 1.0: the first dynamically-loadable kind, only under the worker-isolated
  // signed/capability-gated/audited sandbox.
  "authProvider"
]);

const CAPABILITY_KEYS = [
  "readsPlaintext",
  "writesPlaintext",
  "networkEgress",
  "fileWrite",
  "auditWrite",
  "externalSecrets"
];
// manifest-only is the historical, behavior-preserving path. worker-isolated is
// the 1.0 dynamic-loading runtime — permitted ONLY for kind authProvider and
// only with the Ed25519 signed envelope (see validateWorkerIsolatedManifest).
const VALID_RUNTIMES = new Set(["manifest-only", "worker-isolated"]);

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

    if (plugin.runtime && !VALID_RUNTIMES.has(plugin.runtime)) {
      errors.push("dynamic plugin execution is not supported; set runtime to manifest-only");
    }

    if (plugin.runtime === "worker-isolated") {
      // The 1.0 dynamic-loading path: a separate, stricter contract (signed
      // Ed25519 envelope + a validity window + authProvider-only). Kept apart
      // from the manifest-only checks so the historical path is untouched.
      validateWorkerIsolatedManifest(plugin, errors);
    } else {
      // manifest-only (and any other declared-but-rejected runtime): the
      // historical, behavior-preserving contract — UNCHANGED.
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
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// The worker-isolated runtime is dynamic code-loading; it is permitted ONLY for
// kind authProvider and ONLY with the Ed25519 signed envelope fields. A
// worker-isolated manifest that is not an authProvider, or is missing the signed
// fields / validity window / readsCredentials, is rejected with a clear error.
function validateWorkerIsolatedManifest(plugin, errors) {
  if (plugin.kind !== "authProvider") {
    errors.push("worker-isolated runtime is only supported for kind authProvider");
  }

  // The signed-envelope fields that bind authorship and the exact entry bytes.
  // signature must be a non-empty base64-ish string; entrySha256 must be a
  // 64-char lowercase hex string. Loose shapes signal a malformed/forged manifest.
  if (!plugin.signature || typeof plugin.signature !== "string" || plugin.signature.length === 0) {
    errors.push("missing signature");
  } else if (!/^[A-Za-z0-9+/=]+$/.test(plugin.signature)) {
    errors.push("signature must be a non-empty base64 string");
  }
  requireString(plugin, "signerKeyId", errors);
  if (!plugin.entrySha256 || typeof plugin.entrySha256 !== "string" || plugin.entrySha256.length === 0) {
    errors.push("missing entrySha256");
  } else if (!/^[0-9a-f]{64}$/.test(plugin.entrySha256)) {
    errors.push("entrySha256 must be a 64-character lowercase hex string");
  }

  // A validity window is mandatory for a dynamically-loaded artifact.
  const hasNotBefore = plugin.notBefore !== undefined && plugin.notBefore !== null;
  const hasNotAfter = plugin.notAfter !== undefined && plugin.notAfter !== null;
  if (!hasNotBefore && !hasNotAfter) {
    errors.push("worker-isolated manifest requires a validity window (notBefore and/or notAfter)");
  }

  if (!plugin.capabilities || typeof plugin.capabilities !== "object" || Array.isArray(plugin.capabilities)) {
    errors.push("missing capabilities");
  } else if (plugin.capabilities.readsCredentials !== true) {
    // An authProvider sees the bearer token, so it MUST declare readsCredentials.
    errors.push("worker-isolated authProvider must declare capabilities.readsCredentials = true");
  }
}

function requireString(object, key, errors) {
  if (!object[key] || typeof object[key] !== "string") {
    errors.push(`missing ${key}`);
  }
}
