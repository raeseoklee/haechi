import { mkdir, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHaechi } from "../core/index.mjs";
import { createDefaultFilterEngine } from "../filter/index.mjs";
import { createPolicyProfiles } from "../policy/index.mjs";
import { createLocalCryptoProvider, initLocalKeyFile } from "../crypto/index.mjs";
import { createJsonlAuditSink } from "../audit/index.mjs";
import { createLocalTokenVault } from "../token-vault/index.mjs";
import { loadVerifiedPolicyBundleFileSync } from "../policy-bundle/index.mjs";
import { createProtocolAdapter } from "../protocol-adapters/index.mjs";
import { createMetrics } from "../metrics/index.mjs";
import { applyPrivacyProfile, getPrivacyProfile } from "../privacy-profiles/index.mjs";
import { createBearerAuthProvider } from "../auth/index.mjs";
import { createSandboxedAuthProviderSync, createProcessIsolatedAuthProviderSync } from "../plugin/index.mjs";
import { DEFAULT_PROXY_PORT, hasUsableTlsMaterial } from "../proxy/index.mjs";

// Capability keys an operator may allowlist for a plugin. Mirrors the plugin
// manifest's declared-capability set plus the authProvider-specific
// readsCredentials. Inlined (not imported) to keep the dependency one-way.
const KNOWN_PLUGIN_CAPABILITIES = new Set([
  "readsPlaintext",
  "writesPlaintext",
  "networkEgress",
  "fileWrite",
  "auditWrite",
  "externalSecrets",
  "readsCredentials"
]);

export const DEFAULT_CONFIG_PATH = "haechi.config.json";

// Current config schema version. A versioned anchor so a FUTURE breaking schema
// change has something to compare against. Additive: a config WITHOUT the field
// is treated as the current version; an unknown/newer value fails closed (a
// config written by a newer Haechi may use semantics this build does not
// understand — refuse rather than silently mis-interpret it). See
// docs/current/config-version.md.
export const CONFIG_VERSION = 1;

export function defaultConfig() {
  return {
    configVersion: CONFIG_VERSION,
    mode: "dry-run",
    target: {
      type: "llm-http",
      adapter: "openai-compatible",
      upstream: "http://127.0.0.1:9999"
    },
    proxy: {
      host: "127.0.0.1",
      port: DEFAULT_PROXY_PORT,
      // WS6 TLS hardening (additive; defaults preserve 1.1 loopback-plain-http
      // behavior). proxy.tls null = no TLS material; a non-null object is file
      // PATHS loaded at startup into a tlsContext: { keyFile, certFile } or
      // { pfxFile, passphrase? }. A remote (non-loopback) bind REQUIRES either a
      // usable tlsContext OR trustForwardedProto (see assertSafeProxyBind).
      // proxy.trustForwardedProto false = the operator has NOT acknowledged a
      // fronting TLS terminator; true = a trusted reverse proxy terminates TLS in
      // front of Haechi (Haechi then enforces X-Forwarded-Proto: https).
      tls: null,
      trustForwardedProto: false
    },
    responseProtection: {
      enabled: false,
      mode: "enforce",
      failureMode: "fail-closed",
      allowNonJson: false,
      allowCompressed: false,
      maxBytes: 1048576,
      scanNumbers: false
    },
    streaming: {
      requestMode: "block",
      responseMode: "enforce",
      maxMatchBytes: 256
    },
    limits: {
      maxRequestBytes: 1048576,
      maxNestingDepth: 256,
      upstreamTimeoutMs: 120000,
      // WS4-B resilience (additive; defaults preserve 1.1 behavior).
      // maxInFlight 0 = backpressure disabled (no ceiling). shutdownGraceMs is
      // the graceful-drain grace period before in-flight requests/keep-alive
      // sockets are force-closed on close(). requestTimeoutMs/headersTimeoutMs
      // are null = leave Node's server defaults untouched; set a number to tune.
      maxInFlight: 0,
      shutdownGraceMs: 10000,
      requestTimeoutMs: null,
      headersTimeoutMs: null
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
      customRules: [],
      // WS2c precision dials. minConfidence 0 = current behavior (gate nothing);
      // allowlist [] = no operator FP exceptions. Both additive; neither can
      // suppress a hard-block type (secret/api_key/kr_rrn/card) — see core.
      minConfidence: 0,
      allowlist: []
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
    // WS4-A operability. Additive; defaults preserve 1.1 behavior.
    // logging.format "text" = the current human-readable lines; "json" = a single
    // JSON line per event (startup/shutdown/error) carrying a correlationId but
    // NEVER a payload/header/token/PII value.
    logging: {
      format: "text"
    },
    // metrics.enabled gates the /__haechi/metrics route. Default true; when false
    // the route returns 404. The metric surface is a bounded enum — no per-identity
    // or per-value label cardinality (see packages/metrics/index.mjs).
    metrics: {
      enabled: true
    },
    auth: {
      provider: "none",
      store: ".haechi/auth.json",
      allowedLabelKeys: ["team", "env", "tier", "role"]
    },
    // Top-level kill-switch for dynamic plugin loading (1.0 §2.2). Default true;
    // an operator sets `plugins.enabled: false` to force-refuse construction of
    // any sandboxed plugin (a live force-drop, since revocation is next-load).
    plugins: {
      enabled: true
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
  const overlaid = applyEnvOverlay(raw, process.env);
  return normalizeConfig(overlaid);
}

// WS4-B env-var configuration overlay. A FIXED ALLOWLIST of NON-SECRET
// operational keys may be overridden from the environment for container/12-factor
// deploys; env WINS over the file for these. Applied AFTER reading the file and
// BEFORE normalizeConfig, so the overlaid value goes through the same fail-closed
// validation. An invalid env value (bad port, unknown mode) THROWS — it is never
// silently ignored — naming the offending variable.
//
// SECURITY: secrets/keys/tokens are DELIBERATELY NOT overlayable. There is no
// HAECHI_* key for keys.*, the auth store/tokens, or any path-to-key — those stay
// in the config file or are supplied via injected providers. Adding a secret to
// this allowlist would invite leaking it through a process environment.
const ENV_OVERLAY = [
  {
    env: "HAECHI_PROXY_PORT",
    apply(config, value) {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new Error(`HAECHI_PROXY_PORT must be an integer from 0 to 65535 (got: ${JSON.stringify(value)})`);
      }
      config.proxy = { ...(config.proxy ?? {}), port };
    }
  },
  {
    env: "HAECHI_PROXY_HOST",
    apply(config, value) {
      if (typeof value !== "string" || !value.trim()) {
        throw new Error("HAECHI_PROXY_HOST must be a non-empty string");
      }
      config.proxy = { ...(config.proxy ?? {}), host: value };
    }
  },
  {
    env: "HAECHI_UPSTREAM",
    apply(config, value) {
      if (typeof value !== "string" || !value.trim()) {
        throw new Error("HAECHI_UPSTREAM must be a non-empty URL string");
      }
      try {
        // eslint-disable-next-line no-new
        new URL(value);
      } catch {
        throw new Error(`HAECHI_UPSTREAM must be a valid URL (got: ${JSON.stringify(value)})`);
      }
      config.target = { ...(config.target ?? {}), upstream: value };
    }
  },
  {
    env: "HAECHI_MODE",
    apply(config, value) {
      if (!["dry-run", "report-only", "enforce"].includes(value)) {
        throw new Error(`HAECHI_MODE must be one of dry-run|report-only|enforce (got: ${JSON.stringify(value)})`);
      }
      config.mode = value;
    }
  },
  {
    env: "HAECHI_LOG_FORMAT",
    apply(config, value) {
      if (!["text", "json"].includes(value)) {
        throw new Error(`HAECHI_LOG_FORMAT must be "text" or "json" (got: ${JSON.stringify(value)})`);
      }
      config.logging = { ...(config.logging ?? {}), format: value };
    }
  }
];

export function applyEnvOverlay(rawConfig, env = process.env) {
  // Clone shallowly so we don't mutate the caller's object; nested objects we
  // touch are themselves shallow-cloned in each apply().
  const config = { ...rawConfig };
  for (const { env: key, apply } of ENV_OVERLAY) {
    const value = env[key];
    if (value === undefined) {
      continue;
    }
    apply(config, value);
  }
  return config;
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
  // hmac is only required by features that use it (bearer auth, deterministic
  // tokenization). An encrypt-only external provider is valid otherwise; fail
  // closed at construction rather than deep in a request if a needing feature
  // is configured without it.
  if (typeof cryptoProvider.hmac !== "function"
    && (normalized.auth.provider === "bearer"
      || normalized.auth.provider === "plugin"
      || normalized.tokenVault.deterministic)) {
    throw new Error("cryptoProvider must implement hmac() for bearer/plugin auth / deterministic tokenization");
  }
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

  const authProvider = resolveAuthProvider(normalized, providers, cryptoProvider, auditSink);

  // The proxy's per-identity request rate limiter is an injectable collaborator,
  // mirroring cryptoProvider/auditSink/tokenVault. The default is a per-process
  // in-memory fixed-window counter; a multi-replica operator injects a
  // shared-store implementation. Fail closed at construction if it lacks allow().
  const rateLimiter = providers.rateLimiter ?? createRateLimiter();
  assertProvider("rateLimiter", rateLimiter, ["allow"]);

  // WS4-A telemetry seam. The metrics collector is an injectable collaborator,
  // mirroring auditSink/rateLimiter. The default is a zero-dep in-memory
  // Prometheus-text collector; a multi-replica operator injects a shared/remote
  // collector exposing the same increment/observe/render contract. The proxy
  // reads runtime.metrics. The metric surface is a bounded enum — never an
  // identity/value label (no-PII-in-telemetry invariant; see metrics module).
  const metrics = providers.metrics ?? createMetrics();
  assertProvider("metrics", metrics, ["increment", "observe", "render"]);

  return {
    config: normalized,
    tokenVault,
    auditSink,
    authProvider,
    policyProfiles,
    rateLimiter,
    metrics,
    protocolAdapter: createProtocolAdapter(normalized.target),
    haechi: createHaechi({
      mode: normalized.mode,
      filterEngine,
      policyEngine,
      cryptoProvider,
      tokenVault,
      auditSink,
      // Bound recursion depth so a deeply-nested payload fails closed (4xx)
      // rather than overflowing the stack (uncaught 500).
      limits: { maxNestingDepth: normalized.limits.maxNestingDepth },
      // WS2c precision controls (additive; defaults preserve 1.1 behavior). The
      // detect→decide path drops sub-minConfidence soft detections and suppresses
      // allowlisted soft detections — never a hard-block type (enforced in core).
      precision: {
        minConfidence: normalized.filters.minConfidence,
        allowlist: normalized.filters.allowlist
      }
    })
  };
}

export function normalizeConfig(config) {
  const merged = {
    ...defaultConfig(),
    ...config,
    // A config that omits configVersion (e.g. a 1.1 file written before the
    // stamp existed) is treated as the current version, not undefined.
    configVersion: config.configVersion ?? CONFIG_VERSION,
    target: {
      ...defaultConfig().target,
      ...(config.target ?? {})
    },
    proxy: normalizeProxy(config.proxy),
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
    logging: {
      ...defaultConfig().logging,
      ...(config.logging ?? {})
    },
    metrics: {
      ...defaultConfig().metrics,
      ...(config.metrics ?? {})
    },
    auth: {
      ...defaultConfig().auth,
      ...(config.auth ?? {}),
      allowedLabelKeys: config.auth?.allowedLabelKeys ?? defaultConfig().auth.allowedLabelKeys
    },
    plugins: {
      ...defaultConfig().plugins,
      ...(config.plugins ?? {})
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
  if (typeof merged.proxy.trustForwardedProto !== "boolean") {
    throw new Error("proxy.trustForwardedProto must be boolean");
  }
  // proxy.tls has already been resolved by normalizeProxy into either null or a
  // usable tlsContext ({ key, cert } or { pfx, passphrase? }). A non-null value
  // that is not usable TLS material is a fail-closed error (it would otherwise
  // green-light a remote bind that then serves plaintext). normalizeProxy throws
  // first for a malformed shape / unreadable file; this is the belt-and-braces
  // material assertion mirroring the dashboard's tlsContext check.
  if (merged.proxy.tls !== null && !hasUsableTlsMaterial(merged.proxy.tls)) {
    throw new Error("proxy.tls must resolve to usable TLS material ((key && cert) or pfx)");
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
    throw new Error("Only the local token vault provider is supported");
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
  if (!["text", "json"].includes(merged.logging.format)) {
    throw new Error(`Invalid logging.format: ${merged.logging.format} (expected "text" or "json")`);
  }
  if (typeof merged.metrics.enabled !== "boolean") {
    throw new Error("metrics.enabled must be boolean");
  }
  if (!["fail-closed", "allow"].includes(merged.responseProtection.failureMode)) {
    throw new Error(`Invalid responseProtection.failureMode: ${merged.responseProtection.failureMode}`);
  }
  if (typeof merged.responseProtection.maxBytes !== "number" || merged.responseProtection.maxBytes < 1) {
    throw new Error("responseProtection.maxBytes must be a positive number");
  }
  if (typeof merged.responseProtection.scanNumbers !== "boolean") {
    throw new Error("responseProtection.scanNumbers must be boolean");
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
  if (!Number.isInteger(merged.limits.maxNestingDepth) || merged.limits.maxNestingDepth < 1) {
    throw new Error("limits.maxNestingDepth must be a positive integer");
  }
  if (typeof merged.limits.upstreamTimeoutMs !== "number" || merged.limits.upstreamTimeoutMs < 1) {
    throw new Error("limits.upstreamTimeoutMs must be a positive number");
  }
  // WS4-B resilience limits, fail-closed. maxInFlight 0 disables the ceiling.
  if (!Number.isInteger(merged.limits.maxInFlight) || merged.limits.maxInFlight < 0) {
    throw new Error("limits.maxInFlight must be a non-negative integer (0 disables the in-flight ceiling)");
  }
  if (!Number.isInteger(merged.limits.shutdownGraceMs) || merged.limits.shutdownGraceMs < 0) {
    throw new Error("limits.shutdownGraceMs must be a non-negative integer (milliseconds)");
  }
  // requestTimeoutMs/headersTimeoutMs: null leaves Node's server default; a set
  // value must be a non-negative integer (0 disables that timeout, Node semantics).
  for (const field of ["requestTimeoutMs", "headersTimeoutMs"]) {
    const value = merged.limits[field];
    if (value !== null && value !== undefined
      && (!Number.isInteger(value) || value < 0)) {
      throw new Error(`limits.${field} must be null or a non-negative integer (milliseconds; 0 disables the timeout)`);
    }
  }
  // configVersion: a versioned anchor for future schema changes. Fail closed on a
  // newer/unknown version (a config a newer Haechi wrote may use semantics this
  // build does not understand) and on a non-positive-integer value.
  if (!Number.isInteger(merged.configVersion) || merged.configVersion < 1) {
    throw new Error("configVersion must be a positive integer");
  }
  if (merged.configVersion > CONFIG_VERSION) {
    throw new Error(`Unsupported configVersion ${merged.configVersion}: this Haechi build understands configVersion <= ${CONFIG_VERSION}. Upgrade Haechi or lower configVersion (see docs/current/config-version.md).`);
  }
  validatePolicyExtras(merged.policy);
  validateFilters(merged.filters);
  if (!["none", "bearer", "external", "plugin"].includes(merged.auth.provider)) {
    throw new Error(`Invalid auth.provider: ${merged.auth.provider}`);
  }
  if (typeof merged.auth.store !== "string" || !merged.auth.store.trim()) {
    throw new Error("auth.store must be a non-empty string");
  }
  if (!Array.isArray(merged.auth.allowedLabelKeys)
    || !merged.auth.allowedLabelKeys.every((key) => typeof key === "string" && key.trim())) {
    throw new Error("auth.allowedLabelKeys must be an array of non-empty strings");
  }
  if (merged.auth.provider === "plugin") {
    validatePluginAuthConfig(merged);
  }
  createProtocolAdapter(merged.target);
  return merged;
}

export function isValidPort(port) {
  return Number.isInteger(port) && port >= 0 && port <= 65535;
}

// WS6 proxy normalization. Shallow-merges proxy over the default and resolves
// proxy.tls from FILE PATHS into a tlsContext loaded at startup. proxy.tls may be:
//   - null (default): no TLS material.
//   - { keyFile, certFile }: PEM key+cert file paths → { key, cert }.
//   - { pfxFile, passphrase? }: a PKCS#12 file path → { pfx, passphrase? }.
// Fail-closed, enumerated throws: an unknown shape, a missing required field, an
// unreadable file, or a mix of pfx and key/cert all throw at config time rather
// than degrading to a plaintext listener later. The loaded buffers ARE the
// tlsContext handed to https.createServer; node:fs.readFileSync is a builtin
// (zero runtime dependency).
function normalizeProxy(proxy) {
  const merged = {
    ...defaultConfig().proxy,
    ...(proxy ?? {})
  };
  merged.tls = resolveProxyTls(merged.tls);
  return merged;
}

function resolveProxyTls(tls) {
  if (tls === undefined || tls === null) {
    return null;
  }
  if (typeof tls !== "object" || Array.isArray(tls)) {
    throw new Error("proxy.tls must be null or an object ({ keyFile, certFile } or { pfxFile, passphrase? })");
  }
  // Already a loaded tlsContext (a hand-built config passing { key, cert } / { pfx }
  // directly, e.g. a test or an embedder) — accept it as-is; the material check in
  // normalizeConfig still gates it. Only resolve the FILE-PATH form below.
  const hasFilePaths = tls.keyFile !== undefined || tls.certFile !== undefined || tls.pfxFile !== undefined;
  const hasInlineMaterial = tls.key !== undefined || tls.cert !== undefined || tls.pfx !== undefined;
  if (hasInlineMaterial && !hasFilePaths) {
    return tls;
  }

  const usingPfx = tls.pfxFile !== undefined;
  const usingKeyCert = tls.keyFile !== undefined || tls.certFile !== undefined;
  if (usingPfx && usingKeyCert) {
    throw new Error("proxy.tls must use either { keyFile, certFile } or { pfxFile }, not both");
  }
  if (!usingPfx && !usingKeyCert) {
    throw new Error("proxy.tls must set { keyFile, certFile } or { pfxFile }");
  }

  if (usingPfx) {
    if (typeof tls.pfxFile !== "string" || !tls.pfxFile.trim()) {
      throw new Error("proxy.tls.pfxFile must be a non-empty string path");
    }
    if (tls.passphrase !== undefined && typeof tls.passphrase !== "string") {
      throw new Error("proxy.tls.passphrase must be a string when set");
    }
    const context = { pfx: readTlsFile(tls.pfxFile, "proxy.tls.pfxFile") };
    if (tls.passphrase !== undefined) {
      context.passphrase = tls.passphrase;
    }
    return context;
  }

  if (typeof tls.keyFile !== "string" || !tls.keyFile.trim()) {
    throw new Error("proxy.tls.keyFile must be a non-empty string path");
  }
  if (typeof tls.certFile !== "string" || !tls.certFile.trim()) {
    throw new Error("proxy.tls.certFile must be a non-empty string path");
  }
  return {
    key: readTlsFile(tls.keyFile, "proxy.tls.keyFile"),
    cert: readTlsFile(tls.certFile, "proxy.tls.certFile")
  };
}

function readTlsFile(path, label) {
  try {
    return readFileSync(path);
  } catch (error) {
    throw new Error(`${label} could not be read: ${error.code ?? error.message}`);
  }
}

// Fail-closed validation of the WS2c precision controls. minConfidence is a
// number in [0,1]; allowlist is an array of exact-value strings and/or
// { value?, path? } objects (at least one of value/path must be a non-empty
// string). A malformed config throws rather than silently degrading.
function validateFilters(filters) {
  if (filters.minConfidence !== undefined) {
    if (typeof filters.minConfidence !== "number" || Number.isNaN(filters.minConfidence)
      || filters.minConfidence < 0 || filters.minConfidence > 1) {
      throw new Error("filters.minConfidence must be a number in [0, 1]");
    }
  }
  if (filters.allowlist !== undefined) {
    if (!Array.isArray(filters.allowlist)) {
      throw new Error("filters.allowlist must be an array");
    }
    for (const entry of filters.allowlist) {
      if (typeof entry === "string") {
        if (!entry) {
          throw new Error("filters.allowlist string entries must be non-empty");
        }
        continue;
      }
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        throw new Error("filters.allowlist entries must be a string or a { value?, path? } object");
      }
      const hasValue = entry.value !== undefined;
      const hasPath = entry.path !== undefined;
      if (!hasValue && !hasPath) {
        throw new Error("filters.allowlist object entries must set value and/or path");
      }
      if (hasValue && (typeof entry.value !== "string" || !entry.value)) {
        throw new Error("filters.allowlist entry.value must be a non-empty string");
      }
      if (hasPath && (typeof entry.path !== "string" || !entry.path)) {
        throw new Error("filters.allowlist entry.path must be a non-empty string");
      }
    }
  }
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

// Enumerated, fail-closed validation of auth.provider:"plugin" (1.0 §2.3). Every
// rule throws a distinct error so a bad option is attributable. Mirrors the
// keys/tokenVault rigor — no silent degradation.
function validatePluginAuthConfig(merged) {
  // Kill-switch: refuse to construct any plugin when plugins.enabled is false.
  if (typeof merged.plugins?.enabled !== "boolean") {
    throw new Error("plugins.enabled must be boolean");
  }
  if (merged.plugins.enabled === false) {
    throw new Error("plugins are disabled (plugins.enabled: false); refusing to construct a plugin authProvider");
  }

  const plugin = merged.auth.plugin;
  if (!plugin || typeof plugin !== "object" || Array.isArray(plugin)) {
    throw new Error("auth.provider 'plugin' requires an auth.plugin object");
  }
  if (typeof plugin.manifestPath !== "string" || !plugin.manifestPath.trim()) {
    throw new Error("auth.plugin.manifestPath must be a non-empty string");
  }

  // trustAnchors: a non-empty array of {keyId, publicKey} OR a non-empty object
  // map keyId -> publicKey/anchor.
  const anchors = plugin.trustAnchors;
  if (Array.isArray(anchors)) {
    if (anchors.length === 0) {
      throw new Error("auth.plugin.trustAnchors must be a non-empty array");
    }
    for (const anchor of anchors) {
      if (!anchor || typeof anchor !== "object"
        || typeof anchor.keyId !== "string" || !anchor.keyId.trim()
        || anchor.publicKey === undefined || anchor.publicKey === null) {
        throw new Error("each auth.plugin.trustAnchors entry must be { keyId, publicKey }");
      }
    }
  } else if (anchors && typeof anchors === "object") {
    const keys = Object.keys(anchors);
    if (keys.length === 0) {
      throw new Error("auth.plugin.trustAnchors must be a non-empty object");
    }
    for (const keyId of keys) {
      if (anchors[keyId] === undefined || anchors[keyId] === null) {
        throw new Error(`auth.plugin.trustAnchors.${keyId} must be a public key`);
      }
    }
  } else {
    throw new Error("auth.plugin.trustAnchors must be a non-empty array or object of { keyId, publicKey }");
  }

  // allowCapabilities: an array of known capability keys, including readsCredentials.
  if (!Array.isArray(plugin.allowCapabilities) || plugin.allowCapabilities.length === 0) {
    throw new Error("auth.plugin.allowCapabilities must be a non-empty array of capability keys");
  }
  for (const capability of plugin.allowCapabilities) {
    if (typeof capability !== "string" || !KNOWN_PLUGIN_CAPABILITIES.has(capability)) {
      throw new Error(`auth.plugin.allowCapabilities contains an unknown capability: ${capability}`);
    }
  }
  if (!plugin.allowCapabilities.includes("readsCredentials")) {
    throw new Error("auth.plugin.allowCapabilities must include readsCredentials for an authProvider");
  }

  // isolation: "worker" (default, 1.0 worker_threads — memory/crash isolation) or
  // "process" (1.1 — a --permission child with real capability enforcement).
  const isolation = plugin.isolation ?? "worker";
  if (!["worker", "process"].includes(isolation)) {
    throw new Error(`auth.plugin.isolation must be "worker" or "process" (got: ${JSON.stringify(plugin.isolation)})`);
  }

  if (!Number.isInteger(plugin.timeoutMs) || plugin.timeoutMs <= 0) {
    throw new Error("auth.plugin.timeoutMs must be a positive integer");
  }

  if (isolation === "worker") {
    // worker_threads resourceLimits (heap bound). Required for the worker runtime.
    const limits = plugin.resourceLimits;
    if (!limits || typeof limits !== "object" || Array.isArray(limits)
      || !Number.isInteger(limits.maxOldGenerationSizeMb) || limits.maxOldGenerationSizeMb <= 0) {
      throw new Error("auth.plugin.resourceLimits.maxOldGenerationSizeMb must be a positive integer");
    }
  } else {
    // process-isolated: resourceLimits is N/A (the child is OS-bounded). Validate
    // the network-enforcement policy and the optional host-mediated key material.
    const netEnforcement = plugin.netEnforcement ?? "require-permission";
    if (netEnforcement !== "require-permission") {
      throw new Error(`auth.plugin.netEnforcement must be "require-permission" (got: ${JSON.stringify(plugin.netEnforcement)})`);
    }
    if (plugin.keyMaterial !== undefined && plugin.keyMaterial !== null) {
      const km = plugin.keyMaterial;
      if (typeof km !== "object" || Array.isArray(km) || typeof km.url !== "string" || !km.url.trim()) {
        throw new Error("auth.plugin.keyMaterial must be an object with an operator-declared url string");
      }
      let keyUrl;
      try {
        keyUrl = new URL(km.url);
      } catch {
        throw new Error("auth.plugin.keyMaterial.url must be a valid URL");
      }
      if (keyUrl.protocol !== "https:") {
        throw new Error("auth.plugin.keyMaterial.url must be https");
      }
      for (const field of ["ttlMs", "cooldownMs", "timeoutMs", "maxBytes"]) {
        if (km[field] !== undefined && (typeof km[field] !== "number" || km[field] < 0)) {
          throw new Error(`auth.plugin.keyMaterial.${field} must be a non-negative number`);
        }
      }
    }
  }

  if (plugin.maxPendingCalls !== undefined
    && (!Number.isInteger(plugin.maxPendingCalls) || plugin.maxPendingCalls < 1)) {
    throw new Error("auth.plugin.maxPendingCalls must be a positive integer");
  }
  if (plugin.maxMessageBytes !== undefined
    && (!Number.isInteger(plugin.maxMessageBytes) || plugin.maxMessageBytes < 1)) {
    throw new Error("auth.plugin.maxMessageBytes must be a positive integer");
  }

  if (plugin.pin !== undefined && plugin.pin !== null) {
    if (typeof plugin.pin !== "object" || Array.isArray(plugin.pin)) {
      throw new Error("auth.plugin.pin must be an object");
    }
    for (const field of ["version", "entrySha256", "manifestSha256"]) {
      if (plugin.pin[field] !== undefined && plugin.pin[field] !== null
        && (typeof plugin.pin[field] !== "string" || !plugin.pin[field].trim())) {
        throw new Error(`auth.plugin.pin.${field} must be a non-empty string`);
      }
    }
  }

  if (plugin.revoked !== undefined && plugin.revoked !== null) {
    if (typeof plugin.revoked !== "object" || Array.isArray(plugin.revoked)) {
      throw new Error("auth.plugin.revoked must be an object");
    }
    for (const field of ["signerKeyIds", "entrySha256"]) {
      if (plugin.revoked[field] !== undefined
        && (!Array.isArray(plugin.revoked[field])
          || !plugin.revoked[field].every((v) => typeof v === "string" && v.trim()))) {
        throw new Error(`auth.plugin.revoked.${field} must be an array of non-empty strings`);
      }
    }
  }

  if (plugin.versionFloor !== undefined && plugin.versionFloor !== null) {
    if (typeof plugin.versionFloor !== "object" || Array.isArray(plugin.versionFloor)) {
      throw new Error("auth.plugin.versionFloor must be an object mapping pluginId -> version");
    }
    for (const [id, floor] of Object.entries(plugin.versionFloor)) {
      if (typeof floor !== "string" || !floor.trim()) {
        throw new Error(`auth.plugin.versionFloor.${id} must be a non-empty version string`);
      }
    }
  }
}

function resolveAuthProvider(config, providers, cryptoProvider, auditSink) {
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
  if (config.auth.provider === "plugin") {
    const plugin = config.auth.plugin;
    const common = {
      manifestPath: plugin.manifestPath,
      trustAnchors: normalizeTrustAnchors(plugin.trustAnchors),
      allowCapabilities: plugin.allowCapabilities,
      pin: plugin.pin ?? null,
      revoked: plugin.revoked ?? {},
      versionFloor: plugin.versionFloor ?? {},
      timeoutMs: plugin.timeoutMs,
      maxPendingCalls: plugin.maxPendingCalls,
      maxMessageBytes: plugin.maxMessageBytes,
      coreVersion: plugin.coreVersion ?? null,
      cryptoProvider,
      auditSink,
      allowedLabelKeys: config.auth.allowedLabelKeys
    };
    if ((plugin.isolation ?? "worker") === "process") {
      // 1.1 capability enforcement. Construction fails closed on a Node that
      // cannot enforce --allow-net (netEnforcement: require-permission).
      return createProcessIsolatedAuthProviderSync({
        ...common,
        netEnforcement: plugin.netEnforcement ?? "require-permission",
        keyMaterial: plugin.keyMaterial ?? null
      });
    }
    return createSandboxedAuthProviderSync({ ...common, resourceLimits: plugin.resourceLimits });
  }
  return null;
}

// The config form is a non-empty array of { keyId, publicKey } OR an object map.
// verifySignedPlugin resolves the anchor by signerKeyId against an object map, so
// normalize an array form into that map here.
function normalizeTrustAnchors(anchors) {
  if (Array.isArray(anchors)) {
    const map = {};
    for (const anchor of anchors) {
      map[anchor.keyId] = anchor.publicKey;
    }
    return map;
  }
  return anchors;
}

function createConfiguredCryptoProvider(config) {
  if (config.keys.provider === "external") {
    throw new Error("keys.provider external requires createRuntime(config, { cryptoProvider })");
  }
  return createLocalCryptoProvider({ keyFile: config.keys.keyFile });
}

// Default rate limiter: an in-memory fixed-window counter keyed by identity.
// Per-process — it resets on restart and is NOT shared across replicas, so a
// multi-replica operator injects a shared-store implementation via
// createRuntime(config, { rateLimiter }) (see shared-responsibility.md §4).
//
// The window Map is self-bounding via a lazy, amortized sweep — NO timer (a
// setInterval would keep the event loop alive and hang `node --test`). On
// allow(), when the Map crosses a size threshold we evict a bounded number of
// fully-expired entries (now - windowStart >= windowMs). A one-shot identity's
// slot therefore does not linger forever once it ages past its window. The
// allow(key, limit) -> boolean contract and the fixed-window 429 semantics are
// unchanged; only stale bookkeeping is reclaimed.
export function createRateLimiter({ windowMs = 60000, sweepThreshold = 1024, sweepBudget = 256 } = {}) {
  const windows = new Map();

  function sweepExpired(now) {
    // Bounded amortized eviction: scan at most sweepBudget entries per call (Map
    // iteration is insertion-ordered, so the oldest keys are visited first) and
    // drop any whose window has fully elapsed. Amortized O(1) per allow().
    let scanned = 0;
    for (const [key, slot] of windows) {
      if (scanned >= sweepBudget) {
        break;
      }
      scanned += 1;
      if (now - slot.windowStart >= windowMs) {
        windows.delete(key);
      }
    }
  }

  return {
    allow(key, limit) {
      const now = Date.now();
      // Reclaim aged-out one-shot identities before they accumulate unbounded.
      if (windows.size >= sweepThreshold) {
        sweepExpired(now);
      }
      const slot = windows.get(key);
      if (!slot || now - slot.windowStart >= windowMs) {
        windows.set(key, { windowStart: now, count: 1 });
        return true;
      }
      if (slot.count >= limit) {
        return false;
      }
      slot.count += 1;
      return true;
    },
    // Test-only introspection of the live window count. Innocuous: it exposes a
    // bare integer, never any key/identity value.
    _size() {
      return windows.size;
    }
  };
}

function assertProvider(name, provider, methods) {
  for (const method of methods) {
    if (typeof provider?.[method] !== "function") {
      throw new Error(`${name} provider must implement ${method}()`);
    }
  }
}
