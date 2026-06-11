import test from "node:test";
import assert from "node:assert/strict";
import { normalizeConfig, createRuntime } from "../packages/cli/runtime.mjs";
import {
  buildSignedPlugin,
  referenceCrypto,
  bearer
} from "./helpers/sandbox-fixtures.mjs";

// A minimal valid auth.plugin config block. publicKey is an Ed25519 KeyObject —
// normalizeConfig only checks shape, not key validity (verifySignedPlugin does).
function pluginAuthConfig(overrides = {}) {
  return {
    auth: {
      provider: "plugin",
      plugin: {
        manifestPath: "./some/manifest.json",
        trustAnchors: [{ keyId: "anchor-1", publicKey: "PEM-OR-KEYOBJECT" }],
        allowCapabilities: ["readsCredentials", "networkEgress"],
        timeoutMs: 1000,
        resourceLimits: { maxOldGenerationSizeMb: 64 },
        ...overrides.plugin
      },
      ...overrides.auth
    },
    ...overrides.top
  };
}

test("normalizeConfig accepts a well-formed auth.provider:plugin config", () => {
  const config = normalizeConfig(pluginAuthConfig());
  assert.equal(config.auth.provider, "plugin");
  assert.equal(config.plugins.enabled, true);
});

// Each enumerated fail-closed rule throws.
const badCases = [
  ["missing auth.plugin object", () => pluginAuthConfig({ auth: { plugin: undefined } })],
  ["missing manifestPath", () => pluginAuthConfig({ plugin: { manifestPath: "" } })],
  ["trustAnchors empty array", () => pluginAuthConfig({ plugin: { trustAnchors: [] } })],
  ["trustAnchors bad entry", () => pluginAuthConfig({ plugin: { trustAnchors: [{ keyId: "" }] } })],
  ["trustAnchors empty object", () => pluginAuthConfig({ plugin: { trustAnchors: {} } })],
  ["allowCapabilities empty", () => pluginAuthConfig({ plugin: { allowCapabilities: [] } })],
  ["allowCapabilities unknown key", () => pluginAuthConfig({ plugin: { allowCapabilities: ["readsCredentials", "bogusCap"] } })],
  ["allowCapabilities missing readsCredentials", () => pluginAuthConfig({ plugin: { allowCapabilities: ["networkEgress"] } })],
  ["timeoutMs not positive int", () => pluginAuthConfig({ plugin: { timeoutMs: 0 } })],
  ["timeoutMs fractional", () => pluginAuthConfig({ plugin: { timeoutMs: 1.5 } })],
  ["resourceLimits missing", () => pluginAuthConfig({ plugin: { resourceLimits: undefined } })],
  ["maxOldGenerationSizeMb not positive int", () => pluginAuthConfig({ plugin: { resourceLimits: { maxOldGenerationSizeMb: 0 } } })],
  ["maxPendingCalls bad", () => pluginAuthConfig({ plugin: { maxPendingCalls: 0 } })],
  ["maxMessageBytes bad", () => pluginAuthConfig({ plugin: { maxMessageBytes: -1 } })],
  ["pin not object", () => pluginAuthConfig({ plugin: { pin: "x" } })],
  ["pin.version empty", () => pluginAuthConfig({ plugin: { pin: { version: "" } } })],
  ["revoked not object", () => pluginAuthConfig({ plugin: { revoked: [] } })],
  ["revoked.signerKeyIds bad", () => pluginAuthConfig({ plugin: { revoked: { signerKeyIds: [1] } } })],
  ["versionFloor bad", () => pluginAuthConfig({ plugin: { versionFloor: { p: 1 } } })],
  ["plugins.enabled false (kill-switch)", () => pluginAuthConfig({ top: { plugins: { enabled: false } } })],
  ["plugins.enabled non-boolean", () => pluginAuthConfig({ top: { plugins: { enabled: "yes" } } })]
];

for (const [name, build] of badCases) {
  test(`normalizeConfig rejects: ${name}`, () => {
    assert.throws(() => normalizeConfig(build()), Error, `expected ${name} to throw`);
  });
}

// --- isolation: "process" (1.1 capability enforcement) ---------------------
// normalizeConfig validates shape only (no construction / no --allow-net probe),
// so these run on any Node.

test("normalizeConfig accepts isolation:process without resourceLimits", () => {
  const config = normalizeConfig(pluginAuthConfig({ plugin: { isolation: "process", resourceLimits: undefined } }));
  assert.equal(config.auth.plugin.isolation, "process");
});

test("normalizeConfig accepts isolation:process with an operator-declared keyMaterial https url", () => {
  const config = normalizeConfig(pluginAuthConfig({
    plugin: { isolation: "process", resourceLimits: undefined, keyMaterial: { url: "https://keys.example.com/jwks", ttlMs: 60_000 } }
  }));
  assert.equal(config.auth.plugin.keyMaterial.url, "https://keys.example.com/jwks");
});

const processBadCases = [
  ["isolation bad value", () => pluginAuthConfig({ plugin: { isolation: "vm" } })],
  ["process netEnforcement allow-harness (unsupported)", () => pluginAuthConfig({ plugin: { isolation: "process", resourceLimits: undefined, netEnforcement: "allow-harness" } })],
  ["process keyMaterial non-https url", () => pluginAuthConfig({ plugin: { isolation: "process", resourceLimits: undefined, keyMaterial: { url: "http://keys.example.com/jwks" } } })],
  ["process keyMaterial missing url", () => pluginAuthConfig({ plugin: { isolation: "process", resourceLimits: undefined, keyMaterial: { ttlMs: 1000 } } })],
  ["process keyMaterial negative ttl", () => pluginAuthConfig({ plugin: { isolation: "process", resourceLimits: undefined, keyMaterial: { url: "https://k.example.com/x", ttlMs: -1 } } })]
];
for (const [name, build] of processBadCases) {
  test(`normalizeConfig rejects: ${name}`, () => {
    assert.throws(() => normalizeConfig(build()), Error, `expected ${name} to throw`);
  });
}

test("plugins.enabled:false kill-switch refuses to construct via createRuntime", () => {
  assert.throws(
    () => normalizeConfig(pluginAuthConfig({ top: { plugins: { enabled: false } } })),
    /plugins are disabled/
  );
});

test("createRuntime with auth.provider:plugin requires cryptoProvider.hmac (fail-closed)", () => {
  // An encrypt-only provider (no hmac) must fail closed before wiring the plugin.
  const encryptOnly = {
    async encrypt() { return {}; },
    async decrypt() { return ""; }
  };
  const built = buildSignedPlugin();
  assert.throws(
    () => createRuntime(
      pluginAuthConfig({ plugin: { manifestPath: built.manifestPath, trustAnchors: built.trustAnchors } }),
      { cryptoProvider: encryptOnly }
    ),
    /hmac/
  );
});

// ---------------------------------------------------------------------------
// E2E: createRuntime wires the sandbox; a request authenticates; identity is
// keyed-HMAC and the audit carries no raw subject/credential.
// ---------------------------------------------------------------------------

test("E2E: createRuntime({auth:{provider:plugin}}, {cryptoProvider}) authenticates a request into a keyed-HMAC identity", async () => {
  const built = buildSignedPlugin();
  const events = [];
  const auditSink = { async record(e) { events.push(e); } };

  const runtime = createRuntime(
    {
      auth: {
        provider: "plugin",
        plugin: {
          manifestPath: built.manifestPath,
          trustAnchors: built.trustAnchors,
          allowCapabilities: ["readsCredentials", "networkEgress"],
          timeoutMs: 2000,
          resourceLimits: { maxOldGenerationSizeMb: 64 },
          coreVersion: "1.0.0"
        }
      }
    },
    { cryptoProvider: referenceCrypto, auditSink }
  );

  assert.ok(runtime.authProvider, "the plugin authProvider is wired");
  try {
    const identity = await runtime.authProvider.authenticate(bearer("good-token-carol"));
    assert.ok(identity, "the request authenticates through the plugin");
    assert.equal(typeof identity.subjectHash, "string");
    assert.equal(typeof identity.issuerHash, "string");
    assert.notEqual(identity.subjectHash, "carol");
    assert.equal(identity.provider, `plugin:${built.pluginId}`);

    const dump = JSON.stringify(events);
    assert.ok(!dump.includes("carol"), "no raw subject in the audit");
    assert.ok(!dump.includes("good-token-carol"), "no raw credential in the audit");
    assert.ok(events.some((e) => (e.type ?? e.decision) === "plugin.load.accepted"),
      "load.accepted recorded through the runtime auditSink");
  } finally {
    if (typeof runtime.authProvider.close === "function") {
      await runtime.authProvider.close();
    }
  }
});
