import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { createPolicyProfiles } from "../packages/policy/index.mjs";

const PROFILE_POLICY = {
  mode: "enforce",
  presets: [],
  defaultAction: "allow",
  actions: { email: "redact" },
  profiles: {
    strict: { actions: { email: "block" } },
    internal: { actions: { email: "allow" }, modelAllowlist: ["llama3"], rate: { requestsPerMinute: 120 } }
  },
  profileBinding: {
    byScope: { "team:eng": "internal" },
    byLabel: { "tier=trusted": "internal" },
    default: "strict"
  }
};

test("profile resolution follows scope → label → default", () => {
  const profiles = createPolicyProfiles(PROFILE_POLICY);

  assert.equal(profiles.resolve({ scopes: ["team:eng"], labels: {} }).profile, "internal");
  assert.equal(profiles.resolve({ scopes: [], labels: { tier: "trusted" } }).profile, "internal");
  assert.equal(profiles.resolve({ scopes: ["team:other"], labels: {} }).profile, "strict");
  assert.equal(profiles.resolve(null).profile, "strict");
  // Scope precedes label when both could match.
  assert.equal(profiles.resolve({ scopes: ["team:eng"], labels: { tier: "untrusted" } }).profile, "internal");
});

test("resolved profiles expose their model allowlist and rate", () => {
  const profiles = createPolicyProfiles(PROFILE_POLICY);
  const internal = profiles.resolve({ scopes: ["team:eng"], labels: {} });
  assert.deepEqual(internal.modelAllowlist, ["llama3"]);
  assert.deepEqual(internal.rate, { requestsPerMinute: 120 });
  const strict = profiles.resolve(null);
  assert.equal(strict.modelAllowlist, null);
});

test("a missing or unknown binding default fails closed at compile time", () => {
  assert.throws(() => createPolicyProfiles({
    presets: [], profiles: { a: {} }, profileBinding: { default: "missing" }
  }), /default must name a declared profile/);

  assert.throws(() => createPolicyProfiles({
    presets: [], profiles: { a: {} }
  }), /requires policy.profileBinding/);

  assert.throws(() => createPolicyProfiles({
    presets: [], profiles: { a: {} }, profileBinding: { default: "a", byScope: { "x": "ghost" } }
  }), /unknown profile: ghost/);
});

test("different profiles apply different actions through protectJson", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-profiles-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: PROFILE_POLICY,
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });

  const payload = { message: "mail minji.kim@example.com" };

  // Default (strict) blocks email.
  const strict = runtime.policyProfiles.resolve(null);
  const strictResult = await runtime.haechi.protectJson(payload, { policyEngine: strict.policyEngine });
  assert.equal(strictResult.blocked, true);

  // internal allows email through.
  const internal = runtime.policyProfiles.resolve({ scopes: ["team:eng"], labels: {} });
  const internalResult = await runtime.haechi.protectJson(payload, { policyEngine: internal.policyEngine });
  assert.equal(internalResult.blocked, false);
  assert.match(internalResult.payload.message, /minji\.kim@example\.com/);
});

test("a base policy with no profiles resolves to base (backward compatible)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-noprofiles-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: ["llm-redact"], defaultAction: "redact" },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });
  assert.equal(runtime.policyProfiles.hasProfiles, false);
  const resolved = runtime.policyProfiles.resolve({ scopes: ["anything"] });
  assert.equal(resolved.profile, null);
  const result = await runtime.haechi.protectJson({ message: "mail minji.kim@example.com" });
  assert.match(result.payload.message, /\[REDACTED:email\]/);
});

test("config validation covers profiles, bindings, allowlist, and rate", () => {
  assert.throws(() => normalizeConfig({ policy: { modelAllowlist: [7] } }), /modelAllowlist/);
  assert.throws(() => normalizeConfig({ policy: { rate: { requestsPerMinute: 0 } } }), /requestsPerMinute/);
  assert.throws(() => normalizeConfig({ policy: { profiles: [] } }), /policy.profiles must be an object/);
  assert.throws(() => normalizeConfig({ policy: { profiles: { a: {} }, profileBinding: { byScope: {} } } }), /profileBinding.default/);
  const ok = normalizeConfig({ policy: { profiles: { a: { actions: {} } }, profileBinding: { default: "a" } } });
  assert.ok(ok.policy.profiles.a);
});
