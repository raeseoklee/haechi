import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import {
  signPluginManifest,
  verifySignedPlugin,
  PluginLoadError,
  PLUGIN_LOAD_REASONS,
  validatePluginManifest
} from "../packages/plugin/index.mjs";

// A canonical, signed-and-valid fixture builder. Each test mutates exactly one
// dimension so a refusal is attributable to a single cause.
function fixture(overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signerKeyId = overrides.signerKeyId ?? "anchor-1";
  const entryBytes = overrides.entryBytes ?? "export default { authenticate() { return null; } };";
  const now = overrides.now ?? Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "acme-auth",
      kind: "authProvider",
      version: "1.2.0",
      capabilities: { readsCredentials: true, networkEgress: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 60_000,
      notAfter: now + 60_000,
      ...(overrides.signPayload ?? {})
    },
    privateKey,
    signerKeyId
  );
  const trustAnchors = overrides.trustAnchors ?? { [signerKeyId]: publicKey };
  return {
    publicKey,
    privateKey,
    signerKeyId,
    entryBytes,
    now,
    signed,
    verifyArgs: {
      signed,
      entryBytes,
      trustAnchors,
      allowCapabilities: ["readsCredentials", "networkEgress"],
      now,
      ...(overrides.verifyArgs ?? {})
    }
  };
}

function expectRefusal(reason, fn) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof PluginLoadError, `expected PluginLoadError, got ${error?.name}`);
    assert.equal(error.reason, reason, `expected reason "${reason}", got "${error.reason}"`);
    assert.ok(PLUGIN_LOAD_REASONS.includes(error.reason), "reason must be in the contract set");
    return true;
  });
}

// ---- happy path -----------------------------------------------------------

test("verifySignedPlugin accepts a valid signed plugin (happy path)", () => {
  const f = fixture();
  const payload = verifySignedPlugin(f.verifyArgs);
  assert.equal(payload.pluginId, "acme-auth");
  assert.equal(payload.kind, "authProvider");
  assert.equal(payload.version, "1.2.0");
  assert.equal(payload.capabilities.readsCredentials, true);
  assert.ok(typeof payload.entrySha256 === "string" && payload.entrySha256.length === 64);
  // The returned payload is frozen (attested facts are immutable).
  assert.throws(() => { payload.version = "9.9.9"; });
});

test("verifySignedPlugin also accepts a SPKI-PEM trust anchor (not just a KeyObject)", () => {
  const f = fixture();
  const pem = f.publicKey.export({ type: "spki", format: "pem" });
  const payload = verifySignedPlugin({ ...f.verifyArgs, trustAnchors: { [f.signerKeyId]: pem } });
  assert.equal(payload.pluginId, "acme-auth");
});

// ---- §7.3 refusal matrix: one fail-closed test per reason -----------------

test("refuse: alg !== ed25519", () => {
  const f = fixture();
  const tampered = { ...f.signed, alg: "hmac-sha256" };
  expectRefusal("alg-not-ed25519", () => verifySignedPlugin({ ...f.verifyArgs, signed: tampered }));
});

test("refuse: signerKeyId NOT in trustAnchors (resolve-before-verify)", () => {
  // Critical: a manifest naming a kid that exists in SOME broader keyring is
  // still "unknown-signer" if that kid is not an operator-allowlisted anchor.
  // We prove the key is real (it verifies the signature) yet the verify never
  // runs because the kid is absent from trustAnchors.
  const f = fixture({ signerKeyId: "rogue-kid" });
  const broaderKeyring = { "rogue-kid": f.publicKey }; // the kid's real key exists here...
  // ...but the operator's trustAnchors does NOT contain it.
  expectRefusal("unknown-signer", () => verifySignedPlugin({
    ...f.verifyArgs,
    trustAnchors: { "some-other-anchor": generateKeyPairSync("ed25519").publicKey }
  }));
  // Sanity: with the kid allowlisted it would pass — so the refusal was purely
  // the allowlist, not a bad key.
  const ok = verifySignedPlugin({ ...f.verifyArgs, trustAnchors: broaderKeyring });
  assert.equal(ok.pluginId, "acme-auth");
});

test("refuse: revoked signer", () => {
  const f = fixture();
  expectRefusal("revoked", () => verifySignedPlugin({
    ...f.verifyArgs,
    revoked: { signerKeyIds: [f.signerKeyId] }
  }));
});

test("refuse: entry bytes mutated after signing (path/manifest unchanged) -> tampered-entry", () => {
  const f = fixture();
  // The signed envelope is untouched; only the on-disk entry bytes changed.
  const mutatedEntry = `${f.entryBytes}\n// injected backdoor`;
  expectRefusal("tampered-entry", () => verifySignedPlugin({
    ...f.verifyArgs,
    entryBytes: mutatedEntry
  }));
});

test("refuse: revoked entryHash", () => {
  const f = fixture();
  expectRefusal("revoked", () => verifySignedPlugin({
    ...f.verifyArgs,
    revoked: { entrySha256: [f.signed.payload.entrySha256] }
  }));
});

test("refuse: invalid signature (signature bytes corrupted)", () => {
  const f = fixture();
  const buf = Buffer.from(f.signed.signature, "base64");
  buf[0] ^= 0xff;
  const corrupted = { ...f.signed, signature: buf.toString("base64") };
  expectRefusal("invalid-signature", () => verifySignedPlugin({ ...f.verifyArgs, signed: corrupted }));
});

test("refuse: signature from a different key (wrong anchor) -> invalid-signature", () => {
  const f = fixture();
  // Allowlist the kid, but the anchor is a DIFFERENT ed25519 public key.
  const otherPub = generateKeyPairSync("ed25519").publicKey;
  expectRefusal("invalid-signature", () => verifySignedPlugin({
    ...f.verifyArgs,
    trustAnchors: { [f.signerKeyId]: otherPub }
  }));
});

test("refuse: outside notBefore/notAfter -> expired-window", () => {
  const f = fixture();
  // now far past notAfter.
  expectRefusal("expired-window", () => verifySignedPlugin({
    ...f.verifyArgs,
    now: f.now + 10_000_000
  }));
  // now before notBefore.
  expectRefusal("expired-window", () => verifySignedPlugin({
    ...f.verifyArgs,
    now: f.now - 10_000_000
  }));
});

test("refuse: below version-floor", () => {
  const f = fixture();
  expectRefusal("below-version-floor", () => verifySignedPlugin({
    ...f.verifyArgs,
    versionFloor: { "acme-auth": "1.3.0" } // signed is 1.2.0 < 1.3.0
  }));
  // At/above the floor passes.
  const ok = verifySignedPlugin({ ...f.verifyArgs, versionFloor: { "acme-auth": "1.2.0" } });
  assert.equal(ok.version, "1.2.0");
});

test("refuse: pin mismatch (version / entrySha256)", () => {
  const f = fixture();
  expectRefusal("pin-mismatch", () => verifySignedPlugin({
    ...f.verifyArgs,
    pin: { version: "1.1.0" }
  }));
  expectRefusal("pin-mismatch", () => verifySignedPlugin({
    ...f.verifyArgs,
    pin: { entrySha256: "0".repeat(64) }
  }));
  // A matching pin passes.
  const ok = verifySignedPlugin({
    ...f.verifyArgs,
    pin: { version: "1.2.0", entrySha256: f.signed.payload.entrySha256 }
  });
  assert.equal(ok.version, "1.2.0");
});

test("refuse: capability not in allowlist", () => {
  const f = fixture();
  // networkEgress is requested (true) but not allowlisted.
  expectRefusal("capability-not-allowlisted", () => verifySignedPlugin({
    ...f.verifyArgs,
    allowCapabilities: ["readsCredentials"]
  }));
});

test("refuse: authProvider missing readsCredentials -> capability-not-allowlisted", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "no-creds",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { networkEgress: false }, // no readsCredentials
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: now + 1000
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("capability-not-allowlisted", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials", "networkEgress"],
    now
  }));
});

test("refuse: structurally invalid envelope -> manifest-invalid", () => {
  expectRefusal("manifest-invalid", () => verifySignedPlugin({ signed: null, entryBytes: "x" }));
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed: { alg: "ed25519", signerKeyId: "a", signature: "AA==", payload: { pluginId: "" } },
    entryBytes: "x"
  }));
});

// ---- the manifest validator gate (worker-isolated + manifest-only) --------

test("validatePluginManifest accepts a worker-isolated + authProvider + signed manifest", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      signature: "base64sig",
      signerKeyId: "anchor-1",
      entrySha256: "a".repeat(64),
      notBefore: "2026-01-01T00:00:00Z",
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { readsCredentials: true, networkEgress: true }
    }
  });
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("validatePluginManifest rejects worker-isolated with a non-authProvider kind", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "bad",
      version: "1.0.0",
      kind: "filter-engine",
      runtime: "worker-isolated",
      entrypoint: "./dist/x.mjs",
      signature: "sig",
      signerKeyId: "anchor-1",
      entrySha256: "a".repeat(64),
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { readsCredentials: true }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /only supported for kind authProvider/);
});

test("validatePluginManifest rejects worker-isolated missing signed fields", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      // no signature / signerKeyId / entrySha256 / window
      capabilities: { readsCredentials: true }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /signature/);
  assert.match(result.errors.join("\n"), /signerKeyId/);
  assert.match(result.errors.join("\n"), /entrySha256/);
  assert.match(result.errors.join("\n"), /validity window/);
});

test("validatePluginManifest rejects worker-isolated authProvider without readsCredentials", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      signature: "sig",
      signerKeyId: "anchor-1",
      entrySha256: "a".repeat(64),
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { networkEgress: false }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /readsCredentials/);
});

// REGRESSION GUARD: the historical manifest-only path is unchanged.
test("validatePluginManifest still accepts a manifest-only plugin (regression guard)", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "example-filter",
      version: "0.1.0",
      kind: "filter-engine",
      runtime: "manifest-only",
      entrypoint: "./manifest-only",
      compatibility: { haechiCore: ">=0.2.0 <0.3.0" },
      capabilities: {
        readsPlaintext: true,
        writesPlaintext: false,
        networkEgress: false,
        fileWrite: false,
        auditWrite: false,
        externalSecrets: false
      },
      dataHandling: { retention: "none", logsRawPayload: false }
    }
  });
  assert.equal(result.valid, true, result.errors.join("; "));
});

test("validatePluginManifest still rejects an unknown dynamic runtime (regression guard)", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "dynamic-filter",
      version: "0.1.0",
      kind: "filter-engine",
      runtime: "node",
      entrypoint: "./dist/index.js",
      compatibility: { haechiCore: ">=0.3.0 <0.4.0" },
      capabilities: {
        readsPlaintext: true,
        writesPlaintext: false,
        networkEgress: false,
        fileWrite: false,
        auditWrite: false,
        externalSecrets: false
      },
      dataHandling: { retention: "none", logsRawPayload: false }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /dynamic plugin execution/);
});

// PluginLoadError refuses an off-contract reason at construction.
test("PluginLoadError rejects a reason outside the contract set", () => {
  assert.throws(() => new PluginLoadError("not-a-real-reason"), /off-contract reason/);
});

// ---- FIX A: capability allowlist bypass via non-boolean values --------------

test("FIX A: refuse: capability with value 1 (truthy non-boolean) -> manifest-invalid", () => {
  // A signed plugin whose capabilities has networkEgress: 1 must be rejected
  // at the trust boundary — not silently treated as requested=false.
  // signPluginManifest validates capabilities as an object but does not check
  // boolean values, so we can pass { readsCredentials: true, networkEgress: 1 }.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-caps",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true, networkEgress: 1 },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: now + 60_000
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials", "networkEgress"],
    now
  }));
});

test("FIX A: refuse: capability with value \"true\" (string) -> manifest-invalid", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-caps-str",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true, networkEgress: "true" },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: now + 60_000
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials", "networkEgress"],
    now
  }));
});

// ---- FIX B: validity window fails CLOSED on garbage bounds ------------------

test("FIX B: refuse: notAfter set to \"whenever\" -> manifest-invalid (fail closed)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-window",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: "whenever"
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    now
  }));
});

test("FIX B: refuse: notBefore set to empty string -> manifest-invalid (fail closed)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-window-2",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: "",
      notAfter: now + 60_000
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    now
  }));
});

test("FIX B: refuse: notAfter set to boolean true -> manifest-invalid (fail closed)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-window-3",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: true
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    now
  }));
});

test("FIX B: refuse: notAfter set to NaN -> manifest-invalid (fail closed)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "bad-window-4",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: NaN
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    now
  }));
});

// ---- FIX D: coreVersionRange enforcement ------------------------------------

test("FIX D: refuse: plugin signed for >=2.0.0 <3.0.0 loaded against coreVersion 1.0.0", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "version-mismatch",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=2.0.0 <3.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: now + 60_000
    },
    privateKey,
    "anchor-1"
  );
  expectRefusal("manifest-invalid", () => verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    coreVersion: "1.0.0",
    now
  }));
});

test("FIX D: accept: plugin signed for >=1.0.0 <2.0.0 loaded against coreVersion 1.5.0", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const entryBytes = "export default {};";
  const now = Date.now();
  const signed = signPluginManifest(
    {
      pluginId: "version-ok",
      kind: "authProvider",
      version: "1.0.0",
      capabilities: { readsCredentials: true },
      coreVersionRange: ">=1.0.0 <2.0.0",
      entryBytes,
      notBefore: now - 1000,
      notAfter: now + 60_000
    },
    privateKey,
    "anchor-1"
  );
  const payload = verifySignedPlugin({
    signed,
    entryBytes,
    trustAnchors: { "anchor-1": publicKey },
    allowCapabilities: ["readsCredentials"],
    coreVersion: "1.5.0",
    now
  });
  assert.equal(payload.pluginId, "version-ok");
});

// ---- FIX E: malformed signature/entrySha256 shapes in manifest validator ----

test("FIX E: validatePluginManifest rejects non-base64 signature", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      signature: "not@base64!value#",
      signerKeyId: "anchor-1",
      entrySha256: "a".repeat(64),
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { readsCredentials: true }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /base64/);
});

test("FIX E: validatePluginManifest rejects entrySha256 that is not 64 lowercase hex chars", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      signature: "YWJjZA==",
      signerKeyId: "anchor-1",
      entrySha256: "ABCDEF1234",  // uppercase / too short
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { readsCredentials: true }
    }
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /64-character lowercase hex/);
});

test("FIX E: validatePluginManifest accepts valid base64 signature and 64-char hex entrySha256", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "acme-auth",
      version: "1.2.0",
      kind: "authProvider",
      runtime: "worker-isolated",
      entrypoint: "./dist/auth.mjs",
      signature: "YWJjZA==",
      signerKeyId: "anchor-1",
      entrySha256: "a".repeat(64),
      notAfter: "2027-01-01T00:00:00Z",
      capabilities: { readsCredentials: true }
    }
  });
  assert.equal(result.valid, true, result.errors.join("; "));
});
