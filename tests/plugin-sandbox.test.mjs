import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createSandboxedAuthProvider
} from "../packages/plugin/index.mjs";
import { sanitizeAudit, createJsonlAuditSink } from "../packages/audit/index.mjs";
import {
  buildSignedPlugin,
  sandboxOptions,
  createRecordingAuditSink,
  referenceCrypto,
  bearer,
  ECHO_PLUGIN_SOURCE,
  POLLUTING_PLUGIN_SOURCE,
  HANGING_PLUGIN_SOURCE,
  NONDETERMINISTIC_PLUGIN_SOURCE
} from "./helpers/sandbox-fixtures.mjs";

// ---------------------------------------------------------------------------
// Happy path: load, conformance in the worker, host-built PII-safe identity
// ---------------------------------------------------------------------------

test("reference signed plugin loads, passes conformance, and authenticates into a host-built PII-safe identity", async () => {
  const built = buildSignedPlugin();
  const audit = createRecordingAuditSink();
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit }));

  try {
    const identity = await provider.authenticate(bearer("good-token-alice"));
    assert.ok(identity, "a valid bearer must authenticate");
    // PII-safe: keyed-HMAC hashes, never the raw subject.
    assert.equal(typeof identity.subjectHash, "string");
    assert.equal(typeof identity.issuerHash, "string");
    assert.equal(identity.provider, `plugin:${built.pluginId}`);
    assert.notEqual(identity.subjectHash, "alice");
    // No field anywhere equals the raw subject.
    assert.ok(!JSON.stringify(identity).includes("\"alice\""), "raw subject must not appear in identity");

    // plugin.load.accepted emitted with the resolved entrySha256 + signerKeyId.
    const accepted = audit.eventsOfType("plugin.load.accepted");
    assert.equal(accepted.length, 1, "exactly one load.accepted");
    assert.equal(accepted[0].entrySha256, built.entrySha256);
    assert.equal(accepted[0].signerKeyId, built.signerKeyId);
    assert.equal(accepted[0].pluginId, built.pluginId);
    assert.ok(accepted[0].capabilitiesGranted.includes("readsCredentials"));

    // The raw subject must not appear anywhere in the audit stream.
    const dump = JSON.stringify(audit.events);
    assert.ok(!dump.includes("alice"), "raw subject must never enter the audit log");
    assert.ok(!dump.includes("good-token-alice"), "raw credential must never enter the audit log");
  } finally {
    await provider.close();
  }
});

test("the worker receives ONLY the credential slice — never the body, sink, vault, or key", async () => {
  const built = buildSignedPlugin({ entrySource: ECHO_PLUGIN_SOURCE });
  const provider = await createSandboxedAuthProvider(sandboxOptions(built));
  try {
    // A request with a body + extra headers; only the bearer token should cross.
    const request = {
      headers: { authorization: "Bearer secret-credential-xyz", "x-trace": "should-not-cross" },
      body: { prompt: "SUPER SECRET BODY", apiKey: "sk-leak" },
      tokenVault: "should-not-cross",
      key: "should-not-cross"
    };
    // The echo plugin smuggles what it received back via claims; the HOST keyed-
    // hashes it, so we can't read raw — but we CAN prove the worker saw exactly
    // the credential by re-deriving the hash the host would produce from
    // "echo:<credential>" and "echo-workerData:null".
    const identity = await provider.authenticate(request);
    assert.ok(identity, "echo plugin returns an identity");

    const expectedSubjectHash = await referenceCrypto.hmac({
      data: "echo:secret-credential-xyz",
      domain: "haechi:identity:hash:v1"
    });
    // workerData is the empty object {} the host passed (NO secrets) — stringified
    // as "{}". This proves no key/sink/vault/body was placed in workerData.
    const expectedIssuerHash = await referenceCrypto.hmac({
      data: "echo-workerData:{}",
      domain: "haechi:identity:hash:v1"
    });
    assert.equal(identity.subjectHash, expectedSubjectHash,
      "the worker saw exactly the credential slice (and nothing from the body)");
    assert.equal(identity.issuerHash, expectedIssuerHash,
      "workerData carried no host secrets (it was the empty object)");
  } finally {
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// Fail-closed LOAD matrix — construction throws + plugin.load.refused{reason}
// ---------------------------------------------------------------------------

async function expectRefusedLoad(t, built, options, reason) {
  const audit = createRecordingAuditSink();
  await assert.rejects(
    createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit, ...options })),
    (err) => err instanceof Error
  );
  const refused = audit.eventsOfType("plugin.load.refused");
  assert.ok(refused.length >= 1, `${t}: expected a plugin.load.refused event`);
  assert.equal(refused[0].reason, reason, `${t}: expected reason ${reason}, got ${refused[0].reason}`);
}

test("unsigned manifest is refused (manifest-invalid)", async () => {
  const built = buildSignedPlugin({ unsigned: true });
  await expectRefusedLoad("unsigned", built, {}, "manifest-invalid");
});

test("wrong-signer is refused (unknown-signer)", async () => {
  const built = buildSignedPlugin({ wrongSigner: true });
  await expectRefusedLoad("wrong-signer", built, {}, "unknown-signer");
});

test("tampered entry (path unchanged) is refused (tampered-entry)", async () => {
  const built = buildSignedPlugin({ tamperEntry: true });
  await expectRefusedLoad("tampered", built, {}, "tampered-entry");
});

test("revoked signer is refused (revoked)", async () => {
  const built = buildSignedPlugin();
  await expectRefusedLoad("revoked", built, { revoked: { signerKeyIds: [built.signerKeyId] } }, "revoked");
});

test("pin mismatch is refused (pin-mismatch)", async () => {
  const built = buildSignedPlugin();
  await expectRefusedLoad("pin", built, { pin: { version: "9.9.9" } }, "pin-mismatch");
});

test("capability not allowlisted is refused (capability-not-allowlisted)", async () => {
  const built = buildSignedPlugin({ capabilities: { readsCredentials: true, networkEgress: true } });
  // Allow only readsCredentials, but the manifest also requests networkEgress.
  await expectRefusedLoad("capability", built, { allowCapabilities: ["readsCredentials"] }, "capability-not-allowlisted");
});

test("below version floor is refused (below-version-floor)", async () => {
  const built = buildSignedPlugin({ version: "1.0.0" });
  await expectRefusedLoad("floor", built, { versionFloor: { [built.pluginId]: "2.0.0" } }, "below-version-floor");
});

test("outside validity window is refused (expired-window)", async () => {
  const now = Date.now();
  const built = buildSignedPlugin({ notBefore: now - 10_000, notAfter: now - 5_000 });
  await expectRefusedLoad("window", built, {}, "expired-window");
});

test("a non-conformant (non-deterministic) plugin is refused (conformance-failed)", async () => {
  const built = buildSignedPlugin({ entrySource: NONDETERMINISTIC_PLUGIN_SOURCE });
  await expectRefusedLoad("conformance", built, {}, "conformance-failed");
});

// ---------------------------------------------------------------------------
// Runtime behavior matrix (timeout / deny / sanitizer / concurrency)
// ---------------------------------------------------------------------------

test("a hanging plugin times out -> null + worker terminated + worker.terminated{timeout}", async () => {
  const built = buildSignedPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit, timeoutMs: 300 }));
  try {
    const result = await provider.authenticate(bearer("hang"));
    assert.equal(result, null, "a timeout must deny with null");

    const terminated = audit.eventsOfType("plugin.worker.terminated");
    assert.ok(terminated.some((e) => e.cause === "timeout"), "expected worker.terminated{timeout}");
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "timeout"), "expected authenticate.deny{timeout}");

    // The worker respawns lazily (re-running the gate) — a subsequent good call works.
    const after = await provider.authenticate(bearer("good"));
    assert.ok(after, "the worker respawns after a timeout-terminate");
    // The respawn re-emits load.accepted (the full PR2 gate re-ran).
    const accepted = audit.eventsOfType("plugin.load.accepted");
    assert.ok(accepted.length >= 1);
  } finally {
    await provider.close();
  }
});

test("a plugin that denies/throws -> null + authenticate.deny", async () => {
  const built = buildSignedPlugin();
  const audit = createRecordingAuditSink();
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit }));
  try {
    // unknown token -> the plugin returns { deny: true }
    const denied = await provider.authenticate(bearer("unknown-token"));
    assert.equal(denied, null);
    // an internal throw inside the plugin -> harness converts to deny -> null
    const threw = await provider.authenticate(bearer("throw.boom"));
    assert.equal(threw, null);
    assert.ok(audit.eventsOfType("plugin.authenticate.deny").length >= 2);
  } finally {
    await provider.close();
  }
});

test("a hostile claims object with __proto__/extra keys is sanitized (no pollution, extras dropped, PII-safe)", async () => {
  const built = buildSignedPlugin({ entrySource: POLLUTING_PLUGIN_SOURCE });
  const provider = await createSandboxedAuthProvider(sandboxOptions(built));
  try {
    const identity = await provider.authenticate(bearer("anything"));
    assert.ok(identity, "polluting plugin still yields an identity from allowlisted keys");
    // No prototype pollution leaked into Object.prototype.
    assert.equal({}.polluted, undefined, "Object.prototype must not be polluted");
    assert.equal({}.evil, undefined, "Object.prototype must not be polluted via constructor");
    // Extra keys dropped: identity carries ONLY the PII-safe projection.
    assert.equal(identity.secretExfil, undefined, "extra claim keys must be dropped");
    assert.equal(identity.isAdmin, undefined, "extra claim keys must be dropped");
    // PII-safe.
    assert.equal(typeof identity.subjectHash, "string");
    assert.ok(!JSON.stringify(identity).includes("polluted-subject"), "raw subject must not leak");
  } finally {
    await provider.close();
  }
});

test("two concurrent authenticate calls with distinct cids never cross responses", async () => {
  const built = buildSignedPlugin();
  const provider = await createSandboxedAuthProvider(sandboxOptions(built));
  try {
    const [a, b] = await Promise.all([
      provider.authenticate(bearer("good-token-alpha")),
      provider.authenticate(bearer("good-token-beta"))
    ]);
    assert.ok(a && b, "both concurrent calls resolve to identities");
    // Distinct subjects -> distinct keyed hashes; a crossed response would make
    // them equal or swap them.
    const hashAlpha = await referenceCrypto.hmac({ data: "alpha", domain: "haechi:identity:hash:v1" });
    const hashBeta = await referenceCrypto.hmac({ data: "beta", domain: "haechi:identity:hash:v1" });
    assert.equal(a.subjectHash, hashAlpha, "call A got A's response, not B's");
    assert.equal(b.subjectHash, hashBeta, "call B got B's response, not A's");
  } finally {
    await provider.close();
  }
});

test("a timeout on one call cannot kill a sibling (single-occupancy serialization)", async () => {
  const built = buildSignedPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { timeoutMs: 300 }));
  try {
    // First call hangs (terminated by timeout); the second is a valid call that
    // runs after the worker respawns. Single-occupancy means the second never
    // shared the terminated worker.
    const hang = provider.authenticate(bearer("hang"));
    const ok = provider.authenticate(bearer("good"));
    const [hangResult, okResult] = await Promise.all([hang, ok]);
    assert.equal(hangResult, null, "the hanging call denies");
    assert.ok(okResult, "the sibling call survives and authenticates after respawn");
  } finally {
    await provider.close();
  }
});

test("maxPendingCalls bounds concurrency (excess -> deny with reason over-capacity)", async () => {
  const built = buildSignedPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  // maxPendingCalls=1: while one call is in flight (hanging), a second is denied.
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit, timeoutMs: 1500, maxPendingCalls: 1 }));
  try {
    const first = provider.authenticate(bearer("hang")); // occupies the single slot
    // Give the first a tick to enter the queue.
    await new Promise((r) => setTimeout(r, 30));
    const second = await provider.authenticate(bearer("good-token-x"));
    assert.equal(second, null, "excess over maxPendingCalls must deny");
    // FIX B: the emitted reason must be "over-capacity", not the generic "deny".
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "over-capacity"),
      `over-capacity path must emit reason "over-capacity" (got: ${JSON.stringify(denied.map((e) => e.reason))})`);
    await first; // let the first finish (times out)
  } finally {
    await provider.close();
  }
});

test("maxMessageBytes bounds the wire (oversized credential -> deny with reason oversized)", async () => {
  const built = buildSignedPlugin();
  const audit = createRecordingAuditSink();
  // 256 bytes is enough for the conformance vectors (uuid + ~80-char token) but
  // far below the 500-char credential below.
  const provider = await createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit, maxMessageBytes: 256 }));
  try {
    const huge = "good-token-" + "x".repeat(500);
    const result = await provider.authenticate(bearer(huge));
    assert.equal(result, null, "an oversized message must deny");
    // FIX B: the emitted reason must be "oversized", not the generic "deny".
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "oversized"),
      `oversized path must emit reason "oversized" (got: ${JSON.stringify(denied.map((e) => e.reason))})`);
  } finally {
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// FIX C: entrypoint confinement — absolute / ../-escaping paths refused
// ---------------------------------------------------------------------------

test("absolute entrypoint is refused (manifest-invalid) before any file read", async () => {
  const built = buildSignedPlugin();
  const audit = createRecordingAuditSink();
  // Overwrite the manifest on disk with one whose entrypoint is an absolute path.
  // The target (/etc/hosts) exists on every Unix system; on Windows the test
  // gracefully falls through because the load is still refused (manifest-invalid).
  const { readFileSync: rfs, writeFileSync: wfs } = await import("node:fs");
  const manifest = JSON.parse(rfs(built.manifestPath, "utf8"));
  manifest.haechiPlugin.entrypoint = "/etc/hosts";
  wfs(built.manifestPath, JSON.stringify(manifest, null, 2), "utf8");

  await assert.rejects(
    createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit })),
    (err) => err instanceof Error
  );
  const refused = audit.eventsOfType("plugin.load.refused");
  assert.ok(refused.length >= 1, "absolute entrypoint must emit plugin.load.refused");
  assert.equal(refused[0].reason, "manifest-invalid",
    `absolute entrypoint must be refused with reason manifest-invalid, got: ${refused[0].reason}`);
});

test("../-escaping entrypoint is refused (manifest-invalid) before any file read", async () => {
  const built = buildSignedPlugin();
  const audit = createRecordingAuditSink();
  const { readFileSync: rfs, writeFileSync: wfs } = await import("node:fs");
  const manifest = JSON.parse(rfs(built.manifestPath, "utf8"));
  manifest.haechiPlugin.entrypoint = "../../etc/passwd";
  wfs(built.manifestPath, JSON.stringify(manifest, null, 2), "utf8");

  await assert.rejects(
    createSandboxedAuthProvider(sandboxOptions(built, { auditSink: audit })),
    (err) => err instanceof Error
  );
  const refused = audit.eventsOfType("plugin.load.refused");
  assert.ok(refused.length >= 1, "../-escaping entrypoint must emit plugin.load.refused");
  assert.equal(refused[0].reason, "manifest-invalid",
    `../-escaping entrypoint must be refused with reason manifest-invalid, got: ${refused[0].reason}`);
});

// ---------------------------------------------------------------------------
// FORBIDDEN_KEYS / sanitizeAudit defense-in-depth for plugin events
// ---------------------------------------------------------------------------

test("a synthetic plugin event with raw claims is stripped by sanitizeAudit", () => {
  const event = {
    type: "plugin.authenticate.deny",
    pluginId: "x",
    claims: { subject: "RAW", issuer: "RAW" },
    credential: "Bearer secret",
    signature: "sig",
    entry: "source"
  };
  const sanitized = sanitizeAudit(event);
  assert.equal(sanitized.claims, undefined);
  assert.equal(sanitized.credential, undefined);
  assert.equal(sanitized.signature, undefined);
  assert.equal(sanitized.entry, undefined);
  assert.equal(sanitized.type, "plugin.authenticate.deny");
  assert.equal(sanitized.pluginId, "x");
});

// ---------------------------------------------------------------------------
// FIX A: attacker-controlled label value must NEVER reach the written JSONL
// ---------------------------------------------------------------------------

// A plugin variant that returns a label whose VALUE is a sentinel credential
// string. If the audit identity projection were missing, this value would enter
// the hash-chained JSONL log verbatim (because buildExternalIdentity passes
// labels through to the returned identity, and the pre-fix buildAuditEvent
// embedded context.identity directly).
const MALICIOUS_LABELS_PLUGIN_SOURCE = `
export default function authenticate(credential) {
  if (typeof credential !== 'string' || credential.length === 0) return { deny: true };
  if (credential.startsWith('throw.')) throw new Error('boom');
  if (credential.startsWith('valid.')) {
    const p = credential.split('.');
    return { subject: p[3] || 's', issuer: p[4] || 'i', type: 'user', scopes: [], labels: {} };
  }
  if (credential.startsWith('expired.') || credential.startsWith('notyet.') || credential.startsWith('~malformed~')) {
    return { deny: true };
  }
  // The malicious path: inject a sentinel credential string as a label value.
  // If buildAuditEvent persists labels, this would appear verbatim in audit JSONL.
  return {
    subject: 'test-subject',
    issuer: 'test-issuer',
    type: 'user',
    scopes: ['read', 'SENTINEL_SCOPE_CREDENTIAL_VALUE'],
    labels: { team: 'SENTINEL_LABEL_CREDENTIAL_VALUE' }
  };
}
`;

test("attacker-controlled label/scope values in plugin claims never appear in the written audit JSONL", async () => {
  const SENTINEL = "SENTINEL_LABEL_CREDENTIAL_VALUE";
  const SENTINEL_SCOPE = "SENTINEL_SCOPE_CREDENTIAL_VALUE";

  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-smuggle-"));
  const auditPath = join(dir, "audit.jsonl");
  // Use the REAL hash-chained JSONL sink (not the in-memory recording sink) so
  // we can assert against the WRITTEN bytes — the actual persistence path.
  const auditSink = createJsonlAuditSink({ path: auditPath });

  const built = buildSignedPlugin({ entrySource: MALICIOUS_LABELS_PLUGIN_SOURCE });
  const provider = await createSandboxedAuthProvider(
    sandboxOptions(built, { auditSink })
  );

  try {
    // Authenticate — this causes buildAuditEvent to run inside protectJson,
    // but more directly: the sandbox itself emits plugin.load.accepted with the
    // live plugin info. The critical path is: plugin returns labels/scopes →
    // host calls buildExternalIdentity (labels/scopes pass through to
    // context.identity) → protectJson calls buildAuditEvent → if un-projected,
    // identity.labels.team = SENTINEL enters the JSONL file.
    //
    // We drive a protectJson call with this identity so buildAuditEvent runs.
    const identity = await provider.authenticate(bearer("good-token-malicious"));
    assert.ok(identity, "the plugin must authenticate (we need an identity to pass to protectJson)");

    // Verify that scopes/labels on the returned identity do NOT appear in
    // the identity object returned from authenticate() itself — note that
    // buildExternalIdentity currently strips scopes/labels from the returned
    // identity projection. The real risk is at the audit layer: if a future
    // code path reattaches them. So we also drive a protectJson call to force
    // buildAuditEvent to run with this identity in context.

    const { createHaechi } = await import("../packages/core/index.mjs");
    const { createDefaultFilterEngine } = await import("../packages/filter/index.mjs");
    const { createPolicyEngine } = await import("../packages/policy/index.mjs");

    const filterEngine = createDefaultFilterEngine();
    const policyEngine = createPolicyEngine({ defaultAction: "redact" });
    const cryptoProvider = { encrypt: async () => ({}), decrypt: async () => "" };
    const haechi = createHaechi({ filterEngine, policyEngine, cryptoProvider, auditSink, mode: "dry-run" });

    // Build an identity that has sentinel scopes/labels (simulating what
    // buildExternalIdentity would return if it attached them to the identity
    // object passed through to context).
    const identityWithSentinel = {
      id: "test-id",
      type: "plugin",
      subjectHash: "hash-of-subject",
      issuerHash: "hash-of-issuer",
      provider: `plugin:${built.pluginId}`,
      scopes: [SENTINEL_SCOPE],
      labels: { team: SENTINEL }
    };

    await haechi.protectJson(
      { msg: "hello" },
      { protocol: "test", operation: "protect", identity: identityWithSentinel }
    );

    // Read back the WRITTEN JSONL bytes and assert neither sentinel appears.
    const written = await readFile(auditPath, "utf8");
    assert.doesNotMatch(
      written,
      new RegExp(SENTINEL),
      `SECURITY: sentinel label value "${SENTINEL}" must NEVER appear in the written audit JSONL ` +
      "(the frozen audit-identity contract is exactly {id,type,subjectHash,issuerHash,provider}; " +
      "scopes/labels are stripped before persistence)"
    );
    assert.doesNotMatch(
      written,
      new RegExp(SENTINEL_SCOPE),
      `SECURITY: sentinel scope value "${SENTINEL_SCOPE}" must NEVER appear in the written audit JSONL`
    );
  } finally {
    await provider.close();
  }
});
