import test from "node:test";
import assert from "node:assert/strict";
import {
  createProcessIsolatedAuthProvider
} from "../packages/plugin/index.mjs";
import {
  buildSignedPlugin,
  sandboxOptions,
  createRecordingAuditSink,
  createRecordingCrypto,
  referenceCrypto,
  bearer,
  PROCESS_PROBE_PLUGIN_SOURCE,
  POLLUTING_PLUGIN_SOURCE,
  HANGING_PLUGIN_SOURCE,
  NONDETERMINISTIC_PLUGIN_SOURCE
} from "./helpers/sandbox-fixtures.mjs";

// Build a PROCESS-isolated signed plugin (the only difference from the worker
// fixtures is the manifest runtime string).
function buildProcessPlugin(overrides = {}) {
  return buildSignedPlugin({ runtime: "process-isolated", ...overrides });
}

// ---------------------------------------------------------------------------
// Happy path: load (data: URL, no fs grant), conformance in the child, host
// keyed-HMAC identity
// ---------------------------------------------------------------------------

test("process-isolated signed plugin loads from a data: URL (no fs grant), passes conformance, builds a PII-safe identity", async () => {
  const built = buildProcessPlugin();
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit }));
  try {
    const identity = await provider.authenticate(bearer("good-token-alice"));
    assert.ok(identity, "a valid bearer must authenticate");
    assert.equal(typeof identity.subjectHash, "string");
    assert.equal(typeof identity.issuerHash, "string");
    assert.equal(identity.provider, `plugin:${built.pluginId}`);
    assert.ok(!JSON.stringify(identity).includes("\"alice\""), "raw subject must not appear in identity");

    const accepted = audit.eventsOfType("plugin.load.accepted");
    assert.equal(accepted.length, 1, "exactly one load.accepted");
    assert.equal(accepted[0].entrySha256, built.entrySha256);
    assert.equal(accepted[0].signerKeyId, built.signerKeyId);
    assert.ok(accepted[0].capabilitiesGranted.includes("readsCredentials"));

    const dump = JSON.stringify(audit.events);
    assert.ok(!dump.includes("alice"), "raw subject must never enter the audit log");
    assert.ok(!dump.includes("good-token-alice"), "raw credential must never enter the audit log");
  } finally {
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// §7.1 capability red-team: fs / child_process / worker all kernel-DENIED, and
// the plugin has NO fs grant (it loaded from a data: URL).
// ---------------------------------------------------------------------------

async function runProbe(provider, rec) {
  const identity = await provider.authenticate(bearer("probe"));
  assert.ok(identity, "the probe plugin authenticates (every escape denied still returns claims)");
  const entry = rec.hashed.find(
    (h) => typeof h.data === "string" && h.data.startsWith("{") && h.data.includes("\"fs\"")
  );
  assert.ok(entry, "the host hashed the probe subject (recording crypto captured it)");
  return JSON.parse(entry.data);
}

test("a process-isolated plugin is DENIED fs read, child_process spawn, and worker creation (--permission, zero grants)", async () => {
  const built = buildProcessPlugin({ entrySource: PROCESS_PROBE_PLUGIN_SOURCE });
  const rec = createRecordingCrypto();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { cryptoProvider: rec }));
  try {
    const probe = await runProbe(provider, rec);
    assert.equal(probe.fs, "ERR_ACCESS_DENIED", `fs.readFileSync('/etc/hosts') must be kernel-denied (got ${probe.fs})`);
    assert.equal(probe.spawn, "ERR_ACCESS_DENIED", `child_process must be kernel-denied (got ${probe.spawn})`);
    assert.equal(probe.worker, "ERR_ACCESS_DENIED", `worker_threads must be kernel-denied (got ${probe.worker})`);
  } finally {
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// §7.1 net red-team: net.connect / fetch / dns AND the process.binding('tcp_wrap')
// bypass all kernel-DENIED (no --allow-net) → no credential exfil over the network.
// ---------------------------------------------------------------------------

test("a process-isolated plugin is DENIED net.connect, fetch, dns, and the tcp_wrap bypass (no --allow-net)", async () => {
  const built = buildProcessPlugin({ entrySource: PROCESS_PROBE_PLUGIN_SOURCE });
  const rec = createRecordingCrypto();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { cryptoProvider: rec }));
  try {
    const probe = await runProbe(provider, rec);
    assert.equal(probe.net, "ERR_ACCESS_DENIED", `net.connect must be kernel-denied (got ${probe.net})`);
    assert.equal(probe.dns, "ERR_ACCESS_DENIED", `dns must be kernel-denied (got ${probe.dns})`);
    // The empirically-proven harness bypass: process.binding('tcp_wrap') opens a
    // live socket on a normal Node. Under --permission with no --allow-net it is
    // ITSELF denied — which is why a "delete node:net" harness is not containment.
    assert.equal(probe.tcpwrap, "ERR_ACCESS_DENIED", `process.binding('tcp_wrap') must be kernel-denied (got ${probe.tcpwrap})`);
    assert.notEqual(probe.fetch, "ALLOWED", `fetch must be denied (got ${probe.fetch})`);
  } finally {
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// §7.1 stdio/fd red-team: a plugin writing the credential to stdout/stderr/console
// reaches NO host-visible sink (stdio: ['ignore','ignore','ignore','ipc']).
// ---------------------------------------------------------------------------

test("a plugin writing the credential to stdout/stderr/console reaches no host sink (stdio ignored)", async () => {
  const built = buildProcessPlugin({ entrySource: PROCESS_PROBE_PLUGIN_SOURCE });
  const rec = createRecordingCrypto();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { cryptoProvider: rec }));
  const captured = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  try {
    process.stdout.write = (chunk, ...rest) => { captured.push(String(chunk)); return origOut(chunk, ...rest); };
    process.stderr.write = (chunk, ...rest) => { captured.push(String(chunk)); return origErr(chunk, ...rest); };
    const identity = await provider.authenticate(bearer("CREDLEAKSENTINEL"));
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    assert.ok(identity, "the probe plugin still authenticates");
    const dump = captured.join("");
    assert.ok(!dump.includes("CREDLEAKSENTINEL"), "the credential must never surface on the host stdout/stderr");
    assert.ok(!dump.includes("STDERR_LEAK") && !dump.includes("STDOUT_LEAK") && !dump.includes("CONSOLE_LEAK"),
      "no child stdio write reaches the host (the child's stdout/stderr are ignored)");
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    await provider.close();
  }
});

// ---------------------------------------------------------------------------
// Fail-closed LOAD matrix — construction rejects + plugin.load.refused{reason}
// ---------------------------------------------------------------------------

async function expectRefusedLoad(label, built, options, reason) {
  const audit = createRecordingAuditSink();
  await assert.rejects(
    createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit, ...options })),
    (err) => err instanceof Error
  );
  const refused = audit.eventsOfType("plugin.load.refused");
  assert.ok(refused.length >= 1, `${label}: expected a plugin.load.refused event`);
  assert.equal(refused[0].reason, reason, `${label}: expected reason ${reason}, got ${refused[0].reason}`);
}

test("a worker-isolated manifest fed to the process factory is refused (manifest-invalid)", async () => {
  // expectedRuntime mismatch: the process sandbox requires runtime process-isolated.
  const built = buildSignedPlugin({ runtime: "worker-isolated" });
  await expectRefusedLoad("runtime-mismatch", built, {}, "manifest-invalid");
});

test("unsigned process manifest is refused (manifest-invalid)", async () => {
  const built = buildProcessPlugin({ unsigned: true });
  await expectRefusedLoad("unsigned", built, {}, "manifest-invalid");
});

test("wrong-signer process plugin is refused (unknown-signer)", async () => {
  const built = buildProcessPlugin({ wrongSigner: true });
  await expectRefusedLoad("wrong-signer", built, {}, "unknown-signer");
});

test("tampered entry (path unchanged) is refused (tampered-entry)", async () => {
  const built = buildProcessPlugin({ tamperEntry: true });
  await expectRefusedLoad("tampered", built, {}, "tampered-entry");
});

test("a non-deterministic process plugin fails conformance (conformance-failed)", async () => {
  const built = buildProcessPlugin({ entrySource: NONDETERMINISTIC_PLUGIN_SOURCE });
  await expectRefusedLoad("conformance", built, {}, "conformance-failed");
});

// ---------------------------------------------------------------------------
// Runtime behavior matrix (timeout / deny / sanitizer / single-occupancy)
// ---------------------------------------------------------------------------

test("a hanging process plugin times out -> null + child terminated + respawn", async () => {
  const built = buildProcessPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit, timeoutMs: 400 }));
  try {
    const result = await provider.authenticate(bearer("hang"));
    assert.equal(result, null, "a timeout must deny with null");
    const terminated = audit.eventsOfType("plugin.worker.terminated");
    assert.ok(terminated.some((e) => e.cause === "timeout"), "expected a terminated{timeout} lifecycle event");
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "timeout"), "expected authenticate.deny{timeout}");
    // Respawns lazily (re-running the full gate).
    const after = await provider.authenticate(bearer("good"));
    assert.ok(after, "the child respawns after a timeout-terminate");
  } finally {
    await provider.close();
  }
});

test("a process plugin that denies/throws -> null + authenticate.deny", async () => {
  const built = buildProcessPlugin();
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit }));
  try {
    const denied = await provider.authenticate(bearer("unknown-token"));
    assert.equal(denied, null);
    const threw = await provider.authenticate(bearer("throw.boom"));
    assert.equal(threw, null);
    assert.ok(audit.eventsOfType("plugin.authenticate.deny").length >= 2);
  } finally {
    await provider.close();
  }
});

test("a hostile claims object (__proto__/extra keys) is sanitized over the process IPC", async () => {
  const built = buildProcessPlugin({ entrySource: POLLUTING_PLUGIN_SOURCE });
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built));
  try {
    const identity = await provider.authenticate(bearer("anything"));
    assert.ok(identity, "polluting plugin still yields an identity from allowlisted keys");
    assert.equal({}.polluted, undefined, "Object.prototype must not be polluted");
    assert.equal({}.evil, undefined, "Object.prototype must not be polluted via constructor");
    assert.equal(identity.secretExfil, undefined, "extra claim keys must be dropped");
    assert.equal(identity.isAdmin, undefined, "extra claim keys must be dropped");
    assert.ok(!JSON.stringify(identity).includes("polluted-subject"), "raw subject must not leak");
  } finally {
    await provider.close();
  }
});

test("two concurrent authenticate calls with distinct cids never cross responses (single-occupancy)", async () => {
  const built = buildProcessPlugin();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built));
  try {
    const [a, b] = await Promise.all([
      provider.authenticate(bearer("good-token-alpha")),
      provider.authenticate(bearer("good-token-beta"))
    ]);
    assert.ok(a && b, "both concurrent calls resolve to identities");
    const hashAlpha = await referenceCrypto.hmac({ data: "alpha", domain: "haechi:identity:hash:v1" });
    const hashBeta = await referenceCrypto.hmac({ data: "beta", domain: "haechi:identity:hash:v1" });
    assert.equal(a.subjectHash, hashAlpha, "call A got A's response, not B's");
    assert.equal(b.subjectHash, hashBeta, "call B got B's response, not A's");
  } finally {
    await provider.close();
  }
});

test("kill-switch: closing the provider terminates the child and subsequent calls fail closed", async () => {
  const built = buildProcessPlugin();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built));
  const ok = await provider.authenticate(bearer("good-token-x"));
  assert.ok(ok, "authenticates before close");
  await provider.close();
  const after = await provider.authenticate(bearer("good-token-y"));
  assert.equal(after, null, "after close, authenticate fails closed (null)");
});
