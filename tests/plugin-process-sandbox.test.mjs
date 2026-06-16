import test from "node:test";
import assert from "node:assert/strict";
import {
  createProcessIsolatedAuthProvider
} from "../packages/plugin/index.mjs";
import { netEnforcementSupported } from "../packages/plugin/process-sandbox.mjs";
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
  CRASHING_PLUGIN_SOURCE,
  NONDETERMINISTIC_PLUGIN_SOURCE,
  KEYMATERIAL_PLUGIN_SOURCE,
  OVERSIZED_REPLY_PLUGIN_SOURCE
} from "./helpers/sandbox-fixtures.mjs";

const okText = (body) => async () => ({ ok: true, body: null, text: async () => body });
const publicLookup = async () => [{ address: "93.184.216.34" }];

// The process-isolated runtime fails closed (refuses to construct) on a Node that
// cannot enforce --allow-net (e.g. Node 22 LTS) — capability containment is not
// honest without it. The behavioral tests below therefore only run on a Node that
// enforces it; the fail-closed contract itself is tested on ALL Nodes via the
// `detectNetSupport` seam. (Node 26 enforces --allow-net; Node 22 does not.)
const SUPPORTED = netEnforcementSupported();
const skip = SUPPORTED ? false : "requires a Node that enforces the --allow-net permission (e.g. Node >=24)";
const itNet = (name, fn) => test(name, { skip }, fn);

function buildProcessPlugin(overrides = {}) {
  return buildSignedPlugin({ runtime: "process-isolated", ...overrides });
}

// ---------------------------------------------------------------------------
// Fail-closed network contract — runs on EVERY Node (forces the seam)
// ---------------------------------------------------------------------------

test("require-permission fails closed on a Node that cannot enforce --allow-net", async () => {
  const built = buildProcessPlugin();
  await assert.rejects(
    createProcessIsolatedAuthProvider(sandboxOptions(built, { detectNetSupport: () => false })),
    /requires a Node that enforces|refusing to construct/i,
    "construction must throw (not silently run uncontained) when --allow-net is unsupported"
  );
});

test("an unsupported netEnforcement value is rejected", async () => {
  const built = buildProcessPlugin();
  await assert.rejects(
    createProcessIsolatedAuthProvider(sandboxOptions(built, { netEnforcement: "allow-harness", detectNetSupport: () => true })),
    /unsupported netEnforcement/i,
    "only require-permission is supported in 1.1"
  );
});

// ---------------------------------------------------------------------------
// Happy path: load (data: URL, no fs grant), conformance in the child, host
// keyed-HMAC identity
// ---------------------------------------------------------------------------

itNet("process-isolated signed plugin loads from a data: URL (no fs grant), passes conformance, builds a PII-safe identity", async () => {
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

itNet("a process-isolated plugin is DENIED fs read, child_process spawn, and worker creation (--permission, zero grants)", async () => {
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

itNet("a process-isolated plugin is DENIED net.connect, fetch, dns, and the tcp_wrap bypass (no --allow-net)", async () => {
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

itNet("a plugin writing the credential to stdout/stderr/console reaches no host sink (stdio ignored)", async () => {
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
// (the shared load gate; runs where the runtime can construct)
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

itNet("a worker-isolated manifest fed to the process factory is refused (manifest-invalid)", async () => {
  const built = buildSignedPlugin({ runtime: "worker-isolated" });
  await expectRefusedLoad("runtime-mismatch", built, {}, "manifest-invalid");
});

itNet("unsigned process manifest is refused (manifest-invalid)", async () => {
  const built = buildProcessPlugin({ unsigned: true });
  await expectRefusedLoad("unsigned", built, {}, "manifest-invalid");
});

itNet("wrong-signer process plugin is refused (unknown-signer)", async () => {
  const built = buildProcessPlugin({ wrongSigner: true });
  await expectRefusedLoad("wrong-signer", built, {}, "unknown-signer");
});

itNet("tampered entry (path unchanged) is refused (tampered-entry)", async () => {
  const built = buildProcessPlugin({ tamperEntry: true });
  await expectRefusedLoad("tampered", built, {}, "tampered-entry");
});

itNet("a non-deterministic process plugin fails conformance (conformance-failed)", async () => {
  const built = buildProcessPlugin({ entrySource: NONDETERMINISTIC_PLUGIN_SOURCE });
  await expectRefusedLoad("conformance", built, {}, "conformance-failed");
});

// ---------------------------------------------------------------------------
// Runtime behavior matrix (timeout / deny / sanitizer / single-occupancy)
// ---------------------------------------------------------------------------

itNet("a hanging process plugin times out -> null + child terminated + respawn", async () => {
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
    const after = await provider.authenticate(bearer("good"));
    assert.ok(after, "the child respawns after a timeout-terminate");
  } finally {
    await provider.close();
  }
});

itNet("a process plugin that denies/throws -> null + authenticate.deny", async () => {
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

itNet("a hostile claims object (__proto__/extra keys) is sanitized over the process IPC", async () => {
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

itNet("two concurrent authenticate calls with distinct cids never cross responses (single-occupancy)", async () => {
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

// ---------------------------------------------------------------------------
// §7.2 host-mediated key material — the host fetches an operator-declared URL via
// the core SSRF guard and injects it; the plugin NEVER names a URL.
// ---------------------------------------------------------------------------

itNet("host-mediated key material is fetched via the core guard and injected into the plugin", async () => {
  const built = buildProcessPlugin({ entrySource: KEYMATERIAL_PLUGIN_SOURCE });
  const rec = createRecordingCrypto();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, {
    cryptoProvider: rec,
    keyMaterial: { url: "https://keys.example.com/jwks", fetchImpl: okText("JWKS_DOC_CONTENT"), lookupImpl: publicLookup }
  }));
  try {
    const identity = await provider.authenticate(bearer("needs-keys"));
    assert.ok(identity, "the plugin authenticates with injected key material");
    const entry = rec.hashed.find((h) => typeof h.data === "string" && h.data.startsWith("km:"));
    assert.ok(entry, "the host hashed the subject carrying the injected key material");
    assert.equal(entry.data, "km:JWKS_DOC_CONTENT", "the operator-declared key doc was fetched + injected (the plugin never named a URL)");
  } finally {
    await provider.close();
  }
});

itNet("a host key fetch to a private/metadata address fails closed (the plugin never names the URL)", async () => {
  const built = buildProcessPlugin({ entrySource: KEYMATERIAL_PLUGIN_SOURCE });
  let fetched = false;
  // The operator-declared URL resolves to the cloud-metadata IP → the core guard
  // refuses every fetch → no roundtrip can succeed → construction fails closed
  // (conformance cannot pass). The plugin never gets a chance to exfiltrate.
  await assert.rejects(
    createProcessIsolatedAuthProvider(sandboxOptions(built, {
      keyMaterial: {
        url: "https://keys.example.com/jwks",
        lookupImpl: async () => [{ address: "169.254.169.254" }],
        fetchImpl: async () => { fetched = true; return { ok: true, body: null, text: async () => "x" }; }
      }
    })),
    (err) => err instanceof Error
  );
  assert.equal(fetched, false, "the SSRF guard must refuse before any fetch to a blocked address");
});

// ---------------------------------------------------------------------------
// Lifecycle audit fields (host-computed/enum-only) + spawn-storm circuit breaker
// ---------------------------------------------------------------------------

itNet("load.accepted carries host-computed isolation/netEnforcement/grants fields", async () => {
  const built = buildProcessPlugin();
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit }));
  try {
    const accepted = audit.eventsOfType("plugin.load.accepted")[0];
    assert.ok(accepted, "a load.accepted event was emitted");
    assert.equal(accepted.isolation, "process");
    assert.equal(accepted.netEnforcement, "require-permission");
    assert.deepEqual(accepted.grants, [], "the child is spawned with zero OS permission grants");
  } finally {
    await provider.close();
  }
});

itNet("the spawn-storm circuit breaker trips after repeated kills and then fails closed", async () => {
  const built = buildProcessPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, {
    auditSink: audit,
    timeoutMs: 150,
    respawnMaxKills: 2,
    respawnWindowMs: 5000,
    respawnBackoffMs: 5
  }));
  try {
    await provider.authenticate(bearer("hang")); // kill 1
    await provider.authenticate(bearer("hang")); // kill 2 → trip
    const stormy = audit.eventsOfType("plugin.worker.terminated").some((e) => e.cause === "respawn-storm");
    assert.ok(stormy, "expected a respawn-storm termination event after repeated kills");
    // A tripped breaker denies permanently — even a good credential fails closed.
    const after = await provider.authenticate(bearer("good"));
    assert.equal(after, null, "a tripped breaker fails closed");
  } finally {
    await provider.close();
  }
});

itNet("kill-switch: closing the provider terminates the child and subsequent calls fail closed", async () => {
  const built = buildProcessPlugin();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built));
  const ok = await provider.authenticate(bearer("good-token-x"));
  assert.ok(ok, "authenticates before close");
  await provider.close();
  const after = await provider.authenticate(bearer("good-token-y"));
  assert.equal(after, null, "after close, authenticate fails closed (null)");
});

// ---------------------------------------------------------------------------
// DoS-control parity with the worker sandbox (tests/plugin-sandbox.test.mjs):
// (a) oversized wire, (b) over-capacity queue, (c) timeout (covered above),
// (d) child crash/exit fails the in-flight call closed + the sandbox recovers.
// Same option names + deny reasons as the worker, so the two boundaries match.
// ---------------------------------------------------------------------------

itNet("maxMessageBytes bounds the wire (oversized credential -> deny with reason oversized)", async () => {
  const built = buildProcessPlugin();
  const audit = createRecordingAuditSink();
  // 256 bytes is enough for the conformance vectors (uuid + ~80-char token) but
  // far below the 500-char credential below.
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit, maxMessageBytes: 256 }));
  try {
    const huge = "good-token-" + "x".repeat(500);
    const result = await provider.authenticate(bearer(huge));
    assert.equal(result, null, "an oversized message must deny");
    // The emitted reason must be "oversized", not the generic "deny".
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "oversized"),
      `oversized path must emit reason "oversized" (got: ${JSON.stringify(denied.map((e) => e.reason))})`);
  } finally {
    await provider.close();
  }
});

itNet("maxMessageBytes bounds the INBOUND reply (oversized plugin reply -> deny with reason oversized, never parsed/hung)", async () => {
  // CR2-003: the child has only the --max-old-space-size cap (no implicit OOM like
  // the worker's resourceLimits), so it can build a ~2 MB reply and process.send it.
  // The host must DROP the reply as an oversized deny BEFORE JSON.parse (bounding the
  // host event loop), not parse it, not hang, not throw. maxMessageBytes:4096 is
  // enough for the conformance vectors but far under the multi-MB reply.
  const built = buildProcessPlugin({ entrySource: OVERSIZED_REPLY_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit, maxMessageBytes: 4096 }));
  try {
    const result = await provider.authenticate(bearer("oversized-reply"));
    assert.equal(result, null, "an oversized plugin reply must deny (null), not throw or hang");
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "oversized"),
      `oversized reply path must emit reason "oversized" (got: ${JSON.stringify(denied.map((e) => e.reason))})`);
    // The sandbox stays usable: a subsequent valid call still authenticates.
    const ok = await provider.authenticate(bearer("valid.n.r.alice.acme"));
    assert.ok(ok, "the child survives an oversized reply and a later valid call authenticates");
  } finally {
    await provider.close();
  }
});

itNet("maxPendingCalls bounds concurrency (excess -> deny with reason over-capacity)", async () => {
  const built = buildProcessPlugin({ entrySource: HANGING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  // maxPendingCalls=1: while one call is in flight (hanging), a second is denied.
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit, timeoutMs: 1500, maxPendingCalls: 1 }));
  try {
    const first = provider.authenticate(bearer("hang")); // occupies the single slot
    // Give the first a tick to enter the queue.
    await new Promise((r) => setTimeout(r, 30));
    const second = await provider.authenticate(bearer("good-token-x"));
    assert.equal(second, null, "excess over maxPendingCalls must deny");
    // The over-capacity path must emit reason "over-capacity", not the generic "deny".
    const denied = audit.eventsOfType("plugin.authenticate.deny");
    assert.ok(denied.some((e) => e.reason === "over-capacity"),
      `over-capacity path must emit reason "over-capacity" (got: ${JSON.stringify(denied.map((e) => e.reason))})`);
    await first; // let the first finish (times out)
  } finally {
    await provider.close();
  }
});

itNet("a child crash mid-auth fails the in-flight call closed + child terminated{crash} + respawn", async () => {
  const built = buildProcessPlugin({ entrySource: CRASHING_PLUGIN_SOURCE });
  const audit = createRecordingAuditSink();
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built, { auditSink: audit }));
  try {
    // The plugin calls process.exit(1) on "crash": the child dies mid-round-trip,
    // the exit handler runs terminateChild("crash"), and the pending call settles
    // null -> authenticate fails closed.
    const result = await provider.authenticate(bearer("crash"));
    assert.equal(result, null, "a child crash must deny with null");
    const terminated = audit.eventsOfType("plugin.worker.terminated");
    assert.ok(terminated.some((e) => e.cause === "crash"),
      `expected a terminated{crash} lifecycle event (got: ${JSON.stringify(terminated.map((e) => e.cause))})`);
    // The sandbox stays consistent: the child respawns lazily (re-running the gate)
    // and a subsequent good call works.
    const after = await provider.authenticate(bearer("good"));
    assert.ok(after, "the child respawns after a crash-terminate");
  } finally {
    await provider.close();
  }
});

itNet("a child crash on one call cannot kill a sibling (single-occupancy serialization)", async () => {
  const built = buildProcessPlugin({ entrySource: CRASHING_PLUGIN_SOURCE });
  const provider = await createProcessIsolatedAuthProvider(sandboxOptions(built));
  try {
    // First call crashes the child; the second is a valid call that runs after the
    // child respawns. Single-occupancy means the second never shared the dead child.
    const crashed = provider.authenticate(bearer("crash"));
    const ok = provider.authenticate(bearer("good"));
    const [crashResult, okResult] = await Promise.all([crashed, ok]);
    assert.equal(crashResult, null, "the crashing call denies");
    assert.ok(okResult, "the sibling call survives and authenticates after respawn");
  } finally {
    await provider.close();
  }
});
