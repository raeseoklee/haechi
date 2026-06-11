// The worker-isolated authProvider sandbox (Haechi 1.0 §2.3/§2.4/§7.4).
//
// HONEST MODEL (read packages/../docs/current/release-1.0-implementation-scope.md
// §1): node:worker_threads is NOT a capability sandbox. A worker shares the
// process and a malicious *signed* plugin can still use fs/net/process.env — that
// residual is accepted and gated ONLY by the PR2 signing/trust gate, never by the
// worker. What the worker DOES give us, and all this module claims:
//   - V8-heap memory isolation (the plugin cannot read the host's crypto key,
//     token vault, or audit sink — only a typed JSON-string message crosses);
//   - crash/hang containment via resourceLimits + a per-call timeout that
//     terminates the worker (a hang fails closed → deny);
//   - data minimization (the worker receives ONLY the credential slice, never the
//     request body / key / sink; the HOST builds the keyed-HMAC identity);
//   - a narrow, audited, correlation-id'd contract.
//
// Zero runtime dependency: node:worker_threads + node:crypto + node:fs only, plus
// in-repo haechi/plugin (PR2 verify) and haechi/auth (identity + conformance).

import { Worker } from "node:worker_threads";
import { randomUUID } from "node:crypto";
import { assertAuthProviderConformance, buildExternalIdentity } from "../auth/index.mjs";
import {
  bearerCredentialFromRequest,
  loadAndVerifyPlugin,
  makeFireAndForgetAudit,
  sanitizeClaims
} from "./sandbox-common.mjs";

// The wire harness the host wraps around the worker so a generic codeString plugin
// only has to .on("message")/.postMessage JSON strings. Each plugin entry exports
// (default or named) `authenticate(credential) -> claims | { deny: true } | null`.
// We inline the harness as a string (NOT a path import) because the worker runs
// from the in-memory verified bytes — it has no module graph back to this repo,
// and a shipped packages/ file must never import a tests/ or scripts/ helper.
function workerHarness(entrySource) {
  return [
    "const { parentPort } = require('worker_threads');",
    "let __plugin = null;",
    "async function __load() {",
    "  if (__plugin) return __plugin;",
    "  const mod = await import('data:text/javascript;base64,' + " +
      JSON.stringify(Buffer.from(entrySource, "utf8").toString("base64")) + ");",
    "  __plugin = (typeof mod.default === 'function') ? mod.default",
    "    : (typeof mod.authenticate === 'function') ? mod.authenticate",
    "    : (mod.default && typeof mod.default.authenticate === 'function') ? mod.default.authenticate",
    "    : null;",
    "  if (typeof __plugin !== 'function') throw new Error('plugin entry must export an authenticate function');",
    "  return __plugin;",
    "}",
    "parentPort.on('message', async (raw) => {",
    "  let cid = null;",
    "  try {",
    "    const msg = JSON.parse(raw);",
    "    cid = msg.cid;",
    "    const authenticate = await __load();",
    "    const out = await authenticate(msg.credential);",
    "    if (!out || out.deny === true || typeof out !== 'object') {",
    "      parentPort.postMessage(JSON.stringify({ cid, deny: true }));",
    "      return;",
    "    }",
    "    parentPort.postMessage(JSON.stringify({ cid, claims: out }));",
    "  } catch (err) {",
    // A plugin throw NEVER propagates: it surfaces to the host as a deny.
    "    parentPort.postMessage(JSON.stringify({ cid, deny: true }));",
    "  }",
    "});"
  ].join("\n");
}

function createSandboxedAuthProviderHandle({
  manifestPath,
  trustAnchors,
  allowCapabilities = [],
  pin = null,
  revoked = {},
  versionFloor = {},
  cryptoProvider,
  auditSink,
  timeoutMs,
  maxPendingCalls = 8,
  maxMessageBytes = 16384,
  resourceLimits,
  coreVersion = null,
  now = Date.now,
  allowedLabelKeys
} = {}) {
  if (!manifestPath || typeof manifestPath !== "string") {
    throw new Error("createSandboxedAuthProvider requires a manifestPath string");
  }
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("createSandboxedAuthProvider requires a cryptoProvider with hmac()");
  }
  if (!auditSink || typeof auditSink.record !== "function") {
    throw new Error("createSandboxedAuthProvider requires an auditSink with record()");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("createSandboxedAuthProvider requires a positive integer timeoutMs");
  }
  if (!Number.isInteger(maxPendingCalls) || maxPendingCalls < 1) {
    throw new Error("maxPendingCalls must be a positive integer");
  }
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes < 1) {
    throw new Error("maxMessageBytes must be a positive integer");
  }
  const nowFn = typeof now === "function" ? now : () => now;

  // Fire-and-forget audit; lifecycle audit must never make the auth path throw.
  const audit = makeFireAndForgetAudit(auditSink);

  // Read+validate the manifest + run the FULL PR2 gate. The trust boundary is
  // shared with the process-isolated runtime (packages/plugin/sandbox-common.mjs)
  // so the two sandboxes cannot diverge. Re-run on every (re)spawn — the gate is
  // not a one-time check.
  function loadAndVerify() {
    return loadAndVerifyPlugin({
      manifestPath,
      expectedRuntime: "worker-isolated",
      trustAnchors,
      allowCapabilities,
      pin,
      revoked,
      versionFloor,
      coreVersion,
      now: nowFn(),
      audit
    });
  }

  // ---- worker lifecycle ----------------------------------------------------

  let worker = null;
  let pluginId = null;
  let closed = false;
  // cid -> settle(reply). Drops late/duplicate/unmatched replies by cid. Only one
  // entry is ever live at a time (single-occupancy via the serialization chain).
  const pending = new Map();
  let respawning = null; // single-flight respawn guard
  // Serialization chain: worker round-trips run ONE AT A TIME (single-occupancy),
  // so a per-call timeout-terminate can never kill a sibling. queueDepth bounds
  // how many calls may be waiting+running before the worker; excess → deny.
  let chain = Promise.resolve();
  let queueDepth = 0;

  function spawnFromVerified({ entrySource, pluginId: pid }) {
    const code = workerHarness(entrySource);
    const w = new Worker(code, {
      eval: true,
      resourceLimits,
      // NO host secrets, NO key, NO sink, NO request body cross the boundary.
      workerData: {}
    });
    w.on("message", (raw) => {
      let parsed;
      try {
        parsed = JSON.parse(typeof raw === "string" ? raw : String(raw));
      } catch {
        return; // unparseable → drop
      }
      const cid = parsed?.cid;
      const settle = pending.get(cid);
      if (!settle) {
        return; // unmatched / duplicate / late → drop
      }
      pending.delete(cid);
      settle(parsed);
    });
    // FIX D — stale-worker error race: guard with `worker === w` (same as the
    // exit handler) so a late async error from an already-terminated worker
    // (e.g. from the previous incarnation after a timeout-terminate and respawn)
    // cannot spuriously terminate the live replacement worker.
    w.on("error", () => { if (worker === w) terminateWorker("crash"); });
    w.on("exit", (exitCode) => {
      if (exitCode !== 0 && worker === w) {
        terminateWorker("crash");
      }
    });
    worker = w;
    pluginId = pid;
  }

  // Drop the live worker (audit the cause), failing any matched in-flight call
  // closed. Respawn happens lazily on the next call (re-running the full gate).
  function terminateWorker(cause) {
    const terminated = worker;
    worker = null;
    if (terminated) {
      audit({ type: "plugin.worker.terminated", decision: "plugin.worker.terminated", pluginId, cause });
      try { terminated.terminate(); } catch { /* already gone */ }
    }
    for (const [, settle] of pending) {
      settle(null);
    }
    pending.clear();
  }

  // LAZY (re)spawn behind a single-flight guard that RE-RUNS THE FULL PR2 GATE
  // (re-verify signature + anchor + pin + revocation + capabilities + window).
  async function ensureWorker() {
    if (worker || closed) {
      return;
    }
    if (respawning) {
      return respawning;
    }
    respawning = (async () => {
      const loaded = loadAndVerify();
      spawnFromVerified(loaded);
    })();
    try {
      await respawning;
    } finally {
      respawning = null;
    }
  }

  // One serialized worker round-trip. Resolves to the parsed reply, null (crash /
  // spawn failure), or { __timeout: true }. Runs alone — single-occupancy.
  async function roundTrip(credential) {
    await ensureWorker();
    if (!worker) {
      return null; // spawn failed → fail closed
    }
    const cid = randomUUID();
    const message = JSON.stringify({ cid, credential });
    if (Buffer.byteLength(message, "utf8") > maxMessageBytes) {
      return { __oversized: true };
    }
    return new Promise((resolve) => {
      let done = false;
      const settle = (value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(value);
      };
      const timer = setTimeout(() => {
        pending.delete(cid);
        // Timeout → terminate the worker (audited), deny. Respawn lazily.
        terminateWorker("timeout");
        settle({ __timeout: true });
      }, timeoutMs);
      pending.set(cid, settle);
      try {
        worker.postMessage(message);
      } catch {
        pending.delete(cid);
        settle(null); // worker already dead → fail closed
      }
    });
  }

  // The sandboxed provider as the conformance harness / proxy see it. It proxies
  // authenticate() into the worker, then the HOST sanitizes + builds the identity.
  // NEVER throws into the caller (catch-all → null).
  async function authenticate(request) {
    try {
      const credential = bearerCredentialFromRequest(request);
      if (credential === null) {
        return null; // missing credential → deny (no worker round-trip needed)
      }

      // Pending cap: bound concurrency so a burst can never queue unbounded.
      if (queueDepth >= maxPendingCalls) {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "over-capacity" });
        return null;
      }

      // Serialize: single-occupancy worker. Each call waits its turn; distinct
      // cids guarantee replies never cross even though calls are queued.
      queueDepth += 1;
      const myTurn = chain;
      let release;
      chain = new Promise((r) => { release = r; });
      let reply;
      try {
        await myTurn;
        reply = await roundTrip(credential);
      } finally {
        queueDepth -= 1;
        release();
      }

      if (reply && reply.__oversized) {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "oversized" });
        return null;
      }
      if (!reply || reply.__timeout) {
        if (reply && reply.__timeout) {
          audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "timeout" });
        }
        return null;
      }
      if (reply.deny === true || reply.claims === undefined) {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "deny" });
        return null;
      }

      let claims;
      try {
        claims = sanitizeClaims(reply.claims);
      } catch {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "invalid-claims" });
        return null;
      }

      // The HOST builds the keyed-HMAC identity. The key NEVER crossed to the
      // worker; PII-safety is (re-)enforced here on every call.
      try {
        return await buildExternalIdentity({
          provider: `plugin:${pluginId}`,
          subject: claims.subject,
          issuer: claims.issuer,
          type: claims.type ?? "user",
          scopes: claims.scopes ?? [],
          labels: claims.labels ?? {},
          ...(allowedLabelKeys ? { allowedLabelKeys } : {})
        }, cryptoProvider);
      } catch {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "invalid-claims" });
        return null;
      }
    } catch {
      // Catch-all: authenticate NEVER throws into the caller.
      return null;
    }
  }

  async function close() {
    closed = true;
    const terminated = worker;
    worker = null;
    pending.clear();
    if (terminated) {
      try { await terminated.terminate(); } catch { /* already gone */ }
    }
  }

  // ---- construct: synchronous load+verify+spawn (PR2 gate throws here), then a
  // one-time async conformance gate. The sync gate runs eagerly so a refused load
  // throws at construction; conformance runs through the SAME worker wire.

  const initial = loadAndVerify();
  spawnFromVerified(initial);

  const provider = { id: `plugin:${initial.pluginId}`, authenticate, close };

  // The conformance run, executed once. Emits load.accepted on pass; on fail it
  // emits load.refused{conformance-failed}, closes the worker, and rejects.
  const conformance = assertAuthProviderConformance(provider, { now: nowFn() })
    .then((result) => {
      if (!result.ok) {
        audit({
          type: "plugin.load.refused",
          decision: "plugin.load.refused",
          reason: "conformance-failed",
          pluginId: initial.pluginId,
          signerKeyId: initial.signerKeyId
        });
        return close().then(() => {
          throw new Error(`plugin conformance failed: ${result.failures.join("; ")}`);
        });
      }
      audit({
        type: "plugin.load.accepted",
        decision: "plugin.load.accepted",
        pluginId: initial.pluginId,
        version: initial.verified.version,
        entrySha256: initial.entrySha256,
        signerKeyId: initial.signerKeyId,
        capabilitiesGranted: Object.entries(initial.verified.capabilities)
          .filter(([, v]) => v === true)
          .map(([k]) => k)
      });
      return provider;
    });

  // ready resolves when conformance passes / rejects when it fails — the runtime
  // (sync) path awaits this lazily; direct callers await the returned promise.
  provider.ready = conformance;
  return { provider, conformance, pluginId: initial.pluginId, entrySha256: initial.entrySha256, signerKeyId: initial.signerKeyId };
}

// Async factory: resolves to the live provider AFTER conformance passes, rejects
// on ANY load failure (PR2 gate or conformance). Direct (test) callers await this.
export async function createSandboxedAuthProvider(options) {
  const { conformance } = createSandboxedAuthProviderHandle(options);
  return conformance;
}

// Synchronous factory for the runtime composition root: the PR2 gate runs eagerly
// (so a refused load throws at createRuntime time), and conformance is gated
// lazily behind provider.ready — authenticate() awaits readiness and fails closed
// (null) if conformance rejected. Returns the host-side authProvider immediately.
export function createSandboxedAuthProviderSync(options) {
  const { provider, conformance } = createSandboxedAuthProviderHandle(options);
  // Gate readiness on conformance WITHOUT mutating provider.authenticate — the
  // conformance run itself calls provider.authenticate, so wrapping that method
  // in place would make conformance await itself (deadlock). Return a NEW object
  // whose authenticate awaits readiness then delegates to the (untouched) raw
  // provider.authenticate.
  const ready = conformance.then(() => true, () => false);
  return {
    id: provider.id,
    async authenticate(request) {
      if (!(await ready)) {
        return null; // conformance failed → permanently fail closed
      }
      return provider.authenticate(request);
    },
    close() {
      return provider.close();
    },
    ready
  };
}
