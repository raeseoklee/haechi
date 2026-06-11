// The process-isolated authProvider sandbox (Haechi 1.1 §2.1/§2.2/§2.6).
//
// CAPABILITY ENFORCEMENT (what this adds over the 1.0 worker, read
// docs/current/release-1.1-implementation-scope.md §1): the signed plugin runs in
// a CHILD node process under the Node permission model (`--permission`) with
// ZERO grants — no fs, no child-process, no worker, no addons, no wasi, and (since
// no `--allow-net` is passed) no network. On a Node that enforces `--allow-net`,
// the kernel denies `net`/`fetch`/`dns` AND the `process.binding('tcp_wrap')`
// bypass, so a malicious *signed* plugin CANNOT exfiltrate the credential it
// receives. This is real capability enforcement, not the worker's trust-only model.
//
// Three load-bearing controls the empirical (Node-26) review made mandatory:
//   1. NETWORK = the kernel `--allow-net` denial, never a "delete node:net"
//      harness — a harness is trivially bypassed (tcp_wrap / a fresh import).
//      1.1 PR1 always spawns WITHOUT --allow-net (zero grants); the fail-closed
//      `--allow-net` feature detection + `netEnforcement` config arrives in PR3.
//   2. STDIO fully closed — `stdio:['ignore','ignore','ignore','ipc']`: no stdout,
//      no stderr, no inheritable fd. A plugin writing the credential to stderr
//      reaches NO host-visible sink. The only channel is the dedicated IPC.
//   3. NO fs grant at all — the plugin is loaded from a `data:` URL the host hands
//      to the child over IPC, so there is no temp-dir / realpath / symlink / TOCTOU
//      surface and no `--allow-fs-read`. A runtime import of a host file fails
//      closed (the permission model denies fs).
//
// The trust boundary (load gate, claims sanitizer, bearer extraction, host
// keyed-HMAC identity) is SHARED with the worker via ./sandbox-common.mjs so the
// two runtimes cannot diverge. Only the transport (child_process spawn + IPC) and
// its async spawn/load handshake live here.
//
// Zero runtime dependency: node:child_process + node:crypto + the in-repo
// haechi/plugin (load gate) and haechi/auth (identity + conformance).

import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { assertAuthProviderConformance, buildExternalIdentity } from "../auth/index.mjs";
import { createGuardedKeyFetcher } from "../ssrf/index.mjs";
import {
  bearerCredentialFromRequest,
  loadAndVerifyPlugin,
  makeFireAndForgetAudit,
  sanitizeClaims
} from "./sandbox-common.mjs";

// The child flags. `--permission` enables the deny-by-default Node permission
// model; we pass NO --allow-* grant, so fs/child-process/worker/addons/wasi/net
// are all kernel-denied. `--disable-proto=delete` removes Object.prototype.__proto__.
const CHILD_FLAGS = Object.freeze(["--permission", "--disable-proto=delete"]);

// A CONSTANT bootstrap harness, passed via `node -e`. It is identical for every
// plugin (the plugin bytes arrive over IPC, NOT on the command line — so there is
// no ARG_MAX limit and the harness never varies). It runs as CommonJS under -e and
// uses a dynamic import() of a data: URL to load the verified plugin source.
//
// Wire (JSON strings both directions over the IPC, serialization:'json'):
//   host → child: {t:'load', source:<base64>} | {t:'auth', cid, credential}
//   child → host: {t:'ready'} | {t:'loaded'} | {t:'load-error'} | {t:'auth', cid, claims|deny}
const PROCESS_HARNESS = [
  "'use strict';",
  "let __plugin = null;",
  "function __pick(mod){",
  "  return (typeof mod.default === 'function') ? mod.default",
  "    : (typeof mod.authenticate === 'function') ? mod.authenticate",
  "    : (mod.default && typeof mod.default.authenticate === 'function') ? mod.default.authenticate",
  "    : null;",
  "}",
  "process.on('message', async (raw) => {",
  "  let msg;",
  "  try { msg = JSON.parse(typeof raw === 'string' ? raw : String(raw)); } catch { return; }",
  "  if (!msg || typeof msg !== 'object') return;",
  "  if (msg.t === 'load') {",
  "    try {",
  "      const mod = await import('data:text/javascript;base64,' + msg.source);",
  "      const fn = __pick(mod);",
  "      if (typeof fn !== 'function') throw new Error('plugin entry must export an authenticate function');",
  "      __plugin = fn;",
  "      process.send(JSON.stringify({ t: 'loaded' }));",
  "    } catch (err) {",
  "      process.send(JSON.stringify({ t: 'load-error' }));",
  "    }",
  "    return;",
  "  }",
  "  if (msg.t === 'auth') {",
  "    const cid = msg.cid;",
  "    try {",
  "      if (typeof __plugin !== 'function') { process.send(JSON.stringify({ t: 'auth', cid, deny: true })); return; }",
  // The host injects operator-declared key material (the plugin NEVER names a URL;
  // net is denied in the child, so it cannot fetch keys itself). Plugins that do
  // not need it simply ignore the second argument.
  "      const out = await __plugin(msg.credential, { keyMaterial: (msg.keyMaterial !== undefined ? msg.keyMaterial : null) });",
  "      if (!out || out.deny === true || typeof out !== 'object') { process.send(JSON.stringify({ t: 'auth', cid, deny: true })); return; }",
  "      process.send(JSON.stringify({ t: 'auth', cid, claims: out }));",
  "    } catch (err) {",
  // A plugin throw NEVER propagates: it surfaces to the host as a deny.
  "      process.send(JSON.stringify({ t: 'auth', cid, deny: true }));",
  "    }",
  "    return;",
  "  }",
  "});",
  "process.send(JSON.stringify({ t: 'ready' }));"
].join("\n");

// Detect whether THIS Node enforces network containment under --permission. The
// permission model only gates net if the `--allow-net` flag exists (Node >= 24 /
// experimental in some 22.x lines do not have it). Without it, --permission denies
// fs/exec/worker but NOT net — so a malicious plugin could still exfiltrate the
// credential over the network. We therefore fail closed (refuse to construct) on
// a Node that cannot enforce it, rather than pretend to contain.
//
// Detection (memoized; NO version parsing — we probe BEHAVIOR):
//   1. Fast path: if --allow-net isn't even a recognized flag, net is not gated.
//   2. Authoritative: spawn a `--permission` child with NO --allow-net and confirm
//      net.connect is actually DENIED (ERR_ACCESS_DENIED). This is immune to a Node
//      that lists the flag but does not enforce it — we verify the denial, not the
//      flag. Exit 0 = net is enforced/denied (supported); anything else = not.
let _netSupportMemo;
export function netEnforcementSupported() {
  if (_netSupportMemo !== undefined) {
    return _netSupportMemo;
  }
  try {
    if (!process.allowedNodeEnvironmentFlags?.has?.("--allow-net")) {
      _netSupportMemo = false;
      return false;
    }
    const probeCode =
      "const n=require('net');const s=n.connect({host:'127.0.0.1',port:1});"
      + "s.on('error',e=>process.exit(e&&e.code==='ERR_ACCESS_DENIED'?0:3));"
      + "s.on('connect',()=>{try{s.destroy();}catch{}process.exit(3);});"
      + "setTimeout(()=>process.exit(3),500);";
    const probe = spawnSync(process.execPath, ["--permission", "-e", probeCode], { stdio: "ignore" });
    _netSupportMemo = probe.status === 0;
  } catch {
    _netSupportMemo = false;
  }
  return _netSupportMemo;
}

// Env scrubbing: the permission model does NOT protect inherited env, so a child
// that could be made to read process.env would see host secrets. We pass a fresh,
// EMPTY env — no inherited vars, and critically no NODE_OPTIONS (which could inject
// flags). node --permission -e boots fine with an empty env (verified).
function scrubbedEnv() {
  return {};
}

function createProcessIsolatedAuthProviderHandle({
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
  coreVersion = null,
  now = Date.now,
  allowedLabelKeys,
  execPath = process.execPath,
  // Network containment policy. "require-permission" (the only PR1 mode, and the
  // default) means: this Node MUST enforce --allow-net, else construction throws
  // — the credential-containment guarantee is not honest without it. The
  // best-effort "allow-harness" fallback is deferred to a later minor (see the
  // 1.1 scope doc §2.2). `detectNetSupport` is an injectable seam for tests.
  netEnforcement = "require-permission",
  detectNetSupport = netEnforcementSupported,
  // Optional host-mediated key material (1.1 §2.3): for a CUSTOM-credential plugin
  // that needs a key document (e.g. a JWKS-like doc) to validate its credential.
  // The HOST fetches it from this OPERATOR-declared URL through the SSRF-hardened
  // core guarded fetch and injects it over the IPC — the plugin never names a URL
  // (no plugin-driven SSRF), and net is denied in the child so it cannot fetch
  // keys itself. The fetch is TTL-cached + cooldown-bounded (no outbound pump).
  // Shape: { url, ttlMs?, cooldownMs?, timeoutMs?, maxBytes?, fetchImpl?, lookupImpl? }.
  keyMaterial = null,
  // Spawn-storm circuit breaker (anti-DoS): if the child is killed (timeout/crash)
  // respawnMaxKills times within respawnWindowMs, trip to a PERMANENT fail-closed
  // deny (operator reset = recreate the provider). respawnBackoffMs is the base for
  // an exponential backoff between respawns so a flapping plugin cannot become a
  // spawn storm.
  respawnMaxKills = 5,
  respawnWindowMs = 10_000,
  respawnBackoffMs = 100
} = {}) {
  if (!manifestPath || typeof manifestPath !== "string") {
    throw new Error("createProcessIsolatedAuthProvider requires a manifestPath string");
  }
  if (typeof cryptoProvider?.hmac !== "function") {
    throw new Error("createProcessIsolatedAuthProvider requires a cryptoProvider with hmac()");
  }
  if (!auditSink || typeof auditSink.record !== "function") {
    throw new Error("createProcessIsolatedAuthProvider requires an auditSink with record()");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("createProcessIsolatedAuthProvider requires a positive integer timeoutMs");
  }
  if (!Number.isInteger(maxPendingCalls) || maxPendingCalls < 1) {
    throw new Error("maxPendingCalls must be a positive integer");
  }
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes < 1) {
    throw new Error("maxMessageBytes must be a positive integer");
  }
  // Fail-closed network containment. PR1 supports only the "require-permission"
  // mode; if this Node cannot enforce --allow-net, refuse to construct rather than
  // run a plugin whose network egress is uncontained.
  if (netEnforcement !== "require-permission") {
    throw new Error(`unsupported netEnforcement: ${JSON.stringify(netEnforcement)} (1.1 supports only "require-permission")`);
  }
  if (!detectNetSupport()) {
    throw new Error(
      "process-isolated requires a Node that enforces the --allow-net permission "
      + "(netEnforcement: require-permission); this Node cannot contain plugin network "
      + "egress, so refusing to construct — use worker-isolated, or run on a Node with --allow-net"
    );
  }
  const nowFn = typeof now === "function" ? now : () => now;
  // Every process lifecycle event carries isolation:"process" (a host-computed,
  // fixed-enum discriminator — never child-supplied) so an audit consumer can tell
  // a process-isolated decision from a worker-isolated one. All audit fields here
  // are host-computed/enum-only; no child free-text ever enters an event.
  const auditBase = makeFireAndForgetAudit(auditSink);
  const audit = (event) => auditBase({ isolation: "process", ...event });

  // Optional host-mediated key-material fetcher (operator-declared URL only). The
  // core guarded fetcher validates the https URL at construction and SSRF-guards
  // every fetch; TTL cache + cooldown bound the outbound rate.
  let keyFetcher = null;
  if (keyMaterial !== null && keyMaterial !== undefined) {
    if (typeof keyMaterial !== "object" || Array.isArray(keyMaterial) || typeof keyMaterial.url !== "string") {
      throw new Error("keyMaterial must be an object with an operator-declared https url");
    }
    keyFetcher = createGuardedKeyFetcher({ ...keyMaterial, now: nowFn });
  }

  // Read+validate the manifest + run the FULL PR2 gate (shared with the worker
  // runtime). Re-run on every (re)spawn — the gate is not a one-time check.
  function loadAndVerify() {
    return loadAndVerifyPlugin({
      manifestPath,
      expectedRuntime: "process-isolated",
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

  // ---- child lifecycle -----------------------------------------------------

  let child = null;
  let pluginId = null;
  let closed = false;
  // The construction load is reused for the FIRST spawn; respawns re-load (re-verify).
  let preloaded = null;
  // cid -> settle(reply). Drops late/duplicate/unmatched replies by cid. Only one
  // entry is ever live at a time (single-occupancy via the serialization chain).
  const pending = new Map();
  let respawning = null; // single-flight respawn guard
  let chain = Promise.resolve();
  let queueDepth = 0;
  // Spawn-storm circuit breaker: timestamps of recent kills (pruned to the window)
  // and a permanent trip flag.
  let killTimes = [];
  let breakerTripped = false;

  // Spawn the child, await the {t:'ready'} handshake, hand it the verified plugin
  // bytes as a data: URL over IPC, and await {t:'loaded'}. Bounded by timeoutMs;
  // any failure kills the child and throws → fail closed. NOTE the plugin source
  // crosses over IPC (not the command line) so there is no ARG_MAX limit.
  async function spawnAndLoad({ entrySource, pluginId: pid }) {
    const c = spawn(execPath, [...CHILD_FLAGS, "-e", PROCESS_HARNESS], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      serialization: "json",
      env: scrubbedEnv(),
      windowsHide: true
    });

    let onReady;
    let onLoaded;
    let onFail;
    let handshakeDone = false;
    const ready = new Promise((resolve) => { onReady = resolve; });
    const loaded = new Promise((resolve) => { onLoaded = resolve; });
    // Rejects if the child dies DURING the handshake — so a startup crash fails
    // fast (deny) instead of waiting out the full timeoutMs.
    const failed = new Promise((_, reject) => { onFail = reject; });

    c.on("message", (raw) => {
      let parsed;
      try {
        parsed = JSON.parse(typeof raw === "string" ? raw : String(raw));
      } catch {
        return; // unparseable → drop
      }
      const t = parsed?.t;
      if (t === "ready") { onReady(); return; }
      if (t === "loaded") { onLoaded(true); return; }
      if (t === "load-error") { onLoaded(false); return; }
      if (t === "auth") {
        const settle = pending.get(parsed.cid);
        if (!settle) {
          return; // unmatched / duplicate / late → drop
        }
        pending.delete(parsed.cid);
        settle(parsed);
      }
    });
    // Before the handshake completes, child !== c (child is only set on success),
    // so terminateChild's `child === c` guard would ignore a startup crash. Route
    // an early error/exit to the handshake rejection instead; afterwards the
    // `child === c` guard handles a live-child crash (and ignores a stale one).
    c.on("error", () => {
      if (!handshakeDone) { onFail(new Error("child errored during spawn")); return; }
      if (child === c) terminateChild("crash");
    });
    c.on("exit", (code) => {
      if (!handshakeDone) { onFail(new Error(`child exited during spawn (code ${code})`)); return; }
      if (code !== 0 && child === c) terminateChild("crash");
    });

    let handshakeTimer;
    const handshakeTimeout = new Promise((_, reject) => {
      handshakeTimer = setTimeout(() => reject(new Error("child spawn/load handshake timed out")), timeoutMs);
    });
    try {
      await Promise.race([ready, failed, handshakeTimeout]);
      c.send(JSON.stringify({ t: "load", source: Buffer.from(entrySource, "utf8").toString("base64") }));
      const ok = await Promise.race([loaded, failed, handshakeTimeout]);
      if (!ok) {
        throw new Error("plugin failed to load in the process sandbox");
      }
    } catch (error) {
      handshakeDone = true; // stop the error/exit handlers from acting on this child
      clearTimeout(handshakeTimer);
      try { c.kill("SIGKILL"); } catch { /* already gone */ }
      throw error;
    }
    handshakeDone = true;
    clearTimeout(handshakeTimer);
    // close() may have run while we awaited the handshake; do NOT resurrect a child
    // after close (kill-switch / process-leak). This check + the assignment are
    // synchronous, so close() cannot interleave between them.
    if (closed) {
      try { c.kill("SIGKILL"); } catch { /* already gone */ }
      throw new Error("provider closed during spawn");
    }
    child = c;
    pluginId = pid;
  }

  // Drop the live child (audit the cause), failing any matched in-flight call
  // closed. Respawn happens lazily on the next call (re-running the full gate).
  // A kill feeds the spawn-storm circuit breaker: too many within the window trips
  // to a permanent fail-closed deny (operator reset = recreate the provider).
  function terminateChild(cause) {
    const terminated = child;
    child = null;
    if (terminated) {
      audit({ type: "plugin.worker.terminated", decision: "plugin.worker.terminated", pluginId, cause });
      try { terminated.kill("SIGKILL"); } catch { /* already gone */ }
      const t = nowFn();
      killTimes.push(t);
      killTimes = killTimes.filter((ts) => (t - ts) < respawnWindowMs);
      if (!breakerTripped && killTimes.length >= respawnMaxKills) {
        breakerTripped = true;
        audit({ type: "plugin.worker.terminated", decision: "plugin.worker.terminated", pluginId, cause: "respawn-storm" });
      }
    }
    for (const [, settle] of pending) {
      settle(null);
    }
    pending.clear();
  }

  // LAZY (re)spawn behind a single-flight guard that RE-RUNS THE FULL PR2 GATE.
  // A tripped circuit breaker fails closed permanently (the operator must recreate
  // the provider). Respawns are exponentially backed off so a flapping plugin
  // cannot become a spawn storm.
  async function ensureChild() {
    if (child || closed) {
      return;
    }
    if (breakerTripped) {
      throw new Error("process plugin respawn-storm circuit breaker is tripped (fail-closed; recreate the provider to reset)");
    }
    if (respawning) {
      return respawning;
    }
    respawning = (async () => {
      const recentKills = killTimes.length;
      if (recentKills > 0 && respawnBackoffMs > 0) {
        const backoff = respawnBackoffMs * (2 ** Math.min(recentKills - 1, 6));
        await new Promise((resolve) => setTimeout(resolve, backoff));
        if (closed || breakerTripped) {
          throw new Error("provider closed or breaker tripped during backoff");
        }
      }
      const loaded = preloaded ?? loadAndVerify();
      preloaded = null;
      await spawnAndLoad(loaded);
    })();
    try {
      await respawning;
    } finally {
      respawning = null;
    }
  }

  // One serialized child round-trip. Resolves to the parsed reply, null (crash /
  // spawn failure), { __timeout: true }, or { __oversized: true }. Runs alone.
  async function roundTrip(credential) {
    try {
      await ensureChild();
    } catch {
      return null; // spawn/load failed → fail closed
    }
    if (!child) {
      return null;
    }
    const cid = randomUUID();
    const baseMessage = JSON.stringify({ t: "auth", cid, credential });
    if (Buffer.byteLength(baseMessage, "utf8") > maxMessageBytes) {
      return { __oversized: true };
    }
    // Host-mediated key material (if configured). The credential is bounded by
    // maxMessageBytes above; the key document is separately bounded by the
    // fetcher's maxBytes, so it is added AFTER the credential bound check.
    let message = baseMessage;
    if (keyFetcher) {
      let doc;
      try {
        doc = await keyFetcher.get();
      } catch {
        return { __keyfetch: true }; // host key fetch failed (SSRF refusal / cooldown) → deny
      }
      message = JSON.stringify({ t: "auth", cid, credential, keyMaterial: doc });
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
        // Timeout → terminate the child (audited), deny. Respawn lazily.
        terminateChild("timeout");
        settle({ __timeout: true });
      }, timeoutMs);
      pending.set(cid, settle);
      try {
        child.send(message);
      } catch {
        pending.delete(cid);
        settle(null); // child already dead → fail closed
      }
    });
  }

  // The sandboxed provider. Proxies authenticate() into the child, then the HOST
  // sanitizes + builds the keyed-HMAC identity. NEVER throws into the caller.
  async function authenticate(request) {
    try {
      const credential = bearerCredentialFromRequest(request);
      if (credential === null) {
        return null; // missing credential → deny (no round-trip needed)
      }

      if (queueDepth >= maxPendingCalls) {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "over-capacity" });
        return null;
      }

      // Serialize: single-occupancy child. Each call waits its turn; distinct cids
      // guarantee replies never cross even though calls are queued.
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
      if (reply && reply.__keyfetch) {
        audit({ type: "plugin.authenticate.deny", decision: "plugin.authenticate.deny", pluginId, reason: "key-material-unavailable" });
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
      // child; PII-safety is (re-)enforced here on every call.
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
    const terminated = child;
    child = null;
    pending.clear();
    if (terminated) {
      try { terminated.kill("SIGKILL"); } catch { /* already gone */ }
    }
  }

  // ---- construct: synchronous load+verify (PR2 gate throws here), then a
  // one-time async conformance gate. The eager sync gate makes a refused load throw
  // at construction; the child spawns lazily on the first authenticate (which
  // conformance drives), reusing the construction load via `preloaded`.

  const initial = loadAndVerify();
  preloaded = initial;

  const provider = { id: `plugin:${initial.pluginId}`, authenticate, close };

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
          .map(([k]) => k),
        // Host-computed, enum-only capability-enforcement facts (never child input):
        // the child is spawned with ZERO OS permission grants, and net is contained
        // by the require-permission --allow-net denial.
        netEnforcement,
        grants: []
      });
      return provider;
    });

  provider.ready = conformance;
  return { provider, conformance, pluginId: initial.pluginId, entrySha256: initial.entrySha256, signerKeyId: initial.signerKeyId };
}

// Async factory: resolves to the live provider AFTER conformance passes, rejects
// on ANY load failure (PR2 gate or conformance). Direct (test) callers await this.
export async function createProcessIsolatedAuthProvider(options) {
  const { conformance } = createProcessIsolatedAuthProviderHandle(options);
  return conformance;
}

// Synchronous factory for the runtime composition root: the PR2 gate runs eagerly
// (so a refused load throws at createRuntime time), and conformance is gated lazily
// behind provider.ready — authenticate() awaits readiness and fails closed (null)
// if conformance rejected. Returns the host-side authProvider immediately.
export function createProcessIsolatedAuthProviderSync(options) {
  const { provider, conformance } = createProcessIsolatedAuthProviderHandle(options);
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
