import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime, createRateLimiter } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile, createLocalCryptoProvider } from "../packages/crypto/index.mjs";
import { addToken } from "../packages/auth/index.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";

// WS3 — Horizontal-scale & state safety. The proxy rate limiter is an injectable
// collaborator (providers.rateLimiter, mirroring cryptoProvider/auditSink), and
// the default per-process limiter bounds its window Map (no unbounded growth, no
// timer leak). These tests pin: (a) an injected limiter is the one consulted,
// (b) the default limiter prunes aged-out one-shot identities, and (c) the
// fixed-window 429 semantics are unchanged.

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address())));
}

function echoUpstream() {
  return createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
}

async function project(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return {
    keyFile,
    auditPath: join(dir, ".haechi", "audit.jsonl"),
    storePath: join(dir, ".haechi", "auth.json"),
    cryptoProvider: createLocalCryptoProvider({ keyFile })
  };
}

async function startProxyWithProviders(runtimeConfig, upstream, providers = {}) {
  const upstreamAddress = await listen(upstream);
  runtimeConfig.target = { type: "vllm-openai", upstream: `http://127.0.0.1:${upstreamAddress.port}` };
  const runtime = createRuntime(runtimeConfig, providers);
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const proxyAddress = await proxy.listen();
  return { runtime, proxy, upstream, base: `http://${proxyAddress.host}:${proxyAddress.port}` };
}

test("an injected rateLimiter is the one consulted by the proxy", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-inject-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const tok = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:a"] });

  // An injected limiter that DENIES every call. It is exposed on the runtime and
  // consulted by the proxy — so the very first request is throttled to 429.
  const denyCalls = [];
  const denyLimiter = {
    allow(key, limit) {
      denyCalls.push({ key, limit });
      return false;
    }
  };

  const config = {
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      profiles: { limited: { rate: { requestsPerMinute: 5 } } },
      profileBinding: { byScope: { "tier:a": "limited" }, default: "limited" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  };

  const { runtime, proxy, upstream, base } = await startProxyWithProviders(config, echoUpstream(), { rateLimiter: denyLimiter });
  try {
    // The injected limiter is the one exposed on the runtime object.
    assert.equal(runtime.rateLimiter, denyLimiter);

    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 429);
    assert.equal((await res.json()).error, "haechi_rate_limited");
    // The injected limiter was consulted with the resolved per-minute budget.
    assert.equal(denyCalls.length, 1);
    assert.equal(denyCalls[0].limit, 5);
    assert.match(await readFile(auditPath, "utf8"), /"decision":"rate_limited"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("an injected allow-all rateLimiter lets every request through", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-allow-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const tok = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:a"] });

  let allowCalls = 0;
  const allowLimiter = {
    allow() {
      allowCalls += 1;
      return true;
    }
  };

  const config = {
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      // A budget of 1/min would 429 the second request with the DEFAULT limiter;
      // the injected allow-all limiter overrides that, proving it is consulted.
      profiles: { limited: { rate: { requestsPerMinute: 1 } } },
      profileBinding: { byScope: { "tier:a": "limited" }, default: "limited" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  };

  const { proxy, upstream, base } = await startProxyWithProviders(config, echoUpstream(), { rateLimiter: allowLimiter });
  try {
    async function hit() {
      const res = await fetch(`${base}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
        body: JSON.stringify({ messages: [] })
      });
      return res.status;
    }
    assert.equal(await hit(), 200);
    assert.equal(await hit(), 200);
    assert.equal(await hit(), 200);
    assert.equal(allowCalls, 3);
    assert.doesNotMatch(await readFile(auditPath, "utf8"), /"decision":"rate_limited"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("an injected ASYNC rateLimiter (Promise<boolean>) gates a 429 when it resolves false", async () => {
  // A shared-store (Redis-backed) limiter is inherently async: allow() returns a
  // Promise<boolean>. The proxy `await`s it, so a Promise resolving false must
  // 429 (a naive `!somePromise` is always false — a Promise is truthy — which
  // would silently fail open). This pins the WS3 async-seam core change.
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-async-deny-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const tok = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:a"] });

  const asyncCalls = [];
  const asyncDenyLimiter = {
    async allow(key, limit) {
      asyncCalls.push({ key, limit });
      return false; // resolves a Promise<false>
    }
  };

  const config = {
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      profiles: { limited: { rate: { requestsPerMinute: 5 } } },
      profileBinding: { byScope: { "tier:a": "limited" }, default: "limited" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  };

  const { proxy, upstream, base } = await startProxyWithProviders(config, echoUpstream(), { rateLimiter: asyncDenyLimiter });
  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
      body: JSON.stringify({ messages: [] })
    });
    assert.equal(res.status, 429);
    assert.equal((await res.json()).error, "haechi_rate_limited");
    assert.equal(asyncCalls.length, 1);
    assert.equal(asyncCalls[0].limit, 5);
    assert.match(await readFile(auditPath, "utf8"), /"decision":"rate_limited"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("an injected ASYNC rateLimiter passes when its Promise resolves true", async () => {
  // The other side of the await: a Promise<true> must let the request through to
  // upstream (200), proving the await unwraps the boolean rather than coercing a
  // truthy Promise.
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-async-allow-"));
  const { keyFile, auditPath, storePath, cryptoProvider } = await project(dir);
  const tok = await addToken({ path: storePath, cryptoProvider, type: "service", scopes: ["tier:a"] });

  let allowCalls = 0;
  const asyncAllowLimiter = {
    async allow() {
      allowCalls += 1;
      return true; // resolves a Promise<true>
    }
  };

  const config = {
    mode: "enforce",
    auth: { provider: "bearer", store: storePath },
    policy: {
      mode: "enforce", presets: [], defaultAction: "allow",
      // 1/min would 429 the second request with the default SYNC limiter; the
      // async allow-all limiter must override that across multiple hits.
      profiles: { limited: { rate: { requestsPerMinute: 1 } } },
      profileBinding: { byScope: { "tier:a": "limited" }, default: "limited" }
    },
    keys: { keyFile }, audit: { path: auditPath }
  };

  const { proxy, upstream, base } = await startProxyWithProviders(config, echoUpstream(), { rateLimiter: asyncAllowLimiter });
  try {
    async function hit() {
      const res = await fetch(`${base}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${tok.token}` },
        body: JSON.stringify({ messages: [] })
      });
      return res.status;
    }
    assert.equal(await hit(), 200);
    assert.equal(await hit(), 200);
    assert.equal(allowCalls, 2);
    assert.doesNotMatch(await readFile(auditPath, "utf8"), /"decision":"rate_limited"/);
  } finally {
    await proxy.close();
    upstream.close();
  }
});

test("createRuntime exposes a default rateLimiter implementing allow()", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-default-"));
  const { keyFile, auditPath } = await project(dir);
  const runtime = createRuntime({
    mode: "enforce",
    policy: { mode: "enforce", presets: [], defaultAction: "allow" },
    keys: { keyFile }, audit: { path: auditPath }
  });
  assert.equal(typeof runtime.rateLimiter, "object");
  assert.equal(typeof runtime.rateLimiter.allow, "function");
});

test("createRuntime fails closed when an injected rateLimiter lacks allow()", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-rl-failclosed-"));
  const { keyFile, auditPath } = await project(dir);
  assert.throws(
    () => createRuntime(
      {
        mode: "enforce",
        policy: { mode: "enforce", presets: [], defaultAction: "allow" },
        keys: { keyFile }, audit: { path: auditPath }
      },
      { rateLimiter: { nope() {} } }
    ),
    /rateLimiter provider must implement allow\(\)/
  );
});

test("the default rateLimiter prunes aged-out one-shot identities (bounded window Map)", () => {
  // Drive many DISTINCT one-shot identities, then advance time past the window so
  // every slot is fully expired, then push enough fresh distinct keys to cross
  // the sweep threshold. The aged-out keys must be reclaimed — the Map must NOT
  // retain all the one-shot identities forever (the WS3 unbounded-growth bug).
  const realNow = Date.now;
  const windowMs = 60000;
  const sweepThreshold = 1024;
  let clock = 1_000_000;
  Date.now = () => clock;
  try {
    const limiter = createRateLimiter({ windowMs, sweepThreshold, sweepBudget: 4096 });

    // Phase 1: fill just under the threshold with one-shot identities.
    const firstBatch = sweepThreshold - 1;
    for (let i = 0; i < firstBatch; i += 1) {
      assert.equal(limiter.allow(`old-${i}`, 10), true);
    }
    assert.equal(limiter._size(), firstBatch);

    // Phase 2: age every existing slot past its window.
    clock += windowMs + 1;

    // Phase 3: push fresh distinct keys. Crossing the threshold triggers the
    // amortized sweep, which evicts the now-expired Phase-1 slots.
    const secondBatch = 2000;
    for (let i = 0; i < secondBatch; i += 1) {
      assert.equal(limiter.allow(`new-${i}`, 10), true);
    }

    // The Map must be far smaller than firstBatch + secondBatch (no retention of
    // the aged-out one-shot identities). It holds ~only the fresh keys.
    assert.ok(
      limiter._size() <= secondBatch + 8,
      `expected pruned size ~${secondBatch}, got ${limiter._size()} (aged-out keys leaked)`
    );
    assert.ok(limiter._size() < firstBatch + secondBatch, "no pruning occurred — window Map is unbounded");
  } finally {
    Date.now = realNow;
  }
});

test("the default rateLimiter keeps fixed-window 429 semantics and isolates identities", () => {
  const realNow = Date.now;
  let clock = 5_000_000;
  Date.now = () => clock;
  try {
    const limiter = createRateLimiter();
    // A 2/min budget: two pass, the third in the same window is denied.
    assert.equal(limiter.allow("a", 2), true);
    assert.equal(limiter.allow("a", 2), true);
    assert.equal(limiter.allow("a", 2), false);
    // A different identity has its own window — unaffected by A.
    assert.equal(limiter.allow("b", 2), true);
    // After the window fully elapses, A's budget resets.
    clock += 60001;
    assert.equal(limiter.allow("a", 2), true);
  } finally {
    Date.now = realNow;
  }
});
