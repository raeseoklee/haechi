#!/usr/bin/env node
// Reliability Hardening Track — proxy throughput / latency micro-benchmark.
//
// scripts/bench-payload.mjs measures in-process `protectJson` size scaling and
// scripts/bench-detection.mjs measures detection precision/recall. NEITHER
// measures the PROXY's HTTP throughput / latency under concurrency. This script
// fills that gap: it stands up a deterministic local STUB OpenAI-compatible
// upstream (an instant canned reply — no real model, so the bench measures
// HAECHI'S added overhead, not a model) and the REAL Haechi proxy in front of
// it, then drives load and reports req/s + latency percentiles.
//
// >>> HONESTY <<< This is a LOOPBACK, SINGLE-PROCESS, STUB-UPSTREAM micro-
// benchmark. The stub upstream, the proxy, and the load generator all run in ONE
// Node process on 127.0.0.1, so there is NO real network and NO real model. The
// numbers measure Haechi's added per-request overhead (detection → policy →
// transform → audit + the HTTP plumbing), NOT network throughput, NOT hardware
// capacity, and NOT a production deployment. Numbers vary by machine, Node
// version, and load. Do not quote them as guarantees.
//
// node:-only, zero runtime deps. Override knobs via HAECHI_BENCH_* (printed at
// the top). Run:  npm run bench:throughput
//
// Scenarios:
//   1. throughput + latency at a fixed concurrency (warmup excluded),
//   2. enforce vs dry-run overhead delta (same load, both modes),
//   3. backpressure: a low limits.maxInFlight, saturated, counting 503 vs 200.

import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { createRuntime } from "../packages/cli/runtime.mjs";
import { createHaechiProxy } from "../packages/proxy/index.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";

// ── Knobs (env, sane defaults that run in a few seconds) ────────────────────
const REQUESTS = Math.max(1, Number(process.env.HAECHI_BENCH_REQUESTS ?? 2000));
const CONCURRENCY = Math.max(1, Number(process.env.HAECHI_BENCH_CONCURRENCY ?? 32));
const WARMUP = Math.max(0, Number(process.env.HAECHI_BENCH_WARMUP ?? 100));
const PAYLOAD_KB = Math.max(0, Number(process.env.HAECHI_BENCH_PAYLOAD_KB ?? 1));
// The backpressure scenario sets a low ceiling and fires a burst wider than it.
const MAXINFLIGHT = Math.max(1, Number(process.env.HAECHI_BENCH_MAXINFLIGHT ?? 4));

// ── A deterministic OpenAI-compatible STUB upstream ─────────────────────────
// Mirrors examples/local-proxy-demo/demo.mjs: it echoes the (already-protected)
// last user message back and appends a canned leaked secret so response
// protection has something to do in enforce mode. An optional per-request delay
// (delayMs) lets the backpressure scenario hold slots open long enough to
// saturate the in-flight ceiling — the default 0 keeps the throughput runs as
// fast as the host allows.
function startStubUpstream({ delayMs = 0 } = {}) {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      let echoed = "";
      try { echoed = JSON.parse(body).messages.at(-1).content; } catch { /* ignore */ }
      const reply = () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({
          id: "chatcmpl-bench",
          object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant",
            content: `Noted. You wrote: "${echoed}" (ref token=BENCHleak9876543210notRealzyxwvut)` } }]
        }));
      };
      if (delayMs > 0) {
        const timer = setTimeout(reply, delayMs);
        if (typeof timer.unref === "function") { timer.unref(); }
      } else {
        reply();
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      url: `http://127.0.0.1:${server.address().port}`,
      close: () => new Promise((done) => server.close(done))
    }));
  });
}

// A representative request body: a filler-padded user message that carries an
// email, a phone, and a deploy secret so detection/transform actually fire (the
// enforce vs dry-run delta is meaningless if there is nothing to protect). The
// filler pads to ~PAYLOAD_KB.
function buildBody() {
  const seed = "Contact minji.kim@example.com or 010-1234-5678. Deploy api_key=BENCHkey0123456789notARealSecretabcdef.";
  const fillerBytes = Math.max(0, PAYLOAD_KB * 1024 - seed.length);
  const filler = "a".repeat(fillerBytes);
  return JSON.stringify({
    model: "bench",
    messages: [{ role: "user", content: `${filler} ${seed}` }]
  });
}

// ── Percentiles ─────────────────────────────────────────────────────────────
// NEAREST-RANK on a SORTED ascending sample array: for percentile p the rank is
// ceil(p/100 * N), 1-indexed, clamped to [1, N]. No interpolation. This is the
// classic nearest-rank definition; it returns an actual observed sample, never a
// synthesized value. (Documented choice, per the bench-honesty note.)
function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) { return 0; }
  const rank = Math.ceil((p / 100) * sortedAsc.length);
  const index = Math.min(Math.max(rank, 1), sortedAsc.length) - 1;
  return sortedAsc[index];
}

function summarize(latenciesMs, wallMs, counted) {
  const sorted = [...latenciesMs].sort((a, b) => a - b);
  const reqPerSec = wallMs > 0 ? (counted / wallMs) * 1000 : 0;
  return {
    requests: counted,
    wallMs: round(wallMs),
    reqPerSec: round(reqPerSec),
    p50Ms: round(percentile(sorted, 50)),
    p95Ms: round(percentile(sorted, 95)),
    p99Ms: round(percentile(sorted, 99)),
    maxMs: round(sorted.at(-1) ?? 0)
  };
}

const round = (n) => Math.round(n * 1000) / 1000;

// ── Fixed-size worker-pool load driver ──────────────────────────────────────
// `concurrency` in-flight fetches at a time, draining a shared counter until
// `total` requests are issued. Per-request wall-clock latency is timed with
// performance.now(). The FIRST `warmup` completed requests are EXCLUDED from the
// reported latency sample (JIT + connection warmup skews them) — they still hit
// the proxy, they just don't count. Returns the measured sample + the wall time
// spanning only the counted (post-warmup) requests.
async function drive({ base, total, concurrency, warmup, body }) {
  const latencies = [];
  let issued = 0;
  let completed = 0;
  let countedStart = 0; // wall clock at the moment warmup finishes
  let countedEnd = 0;
  let firstError = null;

  async function worker() {
    while (true) {
      const myIndex = issued;
      if (myIndex >= total) { return; }
      issued += 1;
      const started = performance.now();
      try {
        const res = await fetch(`${base}/v1/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body
        });
        // Drain the body so the socket is freed for reuse (keep-alive).
        await res.arrayBuffer();
        const elapsed = performance.now() - started;
        completed += 1;
        if (completed === warmup) {
          countedStart = performance.now();
        }
        if (completed > warmup) {
          latencies.push(elapsed);
          countedEnd = performance.now();
        }
      } catch (error) {
        if (!firstError) { firstError = error; }
        completed += 1;
      }
    }
  }

  // If warmup >= total there is nothing to count; guard so countedStart is sane.
  const wallStart = performance.now();
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  if (warmup === 0) { countedStart = wallStart; }
  if (countedEnd === 0) { countedEnd = performance.now(); }

  if (firstError) { throw firstError; }
  const wallMs = Math.max(0, countedEnd - countedStart);
  return summarize(latencies, wallMs, latencies.length);
}

// Build a runtime + real proxy in front of the stub for a given mode. enforce
// turns on response protection (so the protection cost is in the measurement);
// dry-run detects + audits but does not mutate/block (NO_ENFORCE_MODES in core).
async function startProxy({ dir, keyFile, mode, upstream, maxInFlight = 0 }) {
  const runtime = createRuntime({
    mode,
    target: { type: "openai-compatible", upstream },
    // Action set: redact/mask (the common enforce shape) — it exercises the full
    // detect → policy → transform → audit pipeline on both request and response.
    // We deliberately do NOT default to `tokenize`: AES-GCM encrypt-per-detection
    // plus the detokenize round-trip is CPU-bound on one thread and would make the
    // default run minutes, not seconds, and would measure crypto contention rather
    // than the proxy's per-request overhead. Probe the crypto path explicitly by
    // overriding the action set in a custom run if you need it.
    policy: {
      mode,
      presets: ["llm-redact"],
      actions: { email: "redact", phone: "mask", secret: "redact", api_key: "redact", card: "block" }
    },
    responseProtection: { enabled: mode === "enforce", mode, failureMode: "fail-closed" },
    limits: { maxInFlight },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", `audit-${mode}-${maxInFlight}.jsonl`) }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const addr = await proxy.listen();
  return { proxy, base: `http://127.0.0.1:${addr.port}` };
}

// ── Backpressure scenario ───────────────────────────────────────────────────
// Set a LOW limits.maxInFlight, point the proxy at a SLOW stub (so slots stay
// occupied), and fire a burst wider than the ceiling all at once. Count the
// ACTUAL responses: 503 (haechi_overloaded, with a Retry-After header) vs 200.
// We do NOT hardcode the split — we observe what the live proxy returns.
async function runBackpressure({ dir, keyFile }) {
  const slowStub = await startStubUpstream({ delayMs: 150 });
  let proxyHandle = null;
  try {
    proxyHandle = await startProxy({
      dir, keyFile, mode: "enforce", upstream: slowStub.url, maxInFlight: MAXINFLIGHT
    });
    const { base } = proxyHandle;
    const body = buildBody();
    // Fire a burst comfortably wider than the ceiling so some requests arrive
    // while all slots are occupied and get shed.
    const burst = MAXINFLIGHT * 6;
    const results = await Promise.all(Array.from({ length: burst }, () =>
      fetch(`${base}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body
      }).then(async (res) => {
        const retryAfter = res.headers.get("retry-after");
        await res.arrayBuffer();
        return { status: res.status, retryAfter };
      }).catch(() => ({ status: 0, retryAfter: null }))
    ));

    const ok = results.filter((r) => r.status === 200).length;
    const shed = results.filter((r) => r.status === 503).length;
    const withRetryAfter = results.filter((r) => r.status === 503 && r.retryAfter != null).length;
    const other = results.length - ok - shed;
    return {
      maxInFlight: MAXINFLIGHT,
      burst,
      upstreamDelayMs: 150,
      status200: ok,
      status503: shed,
      status503WithRetryAfter: withRetryAfter,
      otherStatus: other
    };
  } finally {
    if (proxyHandle) { await proxyHandle.proxy.close(); }
    await slowStub.close();
  }
}

async function main() {
  // Header — make the honesty caveat impossible to miss.
  process.stdout.write("\n");
  process.stdout.write("Haechi proxy throughput / latency micro-benchmark\n");
  process.stdout.write("=".repeat(64) + "\n");
  process.stdout.write("LOOPBACK, single-process, STUB-upstream. The stub, the proxy, and the\n");
  process.stdout.write("load generator all run in ONE Node process on 127.0.0.1 — NO real network,\n");
  process.stdout.write("NO real model. These numbers measure HAECHI'S ADDED OVERHEAD, not network\n");
  process.stdout.write("throughput or hardware capacity. Numbers vary by machine / Node version /\n");
  process.stdout.write("load. Do NOT quote them as guarantees.\n");
  process.stdout.write("-".repeat(64) + "\n");
  process.stdout.write(`config: requests=${REQUESTS} concurrency=${CONCURRENCY} warmup=${WARMUP} `);
  process.stdout.write(`payloadKB=${PAYLOAD_KB} backpressureMaxInFlight=${MAXINFLIGHT}\n`);
  process.stdout.write(`node=${process.version} percentiles=nearest-rank(sorted)\n`);
  process.stdout.write(`warmup: the first ${WARMUP} completed requests are EXCLUDED from the reported stats\n`);
  process.stdout.write("-".repeat(64) + "\n");

  const dir = await mkdtemp(join(tmpdir(), "haechi-bench-throughput-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const body = buildBody();

  const stub = await startStubUpstream();
  const results = {};
  try {
    // Scenario 1 + 2: same load, enforce then dry-run.
    for (const mode of ["enforce", "dry-run"]) {
      const handle = await startProxy({ dir, keyFile, mode, upstream: stub.url });
      try {
        results[mode] = await drive({
          base: handle.base,
          total: REQUESTS,
          concurrency: CONCURRENCY,
          warmup: WARMUP,
          body
        });
      } finally {
        await handle.proxy.close();
      }
    }
  } finally {
    await stub.close();
  }

  // Scenario 3: backpressure (its own slow stub + low ceiling).
  const backpressure = await runBackpressure({ dir, keyFile });

  // Best-effort temp cleanup (never fail the bench on a cleanup error).
  await rm(dir, { recursive: true, force: true }).catch(() => {});

  // ── Report ────────────────────────────────────────────────────────────────
  const fmtRow = (label, s) =>
    `${label.padEnd(10)} req/s=${String(s.reqPerSec).padStart(9)}  ` +
    `p50=${String(s.p50Ms).padStart(7)}ms  p95=${String(s.p95Ms).padStart(7)}ms  ` +
    `p99=${String(s.p99Ms).padStart(7)}ms  max=${String(s.maxMs).padStart(7)}ms`;

  process.stdout.write("\nThroughput + latency (warmup excluded)\n");
  process.stdout.write(fmtRow("enforce", results.enforce) + "\n");
  process.stdout.write(fmtRow("dry-run", results["dry-run"]) + "\n");

  // enforce vs dry-run overhead delta — the COST of protection as a measured
  // number. Positive deltaP50 = enforce is slower (expected: it transforms).
  const e = results.enforce;
  const d = results["dry-run"];
  const pct = (a, b) => (b !== 0 ? round(((a - b) / b) * 100) : 0);
  process.stdout.write("\nenforce vs dry-run overhead (enforce minus dry-run)\n");
  process.stdout.write(
    `  p50 delta = ${round(e.p50Ms - d.p50Ms)}ms (${pct(e.p50Ms, d.p50Ms)}%)  ` +
    `req/s delta = ${round(e.reqPerSec - d.reqPerSec)} (${pct(e.reqPerSec, d.reqPerSec)}%)\n`
  );

  process.stdout.write("\nBackpressure (limits.maxInFlight ceiling under a saturating burst)\n");
  process.stdout.write(
    `  maxInFlight=${backpressure.maxInFlight}  burst=${backpressure.burst}  ` +
    `upstreamDelayMs=${backpressure.upstreamDelayMs}\n`
  );
  process.stdout.write(
    `  200=${backpressure.status200}  503=${backpressure.status503}  ` +
    `503+Retry-After=${backpressure.status503WithRetryAfter}  other=${backpressure.otherStatus}\n`
  );
  if (backpressure.status503 === 0) {
    process.stdout.write(
      "  note: no 503s observed — the host drained the burst faster than the ceiling\n" +
      "  filled. Raise HAECHI_BENCH_MAXINFLIGHT pressure by lowering it, or re-run.\n"
    );
  }

  // Machine-readable tail so a CI job / spreadsheet can ingest one line.
  process.stdout.write("\n" + JSON.stringify({
    config: { requests: REQUESTS, concurrency: CONCURRENCY, warmup: WARMUP, payloadKb: PAYLOAD_KB, maxInFlight: MAXINFLIGHT, node: process.version },
    enforce: results.enforce,
    dryRun: results["dry-run"],
    backpressure
  }) + "\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    process.stderr.write(`bench:throughput failed: ${error?.stack ?? error}\n`);
    process.exit(1);
  });
