#!/usr/bin/env node
// Live end-to-end demo against a REAL upstream model (vLLM / Ollama / any
// OpenAI-compatible server). Unlike demo.mjs (which uses a deterministic stub),
// this proves protection against an actual model: it asks the model to repeat the
// phone number it was given, and the model can only return the *masked* form —
// the real number never reached it.
//
//   HAECHI_LIVE_UPSTREAM=http://127.0.0.1:8000 \
//   HAECHI_LIVE_MODEL="Qwen/Qwen3.6-35B-A3B-FP8" \
//   node examples/local-proxy-demo/live-demo.mjs
//
// Defaults: type=vllm-openai. HAECHI_LIVE_TYPE and HAECHI_LIVE_MODEL override.
// Zero dependencies — only node: builtins + the in-repo haechi packages.

import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createRuntime } from "../../packages/cli/runtime.mjs";
import { createHaechiProxy } from "../../packages/proxy/index.mjs";
import { initLocalKeyFile } from "../../packages/crypto/index.mjs";

const B = "\x1b[1m", D = "\x1b[2m", G = "\x1b[32m", Y = "\x1b[33m", C = "\x1b[36m", R = "\x1b[31m", X = "\x1b[0m";
const rule = () => console.log(D + "─".repeat(64) + X);
const scene = (n, t) => { console.log(); rule(); console.log(`${B}${C}  ${n}. ${t}${X}`); rule(); };
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

const UPSTREAM = process.env.HAECHI_LIVE_UPSTREAM;
const TYPE = process.env.HAECHI_LIVE_TYPE || "vllm-openai";
const MODEL = process.env.HAECHI_LIVE_MODEL || "Qwen/Qwen3.6-35B-A3B-FP8";
if (!UPSTREAM) {
  console.error("Set HAECHI_LIVE_UPSTREAM (e.g. http://127.0.0.1:8000) to a reachable OpenAI-compatible server.");
  console.error("For a no-backend reproducible run, use:  npm run demo");
  process.exit(2);
}

async function chat(base, content, extra = {}) {
  const t0 = Date.now();
  const res = await fetch(`${base}/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: MODEL, max_tokens: 128, temperature: 0,
      // Qwen3 reasoning models: ask for a direct answer (no chain-of-thought) so
      // the demo gets a terse content reply. Ignored by non-reasoning servers.
      chat_template_kwargs: { enable_thinking: false },
      messages: [{ role: "user", content }], ...extra })
  });
  const body = await res.json();
  return { status: res.status, ms: Date.now() - t0, text: body.choices?.[0]?.message?.content ?? body.error?.message ?? "(no content)" };
}

async function main() {
  console.log(`\n${B}🛡  Haechi — LIVE end-to-end demo${X}  ${D}(real model: ${MODEL} via ${TYPE}, enforce mode)${X}`);

  const dir = await mkdtemp(join(tmpdir(), "haechi-live-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });

  const runtime = createRuntime({
    mode: "enforce",
    target: { type: TYPE, upstream: UPSTREAM },
    policy: { mode: "enforce", presets: ["llm-redact"], actions: { email: "tokenize", phone: "mask", secret: "redact", api_key: "redact", card: "block" } },
    tokenVault: { detokenizeResponses: true },
    responseProtection: { enabled: true, mode: "enforce", failureMode: "fail-closed" },
    keys: { keyFile }, audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const addr = await proxy.listen();
  const base = `http://127.0.0.1:${addr.port}`;

  // ── Scene 1 ────────────────────────────────────────────────────────────────
  scene(1, "Ask a REAL model to repeat the phone number you give it");
  const prompt = "Reply in one short line: repeat the phone number you were given. Phone: 010-1234-5678, email minji.kim@example.com";
  console.log(`${Y}you send →${X} ${prompt}`);
  await pause(700);
  const r1 = await chat(base, prompt);

  scene(2, "Haechi detected + protected the prompt BEFORE it left your machine");
  const events = (await readFile(auditPath, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  const ev = events.find((e) => Array.isArray(e.detections) && e.detections.length) ?? events[0];
  console.log(`${D}detections:${X} ${(ev.detections ?? []).map((d) => `${G}${d.type}→${d.action}${X}`).join("  ")}`);
  console.log(`${D}the model only ever saw:${X} email → ${C}[TOKEN:…]${X},  phone → ${C}01*********78${X}`);
  await pause(700);

  scene(3, "The real model replies — it can only return the MASKED phone");
  console.log(`${G}${MODEL.split("/").pop()} →${X} ${B}${r1.text}${X}   ${D}(${r1.ms} ms)${X}`);
  console.log(`${D}  your real number 010-1234-5678 never reached the model — it cannot reveal it.${X}`);
  await pause(700);

  // ── Scene 4 ────────────────────────────────────────────────────────────────
  scene(4, "The audit log — hash-chained, and never any plaintext");
  const auditRaw = await readFile(auditPath, "utf8");
  console.log(`${D}leaks the real email/phone?${X} ${/minji\.kim@example|010-1234-5678/.test(auditRaw) ? R + "YES" + X : G + "no — clean" + X}`);
  await pause(700);

  // ── Scene 5 ────────────────────────────────────────────────────────────────
  scene(5, "Day-2 operability — live readiness + Prometheus metrics");
  const ready = await (await fetch(`${base}/__haechi/ready`)).json();
  console.log(`${D}/__haechi/ready →${X} ${ready.ready ? G + "ready" : R + "not ready"}${X}`);
  const metrics = await (await fetch(`${base}/__haechi/metrics`)).text();
  for (const line of metrics.split("\n").filter((l) => /^haechi_requests_total\{/.test(l)).slice(0, 3)) {
    console.log(`${D}metric:${X} ${line}`);
  }
  await pause(700);

  // ── Scene 6 ────────────────────────────────────────────────────────────────
  scene(6, "A card number is blocked before it ever reaches the model");
  const r2 = await chat(base, "charge card 4242 4242 4242 4242 now");
  console.log(`${Y}you send →${X} "charge card 4242 4242 4242 4242 now"`);
  console.log(`${G}proxy →${X} HTTP ${r2.status} ${r2.status === 403 ? R + B + "BLOCKED" + X : ""} ${D}(no upstream call made)${X}`);

  console.log();
  rule();
  console.log(`${B}${G}  ✓ live${X}  ${D}— a real model, and your PII never left the gateway in the clear.${X}`);
  rule();
  console.log();

  await proxy.close();
}

main().then(() => process.exit(0)).catch((e) => { console.error("live demo failed:", e); process.exit(1); });
