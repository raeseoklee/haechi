#!/usr/bin/env node
// Self-contained, reproducible Haechi demo — no remote model required.
//
// It stands up a tiny OpenAI-compatible *stub* upstream and the REAL Haechi proxy
// in front of it, then walks through what Haechi does to a payload that carries an
// email, a phone number, an API key, and a card:
//   1. the model only ever sees redacted/tokenized values (proven by echoing the
//      exact body the stub received),
//   2. the caller gets the original email back (the token round-trip),
//   3. the audit log carries no plaintext,
//   4. the live /__haechi/metrics + /__haechi/ready operability surface,
//   5. a card is blocked outright (fail-closed).
//
// Run:  node examples/local-proxy-demo/demo.mjs   (or: npm run demo)
// Zero dependencies — only node: builtins and the in-repo haechi packages.

import { createServer } from "node:http";
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

// A minimal OpenAI-compatible stub. It records the EXACT body it receives (which is
// whatever the proxy forwarded, i.e. the protected payload) and replies with a
// canned assistant message that itself leaks a secret, to exercise response protection.
function startStubUpstream() {
  let lastReceived = null;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      lastReceived = body;
      // Echo the (already-protected) user content back so the response exercises the
      // token round-trip, and append a leaked secret so response protection fires.
      let echoed = "";
      try { echoed = JSON.parse(body).messages.at(-1).content; } catch { /* ignore */ }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id: "chatcmpl-demo",
        object: "chat.completion",
        choices: [{ index: 0, message: { role: "assistant",
          content: `Noted — I will follow up. You wrote: "${echoed}" (our ref: token=DEMOleak9876543210notRealzyxwvu)` } }]
      }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}`, received: () => lastReceived }));
  });
}

async function main() {
  console.log(`\n${B}🛡  Haechi — local end-to-end demo${X}  ${D}(stub upstream, real proxy, enforce mode)${X}`);

  const dir = await mkdtemp(join(tmpdir(), "haechi-demo-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  const auditPath = join(dir, ".haechi", "audit.jsonl");
  await initLocalKeyFile(keyFile, { force: true });
  const stub = await startStubUpstream();

  const runtime = createRuntime({
    mode: "enforce",
    target: { type: "openai-compatible", upstream: stub.url },
    policy: {
      mode: "enforce",
      presets: ["llm-redact"],
      actions: { email: "tokenize", phone: "mask", secret: "redact", api_key: "redact", card: "block" }
    },
    tokenVault: { detokenizeResponses: true },
    responseProtection: { enabled: true, mode: "enforce", failureMode: "fail-closed" },
    keys: { keyFile },
    audit: { path: auditPath }
  });
  const proxy = createHaechiProxy({ runtime, port: 0 });
  const addr = await proxy.listen();
  const base = `http://127.0.0.1:${addr.port}`;

  // ── Scene 1 ───────────────────────────────────────────────────────────────
  scene(1, "A prompt with an email, a phone number, and a deploy secret");
  const userText = "Contact minji.kim@example.com or 010-1234-5678. Deploy api_key=DEMOkey0123456789notARealSecretabcdef.";
  console.log(`${Y}you send →${X} ${userText}`);
  await pause(700);
  const r1 = await fetch(`${base}/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: userText }] })
  });
  const out1 = await r1.json();

  scene(2, "What the MODEL actually received (the proxy protected it first)");
  const forwarded = JSON.parse(stub.received());
  console.log(`${G}model sees →${X} ${forwarded.messages[0].content}`);
  console.log(`${D}  (email → [TOKEN:…], phone → masked, secret → [REDACTED])${X}`);
  await pause(700);

  scene(3, "What YOU get back — the email token is restored (round-trip)");
  console.log(`${G}you receive →${X} ${out1.choices[0].message.content}`);
  console.log(`${D}  (email restored from its token; phone stays masked; keys stay redacted both ways)${X}`);
  await pause(700);

  // ── Scene 4 ───────────────────────────────────────────────────────────────
  scene(4, "The audit log — tamper-evident, and never any plaintext");
  const audit = (await readFile(auditPath, "utf8")).trim().split("\n");
  const ev = JSON.parse(audit[0]);
  console.log(`${D}detections:${X} ${ev.detections.map((d) => `${d.type}→${d.action}`).join("  ")}`);
  console.log(`${D}leaks the email/secret/phone?${X} ${audit.join("").match(/minji\.kim@|DEMOkey0123|010-1234-5678/) ? R + "YES" + X : G + "no — clean" + X}`);
  await pause(700);

  // ── Scene 5 ───────────────────────────────────────────────────────────────
  scene(5, "Day-2 operability — live health + Prometheus metrics");
  const ready = await (await fetch(`${base}/__haechi/ready`)).json();
  console.log(`${D}/__haechi/ready →${X} ${ready.ready ? G + "ready" : R + "not ready"}${X} ${D}(audit writable: ${ready.checks?.auditWritable})${X}`);
  const metrics = await (await fetch(`${base}/__haechi/metrics`)).text();
  for (const line of metrics.split("\n").filter((l) => /^haechi_requests_total\{|^haechi_blocks_total /.test(l)).slice(0, 4)) {
    console.log(`${D}metric:${X} ${line}`);
  }
  await pause(700);

  // ── Scene 6 ───────────────────────────────────────────────────────────────
  scene(6, "A card number is blocked outright (fail-closed)");
  const r2 = await fetch(`${base}/v1/chat/completions`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "demo", messages: [{ role: "user", content: "charge card 4242 4242 4242 4242 now" }] })
  });
  console.log(`${Y}you send →${X} "charge card 4242 4242 4242 4242 now"`);
  console.log(`${G}proxy →${X} HTTP ${r2.status} ${r2.status === 403 ? R + B + "BLOCKED" + X : ""} ${D}(the card never reaches the model)${X}`);

  console.log();
  rule();
  console.log(`${B}${G}  ✓ done${X}  ${D}— detection → redact/tokenize/block → forward → audit, all local.${X}`);
  rule();
  console.log(`${D}  config reference: haechi.config.example.json   ·   docs/current/configuration.md${X}\n`);

  await proxy.close();
  stub.server.close();
}

main().then(() => process.exit(0)).catch((e) => { console.error("demo failed:", e); process.exit(1); });
