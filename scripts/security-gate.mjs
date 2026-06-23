#!/usr/bin/env node
// Security gate: a NAMED, independently-required CI check over the cross-cutting
// security invariants. These suites also run inside the full `npm test`, but
// this gate runs them as a distinct, branch-protectable status so a restructure
// of the test suite can never silently drop a load-bearing security invariant —
// and a missing file fails the gate LOUDLY (coverage must not vanish) rather
// than shrinking the gate to whatever still happens to exist.
//
// Each entry names the invariant it guards. Add a row when a new high-severity
// security invariant gets a home; do not remove one without a recorded decision.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const SUITE = [
  ["tests/crypto.test.mjs", "AAD binding + v2 NFKC AAD + AEAD tamper rejection + key rotation/kid selection + freshness"],
  ["tests/nonce-budget.test.mjs", "per-key random-IV invocation limit fails closed (no GCM nonce reuse)"],
  ["tests/audit-plugin-forbidden-keys.test.mjs", "no plaintext/secret/PII in audit (FORBIDDEN_KEYS), plugin path"],
  ["tests/audit-sanitize.test.mjs", "audit event sanitization (no raw payload/prompt values)"],
  ["tests/precision-controls.test.mjs", "hard-block types cannot be suppressed by minConfidence/allowlist"],
  ["tests/privacy-profiles.test.mjs", "privacy profiles strengthen-only (never weaken an explicit action)"],
];

const missing = SUITE.filter(([file]) => !existsSync(join(repoRoot, file)));
if (missing.length > 0) {
  console.error("SECURITY GATE: FAILED — security test file(s) are missing; coverage must not vanish:");
  for (const [file, invariant] of missing) {
    console.error(`  - ${file}  (${invariant})`);
  }
  process.exit(1);
}

console.error("SECURITY GATE — enforcing security invariants:");
for (const [file, invariant] of SUITE) {
  console.error(`  • ${file}: ${invariant}`);
}

const result = spawnSync("node", ["--test", ...SUITE.map(([file]) => file)], {
  cwd: repoRoot,
  stdio: "inherit",
});

if (result.error) {
  console.error(`SECURITY GATE: FAILED to run — ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) {
  console.error("SECURITY GATE: FAILED — a security invariant regressed.");
  process.exit(result.status ?? 1);
}
console.error("SECURITY GATE: passed.");
