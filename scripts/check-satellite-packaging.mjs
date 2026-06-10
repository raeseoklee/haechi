#!/usr/bin/env node
// Packaging gate for the published `@haechi/*` satellite tarballs.
//
//   node scripts/check-satellite-packaging.mjs [workspace ...]   # default: @haechi/crypto-kms
//
// The core gate (check-core-packaging.mjs) guards `haechi`; this guards the
// satellites, before the irreversible publish. Invariants per satellite tarball:
//   1. ZERO runtime `dependencies` — a satellite carries its KMS/AWS client as an
//      OPTIONAL peer dependency, never a hard runtime dep (and the `haechi`
//      workspace devDep must be stripped by `npm pack`).
//   2. Every `files` entry and every `exports` target is actually in the tarball
//      (a missing main/subpath export ships a broken package).
//   3. No `*.test.mjs` leaks into the published tarball.
//
// The evaluation is pure and exported so it is unit-tested (a leaked test file /
// a promoted dependency / a missing export must each make it fail).

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const norm = (p) => p.replace(/^package\//, "").replace(/^\.\//, "");

export function evaluateSatellitePackaging({ name, files, manifest }) {
  const label = name || manifest.name || "satellite";
  const problems = [];
  const present = new Set(files.map(norm));

  const deps = manifest.dependencies && typeof manifest.dependencies === "object" ? Object.keys(manifest.dependencies) : [];
  if (deps.length > 0) {
    problems.push(`${label} declares runtime dependencies (use optional peer deps instead): ${deps.join(", ")}`);
  }

  for (const f of manifest.files || []) {
    if (typeof f !== "string" || f.endsWith("/")) continue;
    if (!present.has(norm(f))) problems.push(`${label}: declared file missing from tarball: ${f}`);
  }

  const targets = [];
  const collect = (v) => {
    if (typeof v === "string") targets.push(v);
    else if (v && typeof v === "object") Object.values(v).forEach(collect);
  };
  collect(manifest.exports);
  for (const t of targets) {
    if (!present.has(norm(t))) problems.push(`${label}: exports target missing from tarball: ${t}`);
  }

  const leakedTests = files.map(norm).filter((p) => /\.test\.mjs$/.test(p));
  if (leakedTests.length > 0) {
    problems.push(`${label}: test files leaked into the tarball: ${leakedTests.join(", ")}`);
  }

  return { ok: problems.length === 0, problems };
}

export function packSatellite(workspace) {
  const dir = mkdtempSync(join(tmpdir(), "haechi-sat-pack-"));
  try {
    const out = execFileSync("npm", ["pack", "-w", workspace, "--json", "--pack-destination", dir], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"]
    });
    const meta = JSON.parse(out);
    const entry = Array.isArray(meta) ? meta[0] : meta;
    if (entry && entry.error) {
      throw new Error(`npm pack -w ${workspace} failed: ${entry.error.summary || entry.error.detail || "unknown error"}`);
    }
    const files = (entry.files || []).map((f) => f.path);
    if (files.length === 0) {
      throw new Error(`npm pack -w ${workspace} produced an empty file list`);
    }
    const tgz = entry.filename
      ? join(dir, entry.filename.split("/").pop())
      : join(dir, readdirSync(dir).find((n) => n.endsWith(".tgz")));
    const manifestText = execFileSync("tar", ["-xzOf", tgz, "package/package.json"], { encoding: "utf8" });
    return { name: workspace, files, manifest: JSON.parse(manifestText) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main(argv) {
  const workspaces = argv.length > 0 ? argv : ["@haechi/crypto-kms"];
  let ok = true;
  for (const ws of workspaces) {
    const { name, files, manifest } = packSatellite(ws);
    const result = evaluateSatellitePackaging({ name, files, manifest });
    if (!result.ok) {
      ok = false;
      for (const p of result.problems) process.stderr.write(`satellite-packaging: FAIL ${p}\n`);
    } else {
      process.stderr.write(`satellite-packaging: OK ${manifest.name}@${manifest.version} — zero deps, exports+files present, no test leak (${files.length} files)\n`);
    }
  }
  process.exitCode = ok ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`check-satellite-packaging: ${error.message}\n`);
    process.exitCode = 1;
  });
}
