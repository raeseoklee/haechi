#!/usr/bin/env node
// No-leak + zero-dep gate for the published core `haechi` tarball.
//
//   node scripts/check-core-packaging.mjs
//
// Two invariants the monorepo conversion must never break (release-0.8 §2.1/§6.1):
//   1. No satellite files leak into the core tarball (satellites/ are their own
//      published packages, not part of `haechi`).
//   2. The packed core manifest declares ZERO runtime dependencies — core stays
//      `node:`-only. We inspect the **packed** package.json (extracted from the
//      tarball `npm pack` produces), not the installed node_modules SBOM, which
//      passes vacuously today and would miss a future runtime-dep leak.
//
// The check logic is pure and exported so it can be exercised by negative tests
// (a satellite path / a runtime dep must make it fail) — a gate that is never
// seen to fail is not a gate.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// --- pure checks -----------------------------------------------------------

// npm pack lists files at the tarball root WITHOUT the leading `package/` that
// the archive itself uses, e.g. "packages/core/index.mjs". A satellite leak
// shows up as a path under "satellites/".
export function findSatellitePaths(fileNames) {
  return fileNames.filter((name) => /^(\.\/)?satellites\//.test(name.replace(/^package\//, "")));
}

// Returns the runtime dependency names declared by the packed manifest. Empty or
// missing `dependencies` is the only acceptable state for zero-dep core.
export function findRuntimeDeps(manifest) {
  const deps = manifest && manifest.dependencies;
  if (!deps || typeof deps !== "object") {
    return [];
  }
  return Object.keys(deps);
}

export function evaluatePackaging({ files, manifest }) {
  const problems = [];
  const leaked = findSatellitePaths(files);
  if (leaked.length > 0) {
    problems.push(`satellite files leaked into the core tarball: ${leaked.join(", ")}`);
  }
  const deps = findRuntimeDeps(manifest);
  if (deps.length > 0) {
    problems.push(`core declares runtime dependencies (must be zero): ${deps.join(", ")}`);
  }
  return { ok: problems.length === 0, problems };
}

// --- tarball acquisition (CLI side) ---------------------------------------

// Pack core to a temp dir and return { files, manifest } read back from the
// actual tarball — files from `npm pack --json`, manifest extracted via tar so
// we inspect exactly what consumers download.
export function packCore() {
  const dir = mkdtempSync(join(tmpdir(), "haechi-pack-"));
  try {
    const out = execFileSync("npm", ["pack", "--json", "--pack-destination", dir], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"]
    });
    const meta = JSON.parse(out);
    const entry = Array.isArray(meta) ? meta[0] : meta;
    if (entry && entry.error) {
      throw new Error(`npm pack failed: ${entry.error.summary || entry.error.detail || "unknown error"}`);
    }
    const files = (entry.files || []).map((f) => f.path);
    // A real core pack lists dozens of files. An empty list would make the
    // no-leak check pass vacuously, so refuse it rather than report a false OK.
    if (files.length === 0) {
      throw new Error("npm pack --json produced an empty file list — refusing to vacuously pass the no-leak check");
    }
    const tgz = entry.filename
      ? join(dir, basenameOf(entry.filename))
      : join(dir, readdirSync(dir).find((n) => n.endsWith(".tgz")));
    // `-O` writes the extracted member to stdout; the path inside the archive is
    // always `package/package.json` regardless of the package name.
    const manifestText = execFileSync("tar", ["-xzOf", tgz, "package/package.json"], { encoding: "utf8" });
    return { files, manifest: JSON.parse(manifestText) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// npm sometimes reports `filename` with the scope folded into a path-safe form;
// for the unscoped `haechi` it is a plain basename, but stay defensive.
function basenameOf(filename) {
  return filename.split("/").pop();
}

async function main() {
  const { files, manifest } = packCore();
  const { ok, problems } = evaluatePackaging({ files, manifest });
  if (!ok) {
    for (const p of problems) {
      process.stderr.write(`core-packaging: FAIL ${p}\n`);
    }
    process.exitCode = 1;
    return;
  }
  process.stderr.write(`core-packaging: OK ${manifest.name}@${manifest.version} — no satellite leak, zero runtime deps (${files.length} files)\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`check-core-packaging: ${error.message}\n`);
    process.exitCode = 1;
  });
}
