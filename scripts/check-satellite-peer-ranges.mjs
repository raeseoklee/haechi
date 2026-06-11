#!/usr/bin/env node
/**
 * check-satellite-peer-ranges.mjs
 *
 * Zero-dependency (node: builtins only) gate that asserts every satellite's
 * peerDependencies range for "haechi" (and "haechi-auth-jwt" where present)
 * is satisfied by the version this repo would publish.
 *
 * Exits 0 if all ranges are satisfied; exits 1 with a clear error otherwise.
 *
 * Exported for unit-testing:
 *   satisfies(version, range)  — minimal ">=A <B" semver satisfies check
 *   checkAll()                 — run all satellite checks, returns { ok, errors }
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = resolve(__dirname, "..");

// ---------------------------------------------------------------------------
// Minimal semver helpers — handles exactly the ">=LOWER <UPPER" two-comparator
// shape used in every satellite peerDependency. Throws on any other shape so
// a future odd range is caught immediately, not silently passed.
// ---------------------------------------------------------------------------

/**
 * Parse "MAJOR.MINOR.PATCH" (no pre-release, no build metadata) into [M, N, P].
 * Throws if the string is not three dot-separated non-negative integers.
 */
function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) throw new Error(`Cannot parse version: ${JSON.stringify(v)}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/**
 * Compare two [M,N,P] tuples.
 * Returns -1 if a < b, 0 if equal, 1 if a > b.
 */
function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

/**
 * satisfies(version, range)
 *
 * Handles exactly the ">=A.B.C <D.E.F" two-comparator shape.
 * Throws if range is any other shape.
 *
 * @param {string} version  — e.g. "1.0.0"
 * @param {string} range    — e.g. ">=0.8.0 <2.0.0"
 * @returns {boolean}
 */
export function satisfies(version, range) {
  const m = /^>=(\d+\.\d+\.\d+)\s+<(\d+\.\d+\.\d+)$/.exec(range.trim());
  if (!m) {
    throw new Error(
      `Unsupported peer range shape (expected ">=A.B.C <D.E.F"): ${JSON.stringify(range)}`
    );
  }
  const v = parseVersion(version);
  const lower = parseVersion(m[1]);
  const upper = parseVersion(m[2]);
  return cmp(v, lower) >= 0 && cmp(v, upper) < 0;
}

// ---------------------------------------------------------------------------
// Core check logic
// ---------------------------------------------------------------------------

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * checkAll()
 *
 * Reads core version from root package.json, then walks each
 * satellites/<name>/package.json checking peerDependencies for "haechi" and "haechi-auth-jwt".
 *
 * @returns {{ ok: boolean, errors: string[], lines: string[] }}
 */
export function checkAll() {
  const rootPkg = readJson(join(ROOT, "package.json"));
  const coreVersion = rootPkg.version;

  // Resolve the in-repo version for each known peer package.
  const peerVersions = {
    haechi: coreVersion,
    "haechi-auth-jwt": readJson(
      join(ROOT, "satellites", "auth-jwt", "package.json")
    ).version,
  };

  const satellitesDir = join(ROOT, "satellites");
  const satelliteDirs = readdirSync(satellitesDir).filter((name) => {
    const p = join(satellitesDir, name);
    return statSync(p).isDirectory();
  });

  const errors = [];
  const lines = [];

  for (const dir of satelliteDirs.sort()) {
    const pkgPath = join(satellitesDir, dir, "package.json");
    let pkg;
    try {
      pkg = readJson(pkgPath);
    } catch {
      errors.push(`::error:: ${dir}: cannot read package.json at ${pkgPath}`);
      continue;
    }

    const peers = pkg.peerDependencies ?? {};
    const satelliteName = pkg.name ?? dir;
    let satelliteOk = true;

    for (const [dep, range] of Object.entries(peers)) {
      if (!(dep in peerVersions)) continue; // only check haechi / haechi-auth-jwt

      const inRepoVersion = peerVersions[dep];
      let ok;
      try {
        ok = satisfies(inRepoVersion, range);
      } catch (err) {
        errors.push(
          `::error:: ${satelliteName}: peer "${dep}" range ${JSON.stringify(range)} — ${err.message}`
        );
        satelliteOk = false;
        continue;
      }

      if (!ok) {
        errors.push(
          `::error:: ${satelliteName}: peer "${dep}" range ${JSON.stringify(range)} does NOT satisfy in-repo version ${inRepoVersion}`
        );
        satelliteOk = false;
      } else {
        lines.push(
          `satellite-peer-ranges: OK  ${satelliteName}  "${dep}": "${range}"  (in-repo: ${inRepoVersion})`
        );
      }
    }

    if (satelliteOk && Object.keys(peers).filter((d) => d in peerVersions).length === 0) {
      lines.push(`satellite-peer-ranges: OK  ${satelliteName}  (no haechi/haechi-auth-jwt peer)`);
    }
  }

  return { ok: errors.length === 0, errors, lines };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { ok, errors, lines } = checkAll();

  for (const line of lines) {
    process.stdout.write(line + "\n");
  }
  for (const err of errors) {
    process.stderr.write(err + "\n");
  }

  if (ok) {
    process.stdout.write("satellite-peer-ranges: all checks passed\n");
    process.exit(0);
  } else {
    process.stderr.write(
      `satellite-peer-ranges: ${errors.length} check(s) failed\n`
    );
    process.exit(1);
  }
}
