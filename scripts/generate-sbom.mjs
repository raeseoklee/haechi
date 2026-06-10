#!/usr/bin/env node
// Generate a CycloneDX SBOM for the PUBLISHED `haechi` core artifact only.
//
// Caveat handled here: the repo is an npm workspaces monorepo whose root self-
// lists (`workspaces: [".", "satellites/*"]`) so satellites can resolve core.
// `npm sbom` therefore reports the local `haechi-*` satellites as if they were
// dependencies of `haechi` — they are NOT (core's package.json has zero
// `dependencies`; satellites are independently published siblings). We strip
// those local workspace components so the SBOM describes the zero-dependency
// `haechi` tarball, matching what `scripts/check-core-packaging.mjs` enforces.
//
// The transform is pure and exported so the satellite-stripping logic is unit
// tested (over-strip / under-strip) without invoking `npm sbom`.

import { spawnSync } from "node:child_process";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// Names of the local satellite workspaces (e.g. "haechi-crypto-kms") — these
// are sibling packages, never runtime deps of core.
export async function localSatelliteNames(root = "satellites") {
  const names = new Set();
  let entries = [];
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return names;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      const pkg = JSON.parse(await readFile(`${root}/${entry.name}/package.json`, "utf8"));
      if (pkg.name) names.add(pkg.name);
    } catch {
      // ignore unreadable/non-package dirs
    }
  }
  return names;
}

// A SBOM ref/purl identifies a satellite if its package coordinate IS one of the
// local packages — matched on the package-name boundary, not a loose substring,
// so a future real dep like "haechi-crypto-kms-utils" is never mistaken for the
// "haechi-crypto-kms" satellite. Handles both the bom-ref form
// ("haechi-crypto-kms@0.1.0") and the purl form ("pkg:npm/%40haechi/crypto-kms@0.1.0").
export function refIsSatellite(ref, satelliteNames) {
  if (!ref) return false;
  let coord = String(ref);
  try {
    coord = decodeURIComponent(coord);
  } catch {
    // malformed %-encoding: fall back to the raw string
  }
  coord = coord.replace(/^pkg:npm\//, "");
  for (const name of satelliteNames) {
    // exact name, or name immediately followed by the "@version" separator
    if (coord === name || coord.startsWith(`${name}@`)) return true;
  }
  return false;
}

// Pure transform: stamp the core metadata component and drop local satellite
// components + their dependency-graph edges, so the SBOM reflects core's actual
// (empty) runtime dependency closure. Returns a new SBOM object.
export function stripSatellites(sbom, satelliteNames, { name, version } = {}) {
  const out = { ...sbom };
  if (out.metadata?.component && name && version) {
    out.metadata = {
      ...out.metadata,
      component: {
        ...out.metadata.component,
        name,
        version,
        "bom-ref": `${name}@${version}`
      }
    };
  }
  if (Array.isArray(out.components)) {
    out.components = out.components.filter(
      (c) => !refIsSatellite(c["bom-ref"] ?? c.purl, satelliteNames)
    );
  }
  if (Array.isArray(out.dependencies)) {
    out.dependencies = out.dependencies
      .filter((d) => !refIsSatellite(d.ref, satelliteNames))
      .map((d) => ({
        ...d,
        ...(Array.isArray(d.dependsOn)
          ? { dependsOn: d.dependsOn.filter((ref) => !refIsSatellite(ref, satelliteNames)) }
          : {})
      }));
  }
  return out;
}

async function main() {
  const result = spawnSync("npm", ["sbom", "--sbom-format", "cyclonedx", "--omit", "dev"], {
    encoding: "utf8"
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }

  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const rawSbom = JSON.parse(result.stdout);
  const satelliteNames = await localSatelliteNames();
  const sbom = stripSatellites(rawSbom, satelliteNames, {
    name: packageJson.name,
    version: packageJson.version
  });

  await writeFile("sbom.cdx.json", `${JSON.stringify(sbom, null, 2)}\n`, "utf8");
  const stripped = satelliteNames.size ? ` (stripped ${satelliteNames.size} local satellite workspace(s))` : "";
  process.stderr.write(`wrote sbom.cdx.json for ${packageJson.name}@${packageJson.version}${stripped}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`generate-sbom: ${error.message}\n`);
    process.exitCode = 1;
  });
}
