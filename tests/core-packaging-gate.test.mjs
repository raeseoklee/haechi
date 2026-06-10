import test from "node:test";
import assert from "node:assert/strict";
import {
  findSatellitePaths,
  findRuntimeDeps,
  evaluatePackaging,
  packCore
} from "../scripts/check-core-packaging.mjs";

// A representative slice of what `npm pack --json` reports for core.
const CLEAN_FILES = [
  "README.md",
  "package.json",
  "packages/core/index.mjs",
  "packages/crypto/index.mjs",
  "examples/crypto-kms-reference/README.md",
  "scripts/release-checksums.mjs"
];

test("findSatellitePaths ignores core files and flags satellite leaks", () => {
  assert.deepEqual(findSatellitePaths(CLEAN_FILES), []);
  assert.deepEqual(
    findSatellitePaths([...CLEAN_FILES, "satellites/crypto-kms/index.mjs"]),
    ["satellites/crypto-kms/index.mjs"]
  );
  // Defensive: `npm pack --json` reports paths WITHOUT the archive's `package/`
  // prefix (so packCore never passes one), but findSatellitePaths strips it
  // anyway so it stays correct if reused on raw tar member names. A `./` prefix
  // is likewise tolerated.
  assert.deepEqual(findSatellitePaths(["package/satellites/x.mjs"]), ["package/satellites/x.mjs"]);
  assert.deepEqual(findSatellitePaths(["./satellites/x.mjs"]), ["./satellites/x.mjs"]);
});

test("findRuntimeDeps treats empty/missing dependencies as zero-dep", () => {
  assert.deepEqual(findRuntimeDeps({}), []);
  assert.deepEqual(findRuntimeDeps({ dependencies: {} }), []);
  assert.deepEqual(findRuntimeDeps({ dependencies: { "@aws-sdk/client-kms": "^3" } }), ["@aws-sdk/client-kms"]);
});

test("evaluatePackaging passes the clean case", () => {
  const result = evaluatePackaging({ files: CLEAN_FILES, manifest: { name: "haechi", version: "0.8.0" } });
  assert.equal(result.ok, true);
  assert.deepEqual(result.problems, []);
});

test("evaluatePackaging FAILS when a satellite file leaks into the tarball", () => {
  const result = evaluatePackaging({
    files: [...CLEAN_FILES, "satellites/crypto-kms/index.mjs"],
    manifest: { name: "haechi", version: "0.8.0" }
  });
  assert.equal(result.ok, false);
  assert.match(result.problems.join("\n"), /satellite files leaked/);
});

test("evaluatePackaging FAILS when core declares a runtime dependency", () => {
  const result = evaluatePackaging({
    files: CLEAN_FILES,
    manifest: { name: "haechi", version: "0.8.0", dependencies: { lodash: "^4" } }
  });
  assert.equal(result.ok, false);
  assert.match(result.problems.join("\n"), /runtime dependencies/);
});

test("the real packed core tarball is clean (no satellite leak, zero runtime deps)", () => {
  const { files, manifest } = packCore();
  const result = evaluatePackaging({ files, manifest });
  assert.equal(manifest.name, "haechi");
  assert.equal(result.ok, true, `core packaging problems: ${result.problems.join("; ")}`);
  // and nothing under satellites/ ships
  assert.equal(files.some((f) => f.includes("satellites/")), false);
});
