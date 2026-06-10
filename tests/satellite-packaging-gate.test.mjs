import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSatellitePackaging, packSatellite } from "../scripts/check-satellite-packaging.mjs";

const CLEAN = {
  name: "haechi-crypto-kms",
  files: ["package.json", "index.mjs", "aws.mjs", "README.md"],
  manifest: {
    name: "haechi-crypto-kms",
    version: "0.1.0",
    files: ["index.mjs", "aws.mjs", "README.md"],
    exports: { ".": "./index.mjs", "./aws": "./aws.mjs" },
    peerDependencies: { haechi: ">=0.8.0 <1.0.0", "@aws-sdk/client-kms": "^3" },
    peerDependenciesMeta: { "@aws-sdk/client-kms": { optional: true } }
  }
};

test("evaluateSatellitePackaging passes the clean satellite", () => {
  const r = evaluateSatellitePackaging(CLEAN);
  assert.equal(r.ok, true, r.problems.join("; "));
});

test("FAILS when the satellite declares a runtime dependency (peer must stay peer)", () => {
  const r = evaluateSatellitePackaging({
    ...CLEAN,
    manifest: { ...CLEAN.manifest, dependencies: { "@aws-sdk/client-kms": "^3" } }
  });
  assert.equal(r.ok, false);
  assert.match(r.problems.join("\n"), /runtime dependencies/);
});

test("FAILS when an exports target is missing from the tarball", () => {
  const r = evaluateSatellitePackaging({ ...CLEAN, files: ["package.json", "index.mjs", "README.md"] });
  assert.equal(r.ok, false);
  assert.match(r.problems.join("\n"), /exports target missing.*aws/);
});

test("FAILS when a declared file is missing from the tarball", () => {
  const r = evaluateSatellitePackaging({
    ...CLEAN,
    files: ["package.json", "index.mjs", "aws.mjs"] // README.md absent
  });
  assert.equal(r.ok, false);
  assert.match(r.problems.join("\n"), /declared file missing.*README/);
});

test("FAILS when a test file leaks into the tarball", () => {
  const r = evaluateSatellitePackaging({
    ...CLEAN,
    files: [...CLEAN.files, "aws.test.mjs"]
  });
  assert.equal(r.ok, false);
  assert.match(r.problems.join("\n"), /test files leaked/);
});

test("the real packed haechi-crypto-kms tarball is clean", () => {
  const { files, manifest } = packSatellite("haechi-crypto-kms");
  const r = evaluateSatellitePackaging({ name: "haechi-crypto-kms", files, manifest });
  assert.equal(manifest.name, "haechi-crypto-kms");
  assert.equal(r.ok, true, r.problems.join("; "));
  assert.deepEqual(manifest.dependencies ?? {}, {}); // optional peer not promoted to a runtime dep
});
