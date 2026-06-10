import test from "node:test";
import assert from "node:assert/strict";
import { refIsSatellite, stripSatellites } from "../scripts/generate-sbom.mjs";

const SATS = new Set(["haechi-crypto-kms"]);

test("refIsSatellite matches the bom-ref and purl forms of a satellite", () => {
  assert.equal(refIsSatellite("haechi-crypto-kms@0.1.0", SATS), true);
  assert.equal(refIsSatellite("pkg:npm/haechi-crypto-kms@0.1.0", SATS), true);
  assert.equal(refIsSatellite("pkg:npm/haechi-crypto-kms@0.1.0?type=tgz", SATS), true);
  assert.equal(refIsSatellite("haechi-crypto-kms", SATS), true); // no version
});

test("refIsSatellite does NOT over-strip a different package sharing the name as a prefix", () => {
  // The previous substring match would have wrongly stripped these.
  assert.equal(refIsSatellite("haechi-crypto-kms-utils@1.0.0", SATS), false);
  assert.equal(refIsSatellite("pkg:npm/haechi-crypto-kms-extra@2.0.0", SATS), false);
  assert.equal(refIsSatellite("haechi-crypto@1.0.0", SATS), false);
  assert.equal(refIsSatellite("haechi@0.8.0", SATS), false);
});

test("refIsSatellite is safe on empty/malformed refs", () => {
  assert.equal(refIsSatellite("", SATS), false);
  assert.equal(refIsSatellite(null, SATS), false);
  assert.equal(refIsSatellite("pkg:npm/%ZZbad@1.0.0", SATS), false); // bad %-encoding, no throw
});

test("stripSatellites removes satellite components and dep edges, stamps core metadata", () => {
  const raw = {
    metadata: { component: { name: "p2p-encryption", version: "0.0.0", "bom-ref": "x" } },
    components: [
      { name: "haechi-crypto-kms", "bom-ref": "haechi-crypto-kms@0.1.0", purl: "pkg:npm/haechi-crypto-kms@0.1.0" }
    ],
    dependencies: [
      { ref: "haechi@0.8.0", dependsOn: ["haechi-crypto-kms@0.1.0"] },
      { ref: "haechi-crypto-kms@0.1.0", dependsOn: [] }
    ]
  };
  const out = stripSatellites(raw, SATS, { name: "haechi", version: "0.8.0" });
  assert.deepEqual(out.components, []);
  assert.equal(out.metadata.component.name, "haechi");
  assert.equal(out.metadata.component.version, "0.8.0");
  assert.equal(out.metadata.component["bom-ref"], "haechi@0.8.0");
  // the haechi node remains but no longer depends on the satellite; the
  // satellite's own dependency node is gone
  assert.deepEqual(out.dependencies.map((d) => d.ref), ["haechi@0.8.0"]);
  assert.deepEqual(out.dependencies[0].dependsOn, []);
});

test("stripSatellites preserves a genuine runtime dependency (must not over-strip)", () => {
  // If core ever legitimately depended on a registry package, the SBOM must keep
  // it. (The check:packaging gate independently forbids core runtime deps, so
  // this is belt-and-suspenders: the SBOM never hides a real dep.)
  const raw = {
    components: [{ name: "left-pad", "bom-ref": "left-pad@1.3.0", purl: "pkg:npm/left-pad@1.3.0" }],
    dependencies: [
      { ref: "haechi@0.8.0", dependsOn: ["left-pad@1.3.0", "haechi-crypto-kms@0.1.0"] },
      { ref: "left-pad@1.3.0", dependsOn: [] }
    ]
  };
  const out = stripSatellites(raw, SATS, { name: "haechi", version: "0.8.0" });
  assert.deepEqual(out.components.map((c) => c.name), ["left-pad"]);
  assert.deepEqual(out.dependencies[0].dependsOn, ["left-pad@1.3.0"]);
  assert.deepEqual(out.dependencies.map((d) => d.ref), ["haechi@0.8.0", "left-pad@1.3.0"]);
});
