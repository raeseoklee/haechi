import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { getPrivacyProfile, listPrivacyProfiles, applyPrivacyProfile } from "../packages/privacy-profiles/index.mjs";

test("privacy profiles expose regional policy metadata", () => {
  const profiles = listPrivacyProfiles();
  assert.deepEqual(profiles.map((profile) => profile.id).sort(), ["eu-gdpr", "jp-appi", "kr-pipa", "us-general"]);
  assert.equal(getPrivacyProfile("eu-gdpr").transfer.requiresAssessment, true);
});

test("international PII types map to block where regionally appropriate", () => {
  // EU profile blocks the EU national IDs and (cross-region) My Number.
  const eu = getPrivacyProfile("eu-gdpr").policy.actions;
  for (const type of ["fr_nir", "es_dni", "uk_nino", "jp_mynumber"]) {
    assert.equal(eu[type], "block", `eu-gdpr must block ${type}`);
  }
  // jp_mynumber is blocked in every profile (a checksummed national-ID leak).
  for (const id of ["kr-pipa", "eu-gdpr", "us-general", "jp-appi"]) {
    assert.equal(getPrivacyProfile(id).policy.actions.jp_mynumber, "block", `${id} must block jp_mynumber`);
  }
  // The JP profile is the regional home for My Number.
  assert.equal(getPrivacyProfile("jp-appi").region, "JP");
});

test("applyPrivacyProfile strengthens but never weakens an explicit user action (international PII)", () => {
  // A user who already encrypts fr_nir must NOT be downgraded to block (encrypt
  // is weaker than block by ACTION_STRENGTH, so block would strengthen) — but a
  // user who explicitly BLOCKS jp_mynumber stays at block, and a missing action
  // gets the profile's block.
  const merged = applyPrivacyProfile({ actions: { fr_nir: "block", uk_nino: "redact" } }, "eu-gdpr");
  assert.equal(merged.actions.fr_nir, "block", "an explicit block is preserved");
  assert.equal(merged.actions.uk_nino, "block", "a weaker explicit redact is strengthened to the profile block");
  assert.equal(merged.actions.es_dni, "block", "a missing action takes the profile block");
  assert.equal(merged.privacyProfile, "eu-gdpr");
});

test("runtime applies privacy profile actions before enforcement", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-privacy-profile-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const runtime = createRuntime({
    mode: "enforce",
    privacy: {
      profile: "eu-gdpr"
    },
    policy: {
      mode: "enforce",
      presets: [],
      defaultAction: "allow",
      actions: {}
    },
    keys: { keyFile },
    audit: { path: join(dir, ".haechi", "audit.jsonl") }
  });

  const result = await runtime.haechi.protectJson({
    message: "contact minji.kim@example.com"
  });

  assert.match(result.payload.message, /\[TOKEN:tok_email_/);
});
