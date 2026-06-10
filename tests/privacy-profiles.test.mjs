import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile } from "../packages/crypto/index.mjs";
import { getPrivacyProfile, listPrivacyProfiles } from "../packages/privacy-profiles/index.mjs";

test("privacy profiles expose regional policy metadata", () => {
  const profiles = listPrivacyProfiles();
  assert.deepEqual(profiles.map((profile) => profile.id).sort(), ["eu-gdpr", "kr-pipa", "us-general"]);
  assert.equal(getPrivacyProfile("eu-gdpr").transfer.requiresAssessment, true);
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
