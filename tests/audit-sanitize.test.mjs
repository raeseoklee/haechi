import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createJsonlAuditSink, sanitizeAudit } from "../packages/audit/index.mjs";

// The OIDC-broker token / secret / OAuth-flow parameter keys that core's audit
// sink must strip if such a field ever appears on an event. These are additive
// to the pre-existing value/plaintext/payload/content/message/prompt/secret set.
const OIDC_FORBIDDEN_KEYS = [
  "access_token", "id_token", "refresh_token", "code", "code_verifier",
  "client_secret", "state", "nonce"
];

test("sanitizeAudit strips OIDC token/secret/flow-parameter keys at every depth", () => {
  const event = {
    id: "e-1",
    provider: "oidc",
    subjectHash: "keyed-hmac-subject",
    // A future/hostile audit field carrying raw OAuth/OIDC material.
    access_token: "AT-raw",
    id_token: "eyJ-raw",
    refresh_token: "RT-raw",
    code: "authz-code",
    code_verifier: "pkce-verifier",
    client_secret: "shhh",
    state: "csrf-state",
    nonce: "anti-replay",
    nested: {
      access_token: "AT-nested",
      reasonCode: "ok"
    },
    list: [{ refresh_token: "RT-in-array", keep: 1 }]
  };

  const sanitized = sanitizeAudit(event);

  for (const key of OIDC_FORBIDDEN_KEYS) {
    assert.equal(key in sanitized, false, `top-level ${key} must be stripped`);
  }
  assert.equal("access_token" in sanitized.nested, false, "nested token must be stripped");
  assert.equal("refresh_token" in sanitized.list[0], false, "array-nested token must be stripped");

  // Non-forbidden, identity-safe fields are preserved untouched.
  assert.equal(sanitized.provider, "oidc");
  assert.equal(sanitized.subjectHash, "keyed-hmac-subject");
  assert.equal(sanitized.nested.reasonCode, "ok");
  assert.equal(sanitized.list[0].keep, 1);

  // sub/email are deliberately NOT blanket-redacted by core.
  const passthrough = sanitizeAudit({ sub: "subject-id", email: "a@b.test" });
  assert.equal(passthrough.sub, "subject-id");
  assert.equal(passthrough.email, "a@b.test");
});

test("the audit sink strips OIDC token/secret keys from the written record", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-audit-oidc-"));
  const path = join(dir, "audit.jsonl");
  const sink = createJsonlAuditSink({ path });

  await sink.record({
    id: "e-1",
    timestamp: new Date(0).toISOString(),
    protocol: "test",
    operation: "oidc.login.success",
    mode: "enforce",
    enforced: true,
    blocked: false,
    provider: "oidc",
    access_token: "AT-raw",
    id_token: "eyJ-raw",
    refresh_token: "RT-raw",
    code: "authz-code",
    code_verifier: "pkce-verifier",
    client_secret: "shhh",
    state: "csrf-state",
    nonce: "anti-replay",
    summary: { detectionCount: 0, byType: {}, byAction: {} }
  });

  const raw = (await readFile(path, "utf8")).trim();
  const record = JSON.parse(raw);

  // None of the forbidden keys survive into the persisted record...
  for (const key of OIDC_FORBIDDEN_KEYS) {
    assert.equal(key in record, false, `${key} must not be persisted`);
  }
  // ...and none of their raw values appear anywhere in the serialized line.
  for (const secret of ["AT-raw", "eyJ-raw", "RT-raw", "authz-code", "pkce-verifier", "shhh", "csrf-state", "anti-replay"]) {
    assert.equal(raw.includes(secret), false, `raw value ${secret} must not leak into the audit line`);
  }

  // The event still records normally (integrity chain + safe fields intact).
  assert.equal(record.provider, "oidc");
  assert.equal(record.operation, "oidc.login.success");
  assert.equal(record.auditIntegrity.sequence, 1);
});
