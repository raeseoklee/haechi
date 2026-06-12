import test from "node:test";
import assert from "node:assert/strict";
import { createDefaultFilterEngine } from "../packages/filter/index.mjs";
import { collectStringEntries } from "../packages/core/index.mjs";

test("default filter detects common PII and secrets", async () => {
  const filter = createDefaultFilterEngine();
  const payload = {
    message: "Email minji.kim@example.com, phone 010-1234-5678, token sk_demo_1234567890abcdef1234567890abcdef"
  };

  const detections = await filter.detect({ entries: collectStringEntries(payload), context: {} });
  const types = detections.map((detection) => detection.type).sort();

  assert.deepEqual(types, ["api_key", "email", "phone"]);
});

test("custom filter rule can be added without changing core", async () => {
  const filter = createDefaultFilterEngine({
    customRules: [
      {
        id: "internal-contract",
        type: "contract_id",
        pattern: "CT-[0-9]{6}",
        confidence: 0.8
      }
    ]
  });

  const detections = await filter.detect({
    entries: collectStringEntries({ message: "internal id CT-123456" }),
    context: {}
  });

  assert.equal(detections[0].type, "contract_id");
});

test("KR RRN detector requires checksum-valid synthetic values", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({
      valid: "synthetic 900101-1234568",
      invalid: "synthetic 900101-1234567"
    }),
    context: {}
  });

  assert.equal(detections.filter((detection) => detection.type === "kr_rrn").length, 1);
});

test("Haechi's own transform markers are never re-detected (no self-flagging)", async () => {
  const filter = createDefaultFilterEngine();
  // `[TOKEN:` reads like a `token:<secret>` assignment; without marker exclusion
  // Haechi would flag its own token as a `secret` (and block a tokenized
  // round-trip in response-enforce). The encrypt/redact markers must be inert too.
  const detections = await filter.detect({
    entries: collectStringEntries({
      tokenized: "please email [TOKEN:tok_email_a6d376389bb21964] today",
      encrypted: "value [HAECHI_ENC:eyJhbGciOiJBMjU2R0NNIn0] here",
      redacted: "value [REDACTED:email] here"
    }),
    context: { direction: "response" }
  });
  assert.deepEqual(detections, []);
});

test("marker exclusion is response-only: a request can't smuggle a secret in a fake marker", async () => {
  const filter = createDefaultFilterEngine();
  // On the REQUEST direction (Haechi hasn't transformed anything yet), a
  // marker-shaped wrapper is NOT trusted — the real key inside is still detected.
  const detections = await filter.detect({
    entries: collectStringEntries({ evasion: "key is [TOKEN:sk_demo_0123456789abcdef01234567] hidden" }),
    context: { direction: "request" }
  });
  assert.ok(detections.some((d) => d.type === "api_key"), "request-side must still detect the wrapped key");
});

test("marker exclusion is positional: a real secret ADJACENT to a marker is still detected on the response", async () => {
  const filter = createDefaultFilterEngine();
  // The exclusion drops only detections that OVERLAP a marker span — a key that
  // merely sits next to a marker must still be caught, so a marker boundary
  // cannot be used to hide an adjacent secret the model leaks.
  const detections = await filter.detect({
    entries: collectStringEntries({
      glued: "[TOKEN:tok_abc]sk_demo_0123456789abcdef01234567",
      spaced: "[TOKEN:tok_abc] sk_demo_0123456789abcdef01234567"
    }),
    context: { direction: "response" }
  });
  assert.equal(detections.filter((d) => d.type === "api_key").length, 2);
});

test("response-direction skips bare number leaves (metadata) but keeps strings and request numbers", async () => {
  const filter = createDefaultFilterEngine();
  // A long Luhn-passing duration / 13-digit count is inference-server metadata,
  // not a model-leaked card/RRN — not scanned on the response.
  const respNumber = await filter.detect({
    entries: collectStringEntries({ total_duration: 4242424242424242, eval_duration: 1781129892000 }),
    context: { direction: "response" }
  });
  assert.deepEqual(respNumber, []);
  // But a card the model leaks in generated TEXT (a string) is still caught.
  const respText = await filter.detect({
    entries: collectStringEntries({ choices: [{ message: { content: "your card is 4242 4242 4242 4242" } }] }),
    context: { direction: "response" }
  });
  assert.ok(respText.some((d) => d.type === "card"));
  // The exemption is narrow — a card inside a STRINGIFIED-JSON string (kind
  // "value", not "number") is still detected on the response.
  const respStringified = await filter.detect({
    entries: collectStringEntries({ tool: JSON.stringify({ card: 4242424242424242 }) }),
    context: { direction: "response" }
  });
  assert.ok(respStringified.some((d) => d.type === "card"));
  // And the REQUEST direction still scans numbers (a client can send a card/RRN as a number).
  const reqNumber = await filter.detect({
    entries: collectStringEntries({ card: 4242424242424242, rrn: 9001011234568 }),
    context: { direction: "request" }
  });
  const reqTypes = reqNumber.map((d) => d.type);
  assert.ok(reqTypes.includes("card") && reqTypes.includes("kr_rrn"));
});

test("responseProtection.scanNumbers opts back into scanning response number leaves", async () => {
  const filter = createDefaultFilterEngine();
  // A strict deployment can set scanNumbers: true (threaded as context.scanNumbers)
  // to scan response numbers too — accepting the metadata false positives.
  const scanned = await filter.detect({
    entries: collectStringEntries({ card: 4242424242424242 }),
    context: { direction: "response", scanNumbers: true }
  });
  assert.ok(scanned.some((d) => d.type === "card"), "scanNumbers:true scans response number leaves");
});

test("the phone-rule tightening does not affect card detection", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({ card: "4242 4242 4242 4242" }),
    context: {}
  });
  const types = detections.map((d) => d.type);
  assert.ok(types.includes("card"), "a Luhn-valid 16-digit card is still detected as card");
  assert.ok(!types.includes("phone"), "a card is not misclassified as a phone");
});

test("KR phone detector ignores bare ambiguous numbers but keeps real phone formats", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({
      timestamp: 1781129892,            // unix seconds — looks phone-shaped, is not
      counter: "1719999999",            // bare 10-digit, no separator, not 0-led
      sep: "010-1234-5678",             // real, separated
      noSep: "01012345678",             // real, no separator, 0-led
      intl: "+82 10 1234 5678"          // real, +82
    }),
    context: {}
  });
  const phones = detections.filter((d) => d.type === "phone").map((d) => d.path.join(".")).sort();
  assert.deepEqual(phones, ["intl", "noSep", "sep"]);
});

// All values below are SYNTHETIC test fixtures (documented examples / fabricated
// random chars) — never real credentials, per CLAUDE.md.
async function typesFor(text, direction = "request") {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({ content: text }),
    context: { direction }
  });
  return new Set(detections.map((d) => d.type));
}

test("WS2b credential rules detect anchored cloud/VCS/JWT/PEM formats", async () => {
  // AWS access key id: anchored AKIA/ASIA + exactly 16 uppercase-alnum.
  assert.ok((await typesFor("AWS access key AKIAIOSFODNN7EXAMPLE used")).has("api_key"));
  // GitHub token: anchored gh[pousr]_ + long base64-ish body.
  assert.ok((await typesFor("PAT ghp_0123456789abcdefghijklmnopqrstuvwxyzAB leaked")).has("secret"));
  // Google API key: anchored AIza + 35 chars.
  assert.ok((await typesFor("key AIzaSyA1234567890abcdefghijklmnopqrstuv here")).has("api_key"));
  // Slack token: anchored xox[baprs]- + >=10-char body (low-entropy placeholder).
  assert.ok((await typesFor("xoxb-PLACEHOLDER-PLACEHOLDER-notARealSlackTokenForTests")).has("secret"));
  // JWT: three base64url segments, first starts eyJ.
  assert.ok((await typesFor("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")).has("secret"));
  // PEM private key header.
  assert.ok((await typesFor("-----BEGIN RSA PRIVATE KEY----- MIIBOg... -----END RSA PRIVATE KEY-----")).has("secret"));
});

test("WS2b credential rules are anchored — no bare-prefix / no-armor false positives", async () => {
  // AKIA without the full 16-char body must not match.
  assert.ok(!(await typesFor("the value AKIA1234 and AKIANOTLONGENOUGH appear")).has("api_key"));
  // ghp_ with a short body must not match.
  assert.ok(!(await typesFor("see ghp_short in the notes")).has("secret"));
  // AIza without a 35-char body must not match.
  assert.ok(!(await typesFor("AIzaShort is not a key")).has("api_key"));
  // Slack: too-short body and a non-allowlisted prefix char.
  assert.ok(!(await typesFor("xoxb-short and xoxe-unknownprefix")).has("secret"));
  // A dotted triplet whose first segment is not eyJ is not a JWT.
  assert.ok(!(await typesFor("build foo.bar.baz and abc.def.ghi")).has("secret"));
  // The words "private key" with no PEM armor header are not a secret.
  assert.ok(!(await typesFor("rotate the private key before the deploy")).has("secret"));
});

test("WS2b expanded assignment-secret vocabulary catches cloud/OAuth secret assignments", async () => {
  assert.ok((await typesFor("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).has("secret"));
  assert.ok((await typesFor("client_secret: 0123456789abcdef0123 committed")).has("secret"));
  assert.ok((await typesFor("refresh_token = 0123456789abcdef0123 in the env")).has("secret"));
});

test("WS2b US SSN rule + SSA-range validator", async () => {
  // The public synthetic SSN passes the validator.
  assert.ok((await typesFor("US SSN 078-05-1120 on the form")).has("us_ssn"));
  // Area 666 is never issued — rejected by the validator.
  assert.ok(!(await typesFor("SSN 666-12-1234 is invalid")).has("us_ssn"));
  // Area 900-999, group 00, serial 0000 are rejected too.
  assert.ok(!(await typesFor("SSN 900-12-1234")).has("us_ssn"));
  assert.ok(!(await typesFor("SSN 078-00-1120")).has("us_ssn"));
  assert.ok(!(await typesFor("SSN 078-05-0000")).has("us_ssn"));
  // A bare 9-digit id (no separators) is never an SSN.
  assert.ok(!(await typesFor("order number 078051120 shipped")).has("us_ssn"));
});

test("WS2b IBAN rule + mod-97 checksum validator", async () => {
  // The public ECB German IBAN example passes mod-97.
  assert.ok((await typesFor("IBAN DE89370400440532013000 from ECB")).has("iban"));
  // An IBAN-shaped string that breaks mod-97 is rejected.
  assert.ok(!(await typesFor("ref DE89370400440532013001 fails checksum")).has("iban"));
});

test("WS2b phone rules: E.164 needs a leading +, US national needs separators, bare runs rejected", async () => {
  // E.164 with a leading +.
  assert.ok((await typesFor("call +14155552671 now")).has("phone"));
  // US national with separators (both parenthesized and dashed forms).
  assert.ok((await typesFor("call (415) 555-2671 today")).has("phone"));
  assert.ok((await typesFor("call 415-555-2671 today")).has("phone"));
  // A bare separator-less, plus-less digit run is NOT a phone (collides with ids).
  assert.ok(!(await typesFor("account id 12345678901 and ticket 4155552671")).has("phone"));
});

test("WS2c kr-phone boundary: a UUID substring is not mis-detected as a phone, real numbers still match", async () => {
  const filter = createDefaultFilterEngine();
  // The '…a716-446655440000' tail of a UUID used to mis-fire (the inner
  // 16-44665544 ran the kr-phone rule). The word-boundary anchors stop a phone
  // matching as a SUBSTRING of a longer hex/dashed run.
  const uuid = await filter.detect({
    entries: collectStringEntries({ requestId: "550e8400-e29b-41d4-a716-446655440000" }),
    context: {}
  });
  assert.ok(!uuid.some((d) => d.type === "phone"), "a UUID must not produce a phone detection");
  // A bare phone-shaped run embedded in a longer alnum run is also rejected.
  const embedded = await filter.detect({
    entries: collectStringEntries({ blob: "x01012345678x" }),
    context: {}
  });
  assert.ok(!embedded.some((d) => d.type === "phone"), "a phone glued inside a longer alnum run is not matched");
  // Recall preserved: a real separated KR mobile and a +82 form still match.
  const real = await filter.detect({
    entries: collectStringEntries({
      sep: "010-1234-5678",
      intl: "+82 10 1234 5678",
      noSep: "01012345678"
    }),
    context: {}
  });
  const phonePaths = real.filter((d) => d.type === "phone").map((d) => d.path.join(".")).sort();
  assert.deepEqual(phonePaths, ["intl", "noSep", "sep"], "real KR mobile / +82 numbers still detected");
});

test("custom filter rejects unsafe regex shapes", () => {
  assert.throws(
    () => createDefaultFilterEngine({
      customRules: [
        {
          id: "unsafe",
          type: "unsafe",
          pattern: "(a+)+"
        }
      ]
    }),
    /nested quantifiers/
  );
});
