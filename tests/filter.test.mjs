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
