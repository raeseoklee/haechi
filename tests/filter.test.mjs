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
