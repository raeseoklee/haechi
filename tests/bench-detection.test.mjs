import test from "node:test";
import assert from "node:assert/strict";
import {
  scoreCorpus,
  ratios,
  compareToBaseline,
  buildBaseline,
  SCORED_TYPES,
  loadCorpus,
  CORPUS_PATH
} from "../scripts/bench-detection.mjs";

// A tiny deterministic engine that "detects" a type when the corpus text
// contains a sentinel substring `<<type>>`. Lets us assert the bench math
// against hand-computed precision/recall without depending on the real rules.
function fakeEngine() {
  return {
    async detect({ entries }) {
      const text = entries.map((entry) => entry.value).join(" ");
      const detections = [];
      for (const type of SCORED_TYPES) {
        if (text.includes(`<<${type}>>`)) {
          detections.push({ type });
        }
      }
      return detections;
    }
  };
}

test("ratios: precision = TP/(TP+FP), recall = TP/(TP+FN)", () => {
  assert.deepEqual(ratios({ tp: 3, fp: 1, fn: 1 }), { precision: 0.75, recall: 0.75 });
  assert.deepEqual(ratios({ tp: 0, fp: 0, fn: 0 }), { precision: 1, recall: 1 });
  assert.deepEqual(ratios({ tp: 0, fp: 2, fn: 0 }), { precision: 0, recall: 1 });
  assert.deepEqual(ratios({ tp: 0, fp: 0, fn: 4 }), { precision: 1, recall: 0 });
});

test("scoreCorpus computes the hand-checked per-type confusion matrix", async () => {
  // email: 1 TP (detected+expected) + 1 FN (expected, not detected) -> P=1, R=0.5
  // card:  1 FP (detected, expected-absent)                          -> P=0, R=1
  const cases = [
    { text: "hit <<email>>", expect: [{ type: "email", present: true }], note: "tp" },
    { text: "miss email", expect: [{ type: "email", present: true }], note: "fn" },
    { text: "lookalike <<card>>", expect: [{ type: "card", present: false }], note: "fp" },
    { text: "clean", expect: [{ type: "card", present: false }], note: "tn (uncounted)" }
  ];
  const scores = await scoreCorpus(fakeEngine(), cases);

  assert.deepEqual(
    { tp: scores.perType.email.tp, fp: scores.perType.email.fp, fn: scores.perType.email.fn },
    { tp: 1, fp: 0, fn: 1 }
  );
  assert.equal(scores.perType.email.precision, 1);
  assert.equal(scores.perType.email.recall, 0.5);

  assert.deepEqual(
    { tp: scores.perType.card.tp, fp: scores.perType.card.fp, fn: scores.perType.card.fn },
    { tp: 0, fp: 1, fn: 0 }
  );
  assert.equal(scores.perType.card.precision, 0);
  assert.equal(scores.perType.card.recall, 1);

  // Totals aggregate across types: TP=1, FP=1, FN=1 -> P=R=0.5
  assert.deepEqual(
    { tp: scores.totals.tp, fp: scores.totals.fp, fn: scores.totals.fn },
    { tp: 1, fp: 1, fn: 1 }
  );
  assert.equal(scores.totals.precision, 0.5);
  assert.equal(scores.totals.recall, 0.5);
});

test("scoreCorpus collects known coverage gaps (expected-present + gap + missed)", async () => {
  const cases = [
    { text: "missed", expect: [{ type: "secret", present: true, gap: true }], note: "gap miss" }
  ];
  const scores = await scoreCorpus(fakeEngine(), cases);
  assert.equal(scores.gaps.length, 1);
  assert.equal(scores.gaps[0].type, "secret");
  assert.equal(scores.perType.secret.fn, 1);
});

test("compareToBaseline passes when scores equal the pinned baseline (no regression)", async () => {
  const cases = [
    { text: "<<email>>", expect: [{ type: "email", present: true }], note: "tp" },
    { text: "<<card>> lookalike", expect: [{ type: "card", present: false }], note: "fp" }
  ];
  const scores = await scoreCorpus(fakeEngine(), cases);
  const baseline = buildBaseline(scores);
  const verdict = compareToBaseline(scores, baseline);
  assert.equal(verdict.ok, true);
  assert.deepEqual(verdict.regressions, []);
});

test("compareToBaseline TRIPS on a simulated regression (precision drops below baseline)", async () => {
  // Pin a clean baseline from an engine with no false positive on `card`.
  const baselineCases = [
    { text: "<<card>>", expect: [{ type: "card", present: true }], note: "tp" },
    { text: "order 4242", expect: [{ type: "card", present: false }], note: "tn (no FP)" }
  ];
  const baseline = buildBaseline(await scoreCorpus(fakeEngine(), baselineCases));
  assert.equal(baseline.perType.card.precision, 1);

  // Now the SAME engine on a corpus where a lookalike trips `card` -> a new FP,
  // dropping precision to 0.5. The gate must flag this regression.
  const regressedCases = [
    { text: "<<card>>", expect: [{ type: "card", present: true }], note: "tp" },
    { text: "order <<card>>", expect: [{ type: "card", present: false }], note: "NEW false positive" }
  ];
  const regressed = await scoreCorpus(fakeEngine(), regressedCases);
  assert.equal(regressed.perType.card.precision, 0.5);

  const verdict = compareToBaseline(regressed, baseline);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.regressions.some((r) => r.type === "card" && r.metric === "precision"));
});

test("compareToBaseline does not trip on a recorded gap that stays missed (recall holds)", async () => {
  // A baseline with a known FN (gap): recall 0.5. Re-running the same engine
  // keeps recall at 0.5 -> not below baseline -> no regression.
  const cases = [
    { text: "<<api_key>>", expect: [{ type: "api_key", present: true }], note: "tp" },
    { text: "AKIA gap", expect: [{ type: "api_key", present: true, gap: true }], note: "recorded miss" }
  ];
  const scores = await scoreCorpus(fakeEngine(), cases);
  assert.equal(scores.perType.api_key.recall, 0.5);
  const baseline = buildBaseline(scores);
  const verdict = compareToBaseline(await scoreCorpus(fakeEngine(), cases), baseline);
  assert.equal(verdict.ok, true);
});

test("compareToBaseline tolerates baseline rounding (no phantom regression at 2/3)", async () => {
  // 2 TP / 1 FP -> precision 0.6666…; the baseline stores it rounded to
  // 0.666667. Re-comparing the live 0.6666… against that must NOT regress.
  const cases = [
    { text: "<<phone>>", expect: [{ type: "phone", present: true }], note: "tp1" },
    { text: "<<phone>>", expect: [{ type: "phone", present: true }], note: "tp2" },
    { text: "<<phone>> id", expect: [{ type: "phone", present: false }], note: "fp" }
  ];
  const scores = await scoreCorpus(fakeEngine(), cases);
  const baseline = buildBaseline(scores);
  assert.equal(baseline.perType.phone.precision, 0.666667);
  assert.equal(compareToBaseline(scores, baseline).ok, true);
});

test("the shipped corpus loads and the live engine matches the pinned baseline", async () => {
  // Guards the real corpus + baseline against drift: the committed baseline must
  // describe the committed corpus under the real default engine.
  const { createDefaultFilterEngine } = await import("../packages/filter/index.mjs");
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const baselinePath = fileURLToPath(new URL("../scripts/detection-baseline.json", import.meta.url));

  const cases = loadCorpus(CORPUS_PATH);
  assert.ok(cases.length >= 20, "corpus should have a healthy number of cases");
  const scores = await scoreCorpus(createDefaultFilterEngine(), cases);
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
  const verdict = compareToBaseline(scores, baseline);
  assert.equal(verdict.ok, true, `committed baseline is stale vs corpus: ${JSON.stringify(verdict.regressions)}`);
});
