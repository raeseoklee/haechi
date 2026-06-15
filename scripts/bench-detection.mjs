#!/usr/bin/env node
// WS2a — Detection-quality measurement foundation.
//
// Loads the labeled corpus (tests/fixtures/detection-corpus.json), runs the
// default filter engine over each case, and computes PER-TYPE precision/recall
// (TP / FP / FN). Prints a deterministic table. With `--gate` it compares the
// live scores against a pinned baseline (scripts/detection-baseline.json) and
// FAILS only on a REGRESSION (precision OR recall dropping below baseline for a
// type) — never on an already-recorded coverage gap. With `--write-baseline`
// it (re)writes the baseline snapshot from the current engine state.
//
// node:-only, zero runtime deps, deterministic. This module MEASURES; it does
// not modify any packages/filter rule (that is WS2b).
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createDefaultFilterEngine } from "../packages/filter/index.mjs";
import { collectStringEntries } from "../packages/core/index.mjs";

export const CORPUS_PATH = fileURLToPath(new URL("../tests/fixtures/detection-corpus.json", import.meta.url));
export const BASELINE_PATH = fileURLToPath(new URL("./detection-baseline.json", import.meta.url));

// The fixed set of built-in detection types the corpus scores. Custom-rule
// types are out of scope for the baseline gate.
export const SCORED_TYPES = ["email", "phone", "kr_rrn", "card", "api_key", "secret", "injection", "us_ssn", "iban", "jp_mynumber", "fr_nir", "es_dni", "uk_nino"];

export function loadCorpus(path = CORPUS_PATH) {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed.cases)) {
    throw new Error(`detection corpus at ${path} has no "cases" array`);
  }
  return parsed.cases;
}

// Run one corpus case through an engine and return the SET of types detected.
// Each case is wrapped as a single string leaf so the corpus text is what gets
// scored, independent of any JSON envelope shape.
export async function detectTypes(engine, testCase) {
  const context = { direction: testCase.direction ?? "request" };
  const entries = collectStringEntries({ content: String(testCase.text) });
  const detections = await engine.detect({ entries, context });
  return new Set(detections.map((detection) => detection.type));
}

// Score a corpus against an engine. Returns { perType, totals, gaps } where
// perType[type] = { tp, fp, fn, precision, recall } and `gaps` lists the
// (case, type) pairs labeled as a known coverage gap (expect.present && gap).
//
// Counting model (per type, per case):
//   - expected-present + detected   -> TP
//   - expected-present + missed     -> FN
//   - expected-absent  + detected   -> FP
//   - expected-absent  + not-detected -> true negative (uncounted)
// A case only contributes to a type when that type appears in its `expect` list
// (so unrelated types are not penalized).
export async function scoreCorpus(engine, cases) {
  const perType = Object.create(null);
  for (const type of SCORED_TYPES) {
    perType[type] = { tp: 0, fp: 0, fn: 0 };
  }
  const gaps = [];

  for (const testCase of cases) {
    const detected = await detectTypes(engine, testCase);
    for (const expectation of testCase.expect ?? []) {
      const { type, present } = expectation;
      if (!perType[type]) {
        // A corpus type outside SCORED_TYPES (e.g. a custom-rule type) is tracked
        // lazily so the table still reflects it, but it is not gated.
        perType[type] = { tp: 0, fp: 0, fn: 0 };
      }
      const hit = detected.has(type);
      if (present) {
        if (hit) {
          perType[type].tp += 1;
        } else {
          perType[type].fn += 1;
          if (expectation.gap) {
            gaps.push({ type, text: testCase.text, note: testCase.note });
          }
        }
      } else if (hit) {
        perType[type].fp += 1;
      }
    }
  }

  const result = Object.create(null);
  for (const [type, counts] of Object.entries(perType)) {
    result[type] = { ...counts, ...ratios(counts) };
  }
  return { perType: result, totals: totalsOf(result), gaps };
}

// precision = TP/(TP+FP), recall = TP/(TP+FN). With no positives/negatives the
// denominator is 0; report 1 (a vacuously perfect score) so an unexercised type
// does not drag the table down or trip the gate.
export function ratios({ tp, fp, fn }) {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  return { precision, recall };
}

function totalsOf(perType) {
  const sum = { tp: 0, fp: 0, fn: 0 };
  for (const counts of Object.values(perType)) {
    sum.tp += counts.tp;
    sum.fp += counts.fp;
    sum.fn += counts.fn;
  }
  return { ...sum, ...ratios(sum) };
}

// Compare live scores against a baseline. A type REGRESSES when its live
// precision OR recall is below the baseline value. The baseline is persisted at
// 6-decimal precision (see `round`), so the live metric is rounded to the same
// granularity before comparison — otherwise `0.6666666…` reads as "below" a
// baseline-stored `0.666667`, a phantom regression. Types present in the live
// scores but absent from the baseline are reported as `newTypes` (not a
// regression — the baseline simply predates them).
const EPSILON = 1e-9;

export function compareToBaseline(live, baseline) {
  const regressions = [];
  const newTypes = [];
  for (const [type, counts] of Object.entries(live.perType)) {
    const base = baseline.perType?.[type];
    if (!base) {
      newTypes.push(type);
      continue;
    }
    if (round(counts.precision) < round(base.precision) - EPSILON) {
      regressions.push({ type, metric: "precision", baseline: base.precision, current: counts.precision });
    }
    if (round(counts.recall) < round(base.recall) - EPSILON) {
      regressions.push({ type, metric: "recall", baseline: base.recall, current: counts.recall });
    }
  }
  return { ok: regressions.length === 0, regressions, newTypes };
}

export function buildBaseline(scores) {
  const perType = Object.create(null);
  for (const [type, counts] of Object.entries(scores.perType)) {
    perType[type] = {
      tp: counts.tp,
      fp: counts.fp,
      fn: counts.fn,
      precision: round(counts.precision),
      recall: round(counts.recall)
    };
  }
  return {
    note: "Pinned per-type TP/FP/FN baseline for the detection regression gate (WS2a corpus, WS2b rules, WS2c context anchors, WS2d Unicode-evasion normalization, plus the international-PII expansion: jp_mynumber/fr_nir/es_dni/uk_nino). Records the CURRENT state — WS2b closed the credential/PII coverage gaps (AWS/GitHub/Google/Slack keys, JWT, PEM, US SSN, IBAN, E.164/US phone are true-positives), so recall is at 1 across types. WS2c added a word-boundary anchor to the kr-phone rule that stops a phone matching as a SUBSTRING of a longer hex/dashed run (UUID tail) — a new hard-negative the corpus proves; recall held (no FN reintroduced). WS2d added NFKC normalization in detectEntry so full-width / mathematical / confusable evasion no longer defeats every rule: the new full-width-digit card, full-width KR phone, full-width-@ email, full-width-body sk_ key (same-length NFKC, exact-span redaction) and the mathematical-bold KR RRN (length-divergent NFKC, fail-closed whole-leaf detection) are now true-positives, so TP rose per type while recall held at 1 and the new ligature/ascii hard-negatives added NO false positives (precision for card/phone improved as TP grew with no new FP). The international-PII expansion added four validator-anchored types with a synthetic positive + a checksum/format near-miss each: jp_mynumber (mod-11 check digit), fr_nir (97-control key with Corsica 2A/2B substitution), es_dni (mod-23 check letter, NIE X/Y/Z→0/1/2), and uk_nino (format-only invalid-prefix exclusions — no checksum exists). fr_nir (mod-97 over a 15-digit structured run) and es_dni (mod-23 plus a required check letter) join HARD_BLOCK_TYPES — strong anchors and rare shapes, so a match is effectively a true positive. jp_mynumber and uk_nino stay DIAL-ELIGIBLE: a lone mod-11 check digit passes ~1/11 of common 12-digit runs and uk_nino has no checksum at all, so an operator can allowlist a benign FP (both still detect + block by default). Each new type lands at precision 1.0 / recall 1.0 and adds no false positive to any existing type. The remaining false positives are LEFT by design and stay baked in: phone order-id and a Luhn-passing card order-number are structurally identical to a real bare KR mobile / real card so an anchor would cost recall (card is hard-block); Bearer-in-prose is left because detection runs per string leaf and a real {\"Authorization\":\"Bearer <token>\"} payload walks to a bare \"Bearer <token>\" leaf, so an Authorization-context anchor would MISS the realistic case (a recall regression on the hard-block `secret` type); the password-placeholder is arguably a true positive. An operator clears a benign SOFT-type FP (e.g. the phone order-id, or a uk_nino format-only FP) via filters.minConfidence / filters.allowlist; those controls can NEVER suppress a hard-block type (secret/api_key/kr_rrn/card/fr_nir/es_dni — jp_mynumber and uk_nino are dial-eligible). The gate fails only on a regression below these numbers. Regenerate with: node scripts/bench-detection.mjs --write-baseline.",
    generatedFrom: "tests/fixtures/detection-corpus.json",
    perType
  };
}

function round(value) {
  return Math.round(value * 1e6) / 1e6;
}

function pct(value) {
  return `${(value * 100).toFixed(1)}%`;
}

export function formatTable(scores) {
  const rows = [["type", "TP", "FP", "FN", "precision", "recall"]];
  for (const type of Object.keys(scores.perType)) {
    const c = scores.perType[type];
    rows.push([type, String(c.tp), String(c.fp), String(c.fn), pct(c.precision), pct(c.recall)]);
  }
  const t = scores.totals;
  rows.push(["TOTAL", String(t.tp), String(t.fp), String(t.fn), pct(t.precision), pct(t.recall)]);

  const widths = rows[0].map((_, col) => Math.max(...rows.map((row) => row[col].length)));
  const render = (row) => row.map((cell, col) => col === 0 ? cell.padEnd(widths[col]) : cell.padStart(widths[col])).join("  ");
  const lines = [render(rows[0]), widths.map((w) => "-".repeat(w)).join("  ")];
  for (const row of rows.slice(1, -1)) {
    lines.push(render(row));
  }
  lines.push(widths.map((w) => "-".repeat(w)).join("  "));
  lines.push(render(rows[rows.length - 1]));
  return lines.join("\n");
}

async function main(argv) {
  const writeBaseline = argv.includes("--write-baseline");
  const gate = argv.includes("--gate");

  const engine = createDefaultFilterEngine();
  const cases = loadCorpus();
  const scores = await scoreCorpus(engine, cases);

  process.stdout.write(`Detection benchmark (${cases.length} corpus cases)\n\n`);
  process.stdout.write(`${formatTable(scores)}\n`);

  if (scores.gaps.length > 0) {
    process.stdout.write(`\nKnown coverage gaps (currently MISSED, recorded in baseline; WS2b will close):\n`);
    for (const gap of scores.gaps) {
      process.stdout.write(`  - [${gap.type}] ${truncate(gap.text)}\n`);
    }
  }

  if (writeBaseline) {
    const baseline = buildBaseline(scores);
    writeFileSync(BASELINE_PATH, `${JSON.stringify(baseline, null, 2)}\n`);
    process.stdout.write(`\nWrote baseline -> ${BASELINE_PATH}\n`);
    return 0;
  }

  if (gate) {
    let baseline;
    try {
      baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
    } catch (error) {
      process.stderr.write(`detection gate: cannot read baseline at ${BASELINE_PATH}: ${error.message}\n`);
      process.stderr.write(`detection gate: run \`node scripts/bench-detection.mjs --write-baseline\` to pin one.\n`);
      return 1;
    }
    const verdict = compareToBaseline(scores, baseline);
    if (verdict.newTypes.length > 0) {
      process.stdout.write(`\ndetection gate: new types not in baseline (not a regression): ${verdict.newTypes.join(", ")}\n`);
    }
    if (!verdict.ok) {
      process.stderr.write(`\ndetection gate FAILED — precision/recall regressed below baseline:\n`);
      for (const reg of verdict.regressions) {
        process.stderr.write(`  - ${reg.type} ${reg.metric}: ${pct(reg.baseline)} -> ${pct(reg.current)}\n`);
      }
      process.stderr.write(`If this is an intentional rule change, re-pin with --write-baseline and review the diff.\n`);
      return 1;
    }
    process.stdout.write(`\ndetection gate passed: no per-type precision/recall regression below baseline.\n`);
  }
  return 0;
}

function truncate(text, max = 72) {
  const s = String(text);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

// Only run the CLI when invoked directly (not when imported by the test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => process.exit(code)).catch((error) => {
    process.stderr.write(`${error?.stack ?? error}\n`);
    process.exit(1);
  });
}
