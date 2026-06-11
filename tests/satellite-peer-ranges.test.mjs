/**
 * tests/satellite-peer-ranges.test.mjs
 *
 * Unit tests for the satisfies() helper and the checkAll() gate in
 * scripts/check-satellite-peer-ranges.mjs.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { satisfies, checkAll } from "../scripts/check-satellite-peer-ranges.mjs";

// ---------------------------------------------------------------------------
// satisfies() — the minimal ">=A <B" semver helper
// ---------------------------------------------------------------------------

test("satisfies: 1.0.0 in >=0.8.0 <2.0.0 => true", () => {
  assert.strictEqual(satisfies("1.0.0", ">=0.8.0 <2.0.0"), true);
});

test("satisfies: 1.0.0 in >=0.8.0 <1.0.0 => false (upper bound excludes 1.0.0)", () => {
  assert.strictEqual(satisfies("1.0.0", ">=0.8.0 <1.0.0"), false);
});

test("satisfies: 0.9.0 in >=0.8.0 <2.0.0 => true", () => {
  assert.strictEqual(satisfies("0.9.0", ">=0.8.0 <2.0.0"), true);
});

test("satisfies: 2.0.0 in >=0.8.0 <2.0.0 => false (upper bound is exclusive)", () => {
  assert.strictEqual(satisfies("2.0.0", ">=0.8.0 <2.0.0"), false);
});

test("satisfies: 0.8.0 in >=0.8.0 <2.0.0 => true (lower bound is inclusive)", () => {
  assert.strictEqual(satisfies("0.8.0", ">=0.8.0 <2.0.0"), true);
});

test("satisfies: 0.7.9 in >=0.8.0 <2.0.0 => false (below lower bound)", () => {
  assert.strictEqual(satisfies("0.7.9", ">=0.8.0 <2.0.0"), false);
});

test("satisfies: 1.9.9 in >=0.8.0 <2.0.0 => true (just below upper bound)", () => {
  assert.strictEqual(satisfies("1.9.9", ">=0.8.0 <2.0.0"), true);
});

test("satisfies: malformed range throws", () => {
  assert.throws(
    () => satisfies("1.0.0", "^1.0.0"),
    /Unsupported peer range shape/
  );
});

test("satisfies: range with only lower bound throws", () => {
  assert.throws(
    () => satisfies("1.0.0", ">=1.0.0"),
    /Unsupported peer range shape/
  );
});

test("satisfies: range with only upper bound throws", () => {
  assert.throws(
    () => satisfies("1.0.0", "<2.0.0"),
    /Unsupported peer range shape/
  );
});

test("satisfies: range with tilde throws", () => {
  assert.throws(
    () => satisfies("1.0.0", "~1.0.0"),
    /Unsupported peer range shape/
  );
});

// ---------------------------------------------------------------------------
// checkAll() — verifies all four satellites pass with current in-repo versions
// ---------------------------------------------------------------------------

test("checkAll: all satellites pass with widened ranges (core 0.9.0 satisfies <2.0.0)", () => {
  const { ok, errors, lines } = checkAll();
  assert.strictEqual(ok, true, `Expected all checks to pass, but got errors:\n${errors.join("\n")}`);
  assert.strictEqual(errors.length, 0);
  // Should have lines for each satellite+peer combination
  assert.ok(lines.length > 0, "Expected at least one OK line");
});

test("checkAll: lines include haechi-auth-jwt, haechi-crypto-kms, haechi-dashboard, haechi-auth-oidc", () => {
  const { lines } = checkAll();
  const text = lines.join("\n");
  assert.ok(text.includes("haechi-auth-jwt"), "Expected haechi-auth-jwt in output");
  assert.ok(text.includes("haechi-crypto-kms"), "Expected haechi-crypto-kms in output");
  assert.ok(text.includes("haechi-dashboard"), "Expected haechi-dashboard in output");
  assert.ok(text.includes("haechi-auth-oidc"), "Expected haechi-auth-oidc in output");
});
