import test from "node:test";
import assert from "node:assert/strict";
import {
  scanDoc,
  isHistoricalDesignDoc,
  QUOTING_DESIGN_DOCS,
  HISTORICAL_DESIGN_DOCS,
  INLINE_PATTERNS,
  FRONTMATTER_PATTERNS
} from "./check-doc-freshness.mjs";

function ids(findings) {
  return findings.map((f) => f.id).sort();
}

test("flags every known-stale INLINE phrase on a living publishable doc", () => {
  const text = [
    "# Haechi Configuration Reference",
    "",
    "The proxy has no client authentication yet (planned for 0.6): anyone …",
    "Only the current `0.3.x` development line is considered in scope.",
    "This is Haechi 0.3.x behavior.",
    "Note: 0.2 only supports redaction.",
    "Streaming payloads are not inspected in 0.3.x and must fail closed."
  ].join("\n");

  const found = ids(scanDoc("docs/current/configuration.md", text));
  assert.ok(found.includes("planned-for-0.6"));
  assert.ok(found.includes("no-client-auth"));
  assert.ok(found.includes("only-current-0.3.x"));
  assert.ok(found.includes("haechi-0.3.x"));
  assert.ok(found.includes("0.2-only-supports"));
  assert.ok(found.includes("in-0.3.x"));
});

test("flags stale FRONT-MATTER banners on a living doc (EN + KO)", () => {
  const en = [
    "# Haechi Threat Model",
    "- Status: Draft 0.1",
    "- Target version: 1.0.0"
  ].join("\n");
  const enIds = ids(scanDoc("docs/current/threat-model.md", en));
  assert.ok(enIds.includes("status-draft-0.1"));
  assert.ok(enIds.includes("target-version-1.0.0"));

  const ko = [
    "# Haechi 설정 레퍼런스",
    "- 문서 상태: Draft 0.1",
    "- 기준 버전: 0.6.0"
  ].join("\n");
  const koIds = ids(scanDoc("docs/current/configuration.ko.md", ko));
  assert.ok(koIds.includes("status-draft-0.1"));
  assert.ok(koIds.includes("target-version-0.6.0"));
});

test("does NOT flag a fresh living-doc banner (1.5.x is current)", () => {
  const fresh = [
    "# Haechi Risk Register and Release Gates",
    "- Status: Living document (tracks core 1.5.x)",
    "- Target version: 1.5.x"
  ].join("\n");
  assert.deepEqual(scanDoc("docs/current/risk-register-release-gate.md", fresh), []);
});

test("WHITELIST: reliability-hardening-track docs that QUOTE every phrase are fully exempt", () => {
  const quoting = [
    "- Correct stale claims: `configuration.md` \"the proxy has no client",
    "  authentication yet (planned for 0.6)\"; the `Target version: 0.6.0` /",
    "  `Draft 0.1 / Target 1.0.0` headers; the \"Only the current 0.3.x\" window.",
    "- Add a doc-freshness gate flagging `planned for 0.6`, `Status: Draft 0.1`."
  ].join("\n");
  assert.deepEqual(scanDoc("docs/current/reliability-hardening-track.md", quoting), []);
  assert.deepEqual(scanDoc("docs/current/reliability-hardening-track.ko.md", quoting), []);
  assert.ok(QUOTING_DESIGN_DOCS.has("docs/current/reliability-hardening-track.md"));
  assert.ok(QUOTING_DESIGN_DOCS.has("docs/current/reliability-hardening-track.ko.md"));
});

test("WHITELIST: historical scope docs keep their old front-matter banner, by suffix and by list", () => {
  const banner = [
    "# Release 0.6 Implementation Scope",
    "- Status: Draft 0.1",
    "- Target version: 0.6.0 (after 0.5.0)"
  ].join("\n");

  // matched by the -implementation-scope filename suffix
  assert.deepEqual(scanDoc("docs/current/release-0.6-implementation-scope.md", banner), []);
  assert.deepEqual(scanDoc("docs/current/release-0.6-implementation-scope.ko.md", banner), []);
  assert.deepEqual(scanDoc("docs/current/release-0.3.2-hardening-scope.md", banner), []);
  // matched by the explicit historical list
  assert.deepEqual(scanDoc("docs/current/prd-ai-llm-mcp-encryption.md", banner), []);

  assert.equal(isHistoricalDesignDoc("docs/current/release-1.0-implementation-scope.md"), true);
  assert.equal(isHistoricalDesignDoc("docs/current/mvp-0.1-implementation-scope.ko.md"), true);
  assert.equal(isHistoricalDesignDoc("docs/current/configuration.md"), false);
  assert.equal(isHistoricalDesignDoc("docs/current/risk-register-release-gate.md"), false);
});

test("historical scope docs are STILL scanned for inline stale CLAIMS", () => {
  // A scope doc's front-matter is exempt, but it must not present a stale
  // capability claim as current truth.
  const text = [
    "# Release 0.5 Implementation Scope",
    "- Status: Draft 0.1",
    "",
    "The proxy has no client authentication yet (planned for 0.6)."
  ].join("\n");
  const found = ids(scanDoc("docs/current/release-0.5-implementation-scope.md", text));
  assert.ok(found.includes("planned-for-0.6"));
  assert.ok(found.includes("no-client-auth"));
  // but the front-matter banner is exempt
  assert.ok(!found.includes("status-draft-0.1"));
});

test("inline patterns are case-insensitive", () => {
  const text = "PLANNED FOR 0.6 and NO CLIENT AUTHENTICATION YET";
  const found = ids(scanDoc("README.md", text));
  assert.ok(found.includes("planned-for-0.6"));
  assert.ok(found.includes("no-client-auth"));
});

test("does not false-positive on the api-stability support-line table row", () => {
  // "| `0.3.x` | local inference/proxy safety patch line |" is a legitimate
  // historical support-window reference, not a stale 'in 0.3.x' current claim.
  const text = "| `0.3.x` | local inference/proxy safety patch line (former preview) |";
  assert.deepEqual(scanDoc("docs/current/api-stability.md", text), []);
});

test("reports accurate 1-based line numbers", () => {
  const text = ["line one", "line two", "planned for 0.6 here"].join("\n");
  const found = scanDoc("README.md", text);
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 3);
});

test("pattern tables are non-empty (guards against an accidental empty gate)", () => {
  assert.ok(INLINE_PATTERNS.length >= 5);
  assert.ok(FRONTMATTER_PATTERNS.length >= 3);
  assert.ok(HISTORICAL_DESIGN_DOCS.size >= 8);
});
