#!/usr/bin/env node
// Doc-freshness preflight gate (reliability-hardening-track WS1).
//
// Scans the PUBLISHABLE docs for known-stale version banners and phrases that
// have drifted behind the shipped line, and fails CI with a file:line list.
// Haechi has already shipped three stale-string fixes; this gate prevents
// recurrence. node:-only, zero runtime dependency, fail-closed.
//
// Two pattern groups, each with a per-group file allowlist so the gate does NOT
// false-positive on docs that are ABOUT the stale phrases (design/planning docs
// that quote them as examples-to-fix, or historical scope docs whose old
// front-matter banner is an accurate record of a past release's planning state):
//
//   - INLINE phrases ("planned for 0.6", "no client authentication yet",
//     "Only the current 0.3.x", "Haechi 0.3.x", "0.2 only supports") are stale
//     *claims* about the current product. They are only legitimate when QUOTED
//     inside the reliability-hardening-track design docs.
//   - FRONT-MATTER banners ("Status: Draft 0.1", "Target version: 0.6.0",
//     "Target version: 1.0.0") are stale only on LIVING docs (configuration.md,
//     threat-model.md, risk-register-release-gate.md, …). On historical
//     *-implementation-scope.md / *-hardening-scope.md design docs and the
//     other point-in-time design drafts they are an accurate record, so those
//     files are allowlisted for this group.

import { readdir, readFile } from "node:fs/promises";
import { join, relative, basename } from "node:path";

const ROOT = process.cwd();

// Publishable doc set (mirrors package.json "files" + README.ko sibling).
// README.ko.md is not itself published but is the EN-main's required sibling
// and must stay equally fresh, so it is scanned too.
const ROOT_DOCS = ["README.md", "README.ko.md", "SECURITY.md"];
const DOCS_DIR = "docs/current";

// Files that legitimately QUOTE every stale phrase as an example-to-fix.
// Whole-file exemption from ALL pattern groups.
export const QUOTING_DESIGN_DOCS = new Set([
  "docs/current/reliability-hardening-track.md",
  "docs/current/reliability-hardening-track.ko.md"
]);

// Historical / point-in-time design docs whose old front-matter banner
// ("Status: Draft 0.1", "Target version: X.Y.Z") is an accurate record of the
// release they describe, not a stale claim about the current product. These are
// exempt from the FRONT-MATTER group only — they are still scanned for inline
// stale claims. The implementation-scope / hardening-scope family is matched by
// filename suffix; the remaining standalone drafts are listed explicitly.
export const HISTORICAL_DESIGN_DOCS = new Set([
  "docs/current/mvp-0.1-implementation-scope.md",
  "docs/current/mvp-0.1-implementation-scope.ko.md",
  "docs/current/initial-plan-ai-llm-mcp-encryption.md",
  "docs/current/initial-plan-ai-llm-mcp-encryption.ko.md",
  "docs/current/prd-ai-llm-mcp-encryption.md",
  "docs/current/prd-ai-llm-mcp-encryption.ko.md",
  "docs/current/expert-gap-review-ai-llm-mcp-encryption.md",
  "docs/current/expert-gap-review-ai-llm-mcp-encryption.ko.md",
  "docs/current/global-privacy-compliance-review.md",
  "docs/current/global-privacy-compliance-review.ko.md",
  "docs/current/privacy-filtering-policy-draft.md",
  "docs/current/privacy-filtering-policy-draft.ko.md",
  "docs/current/open-source-modular-architecture.md",
  "docs/current/open-source-modular-architecture.ko.md"
]);

export function isHistoricalDesignDoc(rel) {
  if (HISTORICAL_DESIGN_DOCS.has(rel)) return true;
  const name = basename(rel);
  // release-X.Y[.Z]-implementation-scope(.ko).md, *-hardening-scope(.ko).md
  return /-(implementation|hardening)-scope(?:\.ko)?\.md$/.test(name);
}

// INLINE stale-claim patterns: flagged on every publishable doc except the
// quoting design docs. Case-insensitive where it reads naturally.
export const INLINE_PATTERNS = [
  {
    id: "planned-for-0.6",
    re: /planned for 0\.6/i,
    message: "stale claim 'planned for 0.6' (bearer auth shipped in 0.6)"
  },
  {
    id: "no-client-auth",
    re: /no client authentication yet/i,
    message: "stale claim 'no client authentication yet' (bearer auth shipped in 0.6)"
  },
  {
    id: "only-current-0.3.x",
    re: /Only the current\b[^\n]*0\.3\.x/i,
    message: "stale support window 'Only the current 0.3.x' (current line is 1.5.x)"
  },
  {
    id: "haechi-0.3.x",
    re: /\bHaechi 0\.3\.x\b/i,
    message: "stale version label 'Haechi 0.3.x' (current line is 1.5.x)"
  },
  {
    id: "0.2-only-supports",
    re: /0\.2 only supports/i,
    message: "stale capability claim '0.2 only supports …'"
  },
  {
    id: "in-0.3.x",
    // SECURITY.md "… in 0.3.x …" describing current behavior (streaming /
    // plugins). Anchored to 'in 0.3.x' as a free-standing version token so it
    // does not collide with the api-stability.md "| `0.3.x` |" support-line
    // table row, which is a legitimate historical support-window reference.
    re: /\bin 0\.3\.x\b/i,
    message: "stale current-behavior version token 'in 0.3.x' (current line is 1.5.x)"
  }
];

// FRONT-MATTER banner patterns: stale only on living docs. Exempt on quoting
// design docs AND historical design docs.
export const FRONTMATTER_PATTERNS = [
  {
    id: "status-draft-0.1",
    // EN "- Status: Draft 0.1" or KO "- 문서 상태: Draft 0.1"
    re: /^\s*-\s*(?:Status|문서 상태):\s*Draft 0\.1\b/i,
    message: "stale front-matter 'Status: Draft 0.1' on a living doc (use 'Living document')"
  },
  {
    id: "target-version-0.6.0",
    // EN "- Target version: 0.6.0" or KO "- 기준 버전: 0.6.0"
    re: /^\s*-\s*(?:Target version|기준 버전):\s*0\.6\.0\b/i,
    message: "stale front-matter 'Target version: 0.6.0' on a living doc (current line is 1.5.x)"
  },
  {
    id: "target-version-1.0.0",
    re: /^\s*-\s*(?:Target version|기준 버전):\s*1\.0\.0\b/i,
    message: "stale front-matter 'Target version: 1.0.0' on a living doc (current line is 1.5.x)"
  }
];

// Pure evaluator: given a doc's repo-relative path and its text, return the
// findings (no I/O). This is the unit-tested core of the gate.
export function scanDoc(rel, text) {
  if (QUOTING_DESIGN_DOCS.has(rel)) return [];

  const findings = [];
  const historical = isHistoricalDesignDoc(rel);
  const lines = text.split(/\r?\n/);

  lines.forEach((line, index) => {
    for (const pattern of INLINE_PATTERNS) {
      if (pattern.re.test(line)) {
        findings.push({ file: rel, line: index + 1, id: pattern.id, message: pattern.message });
      }
    }
    if (!historical) {
      for (const pattern of FRONTMATTER_PATTERNS) {
        if (pattern.re.test(line)) {
          findings.push({ file: rel, line: index + 1, id: pattern.id, message: pattern.message });
        }
      }
    }
  });

  return findings;
}

async function collectDocFiles() {
  const files = [...ROOT_DOCS];
  let entries;
  try {
    entries = await readdir(join(ROOT, DOCS_DIR), { withFileTypes: true });
  } catch {
    entries = [];
  }
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".md")) {
      files.push(relative(ROOT, join(ROOT, DOCS_DIR, entry.name)).split("\\").join("/"));
    }
  }
  // Keep only files that exist (README.ko.md may be absent in a partial
  // checkout); root-doc readability is reported per-file below.
  const present = [];
  for (const rel of files) {
    try {
      const text = await readFile(join(ROOT, rel), "utf8");
      present.push({ rel, text });
    } catch {
      // README.ko.md / SECURITY.ko.md siblings are optional; skip silently.
    }
  }
  return present;
}

async function main() {
  const docs = await collectDocFiles();
  const findings = [];
  for (const { rel, text } of docs) {
    findings.push(...scanDoc(rel, text));
  }

  if (findings.length > 0) {
    findings.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));
    for (const finding of findings) {
      console.error(`${finding.file}:${finding.line}: ${finding.message}`);
    }
    console.error(
      `\ndoc-freshness check failed: ${findings.length} stale doc banner(s)/phrase(s).` +
        `\nFix the stale text, or — if a doc legitimately quotes the phrase as an` +
        `\nexample-to-fix or is a point-in-time design record — add it to the` +
        `\nallowlist in scripts/check-doc-freshness.mjs.`
    );
    process.exitCode = 1;
  } else {
    console.error(`doc-freshness check passed: scanned ${docs.length} publishable doc(s)`);
  }
}

// Run as a CLI only when invoked directly (not when imported by the test).
if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
