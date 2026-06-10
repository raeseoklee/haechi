#!/usr/bin/env node
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

const ROOT = process.cwd();
const SKIP_DIRS = new Set([".git", ".codexus", "node_modules"]);
const SKIP_FILES = new Set([".DS_Store", "stale-name-scan.mjs"]);
const PATTERNS = [
  /AICEL/g,
  /Aicel/g,
  /\baicel\b/g,
  /\.aicel/g,
  /aicel\.config/g,
  /packages\/cli\/bin\/aicel/g,
  /p2p-encryption 문서/g
];

const findings = [];

await scan(ROOT);

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.file}:${finding.line}: stale name matched ${finding.pattern}`);
  }
  process.exitCode = 1;
}

async function scan(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        await scan(join(dir, entry.name));
      }
      continue;
    }

    if (!entry.isFile() || SKIP_FILES.has(entry.name)) {
      continue;
    }

    const path = join(dir, entry.name);
    const rel = relative(ROOT, path);
    let text;
    try {
      text = await readFile(path, "utf8");
    } catch {
      continue;
    }

    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const pattern of PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            file: rel,
            line: index + 1,
            pattern: pattern.source
          });
        }
      }
    });
  }
}
