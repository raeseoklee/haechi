#!/usr/bin/env node
// Generate or verify a SHA256SUMS manifest for release artifacts.
//
//   node scripts/release-checksums.mjs <file...>           # print "<hash>  <name>" lines
//   node scripts/release-checksums.mjs --check SHA256SUMS  # verify files against a manifest
//
// Standard `<sha256-hex>  <basename>` format (two spaces), so `sha256sum -c`
// and `shasum -a 256 -c` interoperate with what this prints.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

export function formatManifestLine(hashHex, name) {
  return `${hashHex}  ${name}`;
}

export function parseManifest(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = /^([a-f0-9]{64})\s+(.+)$/.exec(line);
      if (!match) {
        throw new Error(`Malformed SHA256SUMS line: ${line}`);
      }
      return { hash: match[1], name: match[2] };
    });
}

export async function generateManifest(files) {
  const lines = [];
  for (const file of files) {
    lines.push(formatManifestLine(await sha256File(file), basename(file)));
  }
  return `${lines.join("\n")}\n`;
}

export async function verifyManifest(manifestPath) {
  const baseDir = dirname(manifestPath);
  const entries = parseManifest(await readFile(manifestPath, "utf8"));
  const results = [];
  for (const entry of entries) {
    // A manifest is untrusted input: never hash a path that escapes the
    // manifest's own directory (no absolute paths, no `../` traversal).
    const rel = relative(baseDir, join(baseDir, entry.name));
    if (isAbsolute(entry.name) || rel.startsWith("..")) {
      results.push({ name: entry.name, ok: false, reason: "unsafe path" });
      continue;
    }
    let actual = null;
    try {
      actual = await sha256File(join(baseDir, entry.name));
    } catch (error) {
      results.push({ name: entry.name, ok: false, reason: error.code === "ENOENT" ? "missing" : error.message });
      continue;
    }
    results.push({ name: entry.name, ok: actual === entry.hash, reason: actual === entry.hash ? null : "hash mismatch" });
  }
  return { ok: results.every((r) => r.ok), results };
}

async function main(argv) {
  if (argv[0] === "--check") {
    const manifestPath = argv[1];
    if (!manifestPath) {
      throw new Error("--check requires a SHA256SUMS path");
    }
    const { ok, results } = await verifyManifest(manifestPath);
    for (const r of results) {
      process.stderr.write(`${r.ok ? "OK  " : "FAIL"} ${r.name}${r.reason ? ` (${r.reason})` : ""}\n`);
    }
    process.exitCode = ok ? 0 : 1;
    return;
  }
  if (argv.length === 0) {
    throw new Error("usage: release-checksums.mjs <file...> | --check SHA256SUMS");
  }
  process.stdout.write(await generateManifest(argv));
}

// Run only as a CLI (not when imported by tests). fileURLToPath handles
// Windows paths and URL encoding that a raw `file://` compare would miss.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`release-checksums: ${error.message}\n`);
    process.exitCode = 1;
  });
}
