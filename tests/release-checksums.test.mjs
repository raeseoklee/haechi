import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  sha256File, formatManifestLine, parseManifest, generateManifest, verifyManifest
} from "../scripts/release-checksums.mjs";

const SCRIPT = fileURLToPath(new URL("../scripts/release-checksums.mjs", import.meta.url));

// sha256("hello") — a fixed, well-known vector.
const HELLO = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

test("sha256File matches the known vector and generateManifest uses basenames", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-"));
  const file = join(dir, "haechi-0.7.0.tgz");
  await writeFile(file, "hello");
  assert.equal(await sha256File(file), HELLO);

  const manifest = await generateManifest([file]);
  assert.equal(manifest, `${HELLO}  haechi-0.7.0.tgz\n`);
});

test("formatManifestLine uses the two-space sha256sum format", () => {
  assert.equal(formatManifestLine(HELLO, "x.tgz"), `${HELLO}  x.tgz`);
});

test("parseManifest reads valid lines and rejects malformed ones", () => {
  const entries = parseManifest(`${HELLO}  a.tgz\n${HELLO}  b.tgz\n`);
  assert.deepEqual(entries.map((e) => e.name), ["a.tgz", "b.tgz"]);
  assert.throws(() => parseManifest("not-a-hash  a.tgz"), /Malformed SHA256SUMS/);
});

test("verifyManifest passes intact files and fails on mismatch or missing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-verify-"));
  await writeFile(join(dir, "a.tgz"), "hello");
  await writeFile(join(dir, "manifest"), await generateManifest([join(dir, "a.tgz")]));

  const ok = await verifyManifest(join(dir, "manifest"));
  assert.equal(ok.ok, true);
  assert.equal(ok.results[0].ok, true);

  // Tamper the file → hash mismatch.
  await writeFile(join(dir, "a.tgz"), "tampered");
  const bad = await verifyManifest(join(dir, "manifest"));
  assert.equal(bad.ok, false);
  assert.equal(bad.results[0].reason, "hash mismatch");

  // Missing file → reported, not thrown.
  await writeFile(join(dir, "manifest"), `${HELLO}  missing.tgz\n`);
  const missing = await verifyManifest(join(dir, "manifest"));
  assert.equal(missing.ok, false);
  assert.equal(missing.results[0].reason, "missing");
});

test("verifyManifest rejects path-traversal and absolute entry names (untrusted manifest)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-traversal-"));
  await writeFile(join(dir, "evil"), `${HELLO}  ../../../etc/passwd\n${HELLO}  /etc/hosts\n`);
  const result = await verifyManifest(join(dir, "evil"));
  assert.equal(result.ok, false);
  assert.ok(result.results.every((r) => r.reason === "unsafe path"));
});

test("the CLI --check exits 0 on an intact manifest and 1 on a mismatch", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-cli-"));
  await writeFile(join(dir, "a.tgz"), "hello");
  await writeFile(join(dir, "SHA256SUMS"), await generateManifest([join(dir, "a.tgz")]));

  const ok = spawnSync(process.execPath, [SCRIPT, "--check", "SHA256SUMS"], { cwd: dir, encoding: "utf8" });
  assert.equal(ok.status, 0);
  assert.match(ok.stderr, /OK\s+a\.tgz/);

  await writeFile(join(dir, "a.tgz"), "tampered");
  const bad = spawnSync(process.execPath, [SCRIPT, "--check", "SHA256SUMS"], { cwd: dir, encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /FAIL\s+a\.tgz/);
});

test("the CLI generate mode prints the manifest to stdout", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-gen-"));
  await writeFile(join(dir, "a.tgz"), "hello");
  const gen = spawnSync(process.execPath, [SCRIPT, "a.tgz"], { cwd: dir, encoding: "utf8" });
  assert.equal(gen.status ?? 0, 0);
  assert.equal(gen.stdout, `${HELLO}  a.tgz\n`);
});

test("verify round-trips against the actual packed tarball format", async () => {
  // The manifest a generator writes is consumed by the same verifier and by
  // `sha256sum -c` / `shasum -a 256 -c` (two-space format).
  const dir = await mkdtemp(join(tmpdir(), "haechi-sums-roundtrip-"));
  await writeFile(join(dir, "haechi-x.tgz"), "package-bytes");
  const manifest = await generateManifest([join(dir, "haechi-x.tgz")]);
  await writeFile(join(dir, "SHA256SUMS"), manifest);
  assert.match((await readFile(join(dir, "SHA256SUMS"), "utf8")), /^[a-f0-9]{64} {2}haechi-x\.tgz\n$/);
  assert.equal((await verifyManifest(join(dir, "SHA256SUMS"))).ok, true);
});
