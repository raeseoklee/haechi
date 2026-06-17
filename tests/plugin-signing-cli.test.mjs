import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

// Drive the authoring CLI through the real bin (spawnSync) the same way
// tests/cli.test.mjs does — this exercises real exit codes and the fail-closed
// gate signal (non-zero exit on a PluginLoadError), not just an in-process call.
const CLI = resolve("packages/cli/bin/haechi.mjs");

// SYNTHETIC plugin source — not a real entrypoint, just bytes to hash/sign.
const SAMPLE_ENTRY = "export default { authenticate() { return null; } };\n";

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
}

async function tempDir() {
  return mkdtemp(join(tmpdir(), "haechi-plugin-signing-cli-"));
}

test("plugin-keygen writes a 0600 private key + a .pub, JSON omits the private key", async () => {
  const dir = await tempDir();
  const result = run(["plugin-keygen", "--key-id", "test-signer", "--out-dir", dir], dir);
  assert.equal(result.status, 0, result.stderr);

  const out = JSON.parse(result.stdout);
  assert.equal(out.ok, true);
  assert.equal(out.command, "plugin-keygen");
  assert.equal(out.keyId, "test-signer");
  assert.equal(out.privateKeyPath, join(dir, "test-signer.key"));
  assert.equal(out.publicKeyPath, join(dir, "test-signer.pub"));

  // The public key PEM is safe to print (it is the trust anchor).
  assert.match(out.publicKeyPem, /BEGIN PUBLIC KEY/);

  // The private key material is NEVER in the JSON output (only its path).
  assert.doesNotMatch(result.stdout, /BEGIN PRIVATE KEY/);
  assert.doesNotMatch(result.stdout, /privateKeyPem/);

  // The private key file exists, is a PKCS8 PEM, and is mode 0600.
  const privateKeyPem = await readFile(out.privateKeyPath, "utf8");
  assert.match(privateKeyPem, /BEGIN PRIVATE KEY/);
  const info = await stat(out.privateKeyPath);
  assert.equal(info.mode & 0o777, 0o600, `expected 0600, got 0${(info.mode & 0o777).toString(8)}`);

  // The public .pub exists and is SPKI PEM.
  const publicKeyPem = await readFile(out.publicKeyPath, "utf8");
  assert.match(publicKeyPem, /BEGIN PUBLIC KEY/);
});

test("plugin-keygen defaults to a stable fixed keyId (no random/time suffix)", async () => {
  const dir = await tempDir();
  const result = run(["plugin-keygen", "--out-dir", dir], dir);
  assert.equal(result.status, 0, result.stderr);
  const out = JSON.parse(result.stdout);
  assert.equal(out.keyId, "haechi-plugin-signer");
  assert.equal(out.privateKeyPath, join(dir, "haechi-plugin-signer.key"));
});

test("round-trip: keygen -> sign -> verify with the generated public key => valid:true", async () => {
  const dir = await tempDir();
  const keyId = "rt-signer";

  // keygen
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  assert.equal(keygen.status, 0, keygen.stderr);
  const keys = JSON.parse(keygen.stdout);

  // a synthetic entry file
  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  // sign. Empty capabilities + a non-authProvider kind so the prescribed
  // verify call (which uses the default allowCapabilities: []) accepts it — the
  // authProvider capability-allowlist gate is exercised in plugin-signing.test.mjs.
  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "acme-filter",
    "--kind", "filter-engine",
    "--plugin-version", "1.2.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({}),
    "--not-before", String(Date.now() - 60_000),
    "--not-after", String(Date.now() + 60_000)
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signOut = JSON.parse(sign.stdout);
  assert.equal(signOut.ok, true);
  assert.equal(signOut.command, "plugin-sign");
  assert.equal(signOut.pluginId, "acme-filter");
  assert.equal(signOut.signerKeyId, keyId);
  assert.equal(signOut.kind, "filter-engine");
  assert.equal(signOut.version, "1.2.0");
  assert.match(signOut.entrySha256, /^[0-9a-f]{64}$/);
  // Sign output never leaks the private key.
  assert.doesNotMatch(sign.stdout, /BEGIN PRIVATE KEY/);

  // The signed envelope file was written at the default path (relative to cwd).
  assert.equal(signOut.outPath, "acme-filter.signed.json");
  const envelope = JSON.parse(await readFile(join(dir, signOut.outPath), "utf8"));
  assert.equal(envelope.alg, "ed25519");
  assert.equal(envelope.payload.pluginId, "acme-filter");

  // verify with the generated public key as the anchor (run in the same cwd so
  // the relative signed-envelope path resolves).
  const verify = run([
    "plugin-verify", signOut.outPath,
    "--entry", entryPath,
    "--anchor", keys.publicKeyPath,
    "--anchor-key-id", keyId,
    "--core-version", "1.5.0"
  ], dir);
  assert.equal(verify.status, 0, verify.stderr);
  const verifyOut = JSON.parse(verify.stdout);
  assert.equal(verifyOut.ok, true);
  assert.equal(verifyOut.command, "plugin-verify");
  assert.equal(verifyOut.valid, true);
  assert.equal(verifyOut.pluginId, "acme-filter");
  assert.equal(verifyOut.signerKeyId, keyId);
  assert.match(verifyOut.entrySha256, /^[0-9a-f]{64}$/);
});

test("authProvider envelope verifies only WITH --allow-capability readsCredentials", async () => {
  const dir = await tempDir();
  const keyId = "auth-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  assert.equal(keygen.status, 0, keygen.stderr);
  const keys = JSON.parse(keygen.stdout);

  const entryPath = join(dir, "auth-entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  // Core mandates an authProvider declare readsCredentials:true.
  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "acme-auth",
    "--kind", "authProvider",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({ readsCredentials: true })
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signedPath = JSON.parse(sign.stdout).outPath;

  // Without --allow-capability, the declared readsCredentials is not allowlisted
  // -> fail closed (capability-not-allowlisted, non-zero). This is the gap the
  // flag closes: an authProvider (the kind the trust gate exists for) was
  // un-verifiable through the CLI before.
  const denied = run([
    "plugin-verify", signedPath, "--entry", entryPath,
    "--anchor", keys.publicKeyPath, "--anchor-key-id", keyId
  ], dir);
  assert.notEqual(denied.status, 0, "authProvider must fail closed without --allow-capability");
  assert.match(denied.stderr, /capability-not-allowlisted/);

  // With --allow-capability readsCredentials, the same envelope verifies.
  const allowed = run([
    "plugin-verify", signedPath, "--entry", entryPath,
    "--anchor", keys.publicKeyPath, "--anchor-key-id", keyId,
    "--allow-capability", "readsCredentials"
  ], dir);
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(JSON.parse(allowed.stdout).valid, true);
});

test("verify resolves the anchor keyId from the envelope when --anchor-key-id is omitted", async () => {
  const dir = await tempDir();
  const keyId = "implied-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  assert.equal(keygen.status, 0, keygen.stderr);
  const keys = JSON.parse(keygen.stdout);

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "implied-filter",
    "--kind", "filter-engine",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({})
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signedPath = JSON.parse(sign.stdout).outPath;

  // No --anchor-key-id: the keyId defaults to the envelope's signerKeyId.
  const verify = run([
    "plugin-verify", signedPath,
    "--entry", entryPath,
    "--anchor", keys.publicKeyPath
  ], dir);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).valid, true);
});

test("tamper: modifying the entry file after signing fails verify (tampered-entry, non-zero)", async () => {
  const dir = await tempDir();
  const keyId = "tamper-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  const keys = JSON.parse(keygen.stdout);

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "tamper-auth",
    "--kind", "authProvider",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({ readsCredentials: true })
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signedPath = JSON.parse(sign.stdout).outPath;

  // Mutate the entry bytes after signing (path/envelope unchanged).
  await writeFile(entryPath, `${SAMPLE_ENTRY}// injected backdoor\n`, "utf8");

  const verify = run([
    "plugin-verify", signedPath,
    "--entry", entryPath,
    "--anchor", keys.publicKeyPath
  ], dir);
  assert.notEqual(verify.status, 0, "tampered entry must fail closed (non-zero exit)");
  assert.match(verify.stderr, /tampered-entry/);
});

test("wrong anchor: verifying against a different public key fails (invalid-signature, non-zero)", async () => {
  const dir = await tempDir();
  const keyId = "real-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  const keys = JSON.parse(keygen.stdout);

  // A SECOND, unrelated keypair whose public key is the wrong anchor.
  const wrongKeygen = run(["plugin-keygen", "--key-id", "wrong-signer", "--out-dir", dir], dir);
  const wrongKeys = JSON.parse(wrongKeygen.stdout);

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "wrong-anchor-auth",
    "--kind", "authProvider",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({ readsCredentials: true })
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signedPath = JSON.parse(sign.stdout).outPath;

  // The envelope's signerKeyId is allowlisted, but the anchor PEM is the WRONG
  // key -> the signature verification fails (invalid-signature).
  const verify = run([
    "plugin-verify", signedPath,
    "--entry", entryPath,
    "--anchor", wrongKeys.publicKeyPath,
    "--anchor-key-id", keyId
  ], dir);
  assert.notEqual(verify.status, 0, "wrong anchor must fail closed (non-zero exit)");
  assert.match(verify.stderr, /invalid-signature/);
});

test("verify resolves trust anchors from --config auth.plugin.trustAnchors", async () => {
  const dir = await tempDir();
  const keyId = "config-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  const keys = JSON.parse(keygen.stdout);
  const publicKeyPem = await readFile(keys.publicKeyPath, "utf8");

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "config-filter",
    "--kind", "filter-engine",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({})
  ], dir);
  assert.equal(sign.status, 0, sign.stderr);
  const signedPath = JSON.parse(sign.stdout).outPath;

  // A minimal config carrying ONLY the trust anchors array — plugin-verify reads
  // raw JSON, so it does not require a full auth.provider:"plugin" config.
  const configPath = join(dir, "haechi.config.json");
  await writeFile(configPath, JSON.stringify({
    auth: { plugin: { trustAnchors: [{ keyId, publicKey: publicKeyPem }] } }
  }), "utf8");

  const verify = run([
    "plugin-verify", signedPath,
    "--entry", entryPath,
    "--config", configPath
  ], dir);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).valid, true);
});

test("sign rejects a missing required flag (no --signer-key-id)", async () => {
  const dir = await tempDir();
  const keygen = run(["plugin-keygen", "--key-id", "missing-flag", "--out-dir", dir], dir);
  const keys = JSON.parse(keygen.stdout);

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  // Omit --signer-key-id.
  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--plugin-id", "no-signer",
    "--kind", "authProvider",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0"
  ], dir);
  assert.notEqual(sign.status, 0, "missing required flag must exit non-zero");
  assert.match(sign.stderr, /signer-key-id/);
});

test("verify requires either --anchor or --config", async () => {
  const dir = await tempDir();
  const keyId = "no-anchor-signer";
  const keygen = run(["plugin-keygen", "--key-id", keyId, "--out-dir", dir], dir);
  const keys = JSON.parse(keygen.stdout);

  const entryPath = join(dir, "entry.mjs");
  await writeFile(entryPath, SAMPLE_ENTRY, "utf8");

  const sign = run([
    "plugin-sign", entryPath,
    "--key", keys.privateKeyPath,
    "--signer-key-id", keyId,
    "--plugin-id", "no-anchor-auth",
    "--kind", "authProvider",
    "--plugin-version", "1.0.0",
    "--core-range", ">=1.0.0 <2.0.0",
    "--capabilities", JSON.stringify({ readsCredentials: true })
  ], dir);
  const signedPath = JSON.parse(sign.stdout).outPath;

  const verify = run(["plugin-verify", signedPath, "--entry", entryPath], dir);
  assert.notEqual(verify.status, 0, "no trust anchor source must fail closed");
  assert.match(verify.stderr, /--anchor|--config/);
});
