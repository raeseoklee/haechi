import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { assertCryptoProviderConformance } from "haechi/crypto";
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "./index.mjs";
import { createVaultKmsClient, isBlockedAddress } from "./vault.mjs";

// A faithful stand-in for Vault's Transit HTTP API as a `fetchImpl`. It isolates
// by keyName (parsed from the request path), deriving a distinct AES-256-GCM
// master key per keyName from an account seed. The wire shapes match real Vault:
//   encrypt -> data.ciphertext = "vault:v1:" + STANDARD-base64(iv|tag|ct)
//   decrypt -> data.plaintext  = STANDARD-base64(plaintext)   (verify GCM first)
// It REJECTS a ciphertext produced under a different keyName (cross-key
// isolation), a corrupted blob, and a wrong X-Vault-Token. No network. Records
// the headers of the last request so tests can assert X-Vault-Token / namespace.
function createMockVaultServer({ seed = randomBytes(32), token = "s.roottoken" } = {}) {
  const masterFor = (keyName) => Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), `mock-vault:${keyName}`, 32));
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    const u = new URL(url);
    calls.push({ url: u.toString(), headers: options.headers || {}, method: options.method });

    const headers = options.headers || {};
    if (headers["X-Vault-Token"] !== token) {
      return jsonResponse(403, { errors: ["permission denied"] });
    }

    const encMatch = u.pathname.match(/^\/v1\/transit\/encrypt\/(.+)$/);
    const decMatch = u.pathname.match(/^\/v1\/transit\/decrypt\/(.+)$/);
    const body = JSON.parse(options.body);

    if (encMatch) {
      const keyName = decodeURIComponent(encMatch[1]);
      const plaintext = Buffer.from(body.plaintext, "base64"); // Vault expects std-base64
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", masterFor(keyName), iv);
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const blob = Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64");
      return jsonResponse(200, { data: { ciphertext: `vault:v1:${blob}` } });
    }

    if (decMatch) {
      const keyName = decodeURIComponent(decMatch[1]);
      const ciphertext = String(body.ciphertext);
      const blobB64 = ciphertext.replace(/^vault:v1:/, "");
      const buf = Buffer.from(blobB64, "base64");
      try {
        const decipher = createDecipheriv("aes-256-gcm", masterFor(keyName), buf.subarray(0, 12));
        decipher.setAuthTag(buf.subarray(12, 28));
        const plaintext = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]);
        return jsonResponse(200, { data: { plaintext: plaintext.toString("base64") } });
      } catch {
        return jsonResponse(400, { errors: ["cipher: message authentication failed"] });
      }
    }

    return jsonResponse(404, { errors: ["unsupported path"] });
  };
  return { fetchImpl, calls, token };
}

function jsonResponse(status, obj) {
  const text = JSON.stringify(obj);
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() { return text; }
  };
}

// A "vault:v1:..." transit ciphertext of a 32-byte root, encrypted under keyName.
async function makeHmacRoot(server, address, keyName, token, rootBytes = randomBytes(32)) {
  const res = await server.fetchImpl(`${address}/v1/transit/encrypt/${encodeURIComponent(keyName)}`, {
    method: "POST",
    headers: { "X-Vault-Token": token },
    body: JSON.stringify({ plaintext: rootBytes.toString("base64") })
  });
  const parsed = JSON.parse(await res.text());
  return { ciphertext: parsed.data.ciphertext, rootBytes };
}

// A lookupImpl that always resolves to a public address, so the SSRF guard passes
// for the happy-path tests (the mock fetch never touches the network anyway).
const publicLookup = async () => ["93.184.216.34"];

const ADDRESS = "https://vault.example.com:8200";
const KEY = "haechi-root";

test("createVaultKmsClient requires a keyName", () => {
  assert.throws(
    () => createVaultKmsClient({ address: ADDRESS, token: "t", lookupImpl: publicLookup }),
    /requires a keyName/
  );
});

test("createVaultKmsClient requires an address and a token", () => {
  assert.throws(() => createVaultKmsClient({ keyName: KEY, token: "t" }), /requires an address/);
  assert.throws(() => createVaultKmsClient({ keyName: KEY, address: ADDRESS }), /requires a token/);
});

test("createVaultKmsClient rejects a non-https address (no loopback carve-out)", () => {
  assert.throws(
    () => createVaultKmsClient({ keyName: KEY, address: "http://vault.example.com:8200", token: "t", lookupImpl: publicLookup }),
    /must be https/
  );
});

test("Vault-backed provider passes full conformance with an injected fetch mock (no network)", async () => {
  const server = createMockVaultServer();
  const { ciphertext } = await makeHmacRoot(server, ADDRESS, KEY, server.token);
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup, hmacRootCiphertext: ciphertext
  });
  const result = await assertCryptoProviderConformance(createKmsCryptoProvider({ kms }));
  assert.equal(result.ok, true);
});

test("an encrypt-only Vault provider (no hmacRootCiphertext) passes conformance with requireHmac:false", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup
  });
  const { hmac, ...encryptOnly } = createKmsCryptoProvider({ kms });
  const ok = await assertCryptoProviderConformance(encryptOnly, { requireHmac: false });
  assert.equal(ok.ok, true);
});

test("deriveHmacKey throws a clear error when no hmacRootCiphertext is configured", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup
  });
  await assert.rejects(() => kms.deriveHmacKey("haechi:token-vault:v1"), /requires hmacRootCiphertext/);
});

test("deriveHmacKey is deterministic and domain-separated", async () => {
  const server = createMockVaultServer();
  const { ciphertext } = await makeHmacRoot(server, ADDRESS, KEY, server.token);
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup, hmacRootCiphertext: ciphertext
  });
  const a1 = await kms.deriveHmacKey("domain-a");
  const a2 = await kms.deriveHmacKey("domain-a");
  const b = await kms.deriveHmacKey("domain-b");
  assert.deepEqual(a1, a2);     // deterministic
  assert.notDeepEqual(a1, b);   // domain-separated
  assert.equal(a1.length, 32);
});

test("a data key wrapped under one transit key cannot be unwrapped under another (keyName isolation)", async () => {
  const server = createMockVaultServer();
  const a = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: "key-a", fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  const b = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: "key-b", fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  const wrapped = await a.wrap(randomBytes(32));
  await assert.rejects(() => b.unwrap(wrapped));
  // positive control: the SAME keyName round-trips.
  const dataKey = randomBytes(32);
  assert.deepEqual(await a.unwrap(await a.wrap(dataKey)), dataKey);
});

test("a corrupted wrapped data key is rejected", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: KEY, fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  const wrapped = await kms.wrap(randomBytes(32));
  // corrupt the base64 blob inside the vault:v1: envelope
  const blob = Buffer.from(wrapped.replace(/^vault:v1:/, ""), "base64");
  blob[blob.length - 1] ^= 0xff;
  const corrupted = `vault:v1:${blob.toString("base64")}`;
  await assert.rejects(() => kms.unwrap(corrupted));
});

test("a wrong Vault token is rejected (fail closed, generic error)", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({ address: ADDRESS, token: "s.wrongtoken", keyName: KEY, fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  await assert.rejects(() => kms.wrap(randomBytes(32)), /Vault transit request failed/);
});

test("wrap is non-deterministic — the same data key produces different ciphertext (fresh IV)", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: KEY, fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  const dataKey = randomBytes(32);
  assert.notEqual(await kms.wrap(dataKey), await kms.wrap(dataKey));
});

test("the STANDARD-base64 round-trip is correct for a data key that differs under std vs url base64", async () => {
  // 0xfb 0xff produces '+' and '/' in standard base64 but '-' and '_' in
  // base64url. A data key containing such bytes still round-trips because the
  // Vault backend uses STANDARD base64 on the wire (not base64url).
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: KEY, fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  const dataKey = Buffer.from([0xfb, 0xff, 0xbf, 0xfe, ...randomBytes(28)]);
  assert.equal(dataKey.length, 32);
  const wrapped = await kms.wrap(dataKey);
  assert.match(wrapped, /^vault:v1:/);
  assert.deepEqual(await kms.unwrap(wrapped), dataKey);
});

test("the X-Vault-Token and X-Vault-Namespace headers are sent", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY, namespace: "team-a",
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup
  });
  await kms.wrap(randomBytes(32));
  const last = server.calls.at(-1);
  assert.equal(last.headers["X-Vault-Token"], server.token);
  assert.equal(last.headers["X-Vault-Namespace"], "team-a");
});

test("no X-Vault-Namespace header is sent when namespace is omitted", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({ address: ADDRESS, token: server.token, keyName: KEY, fetchImpl: server.fetchImpl, lookupImpl: publicLookup });
  await kms.wrap(randomBytes(32));
  const last = server.calls.at(-1);
  assert.equal(last.headers["X-Vault-Namespace"], undefined);
});

test("the in-memory and Vault clients derive identical HMAC keys from the same root (cross-backend parity)", async () => {
  const server = createMockVaultServer();
  const root = randomBytes(32);
  const { ciphertext } = await makeHmacRoot(server, ADDRESS, KEY, server.token, root);
  const vault = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup, hmacRootCiphertext: ciphertext
  });
  const mem = createInMemoryKms({ masterKey: root });
  assert.deepEqual(await vault.deriveHmacKey("haechi:token-vault:v1"), await mem.deriveHmacKey("haechi:token-vault:v1"));
});

test("the SSRF guard rejects a Vault address whose host resolves to metadata/loopback/private ranges at request time", async () => {
  const server = createMockVaultServer();
  for (const blocked of ["169.254.169.254", "127.0.0.1", "10.1.2.3"]) {
    const kms = createVaultKmsClient({
      address: ADDRESS, token: server.token, keyName: KEY,
      fetchImpl: server.fetchImpl, lookupImpl: async () => [blocked]
    });
    await assert.rejects(() => kms.wrap(randomBytes(32)), /blocked \(private\/loopback\/link-local\/metadata\) range/);
  }
});

test("the SSRF guard rejects when ANY of multiple resolved addresses is blocked", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: async () => ["93.184.216.34", "169.254.169.254"]
  });
  await assert.rejects(() => kms.wrap(randomBytes(32)), /blocked/);
});

test("an explicit loopback dev address is permitted (http carve-out + resolved 127.0.0.1)", async () => {
  const server = createMockVaultServer();
  const kms = createVaultKmsClient({
    address: "http://127.0.0.1:8200", token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: async () => ["127.0.0.1"]
  });
  const dataKey = randomBytes(32);
  assert.deepEqual(await kms.unwrap(await kms.wrap(dataKey)), dataKey);
});

test("the Vault-backed provider works end-to-end through createRuntime (encrypt + tokenize round-trip)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-vault-e2e-"));
  const server = createMockVaultServer();
  const { ciphertext } = await makeHmacRoot(server, ADDRESS, KEY, server.token);
  const kms = createVaultKmsClient({
    address: ADDRESS, token: server.token, keyName: KEY,
    fetchImpl: server.fetchImpl, lookupImpl: publicLookup, hmacRootCiphertext: ciphertext
  });
  const runtime = createRuntime({
    mode: "enforce",
    keys: { provider: "external" },
    policy: { mode: "enforce", presets: [], defaultAction: "allow", actions: { email: "encrypt", api_key: "tokenize" } },
    audit: { path: join(dir, ".haechi", "audit.jsonl") },
    tokenVault: { path: join(dir, ".haechi", "token-vault.json"), revealPolicy: "local-dev" }
  }, { cryptoProvider: createKmsCryptoProvider({ kms }) });

  const result = await runtime.haechi.protectJson({ message: "mail minji.kim@example.com" });
  assert.match(result.payload.message, /\[HAECHI_ENC:/);
  assert.doesNotMatch(result.payload.message, /minji\.kim@example\.com/);

  const tok = await runtime.haechi.protectJson({ secret: "key sk_demo_0123456789abcdef0123456789ab" });
  const token = tok.payload.secret.match(/\[TOKEN:(tok_api_key_[a-f0-9]+)\]/)[1];
  const revealed = await runtime.tokenVault.reveal({ token });
  assert.equal(revealed.plaintext, "sk_demo_0123456789abcdef0123456789ab");

  const audit = await readFile(join(dir, ".haechi", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /minji\.kim@example\.com/);
});

// ---------------------------------------------------------------------------
// The satellite-local isBlockedAddress range table (the deliberate-duplication
// SSRF helper). Comprehensive coverage of the documented ranges.
// ---------------------------------------------------------------------------
test("isBlockedAddress blocks the full documented private/loopback/link-local/metadata range table", () => {
  const blocked = [
    "127.0.0.1", "127.255.255.255",        // 127/8 loopback
    "::1",                                   // IPv6 loopback
    "::",                                    // unspecified
    "10.0.0.1", "10.255.255.255",           // 10/8
    "172.16.0.1", "172.31.255.255",         // 172.16/12
    "192.168.0.1", "192.168.255.255",       // 192.168/16
    "169.254.0.1", "169.254.169.254",       // 169.254/16 link-local incl. metadata
    "0.0.0.0", "0.1.2.3",                   // 0/8
    "fe80::1", "fe80::abcd",                // fe80::/10 link-local
    "fc00::1", "fd12:3456::1",              // fc00::/7 unique-local
    "ff02::1",                               // ff00::/8 multicast
    "::ffff:127.0.0.1",                     // IPv4-mapped loopback (dotted)
    "::ffff:169.254.169.254",               // IPv4-mapped metadata (dotted)
    "::ffff:10.0.0.1",                      // IPv4-mapped private (dotted)
    // P1-CR-002: HEX IPv4-mapped IPv6 (7f00:1 == 127.0.0.1, a00:1 == 10.0.0.1,
    // c0a8:1 == 192.168.0.1, ac10:1 == 172.16.0.1, a9fe:a9fe == 169.254.169.254).
    "::ffff:7f00:1", "::ffff:7f00:0001",   // IPv4-mapped loopback (hex)
    "::ffff:a00:1",                         // IPv4-mapped 10.0.0.1 (hex)
    "::ffff:c0a8:1",                        // IPv4-mapped 192.168.0.1 (hex)
    "::ffff:ac10:1",                        // IPv4-mapped 172.16.0.1 (hex)
    "::ffff:a9fe:a9fe"                      // IPv4-mapped 169.254.169.254 (hex)
  ];
  for (const ip of blocked) {
    assert.equal(isBlockedAddress(ip), true, `${ip} must be blocked`);
  }

  const allowed = [
    "93.184.216.34",                        // example.com public
    "8.8.8.8",                               // public DNS
    "172.15.0.1",                            // just below 172.16/12
    "172.32.0.1",                            // just above 172.16/12
    "192.167.0.1",                           // just below 192.168/16
    "192.169.0.1",                           // just above 192.168/16
    "169.253.0.1",                           // just below 169.254/16
    "169.255.0.1",                           // just above 169.254/16
    "2606:2800:220:1:248:1893:25c8:1946",  // public IPv6 (example.com)
    "::ffff:93.184.216.34",                 // IPv4-mapped public (dotted)
    "::ffff:8.8.8.8", "::ffff:808:808",    // IPv4-mapped 8.8.8.8 (dotted AND hex) — public, allowed
    "::ffff:ac0f:1"                         // hex 172.15.0.1 — just below 172.16/12, allowed
  ];
  for (const ip of allowed) {
    assert.equal(isBlockedAddress(ip), false, `${ip} must be allowed`);
  }

  // Malformed / empty inputs fail closed (blocked).
  for (const bad of ["", "not-an-ip", "999.999.999.999", "1.2.3", null, undefined]) {
    assert.equal(isBlockedAddress(bad), true, `${String(bad)} must fail closed`);
  }
});

// ---------------------------------------------------------------------------
// P2-CR-012: explicit IPv6 loopback policy coverage for the vault guard.
// Closes the gap where the carve-out only proved IPv4 loopback behavior. Per the
// intended vault policy, EVERY IPv6 loopback form is blocked: bare ::1, the
// bracketed host syntax [::1] (a URL .hostname keeps the brackets), and the
// IPv4-mapped loopback in BOTH dotted (::ffff:127.0.0.1) and hex (::ffff:7f00:1)
// forms. A public IPv4-mapped IPv6 stays allowed (no over-block).
// ---------------------------------------------------------------------------
test("isBlockedAddress enforces the IPv6 loopback policy (::1, [::1], dotted + hex mapped) — P2-CR-012", () => {
  const blockedLoopback = [
    "::1",                 // bare IPv6 loopback
    "[::1]",               // bracketed IPv6 loopback (URL hostname form)
    "::ffff:127.0.0.1",    // dotted IPv4-mapped loopback
    "[::ffff:127.0.0.1]",  // bracketed dotted IPv4-mapped loopback
    "::ffff:7f00:1",       // hex IPv4-mapped loopback
    "::ffff:7f00:0001",    // hex IPv4-mapped loopback (leading-zero hextet)
    "[::ffff:7f00:1]"      // bracketed hex IPv4-mapped loopback
  ];
  for (const ip of blockedLoopback) {
    assert.equal(isBlockedAddress(ip), true, `${ip} (IPv6 loopback) must be blocked`);
  }
  // Public IPv4-mapped IPv6 must NOT be over-blocked (dotted AND hex).
  for (const ip of ["::ffff:8.8.8.8", "::ffff:808:808", "[::ffff:808:808]"]) {
    assert.equal(isBlockedAddress(ip), false, `${ip} (public mapped) must be allowed`);
  }
});
