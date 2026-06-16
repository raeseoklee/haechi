import test from "node:test";
import assert from "node:assert/strict";
import { isBlockedAddress, guardedFetch, createGuardedKeyFetcher } from "../packages/ssrf/index.mjs";
import { isBlockedAddress as authJwtIsBlocked } from "haechi-auth-jwt";

// ---------------------------------------------------------------------------
// isBlockedAddress — comprehensive vectors (the canonical truth table)
// ---------------------------------------------------------------------------

const VECTORS = [
  // [address, expectedBlocked]
  ["127.0.0.1", true],
  ["127.255.255.255", true],
  ["10.0.0.1", true],
  ["10.255.255.255", true],
  ["172.16.0.1", true],
  ["172.31.255.255", true],
  ["172.15.0.1", false],
  ["172.32.0.1", false],
  ["192.168.1.1", true],
  ["169.254.169.254", true], // cloud metadata
  ["169.254.0.1", true],
  ["0.0.0.0", true],
  ["8.8.8.8", false],
  ["93.184.216.34", false],
  ["1.1.1.1", false],
  ["::1", true],
  ["::", true],
  ["[::1]", true],            // bracketed literal
  ["fe80::1", true],          // link-local
  ["fe81::1", true],          // within fe80::/10
  ["febf::1", true],
  ["fec0::1", false],         // outside fe80::/10
  ["fc00::1", true],          // ULA
  ["fdff::1", true],
  ["ff00::1", true],          // multicast
  ["::ffff:127.0.0.1", true], // IPv4-mapped loopback (dotted)
  ["::ffff:8.8.8.8", false],  // IPv4-mapped public (dotted)
  // P1-CR-002: HEX IPv4-mapped IPv6 must classify by the embedded v4, not slip
  // through as "public". 7f00:1 == 127.0.0.1, a00:1 == 10.0.0.1, etc.
  ["::ffff:7f00:1", true],    // hex loopback
  ["::ffff:7f00:0001", true], // hex loopback, leading-zero hextet
  ["[::ffff:7f00:1]", true],  // hex loopback, bracketed host syntax
  ["::ffff:a00:1", true],     // hex 10.0.0.1 (RFC1918)
  ["::ffff:c0a8:1", true],    // hex 192.168.0.1 (RFC1918)
  ["::ffff:ac10:1", true],    // hex 172.16.0.1 (RFC1918 lower edge)
  ["::ffff:a9fe:a9fe", true], // hex 169.254.169.254 (cloud metadata)
  ["::ffff:808:808", false],  // hex 8.8.8.8 — public mapped stays ALLOWED
  ["[::ffff:808:808]", false],// hex public, bracketed — still allowed
  ["::ffff:ac0f:1", false],   // hex 172.15.0.1 — just below 172.16/12, allowed
  ["2606:4700:4700::1111", false], // public IPv6
  ["not-an-ip", false],       // hostnames are checked post-DNS, not here
  ["example.com", false]
];

test("isBlockedAddress classifies the canonical vector table", () => {
  for (const [addr, expected] of VECTORS) {
    assert.equal(isBlockedAddress(addr), expected, `isBlockedAddress(${JSON.stringify(addr)}) should be ${expected}`);
  }
});

// ---------------------------------------------------------------------------
// Parity guard: the core copy must agree with the satellite copy. (The
// satellites keep DELIBERATE local copies — a crypto/auth package must not
// runtime-depend on this module; see crypto-kms/ssrf-parity.test.mjs. This test
// guards drift between core and auth-jwt; the existing satellite parity test
// chains auth-jwt <-> crypto-kms, so transitively all three agree.)
// ---------------------------------------------------------------------------

test("core isBlockedAddress agrees with haechi-auth-jwt on every vector", () => {
  for (const [addr] of VECTORS) {
    assert.equal(
      isBlockedAddress(addr),
      authJwtIsBlocked(addr),
      `core vs auth-jwt diverged for ${JSON.stringify(addr)}`
    );
  }
});

// ---------------------------------------------------------------------------
// guardedFetch — https-only, post-DNS re-check, bounded, redirect:error
// ---------------------------------------------------------------------------

const okText = (body) => async () => ({ ok: true, body: null, text: async () => body });
const publicLookup = async () => [{ address: "93.184.216.34" }];

test("guardedFetch refuses non-https", async () => {
  await assert.rejects(guardedFetch("http://example.com/keys", { fetchImpl: okText("x"), lookupImpl: publicLookup }), /must be https/);
});

test("guardedFetch refuses a literal blocked host without fetching", async () => {
  let fetched = false;
  await assert.rejects(
    guardedFetch("https://127.0.0.1/keys", { fetchImpl: async () => { fetched = true; return {}; }, lookupImpl: publicLookup }),
    /blocked/
  );
  assert.equal(fetched, false, "must not fetch a blocked literal host");
});

test("guardedFetch refuses a hostname that resolves to a blocked (metadata) address", async () => {
  let fetched = false;
  await assert.rejects(
    guardedFetch("https://keys.example.com/jwks", {
      lookupImpl: async () => [{ address: "169.254.169.254" }],
      fetchImpl: async () => { fetched = true; return {}; }
    }),
    /resolved to a blocked address/
  );
  assert.equal(fetched, false, "must not fetch after a blocked DNS result");
});

test("guardedFetch passes a redirect:error option and returns the body for an allowed host", async () => {
  let sawRedirectError = false;
  const fetchImpl = async (_href, opts) => {
    if (opts && opts.redirect === "error") sawRedirectError = true;
    return { ok: true, body: null, text: async () => "JWKS_BODY" };
  };
  const body = await guardedFetch("https://keys.example.com/jwks", { fetchImpl, lookupImpl: publicLookup });
  assert.equal(body, "JWKS_BODY");
  assert.ok(sawRedirectError, "guardedFetch must pass redirect:error");
});

test("guardedFetch bounds the response body size", async () => {
  await assert.rejects(
    guardedFetch("https://keys.example.com/jwks", {
      fetchImpl: okText("x".repeat(100)),
      lookupImpl: publicLookup,
      maxBytes: 10
    }),
    /size limit/
  );
});

test("guardedFetch rejects a non-ok response", async () => {
  await assert.rejects(
    guardedFetch("https://keys.example.com/jwks", {
      fetchImpl: async () => ({ ok: false, status: 503 }),
      lookupImpl: publicLookup
    }),
    /fetch failed: 503/
  );
});

// ---------------------------------------------------------------------------
// createGuardedKeyFetcher — TTL cache + cooldown-bounded refetch
// ---------------------------------------------------------------------------

function countingFetcher() {
  let n = 0;
  return {
    get count() { return n; },
    fetchImpl: async () => { n += 1; return { ok: true, body: null, text: async () => `DOC#${n}` }; }
  };
}

test("createGuardedKeyFetcher refuses a non-https url at construction", () => {
  assert.throws(() => createGuardedKeyFetcher({ url: "http://keys.example.com/jwks" }), /must be https/);
});

test("createGuardedKeyFetcher caches within TTL and refetches after it", async () => {
  const clock = { t: 0 };
  const cf = countingFetcher();
  const fetcher = createGuardedKeyFetcher({
    url: "https://keys.example.com/jwks",
    ttlMs: 100,
    cooldownMs: 50,
    now: () => clock.t,
    fetchImpl: cf.fetchImpl,
    lookupImpl: publicLookup
  });
  assert.equal(await fetcher.get(), "DOC#1");
  clock.t = 50; // within TTL → cached
  assert.equal(await fetcher.get(), "DOC#1");
  assert.equal(cf.count, 1, "no refetch within TTL");
  clock.t = 200; // past TTL and past cooldown → refetch
  assert.equal(await fetcher.get(), "DOC#2");
  assert.equal(cf.count, 2);
});

test("createGuardedKeyFetcher serves a stale cache during cooldown (bounds the outbound rate)", async () => {
  const clock = { t: 0 };
  const cf = countingFetcher();
  const fetcher = createGuardedKeyFetcher({
    url: "https://keys.example.com/jwks",
    ttlMs: 100,
    cooldownMs: 1000,
    now: () => clock.t,
    fetchImpl: cf.fetchImpl,
    lookupImpl: publicLookup
  });
  assert.equal(await fetcher.get(), "DOC#1");
  clock.t = 150; // past TTL but within cooldown → serve stale, do NOT refetch
  assert.equal(await fetcher.get(), "DOC#1");
  assert.equal(cf.count, 1, "cooldown bounds the refetch rate");
  clock.t = 1100; // past cooldown → refetch
  assert.equal(await fetcher.get(), "DOC#2");
  assert.equal(cf.count, 2);
});

test("createGuardedKeyFetcher fails closed during cooldown when there is no cache (first fetch failed)", async () => {
  const clock = { t: 0 };
  let n = 0;
  const fetcher = createGuardedKeyFetcher({
    url: "https://keys.example.com/jwks",
    ttlMs: 100,
    cooldownMs: 1000,
    now: () => clock.t,
    fetchImpl: async () => { n += 1; throw new Error("upstream down"); },
    lookupImpl: publicLookup
  });
  await assert.rejects(fetcher.get(), /upstream down/);
  clock.t = 50; // within cooldown, no cache → fail closed without a new fetch
  await assert.rejects(fetcher.get(), /cooling down/);
  assert.equal(n, 1, "must not retry within the cooldown window");
});
