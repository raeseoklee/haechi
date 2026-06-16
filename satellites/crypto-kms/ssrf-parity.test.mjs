// ssrf-parity.test.mjs — CI drift guard for the intentionally duplicated
// isBlockedAddress in vault.mjs.
//
// RATIONALE: A crypto/key-custody package must not runtime-depend on an auth
// package, so vault.mjs carries its own satellite-local copy of isBlockedAddress.
// This test asserts the two copies agree on every IP vector that the function is
// actually called with in production (already-resolved IP addresses). It does NOT
// merge the copies — the duplication is intentional and must stay. This file is
// the enforcement mechanism that prevents silent range drift.
//
// If this test fails, update BOTH copies together and add the new vector here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isBlockedAddress as authJwtIsBlocked } from "haechi-auth-jwt";
import { isBlockedAddress as cryptoKmsIsBlocked } from "./vault.mjs";

// ---------------------------------------------------------------------------
// Shared test helper: assert both copies agree AND match the expected value.
// ---------------------------------------------------------------------------
function assertParity(ip, expectedBlocked) {
  const authResult = authJwtIsBlocked(ip);
  const kmsResult = cryptoKmsIsBlocked(ip);
  assert.strictEqual(
    authResult,
    kmsResult,
    `isBlockedAddress("${ip}") diverged: auth-jwt=${authResult}, crypto-kms=${kmsResult}`
  );
  assert.strictEqual(
    kmsResult,
    expectedBlocked,
    `isBlockedAddress("${ip}"): expected ${expectedBlocked}, got ${kmsResult}`
  );
}

// ---------------------------------------------------------------------------
// Blocked IPv4
// ---------------------------------------------------------------------------
describe("SSRF parity — blocked IPv4", () => {
  it('blocks 0.0.0.0 ("this" network)', () => assertParity("0.0.0.0", true));
  it("blocks 127.0.0.1 (loopback)", () => assertParity("127.0.0.1", true));
  it("blocks 10.0.0.1 (RFC-1918 class A)", () => assertParity("10.0.0.1", true));
  it("blocks 172.16.0.1 (RFC-1918 class B lower edge)", () => assertParity("172.16.0.1", true));
  it("blocks 172.31.255.255 (RFC-1918 class B upper edge)", () => assertParity("172.31.255.255", true));
  it("blocks 192.168.1.1 (RFC-1918 class C)", () => assertParity("192.168.1.1", true));
  it("blocks 169.254.169.254 (link-local / cloud metadata)", () => assertParity("169.254.169.254", true));
});

// ---------------------------------------------------------------------------
// Allowed public IPv4
// ---------------------------------------------------------------------------
describe("SSRF parity — allowed public IPv4", () => {
  it("allows 8.8.8.8 (Google DNS)", () => assertParity("8.8.8.8", false));
  it("allows 93.184.216.34 (example.com)", () => assertParity("93.184.216.34", false));
  it("allows 1.1.1.1 (Cloudflare DNS)", () => assertParity("1.1.1.1", false));
});

// ---------------------------------------------------------------------------
// Blocked IPv6 (bare form — both implementations accept bare addresses)
// ---------------------------------------------------------------------------
describe("SSRF parity — blocked IPv6 (bare)", () => {
  it("blocks ::1 (loopback)", () => assertParity("::1", true));

  // fe80::/10 link-local: lower edge (fe80) and upper edge of the /10 block (febf)
  it("blocks fe80::1 (link-local lower edge)", () => assertParity("fe80::1", true));
  it("blocks febf::1 (link-local upper edge of fe80::/10)", () => assertParity("febf::1", true));

  // fc00::/7 unique-local: two representative addresses
  it("blocks fc00::1 (unique-local lower edge)", () => assertParity("fc00::1", true));
  it("blocks fdff::1 (unique-local upper edge of fc00::/7)", () => assertParity("fdff::1", true));

  // ff02::/8 multicast (ff00::/8 block)
  it("blocks ff02::1 (multicast)", () => assertParity("ff02::1", true));
});

// ---------------------------------------------------------------------------
// Allowed public IPv6
// ---------------------------------------------------------------------------
describe("SSRF parity — allowed public IPv6", () => {
  it("allows 2606:4700:4700::1111 (Cloudflare public DNS)", () => assertParity("2606:4700:4700::1111", false));
});

// ---------------------------------------------------------------------------
// IPv4-mapped IPv6 — both copies must classify by the embedded v4 (P1-CR-002).
// DOTTED (::ffff:127.0.0.1) and HEX (::ffff:7f00:1) forms must agree, and a
// genuinely public mapped address must stay allowed (no over-block).
// ---------------------------------------------------------------------------
describe("SSRF parity — IPv4-mapped IPv6 (dotted + hex, P1-CR-002)", () => {
  // Blocked: loopback / RFC1918 / metadata in dotted and hex forms.
  it("blocks ::ffff:127.0.0.1 (dotted loopback)", () => assertParity("::ffff:127.0.0.1", true));
  it("blocks ::ffff:7f00:1 (hex loopback)", () => assertParity("::ffff:7f00:1", true));
  it("blocks ::ffff:7f00:0001 (hex loopback, leading zero)", () => assertParity("::ffff:7f00:0001", true));
  it("blocks ::ffff:10.0.0.1 (dotted RFC1918)", () => assertParity("::ffff:10.0.0.1", true));
  it("blocks ::ffff:a00:1 (hex 10.0.0.1)", () => assertParity("::ffff:a00:1", true));
  it("blocks ::ffff:c0a8:1 (hex 192.168.0.1)", () => assertParity("::ffff:c0a8:1", true));
  it("blocks ::ffff:ac10:1 (hex 172.16.0.1)", () => assertParity("::ffff:ac10:1", true));
  it("blocks ::ffff:a9fe:a9fe (hex 169.254.169.254 metadata)", () => assertParity("::ffff:a9fe:a9fe", true));
  // Allowed: a genuinely public mapped address (no over-block).
  it("allows ::ffff:8.8.8.8 (dotted public)", () => assertParity("::ffff:8.8.8.8", false));
  it("allows ::ffff:808:808 (hex 8.8.8.8 public)", () => assertParity("::ffff:808:808", false));
  it("allows ::ffff:ac0f:1 (hex 172.15.0.1, just below 172.16/12)", () => assertParity("::ffff:ac0f:1", false));
});

// ---------------------------------------------------------------------------
// KNOWN, INTENTIONAL DIVERGENCE — non-IP string input.
//
// The two copies are called at different points in the egress pipeline:
//
//   auth-jwt (createJwtVerifier): isBlockedAddress is called in TWO phases.
//     Phase 1 — construction time: called on the literal hostname from the URL
//       object (.hostname), which may be a domain name, NOT a resolved IP.
//       A domain name is not a blocked address; the resolved IP is checked next.
//     Phase 2 — fetch time: called on every DNS-resolved address (already an IP).
//     Because of phase 1, the function must return false for a non-IP hostname
//     string ("api.example.com") so that legitimate domain names aren't rejected
//     before DNS resolution. Non-IP → return false.
//
//   crypto-kms (vault.mjs): isBlockedAddress is ONLY ever called on
//     already-resolved IP addresses (from dnsLookup results in assertSafeEgress).
//     A non-IP string arriving here indicates a programming error; fail-closed
//     (return true) is the correct and safe behavior.
//
// This test pins both exact values so that the divergence is intentional and
// visible rather than accidental drift.
// ---------------------------------------------------------------------------
describe("SSRF parity — KNOWN INTENTIONAL DIVERGENCE on non-IP string", () => {
  it('auth-jwt returns false for "not-an-ip" (domain names pass phase-1 for DNS check)', () => {
    assert.strictEqual(
      authJwtIsBlocked("not-an-ip"),
      false,
      'auth-jwt must return false for a non-IP string (hostname resolution is the second check)'
    );
  });

  it('crypto-kms returns true for "not-an-ip" (fail-closed: only called on resolved IPs)', () => {
    assert.strictEqual(
      cryptoKmsIsBlocked("not-an-ip"),
      true,
      'crypto-kms must return true for a non-IP string (fail-closed; function is only called post-DNS)'
    );
  });
});
