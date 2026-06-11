// Core SSRF guard (Haechi 1.1 §2.3) — a node:-only, zero-dependency home for the
// address-blocklist + guarded-fetch pattern so CORE code (the process-isolated
// host-mediated key fetch) can use it. Core cannot import from a satellite, which
// is why this lives here.
//
// NOTE on the satellites: haechi-auth-jwt exports `isBlockedAddress`, and
// haechi-crypto-kms (vault.mjs) keeps a DELIBERATE satellite-local copy — a
// crypto/key-custody package must not runtime-depend on an auth (or core-ssrf)
// module's availability (see satellites/crypto-kms/ssrf-parity.test.mjs). 1.1 does
// NOT force those satellites to re-import this module (that would raise their
// `haechi` peer floor to 1.1 and republish them); instead the range logic here is
// kept byte-for-behavior identical to the satellite copies and guarded by a parity
// test (tests/ssrf.test.mjs). The drift is guarded, not (yet) eliminated.

import { isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";

const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 1024 * 1024; // 1 MiB

// Block literal addresses in private/loopback/link-local ranges + cloud metadata.
// Applied to both a literal host in the URL and every DNS-resolved address. This
// is the canonical copy; the satellite copies must agree (parity-tested).
export function isBlockedAddress(host) {
  // A URL's .hostname keeps the brackets on an IPv6 literal ("[::1]"), and isIP
  // rejects a bracketed string — strip them first so literals are classified.
  const bare = String(host).replace(/^\[|\]$/g, "");
  const v = isIP(bare);
  if (v === 4) {
    const o = bare.split(".").map(Number);
    if (o[0] === 127) return true;                          // 127.0.0.0/8 loopback
    if (o[0] === 10) return true;                           // 10.0.0.0/8
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16/12
    if (o[0] === 192 && o[1] === 168) return true;          // 192.168/16
    if (o[0] === 169 && o[1] === 254) return true;          // 169.254/16 link-local incl. metadata
    if (o[0] === 0) return true;                            // 0.0.0.0/8
    return false;
  }
  if (v === 6) {
    const h = bare.toLowerCase();
    if (h === "::1" || h === "::") return true;             // loopback / unspecified
    if (h.startsWith("::ffff:")) {                          // IPv4-mapped
      const mapped = h.slice("::ffff:".length);
      if (isIP(mapped) === 4) return isBlockedAddress(mapped);
    }
    // Range-check the first hextet: fe80::/10 link-local, fc00::/7 ULA, ff00::/8 multicast.
    const firstHextet = parseInt(h.split(":")[0] || "", 16);
    if (Number.isFinite(firstHextet)) {
      if (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) return true; // link-local
      if (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) return true; // unique local
      if (firstHextet >= 0xff00 && firstHextet <= 0xffff) return true; // multicast
    }
    return false;
  }
  return false; // not a literal IP; resolved addresses are checked separately
}

function parseHttpsUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`${label} must be https`);
  }
  return url;
}

// HTTPS-only, SSRF-hardened fetch returning the response body TEXT (bounded):
//   - https only;
//   - the literal host AND every DNS-resolved address must pass isBlockedAddress
//     (post-DNS re-check catches a hostname mapping to a private/metadata IP);
//   - redirect:"error" (no redirect to an internal target after the check);
//   - an AbortController timeout;
//   - the body is bounded to maxBytes while streaming.
// The residual DNS-rebinding window (resolve-then-connect) is accepted for an
// operator-configured, single-origin URL — same stance as the bearer satellite.
export async function guardedFetch(urlString, {
  fetchImpl = globalThis.fetch,
  lookupImpl = dnsLookup,
  timeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES,
  label = "url"
} = {}) {
  const url = parseHttpsUrl(urlString, label);
  if (isBlockedAddress(url.hostname)) {
    throw new Error(`${label} host is a blocked (private/loopback/link-local/metadata) address`);
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("global fetch is unavailable; pass fetchImpl");
  }
  const records = await lookupImpl(url.hostname, { all: true });
  for (const { address } of records) {
    if (isBlockedAddress(address)) {
      throw new Error(`${label} resolved to a blocked address`);
    }
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(url.href, { signal: controller.signal, redirect: "error" });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Error(`${label} fetch failed: ${res.status}`);
  }
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error(`${label} response exceeds the size limit`);
    }
    return text;
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} response exceeds the size limit`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

// A guarded key-material fetcher with a TTL cache + a refetch cooldown so an
// attacker's credential cannot pump the host's outbound requests (the kid-driven
// refetch is rate-limited, matching the bearer satellite). get() returns the
// cached body within ttlMs; otherwise it refetches, but no more often than
// cooldownMs (returning a stale cache during cooldown, or throwing if none).
export function createGuardedKeyFetcher({
  url,
  ttlMs = 300_000,
  cooldownMs = 60_000,
  now = () => Date.now(),
  ...fetchOptions
} = {}) {
  parseHttpsUrl(url, "keyMaterial.url"); // fail closed at construction on a bad URL
  if (!Number.isFinite(ttlMs) || ttlMs < 0) {
    throw new Error("keyMaterial.ttlMs must be a non-negative number");
  }
  if (!Number.isFinite(cooldownMs) || cooldownMs < 0) {
    throw new Error("keyMaterial.cooldownMs must be a non-negative number");
  }
  let cache = null;
  let fetchedAt = 0;
  let lastAttemptAt = -Infinity;
  let inflight = null;

  return {
    async get() {
      const t = now();
      if (cache !== null && (t - fetchedAt) < ttlMs) {
        return cache;
      }
      if (inflight) {
        return inflight;
      }
      // Cooldown: bound the outbound refetch rate. During cooldown serve the stale
      // cache if we have one; otherwise fail closed.
      if ((t - lastAttemptAt) < cooldownMs) {
        if (cache !== null) {
          return cache;
        }
        throw new Error("key material fetch is cooling down");
      }
      lastAttemptAt = t;
      inflight = guardedFetch(url, { ...fetchOptions, label: "keyMaterial.url" })
        .then((text) => {
          cache = text;
          fetchedAt = now();
          inflight = null;
          return text;
        }, (error) => {
          inflight = null;
          throw error;
        });
      return inflight;
    }
  };
}
