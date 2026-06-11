// HashiCorp Vault Transit client for haechi-crypto-kms.
//
// Returns a `kms` client (the same small interface createInMemoryKms implements:
// keyId / wrap / unwrap / deriveHmacKey) backed by Vault's Transit secrets
// engine, so it plugs straight into createKmsCryptoProvider({ kms }). Unlike the
// AWS/GCP/Azure backends, this has ZERO optional peer: the Transit engine is a
// plain HTTP API reachable with `node:` `fetch`, making it the dependency-lightest
// backend.
//
// Envelope wrapping uses Transit Encrypt/Decrypt on a CSPRNG-generated 32-byte
// data key (the provider generates the data key; Vault only holds the transit
// key). HMAC keys are HKDF-derived from a single Transit-decrypted root, so
// per-domain keys are deterministic and domain-separated without a network
// round-trip per token.
//
// WIRE SHAPES (load-bearing):
//   wrap  = POST {address}/v1/transit/encrypt/{keyName}
//           body { plaintext: STANDARD-base64(dataKey) }
//           -> data.ciphertext  (the "vault:v1:..." string verbatim — that IS the
//              wrapped form, returned as-is)
//   unwrap= POST {address}/v1/transit/decrypt/{keyName}
//           body { ciphertext }  (the "vault:v1:..." string)
//           -> Buffer.from(data.plaintext, "base64")  (STANDARD base64, NOT
//              base64url — Vault uses standard base64; the decode back to the
//              32-byte Buffer is mandatory or the HKDF root is garbage)
//
// ASSUMPTION: the transit key must be NON-DERIVED (no per-context derivation /
// convergent mode) so encrypt/decrypt of a fixed plaintext round-trips without a
// `context`. A derived key would require a stable context on every call.
//
// SSRF HARDENING: an operator-supplied VAULT_ADDR can rebind to a cloud metadata
// endpoint (169.254.169.254). Every egress parses `address` as a URL, requires
// https (with a documented http-loopback dev carve-out), runs lookupImpl(host)
// and rejects if ANY resolved address is private/loopback/link-local/metadata,
// uses redirect:"error", bounds the response body, and applies a fetch timeout.

import { hkdfSync } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";

// IDENTICAL info string to aws.mjs / gcp.mjs / azure.mjs / createInMemoryKms, so
// every backend derives the SAME per-domain key from the SAME 32-byte root
// (cross-backend parity / migration safety).
const HMAC_ROOT_INFO = "haechi:crypto-kms:hmac-root:v1";

const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 1 << 20; // 1 MiB — a transit response is tiny; bound it.

// ---------------------------------------------------------------------------
// Satellite-local SSRF address guard.
//
// DELIBERATE DUPLICATION: a crypto/key-custody package must NOT depend on an auth
// package, so we do not import isBlockedAddress from haechi-auth-jwt. This small
// pure function is intentionally a separate copy (the auth egress in §2.2 keeps
// its own); the duplication is documented and tested here with a range table.
//
// Blocks: 127/8, ::1, 10/8, 172.16/12, 192.168/16, 169.254/16 (incl.
// 169.254.169.254), 0/8, fe80::/10, fc00::/7, ff00::/8, and IPv4-mapped
// ::ffff:<blocked-v4>.
// ---------------------------------------------------------------------------
export function isBlockedAddress(address) {
  if (typeof address !== "string" || address.length === 0) return true; // fail closed
  let ip = address.trim();

  // Strip an IPv6 zone id (fe80::1%eth0).
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:0001) — unwrap to the v4.
  const mapped = ip.match(/^::ffff:(.+)$/i);
  if (mapped) {
    const inner = mapped[1];
    if (inner.includes(".")) {
      return isBlockedV4(inner);
    }
    // hex form ::ffff:7f00:0001 -> reconstruct dotted quad
    const hex = inner.replace(":", "");
    if (/^[0-9a-f]{8}$/i.test(hex)) {
      const b = hex.match(/.{2}/g).map((h) => parseInt(h, 16));
      return isBlockedV4(`${b[0]}.${b[1]}.${b[2]}.${b[3]}`);
    }
  }

  if (ip.includes(":")) return isBlockedV6(ip);
  return isBlockedV4(ip);
}

function isBlockedV4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return true; // malformed → fail closed
  const oct = parts.map((p) => Number(p));
  if (oct.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = oct;
  if (a === 0) return true; // 0.0.0.0/8 ("this" network)
  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  return false;
}

function isBlockedV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true; // loopback / unspecified
  // Expand only the leading group enough to classify prefixes.
  // fe80::/10 (link-local), fc00::/7 (unique-local), ff00::/8 (multicast).
  const firstGroup = lower.split(":")[0];
  if (firstGroup === "" ) {
    // starts with "::" — already handled ::1/:: above; anything else is unspecified-ish
    return true;
  }
  const head = parseInt(firstGroup.padEnd(4, "0").slice(0, 4), 16);
  if (Number.isNaN(head)) return true; // malformed → fail closed
  if ((head & 0xffc0) === 0xfe80) return true; // fe80::/10
  if ((head & 0xfe00) === 0xfc00) return true; // fc00::/7
  if ((head & 0xff00) === 0xff00) return true; // ff00::/8
  return false;
}

export function createVaultKmsClient({
  address,
  token,
  keyName,
  namespace,
  hmacRootCiphertext,
  fetchImpl,
  lookupImpl,
  fetchTimeoutMs = DEFAULT_FETCH_TIMEOUT_MS
} = {}) {
  if (!keyName || typeof keyName !== "string") {
    throw new Error("createVaultKmsClient requires a keyName (a non-derived Vault Transit key name)");
  }
  if (!address || typeof address !== "string") {
    throw new Error("createVaultKmsClient requires an address (the Vault server base URL, e.g. https://vault.example:8200)");
  }
  if (!token || typeof token !== "string") {
    throw new Error("createVaultKmsClient requires a token (a Vault token for X-Vault-Token)");
  }

  let baseUrl;
  try {
    baseUrl = new URL(address);
  } catch {
    throw new Error("createVaultKmsClient address must be a valid URL");
  }
  // Require https; carve out http only for an explicit loopback dev address.
  const isLoopbackHost = baseUrl.hostname === "localhost"
    || baseUrl.hostname === "127.0.0.1"
    || baseUrl.hostname === "::1"
    || baseUrl.hostname === "[::1]";
  if (baseUrl.protocol !== "https:" && !(baseUrl.protocol === "http:" && isLoopbackHost)) {
    throw new Error("createVaultKmsClient address must be https (http is allowed only for an explicit loopback dev address)");
  }

  const doFetch = fetchImpl || globalThis.fetch;
  const doLookup = lookupImpl || (async (host) => {
    const results = await dnsLookup(host, { all: true });
    return results.map((r) => r.address);
  });

  // SSRF re-check immediately before each request (post-DNS, rebinding guard):
  // resolve the host and reject if ANY resolved address is blocked. The loopback
  // dev carve-out above intentionally permits an http loopback address; the IP
  // guard still runs and 127.0.0.1 IS blocked, so a loopback address is only
  // reachable when the host literally is 127.0.0.1/::1 (which the carve-out names)
  // — we therefore allow resolved loopback ONLY when the configured host is itself
  // loopback, never via a rebinding public name.
  async function assertSafeEgress() {
    const host = baseUrl.hostname.replace(/^\[|\]$/g, "");
    const resolved = await doLookup(host);
    const addrs = Array.isArray(resolved) ? resolved : [resolved];
    if (addrs.length === 0) {
      throw new Error("Vault address did not resolve");
    }
    for (const addr of addrs) {
      if (isBlockedAddress(addr)) {
        if (isLoopbackHost && (addr === "127.0.0.1" || addr === "::1")) {
          continue; // explicit loopback dev carve-out
        }
        throw new Error("Vault address resolves to a blocked (private/loopback/link-local/metadata) range");
      }
    }
  }

  async function vaultPost(path, body) {
    await assertSafeEgress();
    const url = new URL(path, baseUrl).toString();
    const headers = { "Content-Type": "application/json", "X-Vault-Token": token };
    if (namespace) headers["X-Vault-Namespace"] = namespace;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), fetchTimeoutMs);
    let res;
    try {
      res = await doFetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        redirect: "error",
        signal: controller.signal
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res || !res.ok) {
      // Generic, fail-closed error — never echo Vault's error body (it can carry
      // key paths / policy detail).
      throw new Error(`Vault transit request failed (status ${res ? res.status : "no response"})`);
    }
    // Bound the response body.
    const text = await readBounded(res);
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error("Vault transit response was not valid JSON");
    }
    return parsed;
  }

  let hmacRootPromise = null;
  function hmacRoot() {
    if (!hmacRootCiphertext) {
      throw new Error(
        "deriveHmacKey requires hmacRootCiphertext: a Vault Transit ciphertext (vault:v1:...) of a 32-byte root. Omit hmac (encrypt-only) if you do not tokenize/authenticate."
      );
    }
    if (!hmacRootPromise) {
      // Don't cache a rejection: a transient decrypt failure should be retryable,
      // not poison hmac for the client's lifetime.
      hmacRootPromise = (async () => {
        const body = await vaultPost(`/v1/transit/decrypt/${encodeURIComponent(keyName)}`, {
          ciphertext: hmacRootCiphertext
        });
        const root = Buffer.from(body?.data?.plaintext ?? "", "base64");
        if (root.length < 32) {
          throw new Error("hmacRootCiphertext decrypts to fewer than 32 bytes; supply a >=32-byte root");
        }
        return root;
      })().catch((err) => {
        hmacRootPromise = null;
        throw err;
      });
    }
    return hmacRootPromise;
  }

  return {
    keyId: keyName,
    async wrap(dataKey) {
      const body = await vaultPost(`/v1/transit/encrypt/${encodeURIComponent(keyName)}`, {
        // STANDARD base64 (Vault requirement), NOT base64url.
        plaintext: Buffer.from(dataKey).toString("base64")
      });
      const ciphertext = body?.data?.ciphertext;
      if (typeof ciphertext !== "string" || !ciphertext.startsWith("vault:")) {
        throw new Error("Vault transit encrypt returned no ciphertext");
      }
      // The "vault:v1:..." string IS the wrapped form — return it verbatim.
      return ciphertext;
    },
    async unwrap(wrapped) {
      const body = await vaultPost(`/v1/transit/decrypt/${encodeURIComponent(keyName)}`, {
        ciphertext: wrapped
      });
      const plaintext = body?.data?.plaintext;
      if (typeof plaintext !== "string") {
        throw new Error("Vault transit decrypt returned no plaintext");
      }
      // STANDARD base64 decode back to the 32-byte Buffer (mandatory).
      return Buffer.from(plaintext, "base64");
    },
    async deriveHmacKey(domain) {
      if (!domain || typeof domain !== "string") {
        throw new Error("deriveHmacKey requires a non-empty domain string");
      }
      const root = await hmacRoot();
      // HKDF-SHA256, domain-separated — matches Haechi's per-domain key discipline
      // and the other backends' info string (cross-backend parity).
      return Buffer.from(hkdfSync("sha256", root, Buffer.alloc(0), `${HMAC_ROOT_INFO}:${domain}`, 32));
    }
  };
}

// Read a fetch Response body with a hard byte cap (defends against a hostile or
// runaway Vault endpoint streaming an unbounded body).
async function readBounded(res) {
  if (typeof res.text === "function" && !res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
      throw new Error("Vault transit response exceeded the byte cap");
    }
    return text;
  }
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        try { await reader.cancel(); } catch { /* ignore */ }
        throw new Error("Vault transit response exceeded the byte cap");
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks).toString("utf8");
  }
  // Fallback for a mock returning text() only.
  const text = await res.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw new Error("Vault transit response exceeded the byte cap");
  }
  return text;
}
