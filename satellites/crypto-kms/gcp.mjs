// Google Cloud KMS client for haechi-crypto-kms.
//
// Returns a `kms` client (the same small interface createInMemoryKms implements:
// keyId / wrap / unwrap / deriveHmacKey) backed by Google Cloud KMS, so it plugs
// straight into createKmsCryptoProvider({ kms }). Envelope wrapping uses the KMS
// crypto-key's Encrypt/Decrypt on a CSPRNG-generated 32-byte data key (the
// provider generates the data key; KMS only ever holds the key material). HMAC
// keys are HKDF-derived from a single KMS-decrypted root, so per-domain keys are
// deterministic and domain-separated without a network round-trip per token.
//
// @google-cloud/kms is an OPTIONAL peer dependency: it is imported lazily, only
// when no `client` is injected. Tests inject a faithful mock of the two KMS
// operations, so the suite needs neither the SDK nor network access.

import { hkdfSync } from "node:crypto";

// IDENTICAL info string to aws.mjs / azure.mjs / vault.mjs / createInMemoryKms,
// so every backend derives the SAME per-domain key from the SAME 32-byte root
// (cross-backend parity / migration safety).
const HMAC_ROOT_INFO = "haechi:crypto-kms:hmac-root:v1";

// The minimal, NORMALIZED KMS operation surface the client needs:
//   encrypt({ name, plaintext: Buffer }) -> { ciphertext: Buffer }
//   decrypt({ name, ciphertext: Buffer }) -> { plaintext: Buffer }
// The Google SDK's KeyManagementServiceClient returns an ARRAY ([response]),
// which the lazy path below adapts into this normalized surface; in tests a mock
// implements this normalized surface directly.
export function createGcpKmsClient({ keyName, client, hmacRootCiphertext } = {}) {
  if (!keyName || typeof keyName !== "string") {
    throw new Error("createGcpKmsClient requires a keyName (a Cloud KMS crypto-key resource path)");
  }

  let opsPromise = null;
  async function ops() {
    if (client) return client;
    if (!opsPromise) {
      // Don't cache a rejection: a failed lazy import should be retryable rather
      // than poisoning the client for its lifetime.
      opsPromise = (async () => {
        let sdk;
        try {
          sdk = await import("@google-cloud/kms");
        } catch {
          throw new Error(
            "@google-cloud/kms is not installed. Install it (it is an optional peer dependency) or inject a `client` with encrypt/decrypt."
          );
        }
        const kms = new sdk.KeyManagementServiceClient();
        // Adapt the SDK's ARRAY return ([{ ciphertext }] / [{ plaintext }]) into
        // the normalized { ciphertext } / { plaintext } surface.
        return {
          encrypt: async ({ name, plaintext }) => {
            const [res] = await kms.encrypt({ name, plaintext: Buffer.from(plaintext) });
            return { ciphertext: Buffer.from(res.ciphertext) };
          },
          decrypt: async ({ name, ciphertext }) => {
            const [res] = await kms.decrypt({ name, ciphertext: Buffer.from(ciphertext) });
            return { plaintext: Buffer.from(res.plaintext) };
          }
        };
      })().catch((err) => {
        opsPromise = null;
        throw err;
      });
    }
    return opsPromise;
  }

  let hmacRootPromise = null;
  function hmacRoot() {
    if (!hmacRootCiphertext) {
      throw new Error(
        "deriveHmacKey requires hmacRootCiphertext: a base64url Cloud KMS-encrypted 32-byte root. Omit hmac (encrypt-only) if you do not tokenize/authenticate."
      );
    }
    if (!hmacRootPromise) {
      // Don't cache a rejection: a transient KMS decrypt failure (throttling,
      // network) should be retryable, not poison hmac for the client's lifetime.
      hmacRootPromise = (async () => {
        const o = await ops();
        const res = await o.decrypt({ name: keyName, ciphertext: Buffer.from(hmacRootCiphertext, "base64url") });
        const root = Buffer.from(res.plaintext);
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
      const o = await ops();
      const res = await o.encrypt({ name: keyName, plaintext: Buffer.from(dataKey) });
      return Buffer.from(res.ciphertext).toString("base64url");
    },
    async unwrap(wrapped) {
      const o = await ops();
      const res = await o.decrypt({ name: keyName, ciphertext: Buffer.from(wrapped, "base64url") });
      return Buffer.from(res.plaintext);
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
