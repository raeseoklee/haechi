// Azure Key Vault client for haechi-crypto-kms.
//
// Returns a `kms` client (the same small interface createInMemoryKms implements:
// keyId / wrap / unwrap / deriveHmacKey) backed by Azure Key Vault, so it plugs
// straight into createKmsCryptoProvider({ kms }). Unlike the AWS/GCP backends —
// which Encrypt/Decrypt an opaque blob — Azure NATIVELY wraps/unwraps a key via
// the vault key's CryptographyClient (RSA-OAEP by default). `wrap` envelopes the
// CSPRNG 32-byte data key; `unwrap` recovers it. HMAC keys are HKDF-derived from
// a single unwrapped root, so per-domain keys are deterministic and
// domain-separated without a network round-trip per token.
//
// @azure/keyvault-keys + @azure/identity are OPTIONAL peer dependencies: they are
// imported lazily, only when no `client` is injected. Tests inject a faithful
// mock of wrapKey/unwrapKey, so the suite needs neither the SDKs nor network.

import { hkdfSync } from "node:crypto";

// IDENTICAL info string to aws.mjs / gcp.mjs / vault.mjs / createInMemoryKms, so
// every backend derives the SAME per-domain key from the SAME 32-byte root
// (cross-backend parity / migration safety).
const HMAC_ROOT_INFO = "haechi:crypto-kms:hmac-root:v1";

// The minimal KMS operation surface the client needs (the Azure-native wrap/unwrap
// shape):
//   wrapKey(algorithm, key: Buffer) -> { result: Buffer }
//   unwrapKey(algorithm, encryptedKey: Buffer) -> { result: Buffer }
// In production these are an Azure CryptographyClient; in tests a mock implements
// them directly.
export function createAzureKmsClient({ keyId, client, hmacRootCiphertext, wrapAlgorithm = "RSA-OAEP-256" } = {}) {
  if (!keyId || typeof keyId !== "string") {
    throw new Error("createAzureKmsClient requires a keyId (an Azure Key Vault key identifier URL)");
  }

  let opsPromise = null;
  async function ops() {
    if (client) return client;
    if (!opsPromise) {
      // Don't cache a rejection: a failed lazy import should be retryable rather
      // than poisoning the client for its lifetime.
      opsPromise = (async () => {
        let keysSdk;
        let identitySdk;
        try {
          keysSdk = await import("@azure/keyvault-keys");
          identitySdk = await import("@azure/identity");
        } catch {
          throw new Error(
            "@azure/keyvault-keys and @azure/identity are not installed. Install them (they are optional peer dependencies) or inject a `client` with wrapKey/unwrapKey."
          );
        }
        const cryptoClient = new keysSdk.CryptographyClient(keyId, new identitySdk.DefaultAzureCredential());
        return {
          wrapKey: (algorithm, key) => cryptoClient.wrapKey(algorithm, Buffer.from(key)),
          unwrapKey: (algorithm, encryptedKey) => cryptoClient.unwrapKey(algorithm, Buffer.from(encryptedKey))
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
        "deriveHmacKey requires hmacRootCiphertext: a base64url Azure-wrapped 32-byte root. Omit hmac (encrypt-only) if you do not tokenize/authenticate."
      );
    }
    if (!hmacRootPromise) {
      // Don't cache a rejection: a transient unwrap failure (throttling, network)
      // should be retryable, not poison hmac for the client's lifetime.
      hmacRootPromise = (async () => {
        const o = await ops();
        const res = await o.unwrapKey(wrapAlgorithm, Buffer.from(hmacRootCiphertext, "base64url"));
        const root = Buffer.from(res.result);
        if (root.length < 32) {
          throw new Error("hmacRootCiphertext unwraps to fewer than 32 bytes; supply a >=32-byte root");
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
    keyId,
    async wrap(dataKey) {
      const o = await ops();
      const res = await o.wrapKey(wrapAlgorithm, Buffer.from(dataKey));
      return Buffer.from(res.result).toString("base64url");
    },
    async unwrap(wrapped) {
      const o = await ops();
      const res = await o.unwrapKey(wrapAlgorithm, Buffer.from(wrapped, "base64url"));
      return Buffer.from(res.result);
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
