// AWS KMS client for haechi-crypto-kms.
//
// Returns a `kms` client (the same small interface createInMemoryKms implements:
// keyId / wrap / unwrap / deriveHmacKey) backed by AWS KMS, so it plugs straight
// into createKmsCryptoProvider({ kms }). Envelope wrapping uses KMS Encrypt/Decrypt
// on a CSPRNG-generated 32-byte data key (the provider generates the data key;
// KMS only ever holds the master key). HMAC keys are HKDF-derived from a single
// KMS-decrypted root, so per-domain keys are deterministic and domain-separated
// without a network round-trip per token.
//
// @aws-sdk/client-kms is an OPTIONAL peer dependency: it is imported lazily, only
// when no `client` is injected. Tests inject a faithful mock of the two KMS
// operations, so the suite needs neither the SDK nor network access.

import { hkdfSync } from "node:crypto";

const HMAC_ROOT_INFO = "haechi:crypto-kms:hmac-root:v1";

// The minimal KMS operation surface the client needs:
//   encrypt({ KeyId, Plaintext: Buffer }) -> { CiphertextBlob: Uint8Array }
//   decrypt({ CiphertextBlob: Uint8Array, KeyId }) -> { Plaintext: Uint8Array }
// In production these wrap the AWS SDK's Encrypt/Decrypt commands; in tests a
// mock implements them directly.
export function createAwsKmsClient({ keyId, region, client, hmacRootCiphertext } = {}) {
  if (!keyId || typeof keyId !== "string") {
    throw new Error("createAwsKmsClient requires a keyId (a KMS key id/ARN/alias)");
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
          sdk = await import("@aws-sdk/client-kms");
        } catch {
          throw new Error(
            "@aws-sdk/client-kms is not installed. Install it (it is an optional peer dependency) or inject a `client` with encrypt/decrypt."
          );
        }
        const kms = new sdk.KMSClient(region ? { region } : {});
        return {
          encrypt: (params) => kms.send(new sdk.EncryptCommand(params)),
          decrypt: (params) => kms.send(new sdk.DecryptCommand(params))
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
        "deriveHmacKey requires hmacRootCiphertext: a base64url KMS-encrypted 32-byte root. Omit hmac (encrypt-only) if you do not tokenize/authenticate."
      );
    }
    if (!hmacRootPromise) {
      // Don't cache a rejection: a transient KMS Decrypt failure (throttling,
      // network) should be retryable, not poison hmac for the client's lifetime.
      hmacRootPromise = (async () => {
        const o = await ops();
        const res = await o.decrypt({ CiphertextBlob: Buffer.from(hmacRootCiphertext, "base64url"), KeyId: keyId });
        const root = Buffer.from(res.Plaintext);
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
    keyId,
    async wrap(dataKey) {
      const o = await ops();
      const res = await o.encrypt({ KeyId: keyId, Plaintext: Buffer.from(dataKey) });
      return Buffer.from(res.CiphertextBlob).toString("base64url");
    },
    async unwrap(wrapped) {
      const o = await ops();
      const res = await o.decrypt({ CiphertextBlob: Buffer.from(wrapped, "base64url"), KeyId: keyId });
      return Buffer.from(res.Plaintext);
    },
    async deriveHmacKey(domain) {
      if (!domain || typeof domain !== "string") {
        throw new Error("deriveHmacKey requires a non-empty domain string");
      }
      const root = await hmacRoot();
      // HKDF-SHA256, domain-separated — matches Haechi's per-domain key discipline.
      return Buffer.from(hkdfSync("sha256", root, Buffer.alloc(0), `${HMAC_ROOT_INFO}:${domain}`, 32));
    }
  };
}
