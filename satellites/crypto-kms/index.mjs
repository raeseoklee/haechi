// KMS-backed cryptoProvider for Haechi (keys.provider: external).
//
// Published as haechi-crypto-kms. It uses envelope encryption: a fresh data key
// per record encrypts the plaintext locally with AES-256-GCM, and the data key
// is wrapped by the KMS. The master key never leaves the KMS. The `kms` client is
// injected, so this package adds no runtime dependency to core — a real adapter
// swaps createInMemoryKms() for an AWS KMS / HashiCorp Vault client implementing
// the same small interface.
//
// Inject it:  createRuntime(config, { cryptoProvider: createKmsCryptoProvider({ kms }) })
// and set keys.provider: "external".

import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
// Import the canonical AAD form from core (resolved via the workspace symlink in
// dev, the consumer's installed `haechi` in production) so this satellite's AAD
// is byte-for-byte identical to the core provider's — no drift.
import { canonicalize } from "haechi/crypto";

const ALG = "AES-256-GCM";
const HMAC_KEY_DOMAIN = "haechi:crypto-kms:hmac-root:v1";

// The injected KMS client must implement:
//   keyId: string
//   async wrap(dataKey: Buffer) -> string            (KMS-encrypt a data key)
//   async unwrap(wrapped: string) -> Buffer          (KMS-decrypt it back)
//   async deriveHmacKey(domain: string) -> Buffer    (KMS-derived per-domain key)
export function createKmsCryptoProvider({ kms }) {
  if (!kms || typeof kms.wrap !== "function" || typeof kms.unwrap !== "function" || typeof kms.deriveHmacKey !== "function") {
    throw new Error("createKmsCryptoProvider requires a kms client with wrap/unwrap/deriveHmacKey");
  }

  function sha256(value) {
    // Plain SHA-256, matching Haechi's core aadHash (defence-in-depth; GCM
    // already authenticates the AAD via the tag).
    return createHash("sha256").update(value).digest("base64url");
  }

  return {
    id: "haechi.crypto.kms-reference",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: true,   // a real KMS adapter calls out to the KMS
      keyCustody: "external-kms"
    },
    async encrypt({ plaintext, aad }) {
      const dataKey = randomBytes(32);
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", dataKey, iv);
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      cipher.setAAD(aadBytes);
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        v: 1,
        alg: ALG,
        kid: kms.keyId,
        iv: iv.toString("base64url"),
        ct: ciphertext.toString("base64url"),
        tag: tag.toString("base64url"),
        wrappedKey: await kms.wrap(dataKey),
        aadHash: sha256(aadBytes)
      };
    },
    async decrypt({ envelope, aad }) {
      if (envelope.alg && envelope.alg !== ALG) {
        throw new Error(`Unsupported algorithm: ${envelope.alg}`);
      }
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      if (envelope.aadHash && envelope.aadHash !== sha256(aadBytes)) {
        throw new Error("AAD hash mismatch");
      }
      const dataKey = await kms.unwrap(envelope.wrappedKey);
      const decipher = createDecipheriv("aes-256-gcm", dataKey, Buffer.from(envelope.iv, "base64url"));
      decipher.setAAD(aadBytes);
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
      return Buffer.concat([
        decipher.update(Buffer.from(envelope.ct, "base64url")),
        decipher.final()
      ]).toString("utf8");
    },
    async hmac({ data, domain }) {
      if (!domain || typeof domain !== "string") {
        throw new Error("hmac requires a non-empty domain string");
      }
      // Domain-separated: derive a per-domain key from the KMS, then HMAC.
      const derived = await kms.deriveHmacKey(domain);
      return createHmac("sha256", derived).update(data).digest("hex");
    }
  };
}

// In-memory stand-in for AWS KMS / Vault — for examples and tests only. A real
// deployment injects a client backed by the cloud KMS.
//
// WARNING: the default masterKey is a fresh random key PER PROCESS. Anything
// encrypted in one run cannot be decrypted in the next — exactly the silent
// data-loss footgun that key rotation must avoid. For any persistence across
// restarts, supply a stable `masterKey` (or, in production, use a real KMS that
// holds the master key). This fake is NOT a production key provider.
export function createInMemoryKms({ keyId = "kms-ref-local", masterKey = randomBytes(32) } = {}) {
  return {
    keyId,
    async wrap(dataKey) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
      const ct = Buffer.concat([cipher.update(dataKey), cipher.final()]);
      const tag = cipher.getAuthTag();
      return Buffer.concat([iv, tag, ct]).toString("base64url");
    },
    async unwrap(wrapped) {
      const buffer = Buffer.from(wrapped, "base64url");
      const iv = buffer.subarray(0, 12);
      const tag = buffer.subarray(12, 28);
      const ct = buffer.subarray(28);
      const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    },
    async deriveHmacKey(domain) {
      // HKDF-SHA256, domain-separated — identical derivation to the AWS client
      // (aws.mjs), so the two clients in this package are interchangeable: the
      // same root + domain yields the same key. (Was HMAC-SHA256; aligned to the
      // standard KDF for cross-backend parity.)
      return Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), `${HMAC_KEY_DOMAIN}:${domain}`, 32));
    }
  };
}
