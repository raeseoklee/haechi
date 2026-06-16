import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const ALG = "AES-256-GCM";

// Single source of truth for parsing + validating an on-disk local key file.
// Both the provider's loadKeys() and initLocalKeyFile() (existing-file path)
// go through here so the 32-byte key invariant is enforced once. Throws a
// specific error per defect so a corrupted-but-present file is caught at init
// time instead of failing later during encrypt/decrypt/token/bundle.
//
// requireActive: init demands an explicit status:"active" key; the provider
// keeps its historical fallback to keys[0] when none is marked active.
async function loadKeyFile(keyFile, { requireActive = false } = {}) {
  const raw = JSON.parse(await readFile(keyFile, "utf8"));
  if (!raw.keys?.length) {
    throw new Error(`No keys found in ${keyFile}`);
  }
  const byKid = new Map();
  for (const entry of raw.keys) {
    const key = Buffer.from(entry.k, "base64url");
    if (key.length !== 32) {
      throw new Error("AES-256-GCM local key must be 32 bytes");
    }
    byKid.set(entry.kid, { kid: entry.kid, key });
  }
  const activeEntry = raw.keys.find((key) => key.status === "active") ?? (requireActive ? null : raw.keys[0]);
  if (!activeEntry) {
    throw new Error("No active key found in local key file");
  }
  return {
    active: byKid.get(activeEntry.kid),
    byKid
  };
}

export function createLocalCryptoProvider({ keyFile }) {
  if (!keyFile) {
    throw new Error("Local crypto provider requires keyFile");
  }

  let cachedKeys = null;

  async function loadKeys() {
    if (cachedKeys) {
      return cachedKeys;
    }
    cachedKeys = await loadKeyFile(keyFile);
    return cachedKeys;
  }

  return {
    id: "haechi.crypto.local-aes-gcm",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: false
    },
    async encrypt({ plaintext, aad }) {
      const { active: { kid, key } } = await loadKeys();
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      cipher.setAAD(aadBytes);
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        v: 1,
        alg: ALG,
        kid,
        iv: iv.toString("base64url"),
        ct: ciphertext.toString("base64url"),
        tag: tag.toString("base64url"),
        aadHash: sha256(aadBytes)
      };
    },
    // Keyed hash over a domain-separated derived key. The raw stored key is an
    // AES-256-GCM key and must never be used for HMAC directly; every use case
    // gets its own versioned domain string (e.g. deterministic tokenization,
    // identity hashing). Uses the active key, so rotation changes outputs.
    async hmac({ data, domain }) {
      if (!domain || typeof domain !== "string") {
        throw new Error("hmac requires a non-empty domain string");
      }
      const { active: { key } } = await loadKeys();
      const derived = createHmac("sha256", key).update(domain).digest();
      return createHmac("sha256", derived).update(data).digest("hex");
    },
    async decrypt({ envelope, aad }) {
      const { active, byKid } = await loadKeys();
      if (envelope.alg && envelope.alg !== ALG) {
        throw new Error(`Unsupported local crypto algorithm: ${envelope.alg}`);
      }
      const selected = envelope.kid ? byKid.get(envelope.kid) : active;
      if (!selected) {
        throw new Error(`Unknown key id in envelope: ${envelope.kid}`);
      }
      const { key } = selected;
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      if (envelope.aadHash && envelope.aadHash !== sha256(aadBytes)) {
        throw new Error("AAD hash mismatch");
      }
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
      decipher.setAAD(aadBytes);
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ct, "base64url")),
        decipher.final()
      ]);
      return plaintext.toString("utf8");
    }
  };
}

export async function initLocalKeyFile(keyFile, { force = false } = {}) {
  await mkdir(dirname(keyFile), { recursive: true });

  let existing = null;
  let fileExists = true;
  try {
    existing = JSON.parse(await readFile(keyFile, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
    fileExists = false;
  }

  if (fileExists && !force) {
    // A present key file must be usable, not merely present: validate the
    // active key (base64url, 32 bytes) and every retired key before reporting
    // success, so a corrupted file is rejected here rather than at first use.
    await loadKeyFile(keyFile, { requireActive: true });
    return { created: false, keyFile };
  }

  // Rotating with --force must not orphan existing envelopes/token vault
  // records, so prior keys are retained as retired and stay kid-addressable.
  const retiredKeys = (existing?.keys ?? []).map((key) => ({
    ...key,
    status: key.status === "active" ? "retired" : key.status
  }));

  const key = {
    version: 1,
    createdAt: new Date().toISOString(),
    keys: [
      {
        kid: `local-${Date.now()}-${randomBytes(3).toString("hex")}`,
        kty: "oct",
        alg: ALG,
        status: "active",
        k: randomBytes(32).toString("base64url")
      },
      ...retiredKeys
    ]
  };

  await writeFile(keyFile, `${JSON.stringify(key, null, 2)}\n`, { mode: 0o600 });
  return { created: true, keyFile, rotated: retiredKeys.length > 0 };
}

// Conformance suite for any cryptoProvider used via keys.provider: external.
// Adapter authors (e.g. a KMS satellite) run this to self-test against the
// contract. encrypt/decrypt are always required; hmac is required for
// tokenization, auth, deterministic tokens, and policy bundles — pass
// { requireHmac: false } for an encrypt-only provider.
export async function assertCryptoProviderConformance(provider, { requireHmac = true } = {}) {
  const failures = [];
  const check = async (name, fn) => {
    try {
      await fn();
    } catch (error) {
      failures.push(`${name}: ${error.message}`);
    }
  };
  const assert = (condition, message) => {
    if (!condition) {
      throw new Error(message);
    }
  };

  if (typeof provider?.encrypt !== "function" || typeof provider?.decrypt !== "function") {
    throw new Error("cryptoProvider must implement encrypt() and decrypt()");
  }

  const plaintext = `conformance-${randomBytes(8).toString("hex")}@example.com`;
  const aad = { purpose: "conformance", path: "messages[0].content", type: "email" };

  const other = `conformance-${randomBytes(8).toString("hex")}@example.org`;

  await check("encrypt/decrypt round-trip", async () => {
    const envelope = await provider.encrypt({ plaintext, aad });
    assert(envelope && typeof envelope === "object", "encrypt must return an envelope object");
    assert(envelope.kid, "envelope must carry a key id (kid)");
    assert(envelope.aadHash, "envelope must carry an aadHash");
    const back = await provider.decrypt({ envelope, aad });
    assert(back === plaintext, "decrypt did not return the original plaintext");
    // A second, distinct plaintext rules out a decrypt that returns a fixed value.
    const back2 = await provider.decrypt({ envelope: await provider.encrypt({ plaintext: other, aad }), aad });
    assert(back2 === other, "decrypt did not return the second plaintext (fixed/garbage output)");
  });

  await check("decrypt rejects a different AAD", async () => {
    const envelope = await provider.encrypt({ plaintext, aad });
    let rejected = false;
    try {
      await provider.decrypt({ envelope, aad: { ...aad, type: "phone" } });
    } catch {
      rejected = true;
    }
    assert(rejected, "decrypt accepted a mismatched AAD (no AAD binding)");
  });

  await check("decrypt rejects tampered ciphertext (real AEAD authentication)", async () => {
    const envelope = await provider.encrypt({ plaintext, aad });
    if (typeof envelope.ct !== "string" || envelope.ct.length === 0) {
      return; // provider uses a non-ct envelope shape; the AAD check above still applies
    }
    // Flip a byte of the ciphertext; a real AEAD provider fails the auth tag.
    const buf = Buffer.from(envelope.ct, "base64url");
    buf[0] ^= 0xff;
    let rejected = false;
    try {
      await provider.decrypt({ envelope: { ...envelope, ct: buf.toString("base64url") }, aad });
    } catch {
      rejected = true;
    }
    assert(rejected, "decrypt accepted tampered ciphertext (no AEAD authentication)");
  });

  if (requireHmac) {
    if (typeof provider.hmac !== "function") {
      failures.push("hmac: provider does not implement hmac() (required for tokenization/auth/bundles)");
    } else {
      await check("hmac is deterministic and data-dependent", async () => {
        const a = await provider.hmac({ data: "x", domain: "haechi:conformance:v1" });
        const b = await provider.hmac({ data: "x", domain: "haechi:conformance:v1" });
        assert(typeof a === "string" && a.length > 0, "hmac must return a non-empty string");
        assert(a === b, "hmac is not deterministic for the same (data, domain)");
        // Different data MUST give different output — else tokens/identities collide.
        const c = await provider.hmac({ data: "y", domain: "haechi:conformance:v1" });
        assert(a !== c, "hmac ignores the data argument (same output for different data)");
      });
      await check("hmac separates domains", async () => {
        const a = await provider.hmac({ data: "x", domain: "haechi:conformance:a" });
        const b = await provider.hmac({ data: "x", domain: "haechi:conformance:b" });
        assert(a !== b, "hmac does not separate domains (same output for different domains)");
      });
      await check("hmac requires a domain", async () => {
        for (const badDomain of ["", undefined, null]) {
          let rejected = false;
          try {
            await provider.hmac({ data: "x", domain: badDomain });
          } catch {
            rejected = true;
          }
          assert(rejected, `hmac accepted an invalid domain (${JSON.stringify(badDomain)})`);
        }
      });
    }
  }

  if (failures.length > 0) {
    throw new Error(`cryptoProvider conformance failed:\n- ${failures.join("\n- ")}`);
  }
  return { ok: true };
}

export function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("base64url");
}
